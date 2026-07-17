#!/usr/bin/env python3
"""Prove the release smoke cannot be selected by the historical host cleanup."""

import argparse
import errno
import json
import os
import re
import stat
import sys
import tempfile
import time
import uuid


SELECTOR = re.compile(br"rustdesk +--server")
NEUTRAL_ARGV0 = b"rd-smoke-server"
SERVER_ROLE = b"--server"
SERVICE_OWNED_ROLE = b"--service-owned-server"
MAX_CMDLINE_BYTES = 1024 * 1024
MAX_RECORD_BYTES = 1024 * 1024
MONITOR_INTERVAL_SECONDS = 0.01
READY_WAIT_SECONDS = 10


class GuardError(Exception):
    pass


def fail(message):
    raise GuardError(message)


def parse_positive_integer(raw, label):
    if not raw.isdigit() or raw.startswith("0"):
        fail("invalid {}: {}".format(label, raw))
    value = int(raw)
    if value <= 0:
        fail("invalid {}: {}".format(label, raw))
    return value


def process_entry_vanished(error):
    return error.errno in (errno.ENOENT, errno.ESRCH)


def read_process_identity(pid, proc_root="/proc"):
    path = os.path.join(proc_root, str(pid), "stat")
    try:
        with open(path, "rb") as stream:
            raw = stream.read(65537)
    except OSError as error:
        if process_entry_vanished(error):
            return None
        fail("cannot read process identity {}: {}".format(pid, error))
    if len(raw) > 65536 or b") " not in raw:
        fail("invalid process identity record: {}".format(pid))
    fields = raw.rsplit(b") ", 1)[1].split()
    if len(fields) < 20:
        fail("short process identity record: {}".format(pid))
    try:
        state = fields[0]
        start = int(fields[19])
    except (ValueError, IndexError):
        fail("invalid process start identity: {}".format(pid))
    if len(state) != 1 or start <= 0:
        fail("invalid process state or start identity: {}".format(pid))
    return state, start


def read_process_cmdline(pid, proc_root="/proc"):
    path = os.path.join(proc_root, str(pid), "cmdline")
    try:
        with open(path, "rb") as stream:
            raw = stream.read(MAX_CMDLINE_BYTES + 1)
    except OSError as error:
        if process_entry_vanished(error):
            return None
        fail("cannot read process command line {}: {}".format(pid, error))
    if len(raw) > MAX_CMDLINE_BYTES:
        fail("process command line exceeds guard bound: {}".format(pid))
    return raw


def visible_command(cmdline):
    return cmdline.rstrip(b"\0").replace(b"\0", b" ")


def selector_matches_cmdline(cmdline):
    return SELECTOR.search(visible_command(cmdline)) is not None


def process_record(pid, start, cmdline):
    return {
        "pid": pid,
        "start": start,
        "cmdline_hex": cmdline.hex(),
    }


def record_key(record):
    return record["pid"], record["start"], record["cmdline_hex"]


def scan_matching_processes(proc_root="/proc"):
    try:
        names = os.listdir(proc_root)
    except OSError as error:
        fail("cannot enumerate host process table: {}".format(error))
    pids = sorted(int(name) for name in names if name.isdigit())
    matches = []
    for pid in pids:
        before = read_process_identity(pid, proc_root)
        if before is None:
            continue
        cmdline = read_process_cmdline(pid, proc_root)
        if cmdline is None:
            continue
        after = read_process_identity(pid, proc_root)
        if after is None or before != after:
            continue
        state, start = after
        if state in (b"Z", b"X") or not cmdline:
            continue
        if selector_matches_cmdline(cmdline):
            matches.append(process_record(pid, start, cmdline))
    matches.sort(key=record_key)
    return matches


def validate_private_regular(path, maximum_size, exact_mode=0o600):
    try:
        metadata = os.lstat(path)
    except OSError as error:
        fail("cannot inspect private guard file {}: {}".format(path, error))
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        fail("guard file is not a single-linked regular file: {}".format(path))
    if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != exact_mode:
        fail("guard file has unexpected owner or mode: {}".format(path))
    if metadata.st_size > maximum_size:
        fail("guard file exceeds size bound: {}".format(path))
    return metadata


def write_exclusive(path, payload):
    if len(payload) > MAX_RECORD_BYTES:
        fail("guard record exceeds size bound")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as error:
        fail("cannot create private guard file {}: {}".format(path, error))
    failure = None
    try:
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException as error:
        failure = error
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError as error:
                if failure is None:
                    failure = error
    if failure is not None:
        fail("cannot commit private guard file {}: {}".format(path, failure))
    validate_private_regular(path, MAX_RECORD_BYTES)


def read_json_record(path):
    expected = validate_private_regular(path, MAX_RECORD_BYTES)
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        fail("cannot open private guard record {}: {}".format(path, error))
    try:
        observed = os.fstat(descriptor)
        if (observed.st_dev, observed.st_ino) != (expected.st_dev, expected.st_ino):
            fail("private guard record changed while being opened: {}".format(path))
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            raw = stream.read(MAX_RECORD_BYTES + 1)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(raw) > MAX_RECORD_BYTES:
        fail("private guard record exceeds size bound: {}".format(path))
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, ValueError) as error:
        fail("invalid private guard record {}: {}".format(path, error))
    return value


def validate_baseline(value):
    if not isinstance(value, dict) or value.get("version") != 1:
        fail("unsupported historical-selector baseline")
    matches = value.get("matches")
    if not isinstance(matches, list):
        fail("historical-selector baseline has no match list")
    result = []
    for item in matches:
        if not isinstance(item, dict) or set(item) != {"pid", "start", "cmdline_hex"}:
            fail("invalid historical-selector baseline entry")
        pid = item["pid"]
        start = item["start"]
        cmdline_hex = item["cmdline_hex"]
        if not isinstance(pid, int) or pid <= 0 or not isinstance(start, int) or start <= 0:
            fail("invalid historical-selector baseline identity")
        if not isinstance(cmdline_hex, str) or len(cmdline_hex) > MAX_CMDLINE_BYTES * 2:
            fail("invalid historical-selector baseline command line")
        try:
            cmdline = bytes.fromhex(cmdline_hex)
        except ValueError:
            fail("non-hex historical-selector baseline command line")
        if not selector_matches_cmdline(cmdline):
            fail("baseline entry does not match the historical selector")
        result.append(item)
    result.sort(key=record_key)
    if len({record_key(item) for item in result}) != len(result):
        fail("duplicate historical-selector baseline identity")
    return result


def new_matches(baseline, current):
    admitted = {record_key(item) for item in baseline}
    return [item for item in current if record_key(item) not in admitted]


def stable_baseline():
    previous = None
    deadline = time.monotonic() + READY_WAIT_SECONDS
    while time.monotonic() < deadline:
        current = scan_matching_processes()
        if previous == current:
            return current
        previous = current
        time.sleep(MONITOR_INTERVAL_SECONDS)
    fail("historical-selector baseline did not stabilize")


def record_baseline(path):
    matches = stable_baseline()
    payload = json.dumps(
        {"version": 1, "matches": matches}, sort_keys=True, separators=(",", ":")
    ).encode("ascii") + b"\n"
    write_exclusive(path, payload)
    print("SMOKE_HOST_BASELINE_OK matches={}".format(len(matches)))


def stop_requested(path):
    if not os.path.lexists(path):
        return False
    validate_private_regular(path, 16)
    try:
        with open(path, "rb") as stream:
            raw = stream.read(17)
    except OSError as error:
        fail("cannot read monitor stop request: {}".format(error))
    if raw != b"stop\n":
        fail("invalid monitor stop request")
    return True


def monitor(baseline_path, ready_path, stop_path, violation_path):
    baseline = validate_baseline(read_json_record(baseline_path))
    current = scan_matching_processes()
    violations = new_matches(baseline, current)
    if violations:
        write_violation(violation_path, violations)
        fail("new historical-selector match appeared before monitor readiness")
    write_exclusive(ready_path, b"ready\n")
    while True:
        current = scan_matching_processes()
        violations = new_matches(baseline, current)
        if violations:
            write_violation(violation_path, violations)
            fail("new host process matched the historical RustDesk cleanup selector")
        if stop_requested(stop_path):
            final = scan_matching_processes()
            violations = new_matches(baseline, final)
            if violations:
                write_violation(violation_path, violations)
                fail("new historical-selector match appeared during final monitor scan")
            print("SMOKE_HOST_MONITOR_OK baseline_matches={}".format(len(baseline)))
            return
        time.sleep(MONITOR_INTERVAL_SECONDS)


def write_violation(path, violations):
    payload = json.dumps(
        {"version": 1, "new_matches": violations}, sort_keys=True, separators=(",", ":")
    ).encode("ascii") + b"\n"
    write_exclusive(path, payload)


def request_stop(path):
    write_exclusive(path, b"stop\n")


def process_is_same_and_running(pid, expected_start):
    identity = read_process_identity(pid)
    if identity is None:
        return False
    state, start = identity
    if start != expected_start:
        fail("monitor pid identity changed")
    return state not in (b"Z", b"X")


def wait_ready(pid, expected_start, ready_path):
    deadline = time.monotonic() + READY_WAIT_SECONDS
    while time.monotonic() < deadline:
        if not process_is_same_and_running(pid, expected_start):
            fail("host monitor exited before readiness")
        if os.path.lexists(ready_path):
            validate_private_regular(ready_path, 16)
            with open(ready_path, "rb") as stream:
                if stream.read(17) != b"ready\n":
                    fail("invalid host monitor readiness record")
            print("SMOKE_HOST_MONITOR_READY")
            return
        time.sleep(MONITOR_INTERVAL_SECONDS)
    fail("host monitor readiness deadline expired")


def expected_executable_metadata(path):
    if not os.path.isabs(path):
        fail("expected server executable path is not absolute")
    try:
        metadata = os.lstat(path)
    except OSError as error:
        fail("cannot inspect expected server executable: {}".format(error))
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o111 == 0:
        fail("expected server executable is not an executable regular file")
    return metadata


def server_identity_matches(pid, expected_start, expected_metadata, expected_argv):
    identity = read_process_identity(pid)
    if identity is None:
        return False
    state, start = identity
    if start != expected_start:
        fail("server pid identity changed before executable proof")
    if state in (b"Z", b"X"):
        return False
    try:
        executable = os.stat("/proc/{}/exe".format(pid))
    except OSError as error:
        if process_entry_vanished(error):
            return False
        fail("cannot inspect running server executable: {}".format(error))
    if (executable.st_dev, executable.st_ino) != (
        expected_metadata.st_dev,
        expected_metadata.st_ino,
    ):
        return False
    cmdline = read_process_cmdline(pid)
    if cmdline is None or not cmdline.endswith(b"\0"):
        return False
    argv = cmdline[:-1].split(b"\0")
    return argv == expected_argv


def wait_server(pid, expected_start, executable_path):
    expected = expected_executable_metadata(executable_path)
    deadline = time.monotonic() + READY_WAIT_SECONDS
    while time.monotonic() < deadline:
        if server_identity_matches(
            pid, expected_start, expected, [NEUTRAL_ARGV0, SERVER_ROLE]
        ):
            print(
                "SMOKE_SERVER_IDENTITY_OK pid={} exe_dev={} exe_ino={} argv0={} role={}".format(
                    pid,
                    expected.st_dev,
                    expected.st_ino,
                    NEUTRAL_ARGV0.decode("ascii"),
                    SERVER_ROLE.decode("ascii"),
                )
            )
            return
        time.sleep(MONITOR_INTERVAL_SECONDS)
    fail("server did not reach the exact executable and neutral-argv role identity")


def service_server_authority_matches(
    pid, expected_start, expected_metadata, expected_parent, expected_generation
):
    if not server_identity_matches(
        pid,
        expected_start,
        expected_metadata,
        [NEUTRAL_ARGV0, SERVER_ROLE, SERVICE_OWNED_ROLE],
    ):
        return False
    try:
        with open("/proc/{}/status".format(pid), "r", encoding="ascii") as stream:
            status = {
                line.split(":", 1)[0]: line.split(":", 1)[1].strip()
                for line in stream
                if ":" in line
            }
        with open("/proc/{}/environ".format(pid), "rb") as stream:
            raw_environment = stream.read(MAX_CMDLINE_BYTES + 1)
    except OSError as error:
        if process_entry_vanished(error):
            return False
        fail("cannot inspect service-owned smoke server authority: {}".format(error))
    if len(raw_environment) > MAX_CMDLINE_BYTES:
        fail("service-owned smoke server environment exceeds the proof bound")
    environment = [entry for entry in raw_environment.split(b"\0") if entry]
    if status.get("PPid") != str(expected_parent):
        return False
    if status.get("Uid", "").split() != ["0"] * 4 or status.get("NoNewPrivs") != "1":
        return False
    for capability_set in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
        if int(status.get(capability_set, "1"), 16) != 0:
            return False
    expected_entries = {
        "RUSTDESK_SERVICE_OWNED_SERVER_LAUNCH_PARENT={}".format(expected_parent).encode("ascii"),
        b"RUSTDESK_SERVICE_OWNED_SERVER_GENERATION=" + expected_generation,
    }
    if not expected_entries.issubset(set(environment)):
        return False
    matching_generations = [
        entry
        for entry in environment
        if entry.startswith(b"RUSTDESK_SERVICE_OWNED_SERVER_GENERATION=")
    ]
    if matching_generations != [
        b"RUSTDESK_SERVICE_OWNED_SERVER_GENERATION=" + expected_generation
    ]:
        return False
    final_identity = read_process_identity(pid)
    return final_identity is not None and final_identity[1] == expected_start


def wait_service_server(pid, expected_start, executable_path, expected_parent, generation):
    try:
        canonical_generation = str(uuid.UUID(generation))
    except (ValueError, AttributeError):
        fail("service-owned smoke generation is not a UUID")
    if canonical_generation != generation:
        fail("service-owned smoke generation is not canonical")
    expected = expected_executable_metadata(executable_path)
    generation_bytes = generation.encode("ascii")
    deadline = time.monotonic() + READY_WAIT_SECONDS
    while time.monotonic() < deadline:
        if service_server_authority_matches(
            pid,
            expected_start,
            expected,
            expected_parent,
            generation_bytes,
        ):
            print(
                "SMOKE_SERVICE_SERVER_IDENTITY_OK pid={} exe_dev={} exe_ino={} "
                "argv0={} role={} marker={} generation={}".format(
                    pid,
                    expected.st_dev,
                    expected.st_ino,
                    NEUTRAL_ARGV0.decode("ascii"),
                    SERVER_ROLE.decode("ascii"),
                    SERVICE_OWNED_ROLE.decode("ascii"),
                    generation,
                )
            )
            return
        time.sleep(MONITOR_INTERVAL_SECONDS)
    fail("service-owned server did not reach its exact executable, role, and launch authority")


def self_test():
    production = b"rustdesk\0--server\0"
    installed = b"/usr/share/rustdesk/rustdesk\0--server\0"
    neutral = NEUTRAL_ARGV0 + b"\0" + SERVER_ROLE + b"\0"
    neutral_service = neutral + SERVICE_OWNED_ROLE + b"\0"
    launcher = b"/work/target/smoke-server-launcher\0/work/target/debug/rustdesk\0"
    inline = b"bash\0-c\0./target/debug/rustdesk --server\0"
    if not selector_matches_cmdline(production):
        fail("selector fixture did not select production argv")
    if not selector_matches_cmdline(installed):
        fail("selector fixture did not select installed production argv")
    if not selector_matches_cmdline(inline):
        fail("selector fixture did not select an inline container shell")
    if selector_matches_cmdline(neutral):
        fail("selector fixture selected neutral smoke server argv")
    if selector_matches_cmdline(neutral_service):
        fail("selector fixture selected neutral service-owned smoke server argv")
    if selector_matches_cmdline(launcher):
        fail("selector fixture selected the smoke launcher argv")
    if not process_entry_vanished(ProcessLookupError(errno.ESRCH, "vanished")):
        fail("process-exit race is not classified as a vanished proc entry")
    if process_entry_vanished(PermissionError(errno.EACCES, "denied")):
        fail("proc permission failure was misclassified as a process-exit race")
    baseline = [process_record(101, 202, production)]
    all_processes = baseline + [process_record(303, 404, neutral)]
    current = [
        item
        for item in all_processes
        if selector_matches_cmdline(bytes.fromhex(item["cmdline_hex"]))
    ]
    if new_matches(baseline, current):
        fail("baseline fixture rejected an admitted pre-existing production match")
    current.append(process_record(505, 606, installed))
    found = new_matches(baseline, current)
    if len(found) != 1 or found[0]["pid"] != 505:
        fail("baseline fixture did not reject a new production-shaped match")
    with tempfile.TemporaryDirectory(prefix="rd-smoke-guard-self-test.") as root:
        baseline_path = os.path.join(root, "baseline.json")
        write_exclusive(
            baseline_path,
            json.dumps({"version": 1, "matches": baseline}).encode("ascii") + b"\n",
        )
        decoded = validate_baseline(read_json_record(baseline_path))
        if decoded != baseline:
            fail("baseline record round trip changed its contents")
    print("smoke process guard self-test: PASS")


def parse_args(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command")
    commands.required = True
    record = commands.add_parser("record")
    record.add_argument("baseline")
    monitor_parser = commands.add_parser("monitor")
    monitor_parser.add_argument("baseline")
    monitor_parser.add_argument("ready")
    monitor_parser.add_argument("stop")
    monitor_parser.add_argument("violation")
    stop = commands.add_parser("request-stop")
    stop.add_argument("stop")
    wait = commands.add_parser("wait-ready")
    wait.add_argument("pid")
    wait.add_argument("start")
    wait.add_argument("ready")
    server = commands.add_parser("wait-server")
    server.add_argument("pid")
    server.add_argument("start")
    server.add_argument("executable")
    service_server = commands.add_parser("wait-service-server")
    service_server.add_argument("pid")
    service_server.add_argument("start")
    service_server.add_argument("executable")
    service_server.add_argument("parent")
    service_server.add_argument("generation")
    commands.add_parser("self-test")
    return parser.parse_args(argv)


def main(argv):
    args = parse_args(argv)
    if args.command == "record":
        record_baseline(args.baseline)
    elif args.command == "monitor":
        monitor(args.baseline, args.ready, args.stop, args.violation)
    elif args.command == "request-stop":
        request_stop(args.stop)
    elif args.command == "wait-ready":
        wait_ready(
            parse_positive_integer(args.pid, "pid"),
            parse_positive_integer(args.start, "start identity"),
            args.ready,
        )
    elif args.command == "wait-server":
        wait_server(
            parse_positive_integer(args.pid, "pid"),
            parse_positive_integer(args.start, "start identity"),
            args.executable,
        )
    elif args.command == "wait-service-server":
        wait_service_server(
            parse_positive_integer(args.pid, "pid"),
            parse_positive_integer(args.start, "start identity"),
            args.executable,
            parse_positive_integer(args.parent, "launch parent"),
            args.generation,
        )
    elif args.command == "self-test":
        self_test()
    else:
        fail("unsupported guard operation")


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except GuardError as error:
        print("smoke process guard: FAIL: {}".format(error), file=sys.stderr)
        raise SystemExit(1)
