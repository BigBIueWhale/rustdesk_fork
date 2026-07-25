#!/usr/bin/env python3
"""Prove exact server process identities inside isolated smoke containers."""

import argparse
import errno
import os
import stat
import sys
import time
import uuid


NEUTRAL_ARGV0 = b"rd-smoke-server"
SERVER_ROLE = b"--server"
SERVICE_OWNED_ROLE = b"--service-owned-server"
MAX_CMDLINE_BYTES = 1024 * 1024
IDENTITY_POLL_INTERVAL_SECONDS = 0.01
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


def server_argv_is_expected(argv, service_owned):
    expected = [NEUTRAL_ARGV0, SERVER_ROLE]
    if service_owned:
        expected.append(SERVICE_OWNED_ROLE)
    return argv == expected


def server_identity_matches(pid, expected_start, expected_metadata, service_owned):
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
    return server_argv_is_expected(argv, service_owned)


def wait_server(pid, expected_start, executable_path):
    expected = expected_executable_metadata(executable_path)
    deadline = time.monotonic() + READY_WAIT_SECONDS
    while time.monotonic() < deadline:
        if server_identity_matches(pid, expected_start, expected, False):
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
        time.sleep(IDENTITY_POLL_INTERVAL_SECONDS)
    fail("server did not reach the exact executable and neutral-argv role identity")


def service_server_authority_matches(
    pid, expected_start, expected_metadata, expected_parent, expected_generation
):
    if not server_identity_matches(
        pid,
        expected_start,
        expected_metadata,
        True,
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
        time.sleep(IDENTITY_POLL_INTERVAL_SECONDS)
    fail("service-owned server did not reach its exact executable, role, and launch authority")


def self_test():
    ordinary = [NEUTRAL_ARGV0, SERVER_ROLE]
    service_owned = ordinary + [SERVICE_OWNED_ROLE]
    if not server_argv_is_expected(ordinary, False):
        fail("ordinary exact-role fixture was rejected")
    if not server_argv_is_expected(service_owned, True):
        fail("service-owned exact-role fixture was rejected")
    for argv, role in (
        ([b"rustdesk", SERVER_ROLE], False),
        ([NEUTRAL_ARGV0, b"--Server"], False),
        ([NEUTRAL_ARGV0, SERVER_ROLE, b"--extra"], False),
        (ordinary, True),
        (service_owned, False),
    ):
        if server_argv_is_expected(argv, role):
            fail("non-exact server role fixture was accepted")
    if not process_entry_vanished(ProcessLookupError(errno.ESRCH, "vanished")):
        fail("process-exit race is not classified as a vanished proc entry")
    if process_entry_vanished(PermissionError(errno.EACCES, "denied")):
        fail("proc permission failure was misclassified as a process-exit race")
    print("smoke process guard self-test: PASS")


def parse_args(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command")
    commands.required = True
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
    if args.command == "wait-server":
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
