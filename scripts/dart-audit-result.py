#!/usr/bin/env python3
"""Prepare and validate one offline Dart/Pub advisory transaction."""

import argparse
from contextlib import redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import time


ADVISORY_ID = re.compile(r"[A-Za-z0-9_.:-]+\Z")
ALLOWED_SCANNER_STATUSES = frozenset((0, 1))
MAX_POLICY_BYTES = 4 * 1024 * 1024
MAX_LOCKFILE_BYTES = 64 * 1024 * 1024
MAX_RESULT_BYTES = 64 * 1024 * 1024
MAX_STDERR_BYTES = 1024 * 1024
EXPECTED_SCANNER_LOCKFILE = "/work/flutter/pubspec.lock"
EXPECTED_SCANNER_DATABASE = "/opt/osv-db/osv-scanner/Pub/all.zip"
EXPECTED_DB_MAX_AGE_DAYS = 30


class AuditResultError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise AuditResultError(message)


def metadata_identity(metadata):
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def stable_read(path, maximum_bytes=None):
    try:
        metadata = os.lstat(str(path))
    except OSError as exc:
        raise AuditResultError("cannot inspect {}: {}".format(path, exc))
    require(not stat.S_ISLNK(metadata.st_mode), "refusing symlink input: {}".format(path))
    require(stat.S_ISREG(metadata.st_mode), "input is not a regular file: {}".format(path))
    require(metadata.st_nlink == 1, "refusing hardlinked input: {}".format(path))
    if maximum_bytes is not None:
        require(
            metadata.st_size <= maximum_bytes,
            "input exceeds {} bytes: {}".format(maximum_bytes, path),
        )

    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(str(path), flags)
    except OSError as exc:
        raise AuditResultError("cannot open {}: {}".format(path, exc))
    try:
        opened = os.fstat(descriptor)
        require(
            metadata_identity(metadata) == metadata_identity(opened),
            "input changed while opening: {}".format(path),
        )
        chunks = []
        total = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if maximum_bytes is not None:
                require(
                    total <= maximum_bytes,
                    "input exceeds {} bytes: {}".format(maximum_bytes, path),
                )
            chunks.append(chunk)
        closed = os.fstat(descriptor)
        require(
            metadata_identity(opened) == metadata_identity(closed),
            "input changed while reading: {}".format(path),
        )
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def read_regular_file(path, maximum_bytes=None):
    raw = stable_read(path, maximum_bytes)
    try:
        return raw.decode("utf-8")
    except UnicodeError as exc:
        raise AuditResultError("cannot read UTF-8 input {}: {}".format(path, exc))


def write_new(path, data, mode=0o600):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(str(path), flags, mode)
    try:
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            require(written > 0, "short write while creating {}".format(path))
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def parse_policy_source(source, path):
    accepted = set()
    for line_number, raw in enumerate(source.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        body, separator, reason = raw.partition("#")
        tokens = body.split()
        require(
            len(tokens) == 1,
            "{}:{}: expected exactly one advisory id".format(path, line_number),
        )
        require(
            bool(separator and reason.strip()),
            "{}:{}: accepted advisory has no reason".format(path, line_number),
        )
        require(
            not any(ord(character) < 0x20 and character != "\t" for character in reason),
            "{}:{}: accepted advisory reason contains a control character".format(
                path, line_number
            ),
        )
        advisory_id = tokens[0]
        require(
            ADVISORY_ID.fullmatch(advisory_id) is not None,
            "{}:{}: invalid advisory id {!r}".format(path, line_number, advisory_id),
        )
        require(
            advisory_id not in accepted,
            "{}:{}: duplicate advisory id {}".format(path, line_number, advisory_id),
        )
        accepted.add(advisory_id)
    return accepted


def parse_policy(path):
    return parse_policy_source(read_regular_file(path, MAX_POLICY_BYTES), path)


def prepare(policy_path, lockfile_path, output):
    try:
        directory = os.lstat(str(output))
    except OSError as exc:
        raise AuditResultError("cannot inspect private output directory {}: {}".format(output, exc))
    require(not stat.S_ISLNK(directory.st_mode), "private output directory is a symlink")
    require(stat.S_ISDIR(directory.st_mode), "private output path is not a directory")
    require(directory.st_uid == os.geteuid(), "private output directory has the wrong owner")
    require(stat.S_IMODE(directory.st_mode) == 0o700, "private output directory must be mode 0700")

    policy_raw = stable_read(policy_path, MAX_POLICY_BYTES)
    try:
        policy_text = policy_raw.decode("utf-8")
    except UnicodeError as exc:
        raise AuditResultError("cannot decode policy {}: {}".format(policy_path, exc))
    accepted = parse_policy_source(policy_text, policy_path)

    lockfile_raw = stable_read(lockfile_path, MAX_LOCKFILE_BYTES)
    require(bool(lockfile_raw), "{} is empty".format(lockfile_path))
    try:
        lockfile_text = lockfile_raw.decode("utf-8")
    except UnicodeError as exc:
        raise AuditResultError("cannot decode lockfile {}: {}".format(lockfile_path, exc))
    require(
        sum(1 for line in lockfile_text.splitlines() if line == "packages:") == 1,
        "{} must contain exactly one top-level packages map".format(lockfile_path),
    )

    write_new(output / "policy.txt", policy_raw)
    write_new(output / "pubspec.lock", lockfile_raw)
    write_new(
        output / "policy.sha256",
        (hashlib.sha256(policy_raw).hexdigest() + "\n").encode("ascii"),
    )
    write_new(
        output / "lockfile.sha256",
        (hashlib.sha256(lockfile_raw).hexdigest() + "\n").encode("ascii"),
    )
    print(len(accepted))
    return 0


def parse_canonical_integer(value, label):
    require(re.fullmatch(r"0|[1-9][0-9]*", value) is not None, "{} is not canonical".format(label))
    return int(value)


def require_fresh(capture_epoch, maximum_days, now_epoch):
    require(
        maximum_days == EXPECTED_DB_MAX_AGE_DAYS,
        "OSV Pub maximum snapshot age must remain exactly {} days".format(
            EXPECTED_DB_MAX_AGE_DAYS
        ),
    )
    age = now_epoch - capture_epoch
    require(age >= -86400, "OSV Pub snapshot capture is more than one day in the future")
    require(
        age <= maximum_days * 86400,
        "OSV Pub snapshot is stale: capture age {} days exceeds the {}-day release limit".format(
            max(0, age // 86400), maximum_days
        ),
    )


def check_freshness(capture_epoch, maximum_days):
    capture = parse_canonical_integer(capture_epoch, "OSV Pub capture epoch")
    days = parse_canonical_integer(maximum_days, "maximum OSV Pub age")
    require_fresh(capture, days, int(time.time()))
    print("fresh")
    return 0


def require_string(value, label):
    require(isinstance(value, str) and bool(value), "{} must be a nonempty string".format(label))
    return value


def require_advisory_id(value, label):
    value = require_string(value, label)
    require(ADVISORY_ID.fullmatch(value) is not None, "{} is malformed".format(label))
    return value


def fixed_version(vulnerability, label):
    affected = vulnerability.get("affected", [])
    require(isinstance(affected, list), "{}.affected must be a list".format(label))
    fixed = ""
    for affected_index, affected_entry in enumerate(affected):
        affected_label = "{}.affected[{}]".format(label, affected_index)
        require(isinstance(affected_entry, dict), "{} must be an object".format(affected_label))
        ranges = affected_entry.get("ranges", [])
        require(isinstance(ranges, list), "{}.ranges must be a list".format(affected_label))
        for range_index, range_entry in enumerate(ranges):
            range_label = "{}.ranges[{}]".format(affected_label, range_index)
            require(isinstance(range_entry, dict), "{} must be an object".format(range_label))
            events = range_entry.get("events", [])
            require(isinstance(events, list), "{}.events must be a list".format(range_label))
            for event_index, event in enumerate(events):
                event_label = "{}.events[{}]".format(range_label, event_index)
                require(isinstance(event, dict), "{} must be an object".format(event_label))
                if "fixed" in event:
                    fixed = require_string(event["fixed"], "{}.fixed".format(event_label))
    return fixed


def parse_findings(data, expected_source):
    require(isinstance(data, dict), "OSV result root must be an object")
    results = data.get("results")
    require(isinstance(results, list), "OSV result must contain a results list")
    require(len(results) <= 1, "one lockfile scan produced more than one result source")
    findings = []
    for result_index, result in enumerate(results):
        result_label = "results[{}]".format(result_index)
        require(isinstance(result, dict), "{} must be an object".format(result_label))
        source = result.get("source")
        require(isinstance(source, dict), "{}.source must be an object".format(result_label))
        require(
            source.get("path") == expected_source and source.get("type") == "lockfile",
            "{}.source does not name the exact mounted lockfile".format(result_label),
        )
        packages = result.get("packages")
        require(isinstance(packages, list) and bool(packages), "{}.packages must be a nonempty list".format(result_label))
        for package_index, package_entry in enumerate(packages):
            package_label = "{}.packages[{}]".format(result_label, package_index)
            require(isinstance(package_entry, dict), "{} must be an object".format(package_label))
            package = package_entry.get("package")
            require(isinstance(package, dict), "{}.package must be an object".format(package_label))
            name = require_string(package.get("name"), "{}.package.name".format(package_label))
            version = require_string(
                package.get("version"), "{}.package.version".format(package_label)
            )
            require(
                package.get("ecosystem") == "Pub",
                "{}.package.ecosystem must be Pub".format(package_label),
            )
            vulnerabilities = package_entry.get("vulnerabilities")
            require(
                isinstance(vulnerabilities, list) and bool(vulnerabilities),
                "{}.vulnerabilities must be a nonempty list".format(package_label),
            )
            for vulnerability_index, vulnerability in enumerate(vulnerabilities):
                vulnerability_label = "{}.vulnerabilities[{}]".format(
                    package_label, vulnerability_index
                )
                require(
                    isinstance(vulnerability, dict),
                    "{} must be an object".format(vulnerability_label),
                )
                advisory_id = require_advisory_id(
                    vulnerability.get("id"), "{}.id".format(vulnerability_label)
                )
                aliases_value = vulnerability.get("aliases", [])
                require(
                    isinstance(aliases_value, list),
                    "{}.aliases must be a list".format(vulnerability_label),
                )
                aliases = set()
                for alias_index, alias in enumerate(aliases_value):
                    alias = require_advisory_id(
                        alias, "{}.aliases[{}]".format(vulnerability_label, alias_index)
                    )
                    require(alias != advisory_id, "{} repeats the canonical id".format(vulnerability_label))
                    require(alias not in aliases, "{} contains a duplicate alias".format(vulnerability_label))
                    aliases.add(alias)
                findings.append(
                    (
                        advisory_id,
                        aliases,
                        name,
                        version,
                        fixed_version(vulnerability, vulnerability_label),
                    )
                )
    return findings


def load_result(path):
    source = read_regular_file(path, MAX_RESULT_BYTES)
    require(bool(source.strip()), "OSV scanner produced an empty result")
    try:
        return json.loads(source)
    except (TypeError, ValueError) as exc:
        raise AuditResultError("OSV scanner result is not valid JSON: {}".format(exc))


def validate_scanner_stderr(path, expected_source):
    source = read_regular_file(path, MAX_STDERR_BYTES)
    require("\r" not in source, "OSV scanner stderr contains a carriage return")
    lines = source.splitlines()
    require(len(lines) == 4, "OSV scanner stderr must contain exactly four telemetry lines")
    require(lines[0] == "Starting filesystem walk for root: /", "unexpected OSV walk diagnostic")
    package_match = re.fullmatch(
        r"Scanned {} file and found ([1-9][0-9]*) packages".format(re.escape(expected_source)),
        lines[1],
    )
    require(package_match is not None, "OSV scanner did not report packages from the exact lockfile")
    duration = r"(?:0|[0-9]+(?:\.[0-9]+)?)(?:ns|µs|ms|s)"
    require(
        re.fullmatch(
            r"End status: 0 dirs visited, 1 inodes visited, 1 Extract calls, {} elapsed, {} wall time".format(
                duration, duration
            ),
            lines[2],
        )
        is not None,
        "unexpected OSV extraction-finality diagnostic",
    )
    require(
        lines[3] == "Loaded Pub local db from {}".format(EXPECTED_SCANNER_DATABASE),
        "OSV scanner did not report the exact local Pub database",
    )
    return int(package_match.group(1))


def evaluate(policy_path, result_path, stderr_path, scanner_status, lockfile):
    require(
        scanner_status in ALLOWED_SCANNER_STATUSES,
        "OSV scanner infrastructure status {} is not an advisory result".format(scanner_status),
    )
    package_count = validate_scanner_stderr(stderr_path, EXPECTED_SCANNER_LOCKFILE)
    require(package_count > 0, "OSV scanner reported no packages")
    accepted_ids = parse_policy(policy_path)
    findings = parse_findings(load_result(result_path), EXPECTED_SCANNER_LOCKFILE)
    if scanner_status == 0:
        require(not findings, "OSV status 0 disagrees with nonempty vulnerability results")
    else:
        require(bool(findings), "OSV status 1 has no vulnerability result")

    accepted = []
    unignored = []
    for advisory_id, aliases, package, version, fixed in findings:
        identities = set((advisory_id,)) | aliases
        if identities & accepted_ids:
            accepted.append((advisory_id, package))
        else:
            unignored.append((advisory_id, package, version, fixed))

    if accepted:
        print("-- {} accepted advisory(ies) (from the accept-list):".format(len(accepted)))
        for advisory_id, package in accepted:
            print("     ACCEPTED  {}  ({})".format(advisory_id, package))

    if unignored:
        print(
            "\nDART-AUDIT: FAIL — {} unignored advisory(ies) against {}:".format(
                len(unignored), lockfile
            )
        )
        for advisory_id, package, version, fixed in unignored:
            fixed_text = "  (fixed in {})".format(fixed) if fixed else ""
            print("     {}  {} {}{}".format(advisory_id, package, version, fixed_text))
        print(
            "\nResolve by an in-range pubspec.lock bump, or add the id to "
            "scripts/dart-audit-ignores.txt WITH A REASON (R-R3)."
        )
        return 1
    return 0


def write_text(path, value):
    with path.open("w", encoding="utf-8") as handle:
        handle.write(value)


def expect_error(action, label):
    try:
        action()
    except AuditResultError:
        return
    raise AuditResultError("self-test accepted {}".format(label))


def evaluate_silently(policy_path, result_path, stderr_path, scanner_status, lockfile):
    output = io.StringIO()
    with redirect_stdout(output):
        return evaluate(policy_path, result_path, stderr_path, scanner_status, lockfile)


def valid_scanner_log(lockfile=EXPECTED_SCANNER_LOCKFILE):
    return (
        "Starting filesystem walk for root: /\n"
        "Scanned {} file and found 199 packages\n"
        "End status: 0 dirs visited, 1 inodes visited, 1 Extract calls, "
        "3.059945ms elapsed, 3.059976ms wall time\n"
        "Loaded Pub local db from {}\n"
    ).format(lockfile, EXPECTED_SCANNER_DATABASE)


def run_self_test():
    checks = 0
    with tempfile.TemporaryDirectory(prefix="dart-audit-result-") as raw_directory:
        directory = Path(raw_directory)
        policy = directory / "policy.txt"
        lockfile = directory / "pubspec.lock"
        result = directory / "result.json"
        stderr = directory / "stderr.log"

        write_text(policy, "# no accepted advisories\n")
        require(parse_policy(policy) == set(), "self-test empty policy mismatch")
        checks += 1

        write_text(policy, "GHSA-test-0001  # reviewed test disposition\n")
        require(parse_policy(policy) == set(("GHSA-test-0001",)), "self-test policy mismatch")
        checks += 1

        for value, label in (
            ("GHSA-test-0001\n", "reasonless policy"),
            ("bad/id # reason\n", "malformed advisory id"),
            ("GHSA-test-0001 # one\nGHSA-test-0001 # two\n", "duplicate policy"),
            ("GHSA-one GHSA-two # reason\n", "multi-id policy line"),
        ):
            write_text(policy, value)
            expect_error(lambda: parse_policy(policy), label)
            checks += 1

        write_text(policy, "# empty\n")
        write_text(stderr, valid_scanner_log())
        write_text(result, '{"experimental_config": {}, "results": []}\n')
        require(
            evaluate_silently(policy, result, stderr, 0, "pubspec.lock") == 0,
            "clean result failed",
        )
        checks += 1

        vulnerability = {
            "results": [
                {
                    "source": {"path": EXPECTED_SCANNER_LOCKFILE, "type": "lockfile"},
                    "packages": [
                        {
                            "package": {
                                "name": "example",
                                "version": "1.0.0",
                                "ecosystem": "Pub",
                            },
                            "vulnerabilities": [
                                {
                                    "id": "GHSA-test-0001",
                                    "aliases": ["CVE-2099-0001"],
                                    "affected": [
                                        {"ranges": [{"events": [{"fixed": "1.0.1"}]}]}
                                    ],
                                }
                            ],
                        }
                    ],
                }
            ]
        }
        write_text(result, json.dumps(vulnerability))
        require(
            evaluate_silently(policy, result, stderr, 1, "pubspec.lock") == 1,
            "finding passed unignored",
        )
        checks += 1

        write_text(policy, "CVE-2099-0001 # accepted through reviewed alias\n")
        require(
            evaluate_silently(policy, result, stderr, 1, "pubspec.lock") == 0,
            "accepted alias failed",
        )
        checks += 1

        for scanner_status in (2, 127, 128, 255):
            expect_error(
                lambda status=scanner_status: evaluate(
                    policy, result, stderr, status, "pubspec.lock"
                ),
                "scanner infrastructure status {}".format(scanner_status),
            )
            checks += 1

        write_text(result, '{"results": []}\n')
        expect_error(
            lambda: evaluate(policy, result, stderr, 1, "pubspec.lock"),
            "status-1 empty result",
        )
        checks += 1

        write_text(result, json.dumps(vulnerability))
        expect_error(
            lambda: evaluate(policy, result, stderr, 0, "pubspec.lock"),
            "status-0 finding",
        )
        checks += 1

        for value, label in (
            ("{", "malformed JSON"),
            ("{}", "missing results"),
            ('{"results": {}}', "non-list results"),
            ('{"results": [{"packages": [{}]}]}', "malformed package result"),
        ):
            write_text(result, value)
            expect_error(lambda: evaluate(policy, result, stderr, 0, "pubspec.lock"), label)
            checks += 1

        hardlink = directory / "policy-hardlink.txt"
        os.link(str(policy), str(hardlink))
        expect_error(lambda: parse_policy(policy), "hardlinked policy")
        hardlink.unlink()
        checks += 1

        require_fresh(1_000_000, 30, 1_000_000 + 30 * 86400)
        checks += 1
        expect_error(
            lambda: require_fresh(1_000_000, 30, 1_000_000 + 30 * 86400 + 1),
            "stale OSV database",
        )
        checks += 1
        expect_error(lambda: require_fresh(1_000_000, 31, 1_000_000), "weakened freshness")
        checks += 1
        expect_error(
            lambda: require_fresh(1_000_000, 30, 1_000_000 - 86401),
            "future OSV capture",
        )
        checks += 1
        require(parse_canonical_integer("0", "test") == 0, "canonical zero mismatch")
        checks += 1
        expect_error(lambda: parse_canonical_integer("030", "test"), "noncanonical integer")
        checks += 1

        write_text(stderr, valid_scanner_log())
        require(
            validate_scanner_stderr(stderr, EXPECTED_SCANNER_LOCKFILE) == 199,
            "scanner telemetry package count mismatch",
        )
        checks += 1
        write_text(stderr, valid_scanner_log() + "warning: ignored\n")
        expect_error(
            lambda: validate_scanner_stderr(stderr, EXPECTED_SCANNER_LOCKFILE),
            "extra scanner diagnostic",
        )
        checks += 1
        write_text(stderr, valid_scanner_log("/work/other.lock"))
        expect_error(
            lambda: validate_scanner_stderr(stderr, EXPECTED_SCANNER_LOCKFILE),
            "different scanned lockfile",
        )
        checks += 1

        write_text(policy, "# empty\n")
        write_text(lockfile, "# generated\npackages:\n  example:\n    version: 1.0.0\n")
        output = directory / "prepared"
        output.mkdir(mode=0o700)
        with redirect_stdout(io.StringIO()):
            prepare(policy, lockfile, output)
        require(
            (output / "policy.txt").read_bytes() == policy.read_bytes()
            and (output / "pubspec.lock").read_bytes() == lockfile.read_bytes()
            and (output / "policy.sha256").read_text(encoding="ascii").strip()
            == hashlib.sha256(policy.read_bytes()).hexdigest()
            and (output / "lockfile.sha256").read_text(encoding="ascii").strip()
            == hashlib.sha256(lockfile.read_bytes()).hexdigest(),
            "private preparation transaction mismatch",
        )
        checks += 1

        lock_hardlink = directory / "pubspec-hardlink.lock"
        os.link(str(lockfile), str(lock_hardlink))
        second_output = directory / "prepared-hardlink"
        second_output.mkdir(mode=0o700)
        expect_error(
            lambda: prepare(policy, lockfile, second_output),
            "hardlinked lockfile",
        )
        checks += 1

    require(checks == 31, "self-test count drifted: {}".format(checks))
    print("dart-audit-result self-test: ok (31 policy/freshness/status/schema decisions)")


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    subparsers = parser.add_subparsers(dest="command")

    validate_parser = subparsers.add_parser("validate-policy")
    validate_parser.add_argument("--policy", required=True, type=Path)

    prepare_parser = subparsers.add_parser("prepare")
    prepare_parser.add_argument("--policy", required=True, type=Path)
    prepare_parser.add_argument("--lockfile", required=True, type=Path)
    prepare_parser.add_argument("--output", required=True, type=Path)

    freshness_parser = subparsers.add_parser("check-freshness")
    freshness_parser.add_argument("--capture-epoch", required=True)
    freshness_parser.add_argument("--max-age-days", required=True)

    evaluate_parser = subparsers.add_parser("evaluate")
    evaluate_parser.add_argument("--policy", required=True, type=Path)
    evaluate_parser.add_argument("--result", required=True, type=Path)
    evaluate_parser.add_argument("--stderr", required=True, type=Path)
    evaluate_parser.add_argument("--scanner-status", required=True)
    evaluate_parser.add_argument("--lockfile", required=True)

    arguments = parser.parse_args(argv)
    try:
        if arguments.self_test:
            require(arguments.command is None, "--self-test takes no command")
            run_self_test()
            return 0
        if arguments.command == "validate-policy":
            accepted = parse_policy(arguments.policy)
            print(len(accepted))
            return 0
        if arguments.command == "prepare":
            return prepare(arguments.policy, arguments.lockfile, arguments.output)
        if arguments.command == "check-freshness":
            return check_freshness(arguments.capture_epoch, arguments.max_age_days)
        if arguments.command == "evaluate":
            scanner_status = parse_canonical_integer(
                arguments.scanner_status, "OSV scanner status"
            )
            return evaluate(
                arguments.policy,
                arguments.result,
                arguments.stderr,
                scanner_status,
                arguments.lockfile,
            )
        parser.error("a command is required")
    except (AuditResultError, OSError) as exc:
        print("dart-audit-result: {}".format(exc), file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    sys.exit(main())
