#!/usr/bin/env python3
"""Validate Dart OSV policy and make one status-bound advisory decision."""

import argparse
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile


ADVISORY_ID = re.compile(r"[A-Za-z0-9_.:-]+\Z")
ALLOWED_SCANNER_STATUSES = frozenset((0, 1))
MAX_RESULT_BYTES = 64 * 1024 * 1024


class AuditResultError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise AuditResultError(message)


def read_regular_file(path, maximum_bytes=None):
    try:
        metadata = os.lstat(str(path))
    except OSError as exc:
        raise AuditResultError("cannot inspect {}: {}".format(path, exc))
    require(not stat.S_ISLNK(metadata.st_mode), "refusing symlink input: {}".format(path))
    require(stat.S_ISREG(metadata.st_mode), "input is not a regular file: {}".format(path))
    if maximum_bytes is not None:
        require(
            metadata.st_size <= maximum_bytes,
            "input exceeds {} bytes: {}".format(maximum_bytes, path),
        )
    try:
        with path.open("r", encoding="utf-8") as handle:
            return handle.read()
    except (OSError, UnicodeError) as exc:
        raise AuditResultError("cannot read UTF-8 input {}: {}".format(path, exc))


def parse_policy(path):
    source = read_regular_file(path)
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


def parse_findings(data):
    require(isinstance(data, dict), "OSV result root must be an object")
    results = data.get("results")
    require(isinstance(results, list), "OSV result must contain a results list")
    findings = []
    for result_index, result in enumerate(results):
        result_label = "results[{}]".format(result_index)
        require(isinstance(result, dict), "{} must be an object".format(result_label))
        packages = result.get("packages")
        require(isinstance(packages, list), "{}.packages must be a list".format(result_label))
        for package_index, package_entry in enumerate(packages):
            package_label = "{}.packages[{}]".format(result_label, package_index)
            require(isinstance(package_entry, dict), "{} must be an object".format(package_label))
            package = package_entry.get("package")
            require(isinstance(package, dict), "{}.package must be an object".format(package_label))
            name = require_string(package.get("name"), "{}.package.name".format(package_label))
            version = require_string(
                package.get("version"), "{}.package.version".format(package_label)
            )
            vulnerabilities = package_entry.get("vulnerabilities")
            require(
                isinstance(vulnerabilities, list),
                "{}.vulnerabilities must be a list".format(package_label),
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
                    aliases.add(
                        require_advisory_id(
                            alias, "{}.aliases[{}]".format(vulnerability_label, alias_index)
                        )
                    )
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


def evaluate(policy_path, result_path, scanner_status, lockfile):
    require(
        scanner_status in ALLOWED_SCANNER_STATUSES,
        "OSV scanner infrastructure status {} is not an advisory result".format(scanner_status),
    )
    accepted_ids = parse_policy(policy_path)
    findings = parse_findings(load_result(result_path))
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


def evaluate_silently(policy_path, result_path, scanner_status, lockfile):
    output = io.StringIO()
    with redirect_stdout(output):
        return evaluate(policy_path, result_path, scanner_status, lockfile)


def run_self_test():
    checks = 0
    with tempfile.TemporaryDirectory(prefix="dart-audit-result-") as raw_directory:
        directory = Path(raw_directory)
        policy = directory / "policy.txt"
        result = directory / "result.json"

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
        write_text(result, '{"experimental_config": {}, "results": []}\n')
        require(
            evaluate_silently(policy, result, 0, "pubspec.lock") == 0,
            "clean result failed",
        )
        checks += 1

        vulnerability = {
            "results": [
                {
                    "packages": [
                        {
                            "package": {"name": "example", "version": "1.0.0"},
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
                    ]
                }
            ]
        }
        write_text(result, json.dumps(vulnerability))
        require(
            evaluate_silently(policy, result, 1, "pubspec.lock") == 1,
            "finding passed unignored",
        )
        checks += 1

        write_text(policy, "CVE-2099-0001 # accepted through reviewed alias\n")
        require(
            evaluate_silently(policy, result, 1, "pubspec.lock") == 0,
            "accepted alias failed",
        )
        checks += 1

        for scanner_status in (2, 127, 128, 255):
            expect_error(
                lambda status=scanner_status: evaluate(
                    policy, result, status, "pubspec.lock"
                ),
                "scanner infrastructure status {}".format(scanner_status),
            )
            checks += 1

        write_text(result, '{"results": []}\n')
        expect_error(lambda: evaluate(policy, result, 1, "pubspec.lock"), "status-1 empty result")
        checks += 1

        write_text(result, json.dumps(vulnerability))
        expect_error(lambda: evaluate(policy, result, 0, "pubspec.lock"), "status-0 finding")
        checks += 1

        for value, label in (
            ("{", "malformed JSON"),
            ("{}", "missing results"),
            ('{"results": {}}', "non-list results"),
            ('{"results": [{"packages": [{}]}]}', "malformed package result"),
        ):
            write_text(result, value)
            expect_error(lambda: evaluate(policy, result, 0, "pubspec.lock"), label)
            checks += 1

    require(checks == 19, "self-test count drifted: {}".format(checks))
    print("dart-audit-result self-test: ok (19 policy/status/schema decisions)")


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    subparsers = parser.add_subparsers(dest="command")

    validate_parser = subparsers.add_parser("validate-policy")
    validate_parser.add_argument("--policy", required=True, type=Path)

    evaluate_parser = subparsers.add_parser("evaluate")
    evaluate_parser.add_argument("--policy", required=True, type=Path)
    evaluate_parser.add_argument("--result", required=True, type=Path)
    evaluate_parser.add_argument("--scanner-status", required=True, type=int)
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
        if arguments.command == "evaluate":
            return evaluate(
                arguments.policy,
                arguments.result,
                arguments.scanner_status,
                arguments.lockfile,
            )
        parser.error("a command is required")
    except AuditResultError as exc:
        print("dart-audit-result: {}".format(exc), file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    sys.exit(main())
