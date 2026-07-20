#!/usr/bin/env python3
"""Prepare and validate the offline Rust dependency-advisory transaction."""

from __future__ import annotations

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
import tomllib


RUSTSEC_ID = re.compile(r"RUSTSEC-\d{4}-\d{4}\Z")
MAX_RESULT_BYTES = 64 * 1024 * 1024
EXPECTED_DB_URLS = ["https://github.com/RustSec/advisory-db"]


class AuditPolicyError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AuditPolicyError(message)


def stable_read(path: Path, maximum: int | None = None) -> bytes:
    metadata = path.lstat()
    require(stat.S_ISREG(metadata.st_mode), f"{path} is not a regular file")
    require(not stat.S_ISLNK(metadata.st_mode), f"{path} must not be a symlink")
    require(metadata.st_nlink == 1, f"{path} must not be hardlinked")
    if maximum is not None:
        require(metadata.st_size <= maximum, f"{path} exceeds {maximum} bytes")
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        require(
            (
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
            == (
                opened.st_dev,
                opened.st_ino,
                opened.st_mode,
                opened.st_nlink,
                opened.st_uid,
                opened.st_gid,
                opened.st_size,
                opened.st_mtime_ns,
                opened.st_ctime_ns,
            ),
            f"{path} changed while opening",
        )
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if maximum is not None:
                require(total <= maximum, f"{path} exceeds {maximum} bytes")
            chunks.append(chunk)
        closed = os.fstat(descriptor)
        require(
            (
                opened.st_dev,
                opened.st_ino,
                opened.st_mode,
                opened.st_nlink,
                opened.st_uid,
                opened.st_gid,
                opened.st_size,
                opened.st_mtime_ns,
                opened.st_ctime_ns,
            )
            == (
                closed.st_dev,
                closed.st_ino,
                closed.st_mode,
                closed.st_nlink,
                closed.st_uid,
                closed.st_gid,
                closed.st_size,
                closed.st_mtime_ns,
                closed.st_ctime_ns,
            ),
            f"{path} changed while reading",
        )
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def write_new(path: Path, data: bytes, mode: int = 0o600) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, mode)
    try:
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            require(written > 0, f"short write while creating {path}")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def load_policy(path: Path) -> tuple[bytes, list[str]]:
    raw = stable_read(path, 4 * 1024 * 1024)
    try:
        policy = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise AuditPolicyError(f"cannot parse {path}: {exc}") from exc
    require(isinstance(policy, dict), f"{path} must contain a TOML table")
    advisories = policy.get("advisories")
    require(isinstance(advisories, dict), f"{path} is missing [advisories]")
    require(
        advisories.get("db-urls") == EXPECTED_DB_URLS,
        f"{path} [advisories].db-urls must name only the official RustSec database",
    )
    require(
        advisories.get("yanked") == "warn",
        f"{path} source policy must retain yanked = \"warn\" for non-release policy users",
    )
    entries = advisories.get("ignore")
    require(isinstance(entries, list), f"{path} [advisories].ignore must be a list")
    accepted: list[str] = []
    seen: set[str] = set()
    for index, entry in enumerate(entries, 1):
        require(
            isinstance(entry, dict) and set(entry) == {"id", "reason"},
            f"{path} ignore entry {index} must contain exactly id and reason",
        )
        advisory_id = entry["id"]
        reason = entry["reason"]
        require(
            isinstance(advisory_id, str) and RUSTSEC_ID.fullmatch(advisory_id) is not None,
            f"{path} ignore entry {index} has an invalid RUSTSEC id",
        )
        require(
            isinstance(reason, str) and bool(reason.strip()),
            f"{path} ignore entry {advisory_id} has no reason",
        )
        require(
            not any(ord(character) < 0x20 and character not in "\t\n" for character in reason),
            f"{path} ignore entry {advisory_id} has a control character in its reason",
        )
        require(advisory_id not in seen, f"{path} has duplicate ignore id {advisory_id}")
        seen.add(advisory_id)
        accepted.append(advisory_id)
    return raw, sorted(accepted)


def render_audit_config() -> bytes:
    # cargo-audit 0.21.1 otherwise consults ambient crates.io index state for
    # yanks. Yank state is mutable registry metadata, not part of RustSec's
    # pinned advisory snapshot, so this reproducible gate deliberately excludes
    # it. deny.toml retains the human-facing warning policy for other callers.
    return (
        "[database]\n"
        "fetch = false\n"
        "stale = false\n\n"
        "[yanked]\n"
        "enabled = false\n"
        "update_index = false\n"
    ).encode("ascii")


def render_deny_config(raw: bytes) -> bytes:
    text = raw.decode("utf-8")
    require(text.count("[advisories]") == 1, "deny.toml must contain one [advisories] table")
    require(text.count('yanked = "warn"') == 1, "deny.toml must contain one yanked warning policy")
    text = text.replace(
        "[advisories]",
        '[advisories]\ndb-path = "/tmp/advisory-dbs"',
        1,
    )
    text = text.replace(
        'yanked = "warn"',
        '# Yank state is mutable registry metadata outside this pinned offline gate.\n'
        'yanked = "allow"',
        1,
    )
    return text.encode("utf-8")


def render_cargo_config(raw: bytes) -> bytes:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AuditPolicyError(f"cargo vendor config is not UTF-8: {exc}") from exc
    require(text.count("directory = ") == 1, "cargo vendor config must have exactly one directory")
    text = re.sub(r'^directory = ".*"$', 'directory = "/vendor"', text, count=1, flags=re.MULTILINE)
    require('directory = "/vendor"' in text, "could not bind cargo vendor config to /vendor")
    require("[net]" not in text, "cargo vendor config unexpectedly contains [net]")
    return (text.rstrip() + "\n\n[net]\noffline = true\n").encode("utf-8")


def prepare(policy: Path, lockfile: Path, vendor_config: Path, output: Path) -> int:
    directory = output.lstat()
    require(stat.S_ISDIR(directory.st_mode), f"{output} is not a directory")
    require(not stat.S_ISLNK(directory.st_mode), f"{output} must not be a symlink")
    require(directory.st_uid == os.geteuid(), f"{output} is not owned by the effective user")
    require(stat.S_IMODE(directory.st_mode) == 0o700, f"{output} must be mode 0700")
    raw_policy, accepted = load_policy(policy)
    raw_lockfile = stable_read(lockfile, 64 * 1024 * 1024)
    raw_vendor_config = stable_read(vendor_config, 1024 * 1024)

    cargo_directory = output / ".cargo"
    cargo_directory.mkdir(mode=0o700)
    write_new(output / "Cargo.lock", raw_lockfile)
    write_new(output / "deny.runtime.toml", render_deny_config(raw_policy))
    write_new(output / "cargo.config.toml", render_cargo_config(raw_vendor_config))
    write_new(cargo_directory / "audit.toml", render_audit_config())
    write_new(output / "policy.sha256", (hashlib.sha256(raw_policy).hexdigest() + "\n").encode("ascii"))
    write_new(output / "lockfile.sha256", (hashlib.sha256(raw_lockfile).hexdigest() + "\n").encode("ascii"))
    write_new(
        output / "vendor-config.sha256",
        (hashlib.sha256(raw_vendor_config).hexdigest() + "\n").encode("ascii"),
    )
    accepted_text = ("\n".join(accepted) + "\n") if accepted else ""
    write_new(output / "accepted-ids.txt", accepted_text.encode("ascii"))
    print(len(accepted))
    return 0


def parse_canonical_integer(value: str, label: str) -> int:
    require(re.fullmatch(r"0|[1-9][0-9]*", value) is not None, f"{label} is not canonical")
    return int(value)


def require_fresh(commit_epoch: int, maximum_days: int, now_epoch: int) -> None:
    require(maximum_days == 90, "RustSec maximum snapshot age must remain exactly 90 days")
    age = now_epoch - commit_epoch
    require(age >= -86400, "RustSec snapshot commit is more than one day in the future")
    require(
        age <= maximum_days * 86400,
        "RustSec snapshot is stale: commit age {} days exceeds the {}-day release limit".format(
            max(0, age // 86400), maximum_days
        ),
    )


def check_freshness(commit_epoch: str, maximum_days: str) -> int:
    commit = parse_canonical_integer(commit_epoch, "advisory commit epoch")
    days = parse_canonical_integer(maximum_days, "maximum advisory age")
    require_fresh(commit, days, int(time.time()))
    print("fresh")
    return 0


def load_json_result(path: Path) -> dict:
    raw = stable_read(path, MAX_RESULT_BYTES)
    require(bool(raw), f"{path} is empty")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AuditPolicyError(f"cannot parse {path}: {exc}") from exc
    require(isinstance(value, dict), f"{path} must contain one JSON object")
    return value


def validate_audit_result(
    path: Path,
    status: str,
    policy_path: Path,
    expected_db_commit: str,
) -> int:
    result_status = parse_canonical_integer(status, "cargo-audit status")
    require(result_status == 0, f"cargo-audit status {result_status} is not a clean advisory result")
    require(
        re.fullmatch(r"[0-9a-f]{40}", expected_db_commit) is not None,
        "expected RustSec commit is malformed",
    )
    _, accepted = load_policy(policy_path)
    value = load_json_result(path)
    database = value.get("database")
    require(isinstance(database, dict), "cargo-audit result is missing database metadata")
    require("last-commit" in database, "cargo-audit result omits its database commit field")
    # cargo-audit 0.21.1 reports null for a caller-supplied --no-fetch database;
    # the container preflight independently proves its Git HEAD. Newer tools may
    # report the exact value, but no different value is acceptable.
    require(
        database["last-commit"] in (None, expected_db_commit),
        "cargo-audit result used a different RustSec commit",
    )
    require(
        isinstance(database.get("advisory-count"), int) and database["advisory-count"] > 0,
        "cargo-audit result has no advisory records",
    )
    vulnerabilities = value.get("vulnerabilities")
    require(isinstance(vulnerabilities, dict), "cargo-audit result is missing vulnerabilities")
    count = vulnerabilities.get("count")
    found = vulnerabilities.get("list")
    require(isinstance(count, int) and count >= 0, "cargo-audit vulnerability count is invalid")
    require(isinstance(found, list), "cargo-audit vulnerability list is invalid")
    require(count == len(found), "cargo-audit vulnerability count/list disagree")
    require(vulnerabilities.get("found") is (count != 0), "cargo-audit found/count disagree")
    require(count == 0, "cargo-audit clean status contains vulnerabilities")
    lockfile = value.get("lockfile")
    require(isinstance(lockfile, dict), "cargo-audit result is missing lockfile metadata")
    dependency_count = lockfile.get("dependency-count")
    require(
        isinstance(dependency_count, int) and dependency_count > 0,
        "cargo-audit found no lockfile packages",
    )
    settings = value.get("settings")
    require(isinstance(settings, dict), "cargo-audit result is missing settings")
    result_ignores = settings.get("ignore")
    require(isinstance(result_ignores, list), "cargo-audit result has no ignore list")
    require(
        sorted(result_ignores) == accepted,
        "cargo-audit result ignore set differs from the reason-bearing policy",
    )
    require(value.get("warnings") == {}, "cargo-audit clean result contains an unaccepted warning")
    print(f"cargo-audit result: clean ({dependency_count} packages, {len(accepted)} accepted ids)")
    return 0


def validate_deny_result(stdout_path: Path, stderr_path: Path, status: str) -> int:
    result_status = parse_canonical_integer(status, "cargo-deny status")
    require(result_status == 0, f"cargo-deny status {result_status} is not a clean advisory result")
    stdout = stable_read(stdout_path, MAX_RESULT_BYTES)
    stderr = stable_read(stderr_path, MAX_RESULT_BYTES)
    require(not stdout, "cargo-deny JSON mode unexpectedly wrote stdout")
    require(bool(stderr), "cargo-deny produced no structured result")
    try:
        text = stderr.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AuditPolicyError(f"cargo-deny result is not UTF-8: {exc}") from exc
    records: list[dict] = []
    for line_number, line in enumerate(text.splitlines(), 1):
        require(bool(line), f"cargo-deny result has an empty line at {line_number}")
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise AuditPolicyError(f"cargo-deny result line {line_number} is not JSON: {exc}") from exc
        require(isinstance(record, dict), f"cargo-deny result line {line_number} is not an object")
        records.append(record)

    summaries = [record for record in records if record.get("type") == "summary"]
    require(len(summaries) == 1, "cargo-deny result must contain exactly one summary")
    require(records[-1] is summaries[0], "cargo-deny summary must be the final record")
    warning_count = 0
    for record in records[:-1]:
        require(record.get("type") == "diagnostic", "cargo-deny emitted an unknown record type")
        fields = record.get("fields")
        require(isinstance(fields, dict), "cargo-deny diagnostic fields are invalid")
        code = fields.get("code")
        severity = fields.get("severity")
        require(
            code == "advisory-not-detected" and severity == "warning",
            f"cargo-deny emitted unexpected diagnostic {code!r}/{severity!r}",
        )
        warning_count += 1

    summary_fields = summaries[0].get("fields")
    require(isinstance(summary_fields, dict), "cargo-deny summary fields are invalid")
    advisories = summary_fields.get("advisories")
    require(isinstance(advisories, dict), "cargo-deny summary is missing advisories")
    for key in ("errors", "helps", "notes", "warnings"):
        require(
            isinstance(advisories.get(key), int) and advisories[key] >= 0,
            f"cargo-deny summary {key} count is invalid",
        )
    require(advisories["errors"] == 0, "cargo-deny summary contains advisory errors")
    require(
        advisories["warnings"] == warning_count,
        "cargo-deny warning summary disagrees with diagnostics",
    )
    print(
        "cargo-deny result: clean ({} policy note(s), {} obsolete accept warning(s))".format(
            advisories["notes"], warning_count
        )
    )
    return 0


def expect_error(action, label: str) -> None:
    try:
        action()
    except AuditPolicyError:
        return
    raise AuditPolicyError(f"self-test accepted {label}")


def self_test() -> int:
    checks = 0
    require_fresh(1_000_000, 90, 1_000_000 + 90 * 86400)
    checks += 1
    expect_error(lambda: require_fresh(1_000_000, 90, 1_000_000 + 90 * 86400 + 1), "stale DB")
    checks += 1
    expect_error(lambda: require_fresh(1_000_000, 91, 1_000_000), "weakened freshness policy")
    checks += 1
    expect_error(lambda: require_fresh(1_000_000, 90, 1_000_000 - 86401), "future DB")
    checks += 1
    require(parse_canonical_integer("0", "test") == 0, "zero integer mismatch")
    checks += 1
    expect_error(lambda: parse_canonical_integer("090", "test"), "noncanonical integer")
    checks += 1
    require(b'enabled = false' in render_audit_config(), "yanked audit config mismatch")
    checks += 1
    with tempfile.TemporaryDirectory(prefix="rust-audit-policy-") as raw_directory:
        directory = Path(raw_directory)
        policy = directory / "deny.toml"
        audit_result = directory / "audit.json"
        deny_stdout = directory / "deny.stdout"
        deny_stderr = directory / "deny.stderr"
        advisory_id = "RUSTSEC-2026-9999"
        db_commit = "1" * 40
        valid_policy = (
            '[advisories]\n'
            'db-urls = ["https://github.com/RustSec/advisory-db"]\n'
            'yanked = "warn"\n'
            f'ignore = [{{ id = "{advisory_id}", reason = "reviewed fixture" }}]\n'
        )
        policy.write_text(valid_policy, encoding="utf-8")
        _, accepted = load_policy(policy)
        require(accepted == [advisory_id], "policy fixture mismatch")
        checks += 1
        hardlink = directory / "deny-hardlink.toml"
        os.link(policy, hardlink)
        expect_error(lambda: load_policy(policy), "hardlinked policy")
        hardlink.unlink()
        checks += 1
        policy.write_text(
            valid_policy.replace(
                f'ignore = [{{ id = "{advisory_id}", reason = "reviewed fixture" }}]',
                "ignore = [\n"
                f'  {{ id = "{advisory_id}", reason = "first" }},\n'
                f'  {{ id = "{advisory_id}", reason = "duplicate" }},\n'
                "]",
            ),
            encoding="utf-8",
        )
        expect_error(lambda: load_policy(policy), "duplicate policy accept")
        policy.write_text(valid_policy, encoding="utf-8")
        checks += 1

        clean_audit = {
            "database": {"advisory-count": 1, "last-commit": None, "last-updated": None},
            "lockfile": {"dependency-count": 1},
            "settings": {"ignore": [advisory_id]},
            "vulnerabilities": {"found": False, "count": 0, "list": []},
            "warnings": {},
        }
        audit_result.write_text(json.dumps(clean_audit), encoding="utf-8")
        with redirect_stdout(io.StringIO()):
            validate_audit_result(audit_result, "0", policy, db_commit)
        checks += 1
        expect_error(
            lambda: validate_audit_result(audit_result, "1", policy, db_commit),
            "nonzero cargo-audit status",
        )
        checks += 1
        clean_audit["settings"] = {"ignore": []}
        audit_result.write_text(json.dumps(clean_audit), encoding="utf-8")
        expect_error(
            lambda: validate_audit_result(audit_result, "0", policy, db_commit),
            "cargo-audit mismatched ignore set",
        )
        checks += 1
        clean_audit["settings"] = {"ignore": [advisory_id]}
        clean_audit["warnings"] = {"unmaintained": [{}]}
        audit_result.write_text(json.dumps(clean_audit), encoding="utf-8")
        expect_error(
            lambda: validate_audit_result(audit_result, "0", policy, db_commit),
            "cargo-audit clean status with warning",
        )
        checks += 1
        clean_audit["warnings"] = {}
        clean_audit["vulnerabilities"] = {"found": True, "count": 1, "list": [{}]}
        audit_result.write_text(json.dumps(clean_audit), encoding="utf-8")
        expect_error(
            lambda: validate_audit_result(audit_result, "0", policy, db_commit),
            "cargo-audit clean status with finding",
        )
        checks += 1

        deny_stdout.write_bytes(b"")
        diagnostic = {
            "type": "diagnostic",
            "fields": {"code": "advisory-not-detected", "severity": "warning"},
        }
        summary = {
            "type": "summary",
            "fields": {"advisories": {"errors": 0, "helps": 0, "notes": 1, "warnings": 1}},
        }
        deny_stderr.write_text(
            json.dumps(diagnostic) + "\n" + json.dumps(summary) + "\n",
            encoding="utf-8",
        )
        with redirect_stdout(io.StringIO()):
            validate_deny_result(deny_stdout, deny_stderr, "0")
        checks += 1
        deny_stdout.write_text("unexpected output\n", encoding="utf-8")
        expect_error(
            lambda: validate_deny_result(deny_stdout, deny_stderr, "0"),
            "cargo-deny unexpected stdout",
        )
        deny_stdout.write_bytes(b"")
        checks += 1
        summary["fields"]["advisories"]["errors"] = 1
        deny_stderr.write_text(
            json.dumps(diagnostic) + "\n" + json.dumps(summary) + "\n",
            encoding="utf-8",
        )
        expect_error(
            lambda: validate_deny_result(deny_stdout, deny_stderr, "0"),
            "cargo-deny summary error",
        )
        summary["fields"]["advisories"]["errors"] = 0
        deny_stderr.write_text(
            json.dumps(diagnostic) + "\n" + json.dumps(summary) + "\n",
            encoding="utf-8",
        )
        checks += 1
        expect_error(
            lambda: validate_deny_result(deny_stdout, deny_stderr, "1"),
            "nonzero cargo-deny status",
        )
        checks += 1
        diagnostic["fields"]["code"] = "index-failure"
        deny_stderr.write_text(
            json.dumps(diagnostic) + "\n" + json.dumps(summary) + "\n",
            encoding="utf-8",
        )
        expect_error(
            lambda: validate_deny_result(deny_stdout, deny_stderr, "0"),
            "cargo-deny index failure warning",
        )
        checks += 1

    require(checks == 20, f"self-test count drifted: {checks}")
    print("rust-audit-policy self-test: ok (20 policy/freshness/result decisions)")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    subparsers = parser.add_subparsers(dest="command")

    validate_parser = subparsers.add_parser("validate-policy")
    validate_parser.add_argument("--policy", required=True, type=Path)

    prepare_parser = subparsers.add_parser("prepare")
    prepare_parser.add_argument("--policy", required=True, type=Path)
    prepare_parser.add_argument("--lockfile", required=True, type=Path)
    prepare_parser.add_argument("--vendor-config", required=True, type=Path)
    prepare_parser.add_argument("--output", required=True, type=Path)

    freshness_parser = subparsers.add_parser("check-freshness")
    freshness_parser.add_argument("--commit-epoch", required=True)
    freshness_parser.add_argument("--max-age-days", required=True)

    result_parser = subparsers.add_parser("validate-audit-result")
    result_parser.add_argument("--result", required=True, type=Path)
    result_parser.add_argument("--status", required=True)
    result_parser.add_argument("--policy", required=True, type=Path)
    result_parser.add_argument("--expected-db-commit", required=True)

    deny_result_parser = subparsers.add_parser("validate-deny-result")
    deny_result_parser.add_argument("--stdout", required=True, type=Path)
    deny_result_parser.add_argument("--stderr", required=True, type=Path)
    deny_result_parser.add_argument("--status", required=True)

    arguments = parser.parse_args(argv)
    try:
        if arguments.self_test:
            return self_test()
        if arguments.command == "validate-policy":
            _, accepted = load_policy(arguments.policy)
            print(len(accepted))
            return 0
        if arguments.command == "prepare":
            return prepare(arguments.policy, arguments.lockfile, arguments.vendor_config, arguments.output)
        if arguments.command == "check-freshness":
            return check_freshness(arguments.commit_epoch, arguments.max_age_days)
        if arguments.command == "validate-audit-result":
            return validate_audit_result(
                arguments.result,
                arguments.status,
                arguments.policy,
                arguments.expected_db_commit,
            )
        if arguments.command == "validate-deny-result":
            return validate_deny_result(arguments.stdout, arguments.stderr, arguments.status)
        parser.error("a command is required")
    except (AuditPolicyError, OSError) as exc:
        print(f"rust-audit-policy: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    sys.exit(main())
