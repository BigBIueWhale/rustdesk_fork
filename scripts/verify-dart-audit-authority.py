#!/usr/bin/env python3
"""Bind Dart advisory freshness/finality to one immutable confined scan."""

import argparse
from pathlib import Path
import re
import sys


IMAGE_ID = "sha256:f80e9869536995a1db9c14ab07c7b2ddfc83a4eaef52be2e49971c767323de0d"
SCANNER_SHA256 = "15314940c10d26af9c6649f150b8a47c1262e8fc7e17b1d1029b0e479e8ed8a0"
DATABASE_SHA256 = "8b1d25767804f7487d7a26d9ae001c00813329252157eb7d267a8fb6f575b87c"
DATABASE_CAPTURE_EPOCH = "1782347599"
DATABASE_MAX_AGE_DAYS = "30"


class ContractError(RuntimeError):
    pass


class Mutation(object):
    def __init__(self, source, old, new, label):
        self.source = source
        self.old = old
        self.new = new
        self.label = label


def require(condition, message):
    if not condition:
        raise ContractError(message)


def require_all(source, tokens, label):
    for token in tokens:
        require(token in source, "{}: missing {!r}".format(label, token))


def require_once(source, token, label):
    count = source.count(token)
    require(count == 1, "{}: expected one occurrence, found {}".format(label, count))


def extract_between(source, start_token, end_token, label, offset=0):
    start = source.find(start_token, offset)
    require(start >= 0, "{}: missing start token".format(label))
    end = source.find(end_token, start)
    require(end >= 0, "{}: missing end token".format(label))
    return source[start : end + len(end_token)], end + len(end_token)


def require_container_floor(block, label):
    require_all(
        block,
        (
            "--rm",
            "--pull=never",
            "--network=none",
            "--read-only",
            '--user "$(id -u):$(id -g)"',
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--memory-swap=",
            "--cpus=",
            "--tmpfs /tmp:rw,noexec,nosuid,nodev",
            '"$IMAGE_ID"',
        ),
        label,
    )
    for forbidden in (
        "docker.sock",
        "--privileged",
        "--cap-add",
        "--pid=host",
        "--pid host",
        "--ipc=host",
        "--ipc host",
        "--uts=host",
        "--uts host",
        "--network=host",
        "--network host",
        "--publish",
        "--expose",
        "--volume",
        "-v ",
        "$PWD",
        '"$IMG"',
        "2>/dev/null",
    ):
        require(forbidden not in block, "{} has forbidden authority {!r}".format(label, forbidden))
    require(
        re.search(r"(?:^|\s)-p(?:\s|=)", block) is None,
        "{} publishes a port".format(label),
    )


def validate_contract(sources):
    shell = sources["shell"]
    result = sources["result"]
    pins = sources["pins"]
    dockerfile = sources["dockerfile"]
    verify = sources["verify"]
    requirements = sources["requirements"]
    hardening = sources["hardening"]
    validator = sources["validator"]

    require_all(
        shell,
        (
            'source "$SCRIPT_DIR/lib.sh"',
            "load_pins",
            "readonly DOCKER_BIN=/usr/bin/docker",
            "readonly PYTHON_BIN=/usr/bin/python3",
            "readonly MAX_SCANNER_OUTPUT_BLOCKS=65536",
            "run_bounded_docker() (",
            'current_limit="$(ulimit -Sf)"',
            'exec "$DOCKER_BIN" "$@"',
            '[ "$(id -u)" -ne 0 ] || dart_audit_die "refuses host or container-root execution"',
            '[ "$(id -g)" -ne 0 ] || dart_audit_die "refuses a root primary group"',
            '[ -f "$LOCKFILE" ] && [ ! -L "$LOCKFILE" ]',
            '[ -f "$IGNORES_FILE" ] && [ ! -L "$IGNORES_FILE" ]',
            ': "${DART_AUDIT_IMAGE_ID:?dart-audit.sh: DART_AUDIT_IMAGE_ID unset in pins.env}"',
            '[[ "$DART_AUDIT_IMAGE_ID" =~ ^sha256:[0-9a-f]{64}$ ]]',
            'AUDIT_TMP="$(umask 077 && mktemp -d /tmp/rustdesk-dart-audit.XXXXXXXXXX)"',
            'AUDIT_TMP_ID="$(/usr/bin/stat -c \'%d:%i\' -- "$AUDIT_TMP")"',
            '--remove-private-root "$AUDIT_TMP" --expected-identity "$AUDIT_TMP_ID"',
            "scripts/dart-audit-result.py prepare",
            '--policy "$IGNORES_FILE" --lockfile "$LOCKFILE" --output "$AUDIT_TMP"',
            "scripts/dart-audit-result.py check-freshness",
            '--capture-epoch "$OSV_DB_PUB_CAPTURE_EPOCH"',
            '--max-age-days "$OSV_DB_PUB_MAX_AGE_DAYS"',
            'SOURCE_LOCK_SHA="$(/usr/bin/sha256sum -- "$LOCKFILE"',
            'SOURCE_POLICY_SHA="$(/usr/bin/sha256sum -- "$IGNORES_FILE"',
            'IMAGE_ID="$($DOCKER_BIN image inspect --format \'{{.Id}}\' "$DART_AUDIT_IMAGE_ID")"',
            '[ "$IMAGE_ID" = "$DART_AUDIT_IMAGE_ID" ]',
            'printf "%s  %s\\n" "$5" /usr/local/bin/osv-scanner',
            'printf "%s  %s\\n" "$6" /opt/osv-db/osv-scanner/Pub/all.zip',
            "sha256sum --check --strict --status -",
            'stat -c "%F:%s:%Y:%a:%u:%g:%h" /opt/osv-db/osv-scanner/Pub/all.zip',
            '[ "$IMAGE_PREFLIGHT_STATUS" -eq 0 ]',
            '[ ! -s "$IMAGE_PREFLIGHT_OUT" ]',
            '[ ! -s "$IMAGE_PREFLIGHT_ERR" ]',
            'case "$SCANNER_STATUS" in\n  0|1) ;;',
            'scripts/dart-audit-result.py evaluate',
            '--result "$RESULT_FILE" --stderr "$ERROR_FILE"',
            '--scanner-status "$SCANNER_STATUS" --lockfile "$LOCKFILE"',
            '[ "$RESULT_BYTES" -le 67108864 ]',
            '[ "$ERROR_BYTES" -le 1048576 ]',
            'sha256sum -- "$AUDIT_TMP/pubspec.lock"',
            'sha256sum -- "$AUDIT_TMP/policy.txt"',
            'AUDIT_SUCCESS_MESSAGE="VERIFY-DART-AUDIT: green',
        ),
        "Dart audit shell authority",
    )
    require(shell.count("scripts/dart-audit-result.py check-freshness") == 2, "freshness must be checked before and after scanning")
    require(shell.count('--capture-epoch "$OSV_DB_PUB_CAPTURE_EPOCH"') == 2, "both freshness checks must use the pinned capture epoch")
    require(shell.count('--max-age-days "$OSV_DB_PUB_MAX_AGE_DAYS"') == 2, "both freshness checks must use the pinned age ceiling")
    require(shell.count("run_bounded_docker run --rm") == 2, "Dart audit must have exactly preflight and scanner containers")
    require("$DOCKER_BIN run" not in shell, "Dart audit bypasses the bounded Docker wrapper")
    for forbidden in (
        "$DOCKER_BIN build",
        "docker build",
        "TAG_IMAGE_ID",
        "readonly IMG=",
        "rd-dart-audit",
        "--pull=always",
        "--network=bridge",
        "curl ",
        "wget ",
        "apt-get",
        "https://",
        "http://",
        "|| true",
        'data.get("results", [])',
    ):
        require(forbidden not in shell, "Dart audit retained forbidden acquisition/fail-open path {!r}".format(forbidden))

    prepare_index = shell.index("scripts/dart-audit-result.py prepare")
    freshness_index = shell.index("scripts/dart-audit-result.py check-freshness")
    inspect_index = shell.index("IMAGE_ID=\"$($DOCKER_BIN image inspect")
    preflight_index = shell.index("run_bounded_docker run --rm")
    scan_index = shell.index("run_bounded_docker run --rm", preflight_index + 1)
    evaluate_index = shell.index("scripts/dart-audit-result.py evaluate")
    postcondition_index = shell.rindex('sha256sum -- "$AUDIT_TMP/pubspec.lock"')
    require(
        prepare_index < freshness_index < inspect_index < preflight_index < scan_index < evaluate_index < postcondition_index,
        "Dart audit transaction order is not prepare/freshness/bind/preflight/scan/evaluate/postcondition",
    )

    preflight, preflight_end = extract_between(
        shell,
        "run_bounded_docker run --rm",
        '>"$IMAGE_PREFLIGHT_OUT" 2>"$IMAGE_PREFLIGHT_ERR"',
        "Dart audit image preflight",
    )
    scanner, _ = extract_between(
        shell,
        "run_bounded_docker run --rm",
        '>"$RESULT_FILE" 2>"$ERROR_FILE"',
        "Dart audit scanner",
        preflight_end,
    )
    require_container_floor(preflight, "Dart audit image preflight")
    require_container_floor(scanner, "Dart audit scanner")
    require_all(
        preflight,
        (
            "--pids-limit=32 --memory=256m --memory-swap=256m --cpus=1",
            "--tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777,size=16m",
            '--env HOME=/tmp --env LC_ALL=C',
            '"$IMAGE_ID" /bin/bash --noprofile --norc -c',
            '"$OSV_SCANNER_SHA256" "$OSV_DB_PUB_SHA256"',
            '"$OSV_DB_PUB_SIZE" "$OSV_DB_PUB_CAPTURE_EPOCH"',
        ),
        "Dart audit image preflight",
    )
    require("--mount " not in preflight, "Dart audit image preflight must have no mount")
    require_all(
        scanner,
        (
            "--pids-limit=64 --memory=512m --memory-swap=512m --cpus=2",
            "--tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777,size=64m",
            '--env HOME=/tmp/audit-home --env LC_ALL=C',
            "--env OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/opt/osv-db",
            '--mount "type=bind,source=$STAGED_LOCKFILE_PATH,target=/work/$LOCKFILE,readonly"',
            '--workdir /work "$IMAGE_ID"',
            'osv-scanner --offline --format=json --lockfile="$LOCKFILE"',
        ),
        "Dart audit scanner",
    )
    require(scanner.count("--mount ") == 1, "Dart audit scanner must have exactly one mount")

    require_all(
        result,
        (
            "ALLOWED_SCANNER_STATUSES = frozenset((0, 1))",
            "EXPECTED_DB_MAX_AGE_DAYS = 30",
            "MAX_RESULT_BYTES = 64 * 1024 * 1024",
            "MAX_STDERR_BYTES = 1024 * 1024",
            "def stable_read(path, maximum_bytes=None):",
            "metadata.st_nlink == 1",
            'flags |= os.O_NOFOLLOW',
            "def prepare(policy_path, lockfile_path, output):",
            'output / "pubspec.lock"',
            'output / "policy.txt"',
            "def require_fresh(capture_epoch, maximum_days, now_epoch):",
            "maximum_days == EXPECTED_DB_MAX_AGE_DAYS",
            "def validate_scanner_stderr(path, expected_source):",
            'len(lines) == 4',
            'lines[0] == "Starting filesystem walk for root: /"',
            '"Loaded Pub local db from {}".format(EXPECTED_SCANNER_DATABASE)',
            'results = data.get("results")',
            "len(results) <= 1",
            'source.get("path") == expected_source and source.get("type") == "lockfile"',
            'package.get("ecosystem") == "Pub"',
            "scanner_status in ALLOWED_SCANNER_STATUSES",
            "OSV status 0 disagrees with nonempty vulnerability results",
            "OSV status 1 has no vulnerability result",
            "require(checks == 31",
            "--capture-epoch",
            "--stderr",
            "--self-test",
        ),
        "Dart audit result authority",
    )
    require_once(result, "def evaluate(policy_path, result_path, stderr_path, scanner_status, lockfile):", "result evaluator")
    require_once(result, "def run_self_test():", "result behavioral self-test")
    require('data.get("results", [])' not in result, "Dart result parser defaults a missing results field")

    require_all(
        pins,
        (
            'OSV_SCANNER_VERSION="2.4.0"',
            'OSV_SCALIBR_VERSION="0.4.5"',
            'OSV_SCANNER_COMMIT="b56b5191101d5f27d4787d5583d8d01e9518a7af"',
            'OSV_SCANNER_BUILT_AT="2026-06-18T12:55:27Z"',
            'OSV_SCANNER_SHA256="{}"'.format(SCANNER_SHA256),
            'OSV_DB_PUB_SHA256="{}"'.format(DATABASE_SHA256),
            'OSV_DB_PUB_SIZE="19437"',
            'OSV_DB_PUB_CAPTURE_EPOCH="{}"'.format(DATABASE_CAPTURE_EPOCH),
            'OSV_DB_PUB_MAX_AGE_DAYS="{}"'.format(DATABASE_MAX_AGE_DAYS),
            'DART_AUDIT_IMAGE_ID="{}"'.format(IMAGE_ID),
        ),
        "Dart advisory immutable pins",
    )
    require_all(
        dockerfile,
        (
            "This file is an acquisition recipe only.",
            "scripts/dart-audit.sh never invokes",
            "then update the exact content ID, scanner/database pins, capture metadata, and",
        ),
        "Dart advisory acquisition separation",
    )

    require_once(verify, "python3 scripts/dart-audit-result.py --self-test", "Dart audit result self-test wiring")
    require_once(
        verify,
        "python3 scripts/verify-dart-audit-authority.py --repo . --self-test",
        "Dart audit authority self-test wiring",
    )
    require('<span class="id">R-S11be</span>' in requirements, "requirements are missing R-S11be")
    require("<tr><td>182</td>" in requirements, "requirements are missing Appendix C #182")
    require_all(
        requirements,
        (
            "never build, pull, or resolve an image tag",
            "exact immutable local image content ID",
            "exactly 30 days",
            "stable private copies",
            "bounded stderr telemetry",
        ),
        "Dart advisory normative closure",
    )
    require(
        "R-S11be/R-S11e-71 — Dart advisory result and scanner authority" in hardening,
        "hardening ledger is missing the Dart audit closure",
    )
    require_all(
        hardening,
        (
            "ACQUISITION REMOVED FROM VERDICT PATH",
            "exact 30-day capture-age ceiling",
            IMAGE_ID,
            "31 policy/freshness/status/schema decisions",
        ),
        "Dart advisory hardening evidence",
    )

    mutation_start = validator.index("\nMUTATIONS = (") + 1
    mutation_end = validator.index("\n)\n\n\ndef mutate_once", mutation_start)
    validator_mutations = validator[mutation_start:mutation_end]
    require_all(
        validator_mutations,
        (
            'Mutation("shell", "--network=none", "--network=bridge"',
            'Mutation("shell", \'case "$SCANNER_STATUS" in\\n  0|1) ;;\'',
            'Mutation("result", "EXPECTED_DB_MAX_AGE_DAYS = 30"',
            'Mutation("pins", \'DART_AUDIT_IMAGE_ID="{}"\''.format(IMAGE_ID),
            'Mutation("requirements", \'<span class="id">R-S11be</span>\'',
            'Mutation("hardening", "ACQUISITION REMOVED FROM VERDICT PATH"',
        ),
        "Dart audit authority validator mutation coverage",
    )


MUTATIONS = (
    Mutation("shell", '[ "$(id -u)" -ne 0 ]', '[ "$(id -u)" -ge 0 ]', "UID-root refusal"),
    Mutation("shell", '[ "$(id -g)" -ne 0 ]', '[ "$(id -g)" -ge 0 ]', "GID-root refusal"),
    Mutation("shell", '[ ! -L "$LOCKFILE" ]', '[ -e "$LOCKFILE" ]', "lockfile symlink refusal"),
    Mutation("shell", '[ ! -L "$IGNORES_FILE" ]', '[ -e "$IGNORES_FILE" ]', "policy symlink refusal"),
    Mutation(
        "shell",
        'AUDIT_TMP="$(umask 077 && mktemp -d /tmp/rustdesk-dart-audit.XXXXXXXXXX)"',
        'AUDIT_TMP="/tmp/rustdesk-dart-audit"',
        "private workspace",
    ),
    Mutation(
        "shell",
        '--remove-private-root "$AUDIT_TMP" --expected-identity "$AUDIT_TMP_ID"',
        'rm -rf -- "$AUDIT_TMP"',
        "descriptor-safe cleanup",
    ),
    Mutation("shell", "readonly MAX_SCANNER_OUTPUT_BLOCKS=65536", "readonly MAX_SCANNER_OUTPUT_BLOCKS=999999", "output file limit"),
    Mutation("shell", "scripts/dart-audit-result.py prepare", "scripts/dart-audit-result.py validate-policy", "stable preparation"),
    Mutation("shell", '--capture-epoch "$OSV_DB_PUB_CAPTURE_EPOCH"', '--capture-epoch "$(date +%s)"', "capture freshness"),
    Mutation("shell", '--max-age-days "$OSV_DB_PUB_MAX_AGE_DAYS"', '--max-age-days 99999', "age ceiling"),
    Mutation("shell", '"$DART_AUDIT_IMAGE_ID")"', '"rd-dart-audit")"', "exact image inspection"),
    Mutation("shell", '[[ "$DART_AUDIT_IMAGE_ID" =~ ^sha256:[0-9a-f]{64}$ ]]', '[ -n "$DART_AUDIT_IMAGE_ID" ]', "image ID syntax"),
    Mutation("shell", '[ "$IMAGE_ID" = "$DART_AUDIT_IMAGE_ID" ]', 'true # exact image identity', "image ID equality"),
    Mutation("shell", "--pull=never", "--pull=always", "pull refusal"),
    Mutation("shell", "--network=none", "--network=bridge", "network isolation"),
    Mutation("shell", "--read-only", "--hostname=dart-audit", "read-only root"),
    Mutation("shell", '--user "$(id -u):$(id -g)"', '--user 0:0', "nonroot user"),
    Mutation("shell", "--cap-drop=ALL", "--cap-add=SYS_ADMIN", "capability drop"),
    Mutation("shell", "--security-opt=no-new-privileges", "--security-opt=label=disable", "no-new-privileges"),
    Mutation("shell", "--pids-limit=32", "--pids-limit=-1", "preflight PID bound"),
    Mutation("shell", "--pids-limit=64", "--pids-limit=-1", "scanner PID bound"),
    Mutation("shell", "--memory=256m", "--memory=0", "preflight memory bound"),
    Mutation("shell", "--memory=512m", "--memory=0", "scanner memory bound"),
    Mutation("shell", "--memory-swap=256m", "--memory-swap=-1", "preflight swap bound"),
    Mutation("shell", "--memory-swap=512m", "--memory-swap=-1", "scanner swap bound"),
    Mutation("shell", "--cpus=1", "--cpuset-cpus=0-255", "preflight CPU bound"),
    Mutation("shell", "--cpus=2", "--cpuset-cpus=0-255", "scanner CPU bound"),
    Mutation("shell", "size=16m", "size=1g", "preflight tmpfs bound"),
    Mutation("shell", "size=64m", "size=1g", "scanner tmpfs bound"),
    Mutation("shell", '"$OSV_SCANNER_SHA256" "$OSV_DB_PUB_SHA256"', '"bad" "$OSV_DB_PUB_SHA256"', "scanner byte pin"),
    Mutation("shell", '"$OSV_DB_PUB_SIZE" "$OSV_DB_PUB_CAPTURE_EPOCH"', '"0" "$OSV_DB_PUB_CAPTURE_EPOCH"', "database metadata pin"),
    Mutation("shell", '[ "$IMAGE_PREFLIGHT_STATUS" -eq 0 ]', '[ "$IMAGE_PREFLIGHT_STATUS" -ge 0 ]', "preflight finality"),
    Mutation("shell", '[ ! -s "$IMAGE_PREFLIGHT_ERR" ]', 'true # preflight stderr', "preflight diagnostics"),
    Mutation(
        "shell",
        '--mount "type=bind,source=$STAGED_LOCKFILE_PATH,target=/work/$LOCKFILE,readonly"',
        '-v "$PWD:/work:rw"',
        "exact private input",
    ),
    Mutation("shell", 'case "$SCANNER_STATUS" in\n  0|1) ;;', 'case "$SCANNER_STATUS" in\n  0|1|127) ;;', "status classification"),
    Mutation("shell", '--scanner-status "$SCANNER_STATUS"', '--scanner-status 0', "status/result binding"),
    Mutation("shell", '[ "$RESULT_BYTES" -le 67108864 ]', '[ "$RESULT_BYTES" -ge 0 ]', "result size bound"),
    Mutation("shell", '[ "$ERROR_BYTES" -le 1048576 ]', '[ "$ERROR_BYTES" -ge 0 ]', "stderr size bound"),
    Mutation("shell", 'sha256sum -- "$AUDIT_TMP/pubspec.lock"', 'sha256sum -- "$LOCKFILE"', "staged lock postcondition"),
    Mutation("shell", 'sha256sum -- "$AUDIT_TMP/policy.txt"', 'sha256sum -- "$IGNORES_FILE"', "staged policy postcondition"),
    Mutation("result", "ALLOWED_SCANNER_STATUSES = frozenset((0, 1))", "ALLOWED_SCANNER_STATUSES = frozenset((0, 1, 127, 128))", "allowed statuses"),
    Mutation("result", "EXPECTED_DB_MAX_AGE_DAYS = 30", "EXPECTED_DB_MAX_AGE_DAYS = 90", "freshness policy"),
    Mutation("result", "metadata.st_nlink == 1", "metadata.st_nlink >= 1", "hardlink refusal"),
    Mutation("result", 'results = data.get("results")', 'results = data.get("results", [])', "required results field"),
    Mutation("result", "len(results) <= 1", "len(results) >= 0", "single source"),
    Mutation("result", 'source.get("path") == expected_source and source.get("type") == "lockfile"', 'source.get("type") == "lockfile"', "exact result source"),
    Mutation("result", 'package.get("ecosystem") == "Pub"', 'bool(package.get("ecosystem"))', "Pub ecosystem"),
    Mutation("result", "len(lines) == 4", "len(lines) >= 0", "stderr telemetry finality"),
    Mutation("result", 'lines[0] == "Starting filesystem walk for root: /"', "True # walk diagnostic", "stderr telemetry grammar"),
    Mutation("result", 'require(not findings, "OSV status 0 disagrees with nonempty vulnerability results")', "pass # status 0 agreement", "clean-status agreement"),
    Mutation("result", 'require(bool(findings), "OSV status 1 has no vulnerability result")', "pass # status 1 agreement", "finding-status agreement"),
    Mutation("result", "require(checks == 31", "require(checks >= 0", "behavioral self-test count"),
    Mutation("pins", 'DART_AUDIT_IMAGE_ID="sha256:f80e9869536995a1db9c14ab07c7b2ddfc83a4eaef52be2e49971c767323de0d"', 'DART_AUDIT_IMAGE_ID="sha256:0000000000000000000000000000000000000000000000000000000000000000"', "image content pin"),
    Mutation("pins", 'OSV_DB_PUB_CAPTURE_EPOCH="1782347599"', 'OSV_DB_PUB_CAPTURE_EPOCH="9999999999"', "capture epoch pin"),
    Mutation("pins", 'OSV_DB_PUB_MAX_AGE_DAYS="30"', 'OSV_DB_PUB_MAX_AGE_DAYS="90"', "capture age pin"),
    Mutation("pins", 'OSV_DB_PUB_SHA256="8b1d25767804f7487d7a26d9ae001c00813329252157eb7d267a8fb6f575b87c"', 'OSV_DB_PUB_SHA256="0000000000000000000000000000000000000000000000000000000000000000"', "database byte pin"),
    Mutation("dockerfile", "This file is an acquisition recipe only.", "The release gate builds this image.", "acquisition separation"),
    Mutation("verify", "python3 scripts/verify-dart-audit-authority.py --repo . --self-test", "python3 scripts/verify-dart-audit-authority.py --repo .", "shared semantic gate"),
    Mutation("requirements", '<span class="id">R-S11be</span>', '<span class="id">R-S11be-disabled</span>', "normative requirement"),
    Mutation("requirements", "<tr><td>182</td>", "<tr><td>182-disabled</td>", "Appendix disposition"),
    Mutation("hardening", "ACQUISITION REMOVED FROM VERDICT PATH", "ACQUISITION RETAINED IN VERDICT PATH", "hardening acquisition record"),
)


def mutate_once(sources, mutation):
    source = sources[mutation.source]
    count = source.count(mutation.old)
    require(count >= 1, "self-test mutation {!r} is absent".format(mutation.label))
    changed = dict(sources)
    changed[mutation.source] = source.replace(mutation.old, mutation.new, 1)
    return changed


def load_sources(repo):
    return {
        "shell": (repo / "scripts/dart-audit.sh").read_text(encoding="utf-8"),
        "result": (repo / "scripts/dart-audit-result.py").read_text(encoding="utf-8"),
        "pins": (repo / "scripts/pins.env").read_text(encoding="utf-8"),
        "dockerfile": (repo / "scripts/Dockerfile.dart-audit").read_text(encoding="utf-8"),
        "verify": (repo / "scripts/verify.sh").read_text(encoding="utf-8"),
        "requirements": (repo / "requirements.html").read_text(encoding="utf-8"),
        "hardening": (repo / "HARDENING_STATUS.md").read_text(encoding="utf-8"),
        "validator": (repo / "scripts/verify-dart-audit-authority.py").read_text(encoding="utf-8"),
    }


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path("."))
    parser.add_argument("--self-test", action="store_true")
    arguments = parser.parse_args(argv)
    try:
        sources = load_sources(arguments.repo.resolve())
        validate_contract(sources)
        if arguments.self_test:
            for mutation in MUTATIONS:
                try:
                    validate_contract(mutate_once(sources, mutation))
                except ContractError:
                    continue
                raise ContractError("self-test mutation was accepted: {}".format(mutation.label))
            print(
                "verify-dart-audit-authority: ok ({} deliberate mutations rejected)".format(
                    len(MUTATIONS)
                )
            )
        else:
            print("verify-dart-audit-authority: ok")
        return 0
    except (ContractError, OSError, UnicodeError, ValueError) as exc:
        print("verify-dart-audit-authority: {}".format(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
