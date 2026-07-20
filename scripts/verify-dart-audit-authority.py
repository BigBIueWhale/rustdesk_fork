#!/usr/bin/env python3
"""Bind Dart advisory scanning to exact finality and confined Docker authority."""

import argparse
from pathlib import Path
import re
import sys


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


def scanner_run_block(source):
    require_once(source, "$DOCKER_BIN run ", "Dart advisory scanner launch")
    start = source.index("$DOCKER_BIN run ")
    end_token = '  >"$RESULT_FILE" 2>"$ERROR_FILE"'
    end = source.index(end_token, start) + len(end_token)
    return source[start:end]


def validate_contract(sources):
    shell = sources["shell"]
    result = sources["result"]
    verify = sources["verify"]
    requirements = sources["requirements"]
    hardening = sources["hardening"]
    validator = sources["validator"]

    require_all(
        shell,
        (
            'readonly DOCKER_BIN=/usr/bin/docker',
            'readonly PYTHON_BIN=/usr/bin/python3',
            '[ "$(id -u)" -ne 0 ] || die "refuses host or container-root execution"',
            '[ "$(id -g)" -ne 0 ] || die "refuses a root primary group"',
            '[ -f "$LOCKFILE" ] && [ ! -L "$LOCKFILE" ]',
            '[ -f "$IGNORES_FILE" ] && [ ! -L "$IGNORES_FILE" ]',
            'AUDIT_TMP="$(umask 077 && mktemp -d /tmp/rustdesk-dart-audit.XXXXXXXXXX)"',
            'AUDIT_TMP_ID="$(/usr/bin/stat -c \'%d:%i\' -- "$AUDIT_TMP")"',
            '--remove-private-root "$AUDIT_TMP" --expected-identity "$AUDIT_TMP_ID"',
            'scripts/dart-audit-result.py validate-policy --policy "$IGNORES_FILE"',
            'IMAGE_ID="$($DOCKER_BIN build -q',
            '[[ "$IMAGE_ID" =~ ^sha256:[0-9a-f]{64}$ ]]',
            "TAG_IMAGE_ID=\"$($DOCKER_BIN image inspect --format '{{.Id}}' \"$IMG\")\"",
            '[ "$TAG_IMAGE_ID" = "$IMAGE_ID" ]',
            'set +e\n$DOCKER_BIN run ',
            'SCANNER_STATUS=$?\nset -e',
            'case "$SCANNER_STATUS" in\n  0|1) ;;',
            'scripts/dart-audit-result.py evaluate',
            '--scanner-status "$SCANNER_STATUS"',
            'RESULT_BYTES="$(/usr/bin/stat -c \'%s\' -- "$RESULT_FILE")"',
            '[ "$RESULT_BYTES" -le 67108864 ]',
            'AUDIT_SUCCESS_MESSAGE="VERIFY-DART-AUDIT: green',
        ),
        "Dart audit shell authority",
    )
    require(
        shell.index('scripts/dart-audit-result.py validate-policy')
        < shell.index('IMAGE_ID="$($DOCKER_BIN build -q'),
        "Dart audit validates policy only after image construction",
    )
    require(
        shell.index('TAG_IMAGE_ID="$($DOCKER_BIN image inspect')
        < shell.index("$DOCKER_BIN run "),
        "Dart audit runs before binding the built content ID",
    )
    require(
        shell.index('case "$SCANNER_STATUS" in')
        < shell.index('scripts/dart-audit-result.py evaluate'),
        "Dart audit parses JSON before classifying scanner finality",
    )

    run = scanner_run_block(shell)
    require_all(
        run,
        (
            "--rm",
            "--pull=never",
            "--network=none",
            "--read-only",
            '--user "$(id -u):$(id -g)"',
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--pids-limit=64",
            "--memory=512m",
            "--memory-swap=512m",
            "--cpus=2",
            "--tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777,size=64m",
            "--env HOME=/tmp/audit-home",
            '--mount "type=bind,source=$LOCKFILE_PATH,target=/work/$LOCKFILE,readonly"',
            '--workdir /work "$IMAGE_ID"',
            'osv-scanner --offline --format=json --lockfile="$LOCKFILE"',
            '>"$RESULT_FILE" 2>"$ERROR_FILE"',
        ),
        "Dart audit scanner container",
    )
    require(run.count("--mount ") == 1, "Dart audit scanner must have exactly one mount")
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
        '--workdir /work "$IMG"',
        "2>/dev/null",
    ):
        require(forbidden not in run, "Dart audit scanner has forbidden authority {!r}".format(forbidden))
    require(
        re.search(r"(?:^|\s)-p(?:\s|=)", run) is None,
        "Dart audit scanner publishes a port",
    )
    for forbidden in (
        "|| true",
        'data.get("results", [])',
        'json.loads(os.environ["OSV_JSON"])',
        'OSV_JSON="$JSON"',
    ):
        require(forbidden not in shell, "Dart audit retained fail-open result path {!r}".format(forbidden))

    require_all(
        result,
        (
            "ALLOWED_SCANNER_STATUSES = frozenset((0, 1))",
            "MAX_RESULT_BYTES = 64 * 1024 * 1024",
            "not stat.S_ISLNK(metadata.st_mode)",
            "stat.S_ISREG(metadata.st_mode)",
            'raw.partition("#")',
            "expected exactly one advisory id",
            "accepted advisory has no reason",
            "duplicate advisory id",
            "scanner_status in ALLOWED_SCANNER_STATUSES",
            "OSV scanner infrastructure status {} is not an advisory result",
            'results = data.get("results")',
            'isinstance(results, list)',
            'isinstance(packages, list)',
            'isinstance(vulnerabilities, list)',
            "OSV status 0 disagrees with nonempty vulnerability results",
            "OSV status 1 has no vulnerability result",
            "require(checks == 19",
            "--self-test",
        ),
        "Dart audit result authority",
    )
    require_once(result, "def evaluate(policy_path, result_path, scanner_status, lockfile):", "result evaluator")
    require_once(result, "def run_self_test():", "result behavioral self-test")

    require_once(
        verify,
        "python3 scripts/dart-audit-result.py --self-test",
        "Dart audit result self-test wiring",
    )
    require_once(
        verify,
        "python3 scripts/verify-dart-audit-authority.py --repo . --self-test",
        "Dart audit authority self-test wiring",
    )
    require('<span class="id">R-S11be</span>' in requirements, "requirements are missing R-S11be")
    require("<tr><td>182</td>" in requirements, "requirements are missing Appendix C #182")
    require(
        "R-S11be/R-S11e-71 — Dart advisory result and scanner authority" in hardening,
        "hardening ledger is missing the Dart audit closure",
    )
    mutation_start = validator.index("\nMUTATIONS = (") + 1
    mutation_end = validator.index("\n)\n\n\ndef mutate_once", mutation_start)
    validator_mutations = validator[mutation_start:mutation_end]
    require_all(
        validator_mutations,
        (
            'Mutation("shell", "--network=none", "--network=bridge"',
            'Mutation("shell", "  0|1) ;;", "  0|1|127) ;;"',
            'Mutation(\n        "result",\n        "ALLOWED_SCANNER_STATUSES = frozenset((0, 1))"',
            'Mutation(\n        "verify",\n        "python3 scripts/verify-dart-audit-authority.py --repo . --self-test"',
            'Mutation(\n        "requirements",\n        \'<span class="id">R-S11be</span>\'',
            'Mutation(\n        "hardening",\n        "R-S11be/R-S11e-71 — Dart advisory result and scanner authority"',
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
    Mutation(
        "shell",
        'scripts/dart-audit-result.py validate-policy --policy "$IGNORES_FILE"',
        'printf 0',
        "policy prevalidation",
    ),
    Mutation("shell", 'IMAGE_ID="$($DOCKER_BIN build -q', 'IMAGE_ID="rd-dart-audit" # $DOCKER_BIN build -q', "build content ID"),
    Mutation(
        "shell",
        '[[ "$IMAGE_ID" =~ ^sha256:[0-9a-f]{64}$ ]]',
        '[ -n "$IMAGE_ID" ]',
        "image ID syntax",
    ),
    Mutation("shell", '[ "$TAG_IMAGE_ID" = "$IMAGE_ID" ]', 'true # image tag identity', "tag identity"),
    Mutation("shell", "--pull=never", "--pull=always", "pull refusal"),
    Mutation("shell", "--network=none", "--network=bridge", "network isolation"),
    Mutation("shell", "--read-only", "--hostname=dart-audit", "read-only root"),
    Mutation("shell", '--user "$(id -u):$(id -g)"', '--user 0:0', "nonroot user"),
    Mutation("shell", "--cap-drop=ALL", "--cap-add=SYS_ADMIN", "capability drop"),
    Mutation(
        "shell",
        "--security-opt=no-new-privileges",
        "--security-opt=label=disable",
        "no-new-privileges",
    ),
    Mutation("shell", "--pids-limit=64", "--pids-limit=-1", "PID bound"),
    Mutation("shell", "--memory=512m", "--memory=0", "memory bound"),
    Mutation("shell", "--memory-swap=512m", "--memory-swap=-1", "swap bound"),
    Mutation("shell", "--cpus=2", "--cpuset-cpus=0-255", "CPU bound"),
    Mutation(
        "shell",
        "--tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777,size=64m",
        "--tmpfs /tmp:rw,exec,mode=1777",
        "temporary storage",
    ),
    Mutation(
        "shell",
        '--mount "type=bind,source=$LOCKFILE_PATH,target=/work/$LOCKFILE,readonly"',
        '-v "$PWD:/work:rw"',
        "exact read-only input",
    ),
    Mutation("shell", '--workdir /work "$IMAGE_ID"', '--workdir /work "$IMG"', "content-ID execution"),
    Mutation("shell", "  0|1) ;;", "  0|1|127) ;;", "status classification"),
    Mutation(
        "shell",
        '--scanner-status "$SCANNER_STATUS"',
        '--scanner-status 0',
        "status/result binding",
    ),
    Mutation(
        "shell",
        '[ "$RESULT_BYTES" -le 67108864 ]',
        '[ "$RESULT_BYTES" -ge 0 ]',
        "result size bound",
    ),
    Mutation(
        "result",
        "ALLOWED_SCANNER_STATUSES = frozenset((0, 1))",
        "ALLOWED_SCANNER_STATUSES = frozenset((0, 1, 127, 128))",
        "allowed scanner statuses",
    ),
    Mutation(
        "result",
        'results = data.get("results")',
        'results = data.get("results", [])',
        "required results field",
    ),
    Mutation(
        "result",
        "require(not findings, \"OSV status 0 disagrees with nonempty vulnerability results\")",
        "pass # status 0/result agreement disabled",
        "clean-status agreement",
    ),
    Mutation(
        "result",
        "require(bool(findings), \"OSV status 1 has no vulnerability result\")",
        "pass # status 1/result agreement disabled",
        "finding-status agreement",
    ),
    Mutation("result", "require(checks == 19", "require(checks >= 0", "behavioral self-test count"),
    Mutation(
        "verify",
        "python3 scripts/verify-dart-audit-authority.py --repo . --self-test",
        "python3 scripts/verify-dart-audit-authority.py --repo .",
        "shared semantic gate",
    ),
    Mutation(
        "requirements",
        '<span class="id">R-S11be</span>',
        '<span class="id">R-S11be-disabled</span>',
        "normative requirement",
    ),
    Mutation(
        "requirements",
        "<tr><td>182</td>",
        "<tr><td>182-disabled</td>",
        "Appendix disposition",
    ),
    Mutation(
        "hardening",
        "R-S11be/R-S11e-71 — Dart advisory result and scanner authority",
        "R-S11be/R-S11e-71 — Dart advisory closure deferred",
        "hardening ledger",
    ),
)


def mutate_once(sources, mutation):
    source = sources[mutation.source]
    count = source.count(mutation.old)
    require(count == 1, "self-test mutation {!r} matched {} times".format(mutation.label, count))
    changed = dict(sources)
    changed[mutation.source] = source.replace(mutation.old, mutation.new, 1)
    return changed


def load_sources(repo):
    return {
        "shell": (repo / "scripts/dart-audit.sh").read_text(encoding="utf-8"),
        "result": (repo / "scripts/dart-audit-result.py").read_text(encoding="utf-8"),
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
    except (ContractError, OSError, UnicodeError) as exc:
        print("verify-dart-audit-authority: {}".format(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
