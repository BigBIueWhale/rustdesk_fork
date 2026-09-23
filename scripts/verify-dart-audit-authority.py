#!/usr/bin/env python3
"""Check the small static complement to the Dart-audit VM entry smoke.

The authoritative execution tests live in smoke-verifier-vm-authority.sh: the
default smoke rejects root and a foreign principal and makes the real entry
perform a Docker client/server request; --dart-audit loads the exact promoted
image and executes the real scan in the no-NIC VM. This checker does only what
source inspection is suited to: prove that those routes remain wired, that the
production audit has no parallel host-Docker path, and that its two scanner
launches retain their confined shape. Scanner result semantics have their own
behavioral self-test in dart-audit-result.py; acquisition and OCI provenance
have separate gates.
"""

import argparse
from pathlib import Path
import re
import sys


class ContractError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise ContractError(message)


def require_all(source, tokens, label):
    for token in tokens:
        require(token in source, "{}: missing {!r}".format(label, token))


def require_once(source, token, label):
    count = source.count(token)
    require(count == 1, "{}: expected one occurrence, found {}".format(label, count))


def extract(source, start_token, end_token, label, offset=0):
    start = source.find(start_token, offset)
    require(start >= 0, "{}: opening token is absent".format(label))
    end = source.find(end_token, start)
    require(end >= 0, "{}: closing token is absent".format(label))
    end += len(end_token)
    return source[start:end], end


def validate_container(block, label):
    require_all(
        block,
        (
            "--rm",
            "--pull=never",
            "--network=none",
            "--read-only",
            '--user "$AUDIT_UID:$AUDIT_GID"',
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
        "/var/run/docker.sock",
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
        "$REPO_ROOT",
        "$PWD",
    ):
        require(forbidden not in block, "{}: forbidden authority {!r}".format(label, forbidden))
    require(
        re.search(r"(?:^|\s)-p(?:\s|=)", block) is None,
        "{}: publishes a port".format(label),
    )


def validate_contract(repo):
    shell = (repo / "scripts/dart-audit.sh").read_text(encoding="utf-8")
    verify = (repo / "scripts/verify.sh").read_text(encoding="utf-8")
    vm_outer = (repo / "scripts/smoke-verifier-vm-authority.sh").read_text(
        encoding="utf-8"
    )
    vm_guest = (repo / "scripts/smoke-verifier-vm-authority-guest.sh").read_text(
        encoding="utf-8"
    )
    entry_preflight = (repo / "scripts/verify-vm-entry-preflight.sh").read_text(
        encoding="utf-8"
    )

    require_all(
        shell,
        (
            "export PATH=/usr/bin:/bin",
            "export LC_ALL=C",
            'readonly AUDIT_UID="$(/usr/bin/id -u)"',
            'readonly AUDIT_GID="$(/usr/bin/id -g)"',
            '[ "$AUDIT_UID" -ne 0 ] || dart_audit_die "refuses host or container-root execution"',
            '[ "$AUDIT_GID" -ne 0 ] || dart_audit_die "refuses a root primary group"',
            "readonly VERIFIER_VM_ENTRY_PREFLIGHT=$SCRIPT_DIR/verify-vm-entry-preflight.sh",
            '"$(/usr/bin/stat -c \'%a:%h\' -- "$VERIFIER_VM_ENTRY_PREFLIGHT")" = 755:1',
            '/usr/bin/bash "$VERIFIER_VM_ENTRY_PREFLIGHT"',
            'source "$SCRIPT_DIR/lib.sh"',
            "load_pins",
            "readonly VERIFIER_VM_AUTHORITY_ROOT=/run/rustdesk-verifier-vm",
            "readonly VERIFIER_VM_DOCKER_CLIENT=/usr/bin/docker",
            "readonly VERIFIER_VM_DOCKER_SOCKET=$VERIFIER_VM_AUTHORITY_ROOT/docker.sock",
            "readonly VERIFIER_VM_DOCKER_CONFIG=$VERIFIER_VM_AUTHORITY_ROOT/docker-config",
            '[ "$VERIFIER_VM_MARKER_DOCKER" = "docker=$VERIFIER_VM_DOCKER_VERSION" ]',
            "verifier_vm_docker() {",
            "run_bounded_docker() (",
            'verifier_vm_docker "$@"',
            "--self-test-vm-authority",
            "verifier_vm_docker version",
            "DART_AUDIT_VM_AUTHORITY=pass uid=%s gid=%s docker=%s channel=guest-unix prepost=replayed",
        ),
        "Dart audit VM entry",
    )

    uid_guard = shell.index('[ "$AUDIT_UID" -ne 0 ]')
    gid_guard = shell.index('[ "$AUDIT_GID" -ne 0 ]')
    initial_preflight = shell.index('/usr/bin/bash "$VERIFIER_VM_ENTRY_PREFLIGHT"')
    source_lib = shell.index('source "$SCRIPT_DIR/lib.sh"')
    input_check = shell.index('[ -f "$LOCKFILE" ]')
    self_test = shell.index("verifier_vm_docker version")
    require(
        uid_guard < gid_guard < initial_preflight < source_lib < self_test < input_check,
        "Dart audit does not refuse root and authenticate the VM before product input",
    )

    wrapper, _ = extract(
        shell,
        "verifier_vm_docker() {",
        '\n}\n\n# Bound stdout',
        "Dart audit verifier-VM Docker wrapper",
    )
    require(
        wrapper.count('/usr/bin/bash "$VERIFIER_VM_ENTRY_PREFLIGHT" >/dev/null || return 1') == 2,
        "Dart audit Docker wrapper must replay VM authority before and after every operation",
    )
    require_all(
        wrapper,
        (
            "/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C HOME=/nonexistent",
            'DOCKER_HOST="unix://$VERIFIER_VM_DOCKER_SOCKET"',
            'DOCKER_CONFIG="$VERIFIER_VM_DOCKER_CONFIG"',
            '"$VERIFIER_VM_DOCKER_CLIENT"',
            '--host "unix://$VERIFIER_VM_DOCKER_SOCKET"',
            '--config "$VERIFIER_VM_DOCKER_CONFIG" "$@" || status=$?',
            'return "$status"',
        ),
        "Dart audit verifier-VM Docker wrapper",
    )

    for forbidden in (
        "/var/run/docker.sock",
        "initialize_local_docker_authority",
        "remove_local_docker_authority",
        "LOCAL_DOCKER_AUTHORITY",
        "local_docker",
        "docker build",
        "verifier_vm_docker build",
        "--pull=always",
        "--network=bridge",
        "curl ",
        "wget ",
        "apt-get",
        "|| true",
        'data.get("results", [])',
    ):
        require(forbidden not in shell, "Dart audit retained forbidden path {!r}".format(forbidden))
    require(
        shell.count("/usr/bin/docker") == 1,
        "Dart audit must name /usr/bin/docker only as the fixed guest client",
    )

    require_all(
        shell,
        (
            "readonly MAX_SCANNER_OUTPUT_BLOCKS=65536",
            'current_limit="$(ulimit -Sf)"',
            '[ -f "$LOCKFILE" ] && [ ! -L "$LOCKFILE" ]',
            '[ -f "$IGNORES_FILE" ] && [ ! -L "$IGNORES_FILE" ]',
            'AUDIT_TMP="$(umask 077 && mktemp -d /tmp/rustdesk-dart-audit.XXXXXXXXXX)"',
            '--remove-private-root "$AUDIT_TMP" --expected-identity "$AUDIT_TMP_ID"',
            "scripts/dart-audit-result.py prepare",
            "scripts/dart-audit-result.py check-freshness",
            '--capture-epoch "$OSV_DB_PUB_CAPTURE_EPOCH"',
            '--max-age-days "$OSV_DB_PUB_MAX_AGE_DAYS"',
            ': "${DART_AUDIT_IMAGE_ID:?dart-audit.sh: DART_AUDIT_IMAGE_ID unset in pins.env}"',
            ': "${DART_AUDIT_IMAGE_CONFIG_ID:?dart-audit.sh: DART_AUDIT_IMAGE_CONFIG_ID unset in pins.env}"',
            '[[ "$DART_AUDIT_IMAGE_ID" =~ ^sha256:[0-9a-f]{64}$ ]]',
            '[[ "$DART_AUDIT_IMAGE_CONFIG_ID" =~ ^sha256:[0-9a-f]{64}$ ]]',
            'IMAGE_ID="$(verifier_vm_docker image inspect --format \'{{.Id}}\' "$DART_AUDIT_IMAGE_CONFIG_ID")"',
            '[ "$IMAGE_ID" = "$DART_AUDIT_IMAGE_CONFIG_ID" ]',
            '[ "$IMAGE_PREFLIGHT_STATUS" -eq 0 ]',
            '[ ! -s "$IMAGE_PREFLIGHT_OUT" ]',
            '[ ! -s "$IMAGE_PREFLIGHT_ERR" ]',
            'case "$SCANNER_STATUS" in\n  0|1) ;;',
            "scripts/dart-audit-result.py evaluate",
            '--scanner-status "$SCANNER_STATUS" --lockfile "$LOCKFILE"',
            '[ "$RESULT_BYTES" -gt 0 ]',
            '[ "$RESULT_BYTES" -le 67108864 ]',
            '[ "$ERROR_BYTES" -gt 0 ]',
            '[ "$ERROR_BYTES" -le 1048576 ]',
            'sha256sum -- "$AUDIT_TMP/pubspec.lock"',
            'sha256sum -- "$AUDIT_TMP/policy.txt"',
            'AUDIT_SUCCESS_MESSAGE="VERIFY-DART-AUDIT: green',
        ),
        "Dart audit result and input finality",
    )
    require(
        shell.count("scripts/dart-audit-result.py check-freshness") == 2,
        "Dart audit must check database freshness before and after the scan",
    )
    require(
        shell.count("run_bounded_docker run --rm") == 2,
        "Dart audit must have exactly one image preflight and one scanner launch",
    )

    prepare_index = shell.index("scripts/dart-audit-result.py prepare")
    freshness_index = shell.index("scripts/dart-audit-result.py check-freshness")
    inspect_index = shell.index("IMAGE_ID=\"$(verifier_vm_docker image inspect")
    preflight_index = shell.index("run_bounded_docker run --rm")
    scan_index = shell.index("run_bounded_docker run --rm", preflight_index + 1)
    evaluate_index = shell.index("scripts/dart-audit-result.py evaluate")
    postcondition_index = shell.rindex('sha256sum -- "$AUDIT_TMP/pubspec.lock"')
    require(
        prepare_index
        < freshness_index
        < inspect_index
        < preflight_index
        < scan_index
        < evaluate_index
        < postcondition_index,
        "Dart audit transaction order is not prepare/freshness/inspect/preflight/scan/evaluate/postcondition",
    )

    preflight, preflight_end = extract(
        shell,
        "run_bounded_docker run --rm",
        '>"$IMAGE_PREFLIGHT_OUT" 2>"$IMAGE_PREFLIGHT_ERR"',
        "Dart audit image preflight",
    )
    scanner, _ = extract(
        shell,
        "run_bounded_docker run --rm",
        '>"$RESULT_FILE" 2>"$ERROR_FILE"',
        "Dart audit scanner",
        preflight_end,
    )
    validate_container(preflight, "Dart audit image preflight")
    validate_container(scanner, "Dart audit scanner")
    require_all(
        preflight,
        (
            "--pids-limit=32 --memory=256m --memory-swap=256m --cpus=1",
            "--tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777,size=16m",
            '"$OSV_SCANNER_SHA256" "$OSV_DB_PUB_SHA256"',
            '"$OSV_DB_PUB_SIZE" "$OSV_DB_PUB_CAPTURE_EPOCH"',
        ),
        "Dart audit image preflight",
    )
    require("--mount " not in preflight, "Dart audit image preflight must be mount-free")
    require_all(
        scanner,
        (
            "--pids-limit=64 --memory=512m --memory-swap=512m --cpus=2",
            "--tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777,size=64m",
            "--env OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/opt/osv-db",
            '--mount "type=bind,source=$STAGED_LOCKFILE_PATH,target=/work/$LOCKFILE,readonly"',
            '--workdir /work "$IMAGE_ID"',
            'osv-scanner --offline --format=json --lockfile="$LOCKFILE"',
        ),
        "Dart audit scanner",
    )
    require(scanner.count("--mount ") == 1, "Dart audit scanner must have one read-only input mount")

    require_all(
        vm_outer,
        (
            "1:--dart-audit)",
            "MODE=dart-audit",
            'readonly DART_AUDIT_IMAGE_ARCHIVE="$ONLINE_INPUTS/verifier-images/dart-audit.docker.tar.gz"',
            'verify_sha256 "$DART_AUDIT_IMAGE_ARCHIVE" "$SHA256_DART_AUDIT_IMAGE_ARCHIVE"',
            "focused Dart audit requires the one checked-out master authority",
            "focused Dart-audit source differs from pushed master",
            "focused Dart audit requires a clean source tree",
            'git_closed -C "$REPO_ROOT" archive --format=tar "$DART_SOURCE_COMMIT"',
            '"dart-audit.docker.tar.gz=$DART_AUDIT_IMAGE_ARCHIVE"',
            'guest_invocation+=" --dart-audit ',
            "-nic none",
            "DART_AUDIT_VM_OUTER=pass",
            "listeners=no-harness-addition",
            "docker=guest-only",
            "cleanup=joined",
        ),
        "focused Dart-audit outer VM route",
    )
    require_all(
        vm_guest,
        (
            "13:--dart-audit)",
            "readonly VERIFIER_VM_NOFILE_LIMIT=524544",
            'ulimit -Hn "$VERIFIER_VM_NOFILE_LIMIT"',
            'ulimit -Sn "$VERIFIER_VM_NOFILE_LIMIT"',
            "run_dart_audit() {",
            "focused Dart-audit source archive digest differs",
            "focused Dart-audit image archive digest differs",
            'python3 -I -S "$source_root/scripts/offline-image-provenance.py"',
            "verify-load",
            '--role dart-audit',
            '--expected-id "$DART_AUDIT_IMAGE_ID"',
            "VM root passed the focused Dart-audit entry",
            "foreign principal passed the focused Dart-audit entry",
            '/bin/bash "$source_root/scripts/dart-audit.sh"',
            "focused Dart advisory green verdict is absent or duplicated",
            'image rm "$DART_AUDIT_IMAGE_CONFIG_ID"',
            "stop_docker_authority",
            "DART_AUDIT_VM=pass",
            "nofile=524544",
            "vm_network=none container_network=none",
            "source=readonly cleanup=joined",
        ),
        "focused Dart-audit guest transaction",
    )
    require_all(
        entry_preflight,
        (
            "readonly VERIFIER_VM_NOFILE_LIMIT=524544",
            '"$VERIFIER_VM_NOFILE_LIMIT:$VERIFIER_VM_NOFILE_LIMIT"',
            "verifier descriptor limit differs",
        ),
        "focused Dart-audit entry descriptor authority",
    )
    require(
        vm_guest.count('/bin/bash "$source_root/scripts/dart-audit.sh"') == 3,
        "focused Dart-audit guest must have root, foreign, and authorized entries",
    )

    require_once(
        verify,
        "if ! python3 scripts/verify-dart-audit-authority.py --repo .; then",
        "Dart audit compact source-gate wiring",
    )
    require(
        "python3 scripts/dart-audit-result.py --self-test" in verify,
        "Dart audit result behavioral self-test is not wired",
    )


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    arguments = parser.parse_args(argv)
    try:
        validate_contract(arguments.repo.resolve())
        print("verify-dart-audit-authority: ok")
        return 0
    except (ContractError, OSError, UnicodeError, ValueError) as exc:
        print("verify-dart-audit-authority: {}".format(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
