#!/usr/bin/env python3
"""Check the static complement to the Rust-audit verifier-VM smoke.

The authoritative authority test boots the no-NIC verifier VM, rejects VM root
and a foreign principal, and makes the real audit entry perform a Docker
client/server request. This checker is deliberately smaller: source inspection
proves there is no parallel host-Docker path and that the immutable-image
preflight and both offline scanner launches retain their confined shapes.
Scanner policy/result semantics, acquisition, and OCI provenance have separate
behavioral gates.
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
            "--pids-limit=",
            "--memory=",
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
        "--pull=always",
    ):
        require(forbidden not in block, "{}: forbidden authority {!r}".format(label, forbidden))
    docker_arguments = block[: block.index('"$IMAGE_ID"')]
    require(
        re.search(r"(?:^|\s)-p(?:\s|=)", docker_arguments) is None,
        "{}: publishes a port".format(label),
    )


def validate_contract(repo):
    shell = (repo / "scripts/audit.sh").read_text(encoding="utf-8")
    verify = (repo / "scripts/verify.sh").read_text(encoding="utf-8")

    require_all(
        shell,
        (
            "export PATH=/usr/bin:/bin",
            "export LC_ALL=C",
            'readonly AUDIT_UID="$(/usr/bin/id -u)"',
            'readonly AUDIT_GID="$(/usr/bin/id -g)"',
            '[ "$AUDIT_UID" -ne 0 ] || audit_die "refuses host or container-root execution"',
            '[ "$AUDIT_GID" -ne 0 ] || audit_die "refuses a root primary group"',
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
            "RUST_AUDIT_VM_AUTHORITY=pass uid=%s gid=%s docker=%s channel=guest-unix prepost=replayed",
        ),
        "Rust audit VM entry",
    )

    uid_guard = shell.index('[ "$AUDIT_UID" -ne 0 ]')
    gid_guard = shell.index('[ "$AUDIT_GID" -ne 0 ]')
    initial_preflight = shell.index('/usr/bin/bash "$VERIFIER_VM_ENTRY_PREFLIGHT"')
    source_lib = shell.index('source "$SCRIPT_DIR/lib.sh"')
    self_test = shell.index("verifier_vm_docker version")
    input_check = shell.index('[ -f "$LOCKFILE" ]')
    require(
        uid_guard < gid_guard < initial_preflight < source_lib < self_test < input_check,
        "Rust audit does not refuse root and authenticate the VM before product input",
    )

    wrapper, _ = extract(
        shell,
        "verifier_vm_docker() {",
        "\n}\n\n# Bound stdout",
        "Rust audit verifier-VM Docker wrapper",
    )
    require(
        wrapper.count('/usr/bin/bash "$VERIFIER_VM_ENTRY_PREFLIGHT" >/dev/null || return 1') == 2,
        "Rust audit Docker wrapper must replay VM authority before and after every operation",
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
        "Rust audit verifier-VM Docker wrapper",
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
    ):
        require(forbidden not in shell, "Rust audit retained forbidden path {!r}".format(forbidden))
    require(
        shell.count("/usr/bin/docker") == 1,
        "Rust audit must name /usr/bin/docker only as the fixed guest client",
    )

    require_all(
        shell,
        (
            "readonly MAX_SCANNER_OUTPUT_BLOCKS=65536",
            'current_limit="$(ulimit -Sf)"',
            '[ -f "$LOCKFILE" ] && [ ! -L "$LOCKFILE" ]',
            '[ -f "$POLICY" ] && [ ! -L "$POLICY" ]',
            '[ -d "$VENDOR_DIR" ] && [ ! -L "$VENDOR_DIR" ]',
            '[ -f "$VENDOR_CONFIG" ] && [ ! -L "$VENDOR_CONFIG" ]',
            'AUDIT_TMP="$(umask 077 && mktemp -d /tmp/rustdesk-rust-audit.XXXXXXXXXX)"',
            '--remove-private-root "$AUDIT_TMP" --expected-identity "$AUDIT_TMP_ID"',
            "scripts/rust-audit-policy.py prepare",
            "scripts/rust-audit-policy.py check-freshness",
            '--max-age-days "$ADVISORY_DB_MAX_AGE_DAYS"',
            "scripts/online-input-provenance.py verify-subtree",
            '--expected "$SHA256_CARGO_VENDOR_CLOSURE_V1"',
            'IMAGE_ID="$(verifier_vm_docker image inspect --format \'{{.Id}}\' "$RUST_AUDIT_IMAGE_ID")"',
            '[ "$IMAGE_ID" = "$RUST_AUDIT_IMAGE_ID" ]',
            'IMAGE_METADATA="$(verifier_vm_docker image inspect --format',
            '[ "$IMAGE_METADATA" = "$EXPECTED_IMAGE_METADATA" ]',
            '[ "$IMAGE_PREFLIGHT_STATUS" -eq 0 ]',
            "scripts/rust-audit-policy.py validate-audit-result",
            '--expected-db-commit "$ADVISORY_DB_COMMIT"',
            "scripts/rust-audit-policy.py validate-deny-result",
            'AUDIT_SUCCESS_MESSAGE="VERIFY-AUDIT: green',
        ),
        "Rust audit result and input finality",
    )
    require(
        shell.count("scripts/online-input-provenance.py verify-subtree") == 2,
        "Rust audit must verify the vendor closure before and after scanner use",
    )
    require(
        shell.count("run_bounded_docker run --rm") == 3,
        "Rust audit must have one image preflight and two scanner launches",
    )
    require(
        shell.count("verifier_vm_docker image inspect --format") == 2,
        "Rust audit must have two fixed-authority image inspections",
    )

    prepare_index = shell.index("scripts/rust-audit-policy.py prepare")
    freshness_index = shell.index("scripts/rust-audit-policy.py check-freshness")
    inspect_index = shell.index('IMAGE_ID="$(verifier_vm_docker image inspect')
    preflight_index = shell.index("run_bounded_docker run --rm")
    audit_index = shell.index("run_bounded_docker run --rm", preflight_index + 1)
    deny_index = shell.index("run_bounded_docker run --rm", audit_index + 1)
    audit_result_index = shell.index("scripts/rust-audit-policy.py validate-audit-result")
    deny_result_index = shell.index("scripts/rust-audit-policy.py validate-deny-result")
    vendor_postcondition = shell.rindex("scripts/online-input-provenance.py verify-subtree")
    green_index = shell.index('AUDIT_SUCCESS_MESSAGE="VERIFY-AUDIT: green')
    require(
        prepare_index
        < freshness_index
        < inspect_index
        < preflight_index
        < audit_index
        < audit_result_index
        < deny_index
        < deny_result_index
        < vendor_postcondition
        < green_index,
        "Rust audit transaction order is not prepare/freshness/inspect/preflight/audit/result/deny/result/postcondition",
    )

    preflight, preflight_end = extract(
        shell,
        "run_bounded_docker run --rm",
        '>"$IMAGE_PREFLIGHT_OUT" 2>"$IMAGE_PREFLIGHT_ERR"',
        "Rust audit image preflight",
    )
    audit, audit_end = extract(
        shell,
        "run_bounded_docker run --rm",
        '>"$AUDIT_RESULT" 2>"$AUDIT_ERROR"',
        "cargo-audit scanner",
        preflight_end,
    )
    deny, _ = extract(
        shell,
        "run_bounded_docker run --rm",
        '>"$DENY_OUTPUT" 2>"$DENY_ERROR"',
        "cargo-deny scanner",
        audit_end,
    )
    validate_container(preflight, "Rust audit image preflight")
    validate_container(audit, "cargo-audit scanner")
    validate_container(deny, "cargo-deny scanner")

    require_all(
        preflight,
        (
            "--pids-limit=32 --memory=256m --memory-swap=256m --cpus=1",
            "--tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777,size=16m",
            '"$SHA256_RUST_AUDIT_CARGO_AUDIT" "$SHA256_RUST_AUDIT_CARGO_DENY"',
            '"$ADVISORY_DB_COMMIT" "$ADVISORY_DB_COMMIT_EPOCH" "$RUST_AUDIT_RUSTC_VERSION"',
        ),
        "Rust audit image preflight",
    )
    require("--mount " not in preflight, "Rust audit image preflight must be mount-free")
    require_all(
        audit,
        (
            "--pids-limit=64 --memory=512m --memory-swap=512m --cpus=2",
            "--tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777,size=32m",
            '--mount "type=bind,source=$AUDIT_TMP,target=/audit,readonly"',
            '"$AUDIT_IMAGE_CARGO_AUDIT" audit --file /audit/Cargo.lock --db "$AUDIT_IMAGE_DB" --no-fetch --deny warnings --json',
            '"${IGNORE_FLAGS[@]}" >"$AUDIT_RESULT" 2>"$AUDIT_ERROR"',
        ),
        "cargo-audit scanner",
    )
    require(audit.count("--mount ") == 1, "cargo-audit must have one read-only input mount")
    require_all(
        deny,
        (
            "--pids-limit=256 --memory=3g --memory-swap=3g --cpus=2",
            "--tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777,size=512m",
            '--mount "type=bind,source=$REPO_ROOT,target=/work,readonly"',
            '--mount "type=bind,source=$AUDIT_TMP,target=/audit,readonly"',
            '--mount "type=bind,source=$REPO_ROOT/$VENDOR_DIR,target=/vendor,readonly"',
            '"$AUDIT_TOOLS/bin/cargo-deny" --format json --locked --offline',
            "--config /audit/deny.runtime.toml check advisories",
            '>"$DENY_OUTPUT" 2>"$DENY_ERROR"',
        ),
        "cargo-deny scanner",
    )
    require(deny.count("--mount ") == 3, "cargo-deny must have three read-only input mounts")

    require_once(
        verify,
        "if ! python3 scripts/verify-rust-audit-authority.py --repo .; then",
        "Rust audit compact source-gate wiring",
    )
    require(
        "python3 scripts/rust-audit-policy.py --self-test" in verify,
        "Rust audit result behavioral self-test is not wired",
    )


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    arguments = parser.parse_args(argv)
    try:
        validate_contract(arguments.repo.resolve())
        print("verify-rust-audit-authority: ok")
        return 0
    except (ContractError, OSError, UnicodeError, ValueError) as exc:
        print("verify-rust-audit-authority: {}".format(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
