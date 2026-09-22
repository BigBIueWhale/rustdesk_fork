#!/usr/bin/env python3
"""Verify the Apple source gate's VM-only execution architecture."""

import argparse
import hashlib
import stat
from pathlib import Path


class VerificationError(Exception):
    pass


def read_regular(repo: Path, relative: str, executable: bool = False) -> str:
    path = repo / relative
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        raise VerificationError(f"not a regular repository file: {relative}")
    if executable and stat.S_IMODE(metadata.st_mode) != 0o755:
        raise VerificationError(f"executable mode differs for {relative}")
    if metadata.st_size > 2 * 1024 * 1024:
        raise VerificationError(f"source exceeds verifier bound: {relative}")
    return path.read_text(encoding="utf-8")


def section(source: str, start: str, end: str, label: str) -> str:
    if source.count(start) != 1:
        raise VerificationError(f"{label} start cardinality differs")
    begin = source.index(start)
    finish = source.find(end, begin + len(start))
    if finish < 0:
        raise VerificationError(f"{label} end is absent")
    return source[begin:finish]


def require(source: str, value: str, label: str) -> None:
    if value not in source:
        raise VerificationError(f"missing {label}")


def forbid(source: str, value: str, label: str) -> None:
    if value in source:
        raise VerificationError(f"forbidden {label}: {value}")


def require_count(source: str, value: str, count: int, label: str) -> None:
    observed = source.count(value)
    if observed != count:
        raise VerificationError(f"{label} count is {observed}, expected {count}")


def require_order(source: str, values: tuple[str, ...], label: str) -> None:
    position = -1
    for value in values:
        found = source.find(value, position + 1)
        if found < 0:
            raise VerificationError(f"missing or out-of-order {label}: {value}")
        position = found


def require_confined_launch(
    source: str,
    label: str,
    *,
    mounts: tuple[str, ...],
    pid_limit: str,
    memory: str,
    cpu: str,
    tmpfs: str,
) -> None:
    for value in (
        "--pull=never",
        "--network=none",
        "--read-only",
        '--user "$BUILD_UID:$BUILD_GID"',
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        pid_limit,
        memory,
        cpu,
        tmpfs,
        *mounts,
    ):
        require(source, value, f"{label} confinement")
    require_count(source, "--mount ", len(mounts), f"{label} mount inventory")
    for value in (
        "--privileged",
        "--cap-add",
        "--network=host",
        "--pid=host",
        "--ipc=host",
        "--uts=host",
        "--publish",
        "--expose",
        "/var/run/docker.sock",
        "/dev/",
    ):
        forbid(source, value, f"{label} host authority")


def validate(repo: Path) -> None:
    apple = read_regular(repo, "scripts/apple-conform-check.sh", executable=True)
    verify = read_regular(repo, "scripts/verify.sh")
    outer = read_regular(repo, "scripts/smoke-verifier-vm-authority.sh", executable=True)
    guest = read_regular(repo, "scripts/smoke-verifier-vm-authority-guest.sh", executable=True)
    pins = read_regular(repo, "scripts/pins.env")
    dockerfile = read_regular(repo, "scripts/Dockerfile.apple-check")

    require_order(
        apple,
        (
            'readonly BUILD_UID="$(/usr/bin/id -u)"',
            'readonly BUILD_GID="$(/usr/bin/id -g)"',
            '[ "$BUILD_UID" -ne 0 ]',
            '[ "$BUILD_GID" -ne 0 ]',
            "for name in DOCKER_HOST DOCKER_CONFIG DOCKER_CONTEXT DOCKER_CERT_PATH",
            '[ -z "${!name:-}" ] || die "caller $name authority is forbidden"',
            'VERIFIER_VM_ENTRY_PREFLIGHT=$SCRIPT_DIR/verify-vm-entry-preflight.sh',
            '/usr/bin/bash "$VERIFIER_VM_ENTRY_PREFLIGHT"',
            'source "$SCRIPT_DIR/lib.sh"',
            "load_pins",
        ),
        "pre-source VM admission",
    )
    for value in (
        "/var/run/docker.sock",
        "local_docker",
        "initialize_local_docker_authority",
        "APPLE_DOCKER_HOST",
        "APPLE_DOCKER_CONFIG",
        "apple_docker",
        "verify_apple_docker_authority",
    ):
        forbid(apple, value, "host Docker authority")

    for value in (
        "DOCKER_HOST",
        "DOCKER_CONFIG",
        "DOCKER_CONTEXT",
        "DOCKER_CERT_PATH",
        "DOCKER_TLS_VERIFY",
        "APPLE_TARGET",
        "APPLE_TARGETS",
        "MACOS_SDK_DIR",
    ):
        require(apple, value, f"caller authority rejection for {value}")

    docker = section(
        apple,
        "verifier_vm_docker() {",
        "\n}\n\nverifier_vm_image_provenance() {",
        "VM Docker wrapper",
    )
    provenance = section(
        apple,
        "verifier_vm_image_provenance() {",
        "\n}\n\nAPPLE_VM_AUTHORITY_SELF_TEST=0",
        "VM provenance wrapper",
    )
    for body, operation in ((docker, '"$VERIFIER_VM_DOCKER_CLIENT"'), (provenance, "offline-image-provenance.py")):
        require_order(
            body,
            (
                '/usr/bin/bash "$VERIFIER_VM_ENTRY_PREFLIGHT" >/dev/null',
                "/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C HOME=/nonexistent",
                'DOCKER_HOST="unix://$VERIFIER_VM_DOCKER_SOCKET"',
                'DOCKER_CONFIG="$VERIFIER_VM_DOCKER_CONFIG"',
                operation,
                '/usr/bin/bash "$VERIFIER_VM_ENTRY_PREFLIGHT" >/dev/null',
            ),
            "VM operation pre/post admission",
        )

    require_order(
        apple,
        (
            "APPLE_VM_AUTHORITY_SELF_TEST=0",
            '[ "$1" = --self-test-vm-authority ]',
            'authority_version="$(verifier_vm_docker version',
            "APPLE_CHECK_VM_AUTHORITY=pass uid=%s gid=%s docker=%s channel=guest-unix prepost=replayed",
            "exit 0",
            'source "$SCRIPT_DIR/verify-scan.sh"',
            "APPLE_CHECK_TMP=$(umask 077 && mktemp -d /tmp/rustdesk-apple-check.XXXXXXXXXX)",
        ),
        "authority self-test before normal inputs",
    )

    expected_targets = """readonly SELECTED_APPLE_TARGETS=(
  aarch64-apple-darwin
  x86_64-apple-darwin
  aarch64-apple-ios
)"""
    require(apple, expected_targets, "exact Apple target matrix")
    require(
        apple,
        'readonly APPLE_RUNTIME_IMAGE_ID="$APPLE_CHECK_IMAGE_CONFIG_ID"',
        "immutable Apple runtime image",
    )
    require(
        apple,
        '[[ "$APPLE_RUNTIME_IMAGE_ID" =~ ^sha256:[0-9a-f]{64}$ ]]',
        "Apple runtime config-ID syntax",
    )
    require_order(
        apple,
        (
            'IMAGE_ID="$(verifier_vm_docker image inspect',
            '[ "$IMAGE_ID" = "$APPLE_RUNTIME_IMAGE_ID" ]',
            "verifier_vm_image_provenance verify-local",
            '--image-ref "$IMAGE_ID" "${APPLE_IMAGE_SPEC[@]}"',
            'archive_current_source >"$APPLE_SOURCE_ARCHIVE"',
            "snapshot-subtree-create",
        ),
        "image proof before source execution",
    )

    image_preflight = section(
        apple,
        "verifier_vm_docker run --rm --pull=never --network=none --read-only",
        "  ' >\"$IMAGE_PREFLIGHT_OUT\"",
        "Apple image preflight launch",
    )
    require_confined_launch(
        image_preflight,
        "Apple image preflight",
        mounts=(),
        pid_limit="--pids-limit=32",
        memory="--memory=256m --memory-swap=256m",
        cpu="--cpus=1",
        tmpfs="--tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777,size=16m",
    )
    metadata = section(apple, "APPLE_READ_RUN=(", '  "$IMAGE_ID")', "metadata launch")
    require_confined_launch(
        metadata,
        "Apple metadata parser",
        mounts=('--mount "type=bind,source=$APPLE_SOURCE,target=/work,readonly"',),
        pid_limit="--pids-limit=64",
        memory="--memory=512m --memory-swap=512m",
        cpu="--cpus=1",
        tmpfs="--tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777,size=64m",
    )
    cross = section(apple, "COMMON_CHECK=(", "  --workdir /work)", "cross-check launch")
    require_confined_launch(
        cross,
        "Apple cross-check",
        mounts=(
            '--mount "type=bind,source=$APPLE_SOURCE,target=/work,readonly"',
            '--mount "type=bind,source=$APPLE_VENDOR,target=/vendor,readonly"',
            '--mount "type=bind,source=$APPLE_TARGET,target=/build"',
            '--mount "type=bind,source=$APPLE_CARGO_CONFIG,target=/tmp/cargo-config.toml,readonly"',
        ),
        pid_limit="--pids-limit=512",
        memory="--memory=12g --memory-swap=12g",
        cpu="--cpus=4",
        tmpfs="--tmpfs /tmp:rw,exec,nosuid,nodev,mode=1777,size=2g",
    )
    for value in (
        "--env CARGO_NET_OFFLINE=true",
        "cargo check --locked --offline --config /tmp/cargo-config.toml --jobs 1",
        '--package hbb_common --target "$target"',
        '--target "$target" --features "$features"',
        'if [ "$anchor_rc" -ne 0 ]',
        'apple_sdk_boundary_after_successful_workspace_anchor "$log"',
        "apple_sdk_boundary_self_test",
    ):
        require(apple, value, "locked Apple source-conformance flow")

    cleanup = section(
        apple,
        "cleanup_apple_check_tmp() {",
        "\n}\ntrap cleanup_apple_check_tmp EXIT",
        "private workspace cleanup",
    )
    require_order(
        cleanup,
        (
            'restore-private-directory-modes.py"',
            '--expected-identity "$APPLE_CHECK_TMP_IDENTITY"',
            '--owner "$APPLE_CHECK_TMP_UID"',
            '--group "$APPLE_CHECK_TMP_GID"',
            'rm -rf -- "$APPLE_CHECK_TMP"',
            'exit "$status"',
        ),
        "identity-bound private cleanup",
    )
    require_order(
        apple,
        (
            'SOURCE_DIGEST_AFTER="$(archive_current_source',
            '[ "$SOURCE_DIGEST_AFTER" = "$SOURCE_DIGEST" ]',
            'FINAL_IMAGE_ID="$(verifier_vm_docker image inspect',
            '[ "$FINAL_IMAGE_ID" = "$IMAGE_ID" ]',
            '/usr/bin/bash "$VERIFIER_VM_ENTRY_PREFLIGHT" >/dev/null',
        ),
        "Apple postconditions",
    )

    dockerfile_digest = hashlib.sha256(dockerfile.encode("utf-8")).hexdigest()
    require(pins, f'SHA256_APPLE_CHECK_DOCKERFILE="{dockerfile_digest}"', "Dockerfile content pin")
    for value in (
        'APPLE_CHECK_IMAGE_ID="sha256:',
        'APPLE_CHECK_IMAGE_CONFIG_ID="sha256:',
        'APPLE_CHECK_IMAGE_MANIFEST_ID="sha256:',
        'SHA256_APPLE_CHECK_IMAGE_ARCHIVE="',
        'SIZE_APPLE_CHECK_IMAGE_ARCHIVE="',
    ):
        require(pins, value, "Apple image provenance pin")

    require(verify, "python3 -I -S scripts/verify-apple-verifier-authority.py --repo .", "focused gate wiring")
    forbid(verify, "verify-apple-verifier-authority.py --repo . --self-test", "mutation-catalog invocation")
    for value in (
        'readonly APPLE_CHECK_SOURCE="$SCRIPT_DIR/apple-conform-check.sh"',
        '"repo/scripts/apple-conform-check.sh=$APPLE_CHECK_SOURCE"',
        "VERIFIER_VM_APPLE_CHECK_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused caller=refused",
    ):
        require(outer, value, "outer VM Apple-check probe")
    for value in (
        'readonly APPLE_CHECK_SCRIPT="$VERIFY_REPO/scripts/apple-conform-check.sh"',
        '/bin/bash "$APPLE_CHECK_SCRIPT" --self-test-vm-authority',
        "setpriv --reuid=4001 --regid=4001 --clear-groups",
        "setpriv --reuid=4000 --regid=4000 --clear-groups",
        'DOCKER_HOST|unix:///tmp/forbidden-docker.sock|FATAL: caller DOCKER_HOST authority is forbidden',
        'APPLE_TARGET|aarch64-apple-ios|FATAL: caller APPLE_TARGET authority is forbidden',
        "APPLE_CHECK_VM_AUTHORITY=pass uid=4000 gid=4000",
        "VERIFIER_VM_APPLE_CHECK_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused caller=refused",
    ):
        require(guest, value, "guest VM Apple-check probe")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=".")
    arguments = parser.parse_args()
    try:
        validate(Path(arguments.repo).resolve())
    except (OSError, UnicodeError, VerificationError) as error:
        raise SystemExit(f"Apple verifier authority: FAIL: {error}") from error
    print(
        "Apple verifier authority architecture: PASS "
        "(VM-only Docker path; exact-image/three-target shape; workload=unexecuted)"
    )


if __name__ == "__main__":
    main()
