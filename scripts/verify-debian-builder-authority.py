#!/usr/bin/env python3
"""Check the Debian builder's sole verifier-VM compiler authority."""

import argparse
import pathlib


class AuthorityError(Exception):
    pass


def require(source: str, token: str, label: str) -> None:
    if token not in source:
        raise AuthorityError(f"missing {label}")


def forbid(source: str, token: str, label: str) -> None:
    if token in source:
        raise AuthorityError(f"forbidden {label}")


def require_count(source: str, token: str, count: int, label: str) -> None:
    observed = source.count(token)
    if observed != count:
        raise AuthorityError(f"{label} count is {observed}, expected {count}")


def extract(source: str, start: str, end: str, label: str) -> str:
    try:
        first = source.index(start)
        last = source.index(end, first)
    except ValueError as error:
        raise AuthorityError(f"missing {label}") from error
    return source[first:last]


def require_order(source: str, tokens: tuple[str, ...], label: str) -> None:
    try:
        positions = tuple(source.index(token) for token in tokens)
    except ValueError as error:
        raise AuthorityError(f"{label} is incomplete") from error
    if positions != tuple(sorted(positions)) or len(set(positions)) != len(positions):
        raise AuthorityError(f"{label} is misordered")


def validate(repo: pathlib.Path) -> None:
    build = (repo / "scripts/build-debian.sh").read_text(encoding="utf-8")
    outer = (repo / "scripts/smoke-verifier-vm-authority.sh").read_text(
        encoding="utf-8"
    )
    guest = (repo / "scripts/smoke-verifier-vm-authority-guest.sh").read_text(
        encoding="utf-8"
    )
    verify = (repo / "scripts/verify.sh").read_text(encoding="utf-8")

    require_order(
        build,
        (
            "export PATH=/usr/bin:/bin",
            'readonly BUILD_UID="$(/usr/bin/id -u)"',
            'readonly BUILD_GID="$(/usr/bin/id -g)"',
            '[ "$BUILD_UID" -ne 0 ]',
            '[ "$BUILD_GID" -ne 0 ]',
            "readonly VERIFIER_VM_ENTRY_PREFLIGHT=",
            '/usr/bin/bash "$VERIFIER_VM_ENTRY_PREFLIGHT"',
            'source "$SCRIPT_DIR/lib.sh"',
            "load_pins",
        ),
        "root refusal and VM admission before repository helpers",
    )
    for token, label in (
        ("set -euo pipefail\numask 077", "private-state shell policy"),
        ("readonly VERIFIER_VM_AUTHORITY_ROOT=/run/rustdesk-verifier-vm",
         "fixed guest authority root"),
        ("readonly VERIFIER_VM_DOCKER_CLIENT=/usr/bin/docker",
         "fixed guest Docker client"),
        ("VERIFIER_VM_DOCKER_SOCKET=$VERIFIER_VM_AUTHORITY_ROOT/docker.sock",
         "fixed guest-private Docker socket"),
        ("VERIFIER_VM_DOCKER_CONFIG=$VERIFIER_VM_AUTHORITY_ROOT/docker-config",
         "fixed root-owned guest configuration"),
        ('"docker=$VERIFIER_VM_DOCKER_VERSION"', "pinned guest Docker version"),
        ("verifier_vm_docker() {", "VM Docker operation funnel"),
        ("verifier_vm_image_provenance() {", "VM provenance funnel"),
        ('require_pinned_builder_image deb-builder "$IMAGE_ID" verifier_vm_image_provenance',
         "VM-only immutable-image provenance"),
        ("debian_compiler_run() {", "single Debian compiler operation"),
        ('debian_compiler_run "$IMAGE_ID"', "production compiler routing"),
        ("run_vm_authority_self_test() {", "real production-profile self-test"),
        ('debian_compiler_run "$PROBE_IMAGE_ID"', "profile self-test routing"),
        ("workload=unexecuted cleanup=joined", "truthful profile receipt"),
    ):
        require(build, token, label)

    for function_name, end, label in (
        ("verifier_vm_docker() {", "\n}\n\nverifier_vm_image_provenance() {",
         "VM Docker operation funnel"),
        ("verifier_vm_image_provenance() {", "\n}\n\nOUT_DIR=",
         "VM provenance funnel"),
    ):
        function = extract(build, function_name, end, label)
        require_count(
            function,
            '/usr/bin/bash "$VERIFIER_VM_ENTRY_PREFLIGHT"',
            2,
            f"{label} pre/post admission replay",
        )
        for token, token_label in (
            ("/usr/bin/env -i", "empty environment"),
            ('DOCKER_HOST="unix://$VERIFIER_VM_DOCKER_SOCKET"',
             "explicit guest Unix endpoint"),
            ('DOCKER_CONFIG="$VERIFIER_VM_DOCKER_CONFIG"',
             "explicit root-owned configuration"),
        ):
            require(function, token, f"{label} {token_label}")

    compiler = extract(
        build,
        "debian_compiler_run() {",
        "\n}\n\nrun_vm_authority_self_test() {",
        "Debian compiler operation",
    )
    require_count(compiler, "verifier_vm_docker run", 1, "sole compiler launch")
    for token, label in (
        ("--rm --pull=never", "no-pull ephemeral container"),
        ("--network=none", "network-none container"),
        ("--read-only", "read-only root"),
        ('--user "$BUILD_UID:$BUILD_GID"', "numeric nonroot principal"),
        ("--cap-drop=ALL", "zero capabilities"),
        ("--security-opt=no-new-privileges", "no privilege gain"),
        ("--security-opt=apparmor=docker-default", "AppArmor confinement"),
        ("--cgroupns=private", "private cgroup namespace"),
        ("--ipc=private", "private IPC namespace"),
        ("--pids-limit=1024", "PID bound"),
        ("--memory=16g", "memory bound"),
        ("--memory-swap=16g", "zero added swap"),
        ("--cpus=4", "CPU bound"),
        ("--ulimit core=0:0", "core-file refusal"),
        ("--ulimit nofile=65536:65536", "descriptor bound"),
        ("--ulimit fsize=4294967296:4294967296", "file-size bound"),
        ("/tmp:rw,exec,nosuid,nodev,mode=1777,size=12g", "bounded scratch"),
        ('--env "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH"',
         "explicit reproducibility epoch"),
        ("--env RUSTDESK_CANARY_OFFLINE=1", "offline canary"),
        ("source=$BUILD_SOURCE_ROOT,target=/src,bind-recursive=disabled",
         "private source-only writable mount"),
        ("/src/.git:ro,noexec,nosuid,nodev,mode=0555,size=1m",
         "hidden Git authority"),
        ("source=$ONLINE_DIR,target=/online,readonly,bind-recursive=disabled",
         "read-only exact online input"),
        ("--workdir /src", "fixed source workdir"),
    ):
        require(compiler, token, label)

    self_test = extract(
        build,
        "run_vm_authority_self_test() {",
        "\n}\n\n# build_one PROFILE FEATURES PASS:",
        "Debian compiler runtime self-test",
    )
    for token, label in (
        ("verifier_vm_docker version", "live client/server request"),
        ("containers_before=", "initial container inventory"),
        ("containers_after=", "final container inventory"),
        ('[ "$containers_after" = "$containers_before" ]', "container cleanup proof"),
        ('[ "$memory_max" = 17179869184 ]', "runtime memory observation"),
        ('[ "$swap_max" = 0 ]', "runtime swap observation"),
        ('[ "$cpu_quota:$cpu_period" = 400000:100000 ]',
         "runtime CPU observation"),
        ('[ "$fsize_limit" = 4294967296:4294967296:bytes ]',
         "runtime file-size observation"),
        ('[ "$cap" = 0000000000000000 ]', "runtime capability observation"),
        ('[ "$nnp" = 1 ]', "runtime no-new-privileges observation"),
        ('[ "$seccomp" = 2 ]', "runtime seccomp observation"),
        ("docker-default", "runtime AppArmor observation"),
        ('[ "$1" = /sys/class/net/lo ]', "runtime loopback-only observation"),
        ('if (: >/forbidden-root-write)', "runtime read-only-root observation"),
        ('if (: >/online/forbidden-write)', "runtime read-only-input observation"),
        ('if (: >/src/.git/forbidden-write)', "runtime hidden-Git observation"),
        ("remove_owned_workspace_exact", "joined private-fixture cleanup"),
    ):
        require(self_test, token, label)

    cleanup = extract(
        build,
        "cleanup_owned_workspace() {",
        "\n}\n\ntrap cleanup_owned_workspace EXIT",
        "Debian workspace cleanup",
    )
    publication = extract(
        build, "publish_result() {", "\n}\n\nmain() {", "Debian publication"
    )
    require(cleanup, "remove_owned_workspace_exact", "exact workspace cleanup")
    require_order(
        publication,
        (
            "verify_active_online_snapshot",
            'verify_build_source_postcondition "final Debian build-source state"',
            '/usr/bin/bash "$VERIFIER_VM_ENTRY_PREFLIGHT"',
            "prepare_pending_result",
            "remove_owned_workspace_exact",
            "--commit",
        ),
        "authority replay, workspace retirement, and publication",
    )

    for token, label in (
        ("initialize_local_docker_authority", "host-Docker authority initialization"),
        ("assert_local_docker_authority", "host-Docker authority assertion"),
        ("remove_local_docker_authority", "host-Docker authority cleanup"),
        ("local_docker", "host-Docker launch funnel"),
        ("/var/run/docker.sock", "host Docker socket"),
        ("/usr/bin/docker run", "direct Docker launch"),
        ('"$DOCKER_BIN"', "caller-selected Docker client"),
        ("--network=host", "host network namespace"),
        ("--privileged", "privileged container"),
        ("--cap-add", "added capability"),
        ("--publish", "published port"),
        ("--pid=host", "host PID namespace"),
        ("--ipc=host", "host IPC namespace"),
        ("source=/run/docker.sock", "Docker socket bind mount"),
    ):
        forbid(build, token, label)

    require_count(build, "verifier_vm_docker run", 1, "single Docker run surface")
    require_count(build, 'debian_compiler_run "$IMAGE_ID"', 1,
                  "single production compiler routing")
    require_count(build, 'debian_compiler_run "$PROBE_IMAGE_ID"', 1,
                  "single runtime-profile routing")

    for source, token, label in (
        (outer, "readonly DEBIAN_BUILDER_SOURCE=", "outer builder source binding"),
        (outer, "readonly DEBIAN_BUILDER_AUTHORITY_CHECKER=",
         "outer focused-checker binding"),
        (outer, '"repo/scripts/build-debian.sh=$DEBIAN_BUILDER_SOURCE"',
         "builder read-only-media transport"),
        (outer, '"repo/scripts/verify-debian-builder-authority.py=$DEBIAN_BUILDER_AUTHORITY_CHECKER"',
         "checker read-only-media transport"),
        (outer, "VERIFIER_VM_DEBIAN_BUILDER_ENTRY=pass",
         "outer behavioral receipt"),
        (guest, "readonly DEBIAN_BUILDER_SCRIPT=", "guest builder binding"),
        (guest, "readonly DEBIAN_BUILDER_AUTHORITY_CHECKER=",
         "guest checker binding"),
        (guest, "verify-debian-builder-authority: ok", "guest source-gate result"),
        (guest, '"$DEBIAN_BUILDER_SCRIPT" --self-test-vm-authority',
         "guest behavioral entry"),
        (guest, "root-debian-builder-entry", "VM-root refusal case"),
        (guest, "foreign-debian-builder-entry", "foreign-principal refusal case"),
        (guest, "DEBIAN_BUILDER_VM_AUTHORITY=pass", "authorized profile receipt"),
        (verify, "/usr/bin/python3 -I -S scripts/verify-debian-builder-authority.py --repo .",
         "shared focused gate wiring"),
    ):
        require(source, token, label)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=pathlib.Path, default=pathlib.Path("."))
    args = parser.parse_args()
    validate(args.repo.resolve())
    print("verify-debian-builder-authority: ok")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AuthorityError, OSError) as error:
        print(f"verify-debian-builder-authority: {error}")
        raise SystemExit(1)
