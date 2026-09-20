#!/usr/bin/env python3
"""Focused source complement for the Android Gradle verifier-VM runtime test."""

from __future__ import annotations

import argparse
from pathlib import Path


class VerificationError(RuntimeError):
    pass


FILES = {
    "gate": "scripts/test-android-gradle-cache.sh",
    "outer": "scripts/smoke-verifier-vm-authority.sh",
    "guest": "scripts/smoke-verifier-vm-authority-guest.sh",
    "verify": "scripts/verify.sh",
    "release": "scripts/verify-release.sh",
}


def require(source: str, token: str, label: str) -> None:
    if token not in source:
        raise VerificationError(f"missing {label}")


def forbid(source: str, token: str, label: str) -> None:
    if token in source:
        raise VerificationError(f"forbidden {label}")


def require_count(source: str, token: str, expected: int, label: str) -> None:
    observed = source.count(token)
    if observed != expected:
        raise VerificationError(
            f"{label} count is {observed}, expected {expected}"
        )


def require_order(source: str, tokens: tuple[str, ...], label: str) -> None:
    offset = 0
    for token in tokens:
        position = source.find(token, offset)
        if position < 0:
            raise VerificationError(f"{label} is incomplete or misordered")
        offset = position + len(token)


def shell_function(source: str, name: str) -> str:
    marker = f"\n{name}() {{\n"
    start = source.find(marker)
    if start < 0:
        raise VerificationError(f"missing shell function {name}")
    end = source.find("\n}\n", start + len(marker))
    if end < 0:
        raise VerificationError(f"unterminated shell function {name}")
    return source[start + 1 : end + 2]


def section(source: str, start: str, end: str, label: str) -> str:
    begin = source.find(start)
    finish = source.find(end, begin + len(start)) if begin >= 0 else -1
    if begin < 0 or finish < 0:
        raise VerificationError(f"missing {label}")
    return source[begin:finish]


def validate_gate(gate: str) -> None:
    require_order(
        gate,
        (
            'readonly BUILD_UID="$(/usr/bin/id -u)"',
            'readonly BUILD_GID="$(/usr/bin/id -g)"',
            '[ "$BUILD_UID" -ne 0 ]',
            '[ "$BUILD_GID" -ne 0 ]',
            'readonly SCRIPT_DIR="$(cd',
            'if [ "${1:-}" = --inside ]; then',
            "inside_container",
            "exit 0",
            "readonly VERIFIER_VM_ENTRY_PREFLIGHT=",
            '/usr/bin/bash "$VERIFIER_VM_ENTRY_PREFLIGHT"',
            'source "$SCRIPT_DIR/lib.sh"',
            "load_pins",
        ),
        "root refusal, inner-role exit, and pre-input VM admission",
    )
    for token, label in (
        ("set -euo pipefail\numask 077", "private-state shell mode"),
        ("export PATH=/usr/bin:/bin", "closed command path"),
        ("export LC_ALL=C", "fixed locale"),
        ("refuses host or container-root execution", "UID-root refusal"),
        ("refuses a root primary group", "GID-root refusal"),
        ("verify-vm-entry-preflight.sh", "verifier-VM admission source"),
        ("'%a:%h'", "entry-preflight metadata check"),
        (
            "readonly VERIFIER_VM_AUTHORITY_ROOT=/run/rustdesk-verifier-vm",
            "fixed VM authority root",
        ),
        ("readonly VERIFIER_VM_DOCKER_CLIENT=/usr/bin/docker", "fixed guest client"),
        ("docker.sock", "fixed guest Unix channel"),
        ("docker-config", "fixed guest configuration"),
        ('"docker=$VERIFIER_VM_DOCKER_VERSION"', "repository Docker-version pin"),
    ):
        require(gate, token, label)

    docker = shell_function(gate, "verifier_vm_docker")
    provenance = shell_function(gate, "verifier_vm_image_provenance")
    for block, label in ((docker, "Docker"), (provenance, "provenance")):
        require_count(
            block,
            '/usr/bin/bash "$VERIFIER_VM_ENTRY_PREFLIGHT" >/dev/null',
            2,
            f"{label} pre/post admission replay",
        )
        for token, description in (
            (
                "/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C HOME=/nonexistent",
                "closed environment",
            ),
            ('DOCKER_HOST="unix://$VERIFIER_VM_DOCKER_SOCKET"', "fixed endpoint"),
            ('DOCKER_CONFIG="$VERIFIER_VM_DOCKER_CONFIG"', "fixed configuration"),
            ("|| status=$?", "operation status preservation"),
            ('return "$status"', "post-replay result return"),
        ):
            require(block, token, f"{label} {description}")
    for token, label in (
        ('"$VERIFIER_VM_DOCKER_CLIENT"', "absolute guest client"),
        ('--host "unix://$VERIFIER_VM_DOCKER_SOCKET"', "explicit guest endpoint"),
        ('--config "$VERIFIER_VM_DOCKER_CONFIG"', "explicit guest configuration"),
    ):
        require(docker, token, label)
    require(
        provenance,
        '/usr/bin/python3 -I -S "$SCRIPT_DIR/offline-image-provenance.py"',
        "isolated provenance parser",
    )

    image = shell_function(gate, "require_verifier_vm_android_builder")
    for token, label in (
        ("verifier_vm_image_provenance verify-local", "VM-only provenance call"),
        ("--role android-builder", "closed image role"),
        ('--expected-id "$ANDROID_BUILDER_IMAGE_ID"', "expected image ID"),
        ('--image-ref "$ANDROID_BUILDER_CONFIG_ID"', "immutable runtime image reference"),
        ("--bootstrap-image-id", "bootstrap image identity"),
        ("--bootstrap-manifest-id", "bootstrap manifest identity"),
        ("--source-date-epoch", "reproducible epoch"),
        ("--config-id", "OCI configuration identity"),
        ("--manifest-id", "OCI manifest identity"),
    ):
        require(image, token, label)

    profiles = (
        (
            "android_gradle_mount_rejection_run",
            (
                "--pids-limit=64 --memory=512m --memory-swap=512m --cpus=1",
                "--ulimit core=0:0 --ulimit nofile=1024:1024",
                "--ulimit fsize=1048576:1048576",
                "--tmpfs /tmp:rw,nosuid,nodev,mode=1777,size=256m",
            ),
        ),
        (
            "android_gradle_semantics_run",
            (
                "--pids-limit=256 --memory=4g --memory-swap=4g --cpus=2",
                "--ulimit core=0:0 --ulimit nofile=4096:4096",
                "--ulimit fsize=1073741824:1073741824",
                "--tmpfs /tmp:rw,nosuid,nodev,mode=1777,size=2g",
            ),
        ),
    )
    for name, bounds in profiles:
        profile = shell_function(gate, name)
        for token, label in (
            (
                "verifier_vm_docker run --rm --pull=never --network=none --read-only",
                "VM-routed immutable networkless run",
            ),
            ('--user "$BUILD_UID:$BUILD_GID"', "numeric nonroot identity"),
            ("--cap-drop=ALL", "capability drop"),
            ("--security-opt=no-new-privileges", "privilege-gain refusal"),
            ("--security-opt=apparmor=docker-default", "explicit AppArmor profile"),
        ):
            require(profile, token, f"{name} {label}")
        for bound in bounds:
            require(profile, bound, f"{name} resource bound")
    require_count(
        gate,
        "verifier_vm_docker run --rm --pull=never --network=none --read-only",
        2,
        "two closed profile launchers",
    )

    inside = shell_function(gate, "inside_container")
    for token, label in (
        ('[ "$$" -eq 1 ]', "PID-1 container-payload proof"),
        ("requires non-root execution", "inner UID refusal"),
        ("requires a non-root primary group", "inner GID refusal"),
        ("android-gradle-cache.py\" self-test", "projector self-test"),
        ("Gradle cache destination already exists", "preexisting destination refusal"),
        ("/gradle-distribution/bin/gradle --no-daemon", "pinned Gradle execution"),
        ("RUSTDESK_GRADLE_START_PARAMETER_OFFLINE=true", "offline semantic verdict"),
        ("RUSTDESK_GRADLE_START_PARAMETER_OFFLINE=false", "unset semantic verdict"),
        ("RUSTDESK_GRADLE_OFFLINE must be unset or exactly 1", "invalid flag refusal"),
        ("APK_MODE must be exactly offline, warm, or rust-check", "mode contract"),
        ("RUSTDESK_GRADLE_OFFLINE is build-internal", "internal flag authority"),
    ):
        require(inside, token, label)

    self_test = section(
        gate,
        'if [ "$SELF_TEST_VM_AUTHORITY" -eq 1 ]; then',
        '\nWORKSPACE=""',
        "VM runtime self-test",
    )
    for token, label in (
        ("verifier_vm_docker version", "real client/server request"),
        ("containers_before=", "pre-run container inventory"),
        ("containers_after=", "post-run container inventory"),
        ("android_gradle_mount_rejection_run", "mount-rejection profile execution"),
        ("android_gradle_semantics_run", "semantics profile execution"),
        ("/proc/self/status", "kernel privilege observation"),
        ("/sys/fs/cgroup/pids.max", "PID-limit observation"),
        ("/sys/fs/cgroup/memory.max", "memory-limit observation"),
        ("/sys/fs/cgroup/memory.swap.max", "swap-limit observation"),
        ("/sys/fs/cgroup/cpu.max", "CPU-limit observation"),
        ("/sys/class/net/lo", "network-namespace observation"),
        ("ANDROID_GRADLE_VM_AUTHORITY=pass", "bounded runtime receipt"),
        ("gradle=unexecuted", "truthful workload limitation"),
        ("cleanup=joined", "joined cleanup receipt"),
    ):
        require(self_test, token, label)

    normal = gate[gate.find('\nWORKSPACE=""') :]
    for token, label in (
        ("require_online_complete", "online closure authentication"),
        ("require_verifier_vm_android_builder", "builder provenance"),
        ("gradle-${ANDROID_GRADLE_WRAPPER}-all", "pinned Gradle distribution"),
        ("same-filesystem nested bind", "private mount-crossing fixture"),
        (
            "source=$SCRIPT_DIR/android-gradle-cache.py,target=$CONTAINER_TEST_ROOT/android-gradle-cache.py,readonly,bind-recursive=disabled",
            "read-only projector mount",
        ),
        (
            "source=$SCRIPT_DIR/android-gradle-offline.init.gradle,target=$CONTAINER_TEST_ROOT/android-gradle-offline.init.gradle,readonly,bind-recursive=disabled",
            "read-only init-script mount",
        ),
        (
            "source=$SCRIPT_DIR/android-apk-build.sh,target=$CONTAINER_TEST_ROOT/android-apk-build.sh,readonly,bind-recursive=disabled",
            "read-only mode-contract mount",
        ),
        (
            "source=$SCRIPT_DIR/test-android-gradle-cache.sh,target=$CONTAINER_TEST_ROOT/test-android-gradle-cache.sh,readonly,bind-recursive=disabled",
            "read-only test-payload mount",
        ),
        (
            "source=$gradle_root,target=/gradle-distribution,readonly,bind-recursive=disabled",
            "read-only Gradle distribution mount",
        ),
        ("accepted a same-filesystem descendant bind mount", "mount-crossing refusal"),
        ("/bin/bash \"$CONTAINER_TEST_ROOT/test-android-gradle-cache.sh\" --inside", "inner workload"),
        (
            "/usr/bin/env -i PATH=/usr/bin:/bin",
            "closed identity-bound workspace cleanup",
        ),
        ("--remove-private-root \"$WORKSPACE\"", "descriptor-safe workspace closer"),
    ):
        require(normal, token, label)
    require_count(normal, "bind-recursive=disabled", 9, "nine exact nonrecursive binds")
    require_count(normal, "require_online_complete", 2, "online pre/post replay")

    for token, label in (
        ("/var/run/docker.sock", "host Docker socket"),
        ("local_docker", "host-local Docker wrapper"),
        ("initialize_local_docker_authority", "host Docker initializer"),
        ("remove_local_docker_authority", "host Docker retirement"),
        ("require_pinned_builder_image", "ambient provenance fallback"),
        ("docker pull", "image-pull fallback"),
        ("docker build", "image-build fallback"),
        ("--privileged", "privileged container"),
        ("--cap-add", "added capability"),
        ("--network=host", "host network namespace"),
        ("--pid=host", "host PID namespace"),
        ("--ipc=host", "host IPC namespace"),
        ("--uts=host", "host UTS namespace"),
        ("--publish", "port publication"),
        ("source=/run/rustdesk-verifier-vm/docker.sock", "guest socket mount"),
        ('rm -rf -- "$WORKSPACE"', "recursive pathname workspace cleanup"),
    ):
        forbid(gate, token, label)


def validate_harness(sources: dict[str, str]) -> None:
    outer = sources["outer"]
    guest = sources["guest"]
    for token, label in (
        (
            'readonly ANDROID_GRADLE_SOURCE="$SCRIPT_DIR/test-android-gradle-cache.sh"',
            "outer gate binding",
        ),
        (
            'readonly ANDROID_GRADLE_CHECKER="$SCRIPT_DIR/verify-android-gradle-authority.py"',
            "outer checker binding",
        ),
        (
            'repo/scripts/test-android-gradle-cache.sh=$ANDROID_GRADLE_SOURCE',
            "read-only gate transport",
        ),
        (
            'repo/scripts/verify-android-gradle-authority.py=$ANDROID_GRADLE_CHECKER',
            "read-only checker transport",
        ),
        ("VERIFIER_VM_ANDROID_GRADLE_SOURCE_GATE=pass", "outer source receipt"),
        ("VERIFIER_VM_ANDROID_GRADLE_ENTRY=pass", "outer runtime receipt"),
    ):
        require(outer, token, label)
    for token, label in (
        (
            "readonly ANDROID_GRADLE_SCRIPT=$VERIFY_REPO/scripts/test-android-gradle-cache.sh",
            "guest gate binding",
        ),
        (
            "readonly ANDROID_GRADLE_CHECKER=$VERIFY_REPO/scripts/verify-android-gradle-authority.py",
            "guest checker binding",
        ),
        ("root-android-gradle-entry", "root refusal execution"),
        ("foreign-android-gradle-entry", "foreign refusal execution"),
        (
            '/bin/bash "$ANDROID_GRADLE_SCRIPT" --self-test-vm-authority "$(<"$ROOT/image-id")"',
            "authorized real profile execution",
        ),
        ("verify-android-gradle-authority: ok", "focused source verdict"),
        ("VERIFIER_VM_ANDROID_GRADLE_SOURCE_GATE=pass", "guest source receipt"),
        ("VERIFIER_VM_ANDROID_GRADLE_ENTRY=pass", "guest runtime receipt"),
        ("profiles=mount-rejection,semantics runtime=real", "two-profile runtime verdict"),
        ("gradle=unexecuted", "truthful workload limitation"),
    ):
        require(guest, token, label)


def validate_wiring(sources: dict[str, str]) -> None:
    require(
        sources["release"],
        "test-android-gradle-cache.sh|non-root immutable Gradle projection",
        "mandatory release child",
    )
    require(
        sources["verify"],
        "python3 scripts/verify-android-gradle-authority.py --repo .",
        "main focused source gate",
    )
    forbid(
        sources["verify"],
        "python3 scripts/verify-android-gradle-authority.py --repo . --self-test",
        "make-believe mutation invocation",
    )


def load_sources(repo: Path) -> dict[str, str]:
    loaded: dict[str, str] = {}
    for name, relative in FILES.items():
        path = repo / relative
        if path.is_symlink() or not path.is_file():
            raise VerificationError(f"required source is not a regular file: {relative}")
        loaded[name] = path.read_text(encoding="utf-8")
    return loaded


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path("."))
    args = parser.parse_args()
    try:
        sources = load_sources(args.repo.resolve())
        validate_gate(sources["gate"])
        validate_harness(sources)
        validate_wiring(sources)
    except (OSError, UnicodeError, VerificationError) as error:
        print(f"verify-android-gradle-authority: FAIL: {error}")
        return 1
    print("verify-android-gradle-authority: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
