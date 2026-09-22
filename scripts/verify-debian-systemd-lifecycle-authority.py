#!/usr/bin/env python3
"""Validate the VM-only installed-Debian lifecycle authority."""

import argparse
import pathlib
import stat


class AuthorityError(Exception):
    pass


def read_regular(repo: pathlib.Path, relative: str, executable: bool = False) -> str:
    path = repo / relative
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise AuthorityError(f"{relative} is not one regular file")
    if executable and metadata.st_mode & 0o111 == 0:
        raise AuthorityError(f"{relative} is not executable")
    return path.read_text(encoding="utf-8")


def require(source: str, token: str, label: str) -> None:
    if token not in source:
        raise AuthorityError(f"missing {label}")


def forbid(source: str, token: str, label: str) -> None:
    if token in source:
        raise AuthorityError(f"forbidden {label}")


def require_order(source: str, tokens: tuple[str, ...], label: str) -> None:
    cursor = 0
    for token in tokens:
        position = source.find(token, cursor)
        if position < 0:
            raise AuthorityError(f"{label} is incomplete at {token!r}")
        cursor = position + len(token)


def section(source: str, start: str, end: str, label: str) -> str:
    begin = source.find(start)
    finish = source.find(end, begin + len(start)) if begin >= 0 else -1
    if begin < 0 or finish < 0:
        raise AuthorityError(f"missing {label}")
    return source[begin:finish]


def validate_stage(source: str) -> None:
    require_order(
        source,
        (
            'readonly STAGE_UID="$(/usr/bin/id -u)"',
            '[ "$STAGE_UID" -ne 0 ]',
            '[ "$STAGE_GID" -ne 0 ]',
            'readonly SCRIPT_DIR=',
            '/usr/bin/bash "$ENTRY_PREFLIGHT"',
            'source "$SCRIPT_DIR/lib.sh"',
            'load_pins',
        ),
        "staging refusal/preflight/repository order",
    )
    wrapper = section(
        source,
        "verifier_vm_docker() {",
        "\n}\n\nrequire_input_file() {",
        "guest Docker wrapper",
    )
    for token, label in (
        ('readonly DOCKER_CLIENT=/usr/bin/docker', "fixed guest Docker client"),
        ('readonly DOCKER_SOCKET=$AUTHORITY_ROOT/docker.sock', "fixed guest Unix socket"),
        ('DOCKER_HOST="unix://$DOCKER_SOCKET"', "closed Docker host"),
        ('DOCKER_CONFIG="$DOCKER_CONFIG"', "closed Docker configuration"),
        ('HOME=/nonexistent', "closed Docker home"),
    ):
        require(source if token.startswith("readonly") else wrapper, token, label)
    if wrapper.count('/usr/bin/bash "$ENTRY_PREFLIGHT" >/dev/null') != 2:
        raise AuthorityError("guest Docker wrapper must replay the preflight exactly twice")

    launch = section(
        source,
        "runtime_library_stage_run() {",
        "\n}\n\nrun_self_test() {",
        "runtime-library launch profile",
    )
    if source.count("verifier_vm_docker run --rm --pull=never") != 1:
        raise AuthorityError("runtime-library staging must have one Docker launch profile")
    for token, label in (
        ("--network=none", "network removal"),
        ("--read-only", "read-only root"),
        ('--user "$STAGE_UID:$STAGE_GID"', "numeric non-root user"),
        ("--cap-drop=ALL", "capability removal"),
        ("--security-opt=no-new-privileges", "no-new-privileges"),
        ("--security-opt=apparmor=docker-default", "AppArmor profile"),
        ("--cgroupns=private", "private cgroup namespace"),
        ("--ipc=private", "private IPC namespace"),
        ("--pids-limit=64", "PID bound"),
        ("--memory=1g", "memory bound"),
        ("--memory-swap=1g", "swap exclusion"),
        ("--cpus=1", "CPU bound"),
        ("--ulimit core=0:0", "core exclusion"),
        ("--ulimit nofile=4096:4096", "descriptor bound"),
        ("--ulimit fsize=268435456:268435456", "file-size bound"),
        ('--tmpfs "/tmp:rw,noexec,nosuid,nodev,mode=700', "bounded private tmpfs"),
        ("size=32m", "tmpfs byte bound"),
        ("source=$binary,target=/input/rustdesk,readonly,bind-recursive=disabled", "exact read-only input"),
        ("source=$output,target=/out,bind-recursive=disabled", "sole writable output"),
        ('--entrypoint "$entrypoint"', "fixed explicit entrypoint"),
    ):
        require(launch, token, label)
    for token, label in (
        ("/var/run/docker.sock", "host Docker socket"),
        ("local_docker", "host local-Docker authority"),
        ("SYSTEMD_SMOKE_DEV_IMAGE", "mutable image selection"),
        ("--privileged", "privileged container"),
        ("--network=host", "host networking"),
        ("--cap-add", "added capability"),
    ):
        forbid(source, token, label)
    for token, label in (
        ('image inspect --format \'{{.Id}}\' "$DEV_CHECK_IMAGE_CONFIG_ID"', "runtime config-ID image selection"),
        ('ldd /input/rustdesk', "exact executable dependency discovery"),
        ('runtime library basename collision', "basename-collision rejection"),
        ('runtime-library count is outside 60..256', "output count bound"),
        ('runtime-library output exceeds 1 GiB', "output byte bound"),
        ('profile=debian-systemd-runtime-libs runtime=real input=private-fixture-only workload=unexecuted', "truthful fast receipt"),
        ('[ "$uid" = 4000:4000:4000:4000 ]', "behavioral numeric identity proof"),
        ('[ "$seccomp" = 2 ]', "behavioral seccomp proof"),
        ('[ "$pids_max" = 64 ]', "behavioral PID proof"),
        ('[ "$fsize_limit" = 268435456:268435456:bytes ]', "behavioral file-size proof"),
        ('[ "$#" = 1 ] && [ "$1" = /sys/class/net/lo ]', "behavioral network proof"),
        ('if (: >/input/rustdesk)', "behavioral input-write refusal"),
    ):
        require(source, token, label)


def validate_outer(source: str) -> None:
    require_order(
        source,
        (
            'readonly HOST_UID="$(/usr/bin/id -u)"',
            '[ "$HOST_UID" -ne 0 ]',
            '[ "$HOST_GID" -ne 0 ]',
            'readonly SCRIPT_DIR=',
            'source "$SCRIPT_DIR/lib.sh"',
            'load_pins',
        ),
        "outer-VM refusal/repository order",
    )
    for token, label in (
        ('--debian-systemd-lifecycle)', "installed lifecycle scenario"),
        ('--devcheck-archive', "exact devcheck archive argument"),
        ('VERIFIER_VM_INPUT_ROOT', "separate immutable-input authority"),
        ('VERIFIER_VM_RUN_ROOT', "separate run scratch"),
        ('readonly VM_TIMEOUT_SECONDS=480', "bounded lifecycle timeout"),
        ('readonly OVERLAY_SIZE=8G', "bounded lifecycle overlay"),
        ('current_commit="$(git_closed -C "$REPO_ROOT" rev-parse', "detached-source identity"),
        ('lifecycle source must be one detached release snapshot', "detached-source refusal"),
        ('verify-debian-package-authority.py', "independent package verifier"),
        ('SHA256_DEV_CHECK_IMAGE_ARCHIVE', "pinned devcheck archive"),
        ('"devcheck.docker.tar.gz=$DEV_CHECK_ARCHIVE"', "read-only archive payload"),
        ('"artifact/rustdesk-x86_64.deb=$LIFECYCLE_ARTIFACT"', "read-only artifact payload"),
        ('payload_identity=(-uid 4000 -gid 4000)', "payload numeric verifier ownership"),
        ('-nic none', "VM network removal"),
        ('channels=unix listeners=unchanged', "host listener postcondition"),
        ('LIFECYCLE_ARTIFACT_ID=', "artifact precondition"),
        ('DEV_CHECK_ARCHIVE_ID=', "archive precondition"),
        ('lifecycle artifact identity changed during execution', "artifact postcondition"),
        ('devcheck archive identity changed during execution', "archive postcondition"),
        ('VERIFIER_VM_DEBIAN_SYSTEMD_LIFECYCLE=pass', "exact guest lifecycle receipt"),
        ('mode=debian-systemd-lifecycle', "exact outer lifecycle receipt"),
    ):
        require(source, token, label)
    if source.count("-nic none") != 1:
        raise AuthorityError("the common verifier VM must declare exactly one no-NIC boundary")
    for token, label in (
        ("SYSTEMD_SMOKE_IMAGE=", "legacy systemd image override"),
        ("SYSTEMD_SMOKE_STATE_DIR=", "legacy systemd scratch override"),
        ("/var/run/docker.sock", "host Docker socket"),
        ("-nic user", "QEMU user networking"),
        ("hostfwd", "QEMU host forwarding"),
        ("guestfwd", "QEMU guest forwarding"),
        ("--debian-systemd-smoke-image", "duplicate VM image acquisition"),
    ):
        forbid(source, token, label)


def validate_guest(source: str) -> None:
    for token, label in (
        ('source "$VERIFY_REPO/scripts/pins.env"', "pinned guest provenance"),
        ('verify-load', "offline archive verification/load"),
        ('--expected-id "$DEV_CHECK_IMAGE_ID"', "exact devcheck image ID"),
        ('chmod 0711 "$lifecycle_root" "$extracted"', "non-writable staging traversal"),
        ('setpriv --reuid=4000 --regid=4000 --clear-groups', "admitted staging principal"),
        ('setpriv --reuid=4001 --regid=4001 --clear-groups', "foreign-principal refusal probe"),
        ('root systemd runtime-library refusal', "root refusal probe"),
        ('foreign systemd runtime-library refusal', "foreign refusal proof"),
        ('authorized systemd runtime-library verifier entry failed', "admitted-entry proof"),
        ('stop_docker_authority', "joined Docker retirement"),
        ('mount -o remount,bind,ro,nodev,nosuid,noexec "$libraries"', "sealed library handoff"),
        ('/bin/bash "$SYSTEMD_LIFECYCLE_SCRIPT" --release-deb', "release-only installed lifecycle"),
        ('docker=retired network=none cleanup=joined', "installed-lifecycle receipt"),
        ('VERIFIER_VM_SYSTEMD_LIBS_ENTRY=pass', "fast real-profile receipt"),
    ):
        require(source, token, label)
    require_order(
        source,
        (
            'stage_output="$(',
            'stop_docker_authority\n',
            'mount -o remount,bind,ro,nodev,nosuid,noexec "$libraries"',
            '/bin/bash "$SYSTEMD_LIFECYCLE_SCRIPT" --release-deb',
        ),
        "stage/Docker retirement/installed lifecycle order",
    )
    for token, label in (
        ("/var/run/docker.sock", "host Docker socket"),
        ("--network=host", "host networking"),
        ("--privileged", "privileged container"),
    ):
        forbid(source, token, label)


def validate_lifecycle(source: str) -> None:
    for token, label in (
        ('[ "$#" -eq 6 ] && [ "$1" = --release-deb ]', "release-only lifecycle CLI"),
        ('[ "$(cat /proc/1/comm)" = systemd ]', "real systemd PID 1"),
        ('cmp -s "$UNIT_SOURCE" /usr/lib/systemd/system/rustdesk.service', "exact production unit"),
        ('systemd-analyze verify /usr/lib/systemd/system/rustdesk.service', "systemd unit validation"),
        ('status.get("Uid", "").split() != [str(seat_uid)] * 4', "non-root service child"),
        ('status.get("NoNewPrivs") != "1"', "service-child no-new-privileges"),
        ('systemd-run --unit="$PORTABLE_UNIT"', "portable sibling"),
        ('systemctl restart "$UNIT"', "normal restart"),
        ('systemctl stop "$UNIT"', "normal stop"),
        ('systemctl kill --kill-whom=main --signal=KILL "$UNIT"', "crash recovery"),
        ('dpkg -r "$PACKAGE"', "package removal"),
        ('dpkg --purge "$PACKAGE"', "package purge"),
        ('dpkg --verify "$PACKAGE"', "installed payload verification"),
        ('DEBIAN_RELEASE_ARTIFACT_LIFECYCLE=pass', "exact artifact receipt"),
    ):
        require(source, token, label)
    for token, label in (
        ("--source", "source-mode lifecycle"),
        ("build_package", "synthetic package fixture"),
        ("SYSTEMD_SMOKE", "legacy smoke override"),
    ):
        forbid(source, token, label)


def validate_release(build: str, release: str) -> None:
    final = section(
        build,
        "run_final_debian_artifact_lifecycle() {",
        "\n}\n\nwrite_manifest() {",
        "final Debian lifecycle transaction",
    )
    for token, label in (
        ('VERIFIER_VM_INPUT_ROOT="$HOST_VERIFIER_VM_INPUT_ROOT"', "immutable VM input root"),
        ('VERIFIER_VM_RUN_ROOT="$VERIFIER_VM_RUN_ROOT"', "private VM run root"),
        ('"$SOURCE_A/scripts/smoke-verifier-vm-authority.sh"', "snapshot-owned common VM driver"),
        ('--debian-systemd-lifecycle', "installed lifecycle scenario"),
        ('--release-deb "$artifact"', "exact release artifact"),
        ('--sha256 "$artifact_hash"', "artifact digest binding"),
        ('--commit "$PINNED_HEAD"', "source commit binding"),
        ('local devcheck_archive="$ONLINE_SNAPSHOT_PARENT/online/verifier-images/devcheck.docker.tar.gz"', "authenticated image archive selection"),
        ('--devcheck-archive "$devcheck_archive"', "authenticated image archive handoff"),
    ):
        require(final, token, label)
    for token, label in (
        ("smoke-debian-systemd-lifecycle.sh", "deleted host lifecycle driver"),
        ("SYSTEMD_SMOKE_IMAGE=", "legacy image override"),
        ("SYSTEMD_SMOKE_STATE_DIR=", "legacy state override"),
    ):
        forbid(build, token, label)
        forbid(release, token, label)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True, type=pathlib.Path)
    args = parser.parse_args()
    repo = args.repo.resolve()
    legacy = repo / "scripts/smoke-debian-systemd-lifecycle.sh"
    if legacy.exists() or legacy.is_symlink():
        raise AuthorityError("legacy host lifecycle driver still exists")
    validate_stage(read_regular(repo, "scripts/stage-debian-systemd-runtime-libs.sh", True))
    validate_outer(read_regular(repo, "scripts/smoke-verifier-vm-authority.sh", True))
    validate_guest(read_regular(repo, "scripts/smoke-verifier-vm-authority-guest.sh", True))
    validate_lifecycle(read_regular(repo, "scripts/smoke-debian-systemd-lifecycle-guest.sh", True))
    validate_release(
        read_regular(repo, "scripts/build-release.sh", True),
        read_regular(repo, "scripts/verify-release.sh", True),
    )
    print("verify-debian-systemd-lifecycle-authority: ok")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AuthorityError, OSError, UnicodeError) as error:
        raise SystemExit(f"verify-debian-systemd-lifecycle-authority: {error}") from error
