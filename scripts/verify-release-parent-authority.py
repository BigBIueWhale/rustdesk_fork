#!/usr/bin/env python3
"""Verify that the release parent is Docker-free and cleans only its own tree."""

import argparse
import os
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
    begin = source.find(start)
    if begin < 0:
        raise VerificationError(f"missing {label} start")
    finish = source.find(end, begin + len(start))
    if finish < 0:
        raise VerificationError(f"missing {label} end")
    return source[begin:finish]


def require(source: str, value: str, label: str) -> None:
    if value not in source:
        raise VerificationError(f"missing {label}")


def forbid(source: str, value: str, label: str) -> None:
    if value in source:
        raise VerificationError(f"forbidden {label}: {value}")


def require_order(source: str, values: tuple[str, ...], label: str) -> None:
    position = -1
    for value in values:
        found = source.find(value, position + 1)
        if found < 0:
            raise VerificationError(f"missing or out-of-order {label}: {value}")
        position = found


def validate(repo: Path) -> None:
    build = read_regular(repo, "scripts/build-release.sh", executable=True)
    verify = read_regular(repo, "scripts/verify.sh")
    vm_outer = read_regular(repo, "scripts/smoke-verifier-vm-authority.sh", executable=True)
    vm_guest = read_regular(repo, "scripts/smoke-verifier-vm-authority-guest.sh", executable=True)
    children = {
        name: read_regular(repo, path, executable=True)
        for name, path in (
            ("Android", "scripts/build-android.sh"),
            ("Debian", "scripts/build-debian.sh"),
            ("Windows", "scripts/build-windows-vm.sh"),
        )
    }

    require(build, "#!/usr/bin/env -S -i /usr/bin/bash --noprofile --norc", "closed entrypoint")
    require_order(
        build,
        (
            "bootstrap_closed_environment() {",
            'uid="$(/usr/bin/id -u)"',
            'gid="$(/usr/bin/id -g)"',
            '[ "$uid" -ne 0 ]',
            '[ "$gid" -ne 0 ]',
            'source "$SCRIPT_DIR/lib.sh"',
            "load_pins",
        ),
        "pre-source principal refusal",
    )
    require_order(
        build,
        (
            '0:|1:--self-test-vm-authority) RELEASE_VM_REQUIRED=1',
            '[ "$RELEASE_VM_REQUIRED" -eq 1 ]',
            'VERIFIER_VM_ENTRY_PREFLIGHT="$SCRIPT_DIR/verify-vm-entry-preflight.sh"',
            '/usr/bin/bash "$VERIFIER_VM_ENTRY_PREFLIGHT" >/dev/null',
            'source "$SCRIPT_DIR/lib.sh"',
        ),
        "production verifier-VM admission",
    )
    for inherited in ("DOCKER_*", "BUILDKIT_*", "COMPOSE_*"):
        require(build, inherited, f"closed inherited {inherited} state")
    for token, label in (
        ("/var/run/docker.sock", "host Docker socket"),
        ("local_docker", "shared local-Docker wrapper"),
        ("initialize_local_docker_authority", "local-Docker initialization"),
        ("require_pinned_builder_image", "parent daemon image provenance"),
        ("DOCKER_AUTHORITY_ROOT", "parent Docker configuration root"),
        ("docker run", "parent container launch"),
        ("--cap-add", "parent capability grant"),
        ("--check-exact-descriptor-budget", "container-only descriptor check"),
        ("fixture-probe", "fake Docker fixture"),
    ):
        forbid(build, token, label)

    image_ids = section(
        build,
        "assert_release_builder_image_ids() {",
        "\n}\n\nacquire_publication_lock() {",
        "builder image-ID validation",
    )
    for value in ("DEBIAN_IMAGE_ID", "ANDROID_IMAGE_ID", "WINDOWS_IMAGE_ID"):
        require(image_ids, value, f"{value} validation")
    require(image_ids, '[[ "$image_id" =~ ^sha256:[0-9a-f]{64}$ ]]', "content-ID syntax")
    preflight = section(build, "release_preflight() {", "\n}\n\nassert_snapshot_exact() {", "release preflight")
    require_order(
        preflight,
        (
            'DEBIAN_IMAGE_ID="${DEB_BUILDER_CONFIG_ID:-}"',
            'ANDROID_IMAGE_ID="${ANDROID_BUILDER_CONFIG_ID:-}"',
            'WINDOWS_IMAGE_ID="${WIN_HELPER_CONFIG_ID:-}"',
            "assert_release_builder_image_ids",
            "verify_private_tree_cleanup_preflight",
        ),
        "parent content-ID and cleanup preflight",
    )

    descriptor_runner = section(
        build,
        "run_private_tree_closure_from_descriptor() {",
        "\n}\n\nremove_owned_tree_contents() {",
        "descriptor executor",
    )
    for value in (
        '[ -n "$PRIVATE_TREE_CLOSURE_FD" ] && [ -n "$PRIVATE_TREE_CLOSURE_HASH" ]',
        '/usr/bin/python3 -I -S -c "$PRIVATE_TREE_CLOSURE_EXECUTOR"',
        '"$PRIVATE_TREE_CLOSURE_HASH" "$@"',
        '< "/proc/self/fd/$PRIVATE_TREE_CLOSURE_FD"',
    ):
        require(descriptor_runner, value, "authenticated descriptor execution")

    normalizer = section(
        build,
        "normalize_owned_tree_modes() {",
        "\n}\n\nverify_private_tree_authority_capacity() {",
        "owner-only normalizer",
    )
    remover = section(
        build,
        "remove_owned_tree_contents() {",
        "\n}\n\nverify_private_tree_owner_removal() {",
        "owner-only remover",
    )
    for body, operation in (
        (normalizer, "--normalize-owned-root"),
        (remover, "--remove-owned-tree-contents"),
    ):
        require_order(
            body,
            (
                '[ "$resolved" = "$path" ]',
                '[ "$observed" = "$expected_identity:$uid:$gid:700" ]',
                'run_private_tree_closure_from_descriptor --mount-root "$path"',
                f'{operation} "$path" --expected-identity "$expected_identity"',
            ),
            f"descriptor-bound {operation}",
        )
        for token in ("docker", "--user", "--cap-", "rm -rf", "chmod -R", "find "):
            forbid(body, token, f"pathname or container fallback in {operation}")

    capacity = section(
        build,
        "verify_private_tree_authority_capacity() {",
        "\n}\n\nacquire_private_tree_closure_execution() {",
        "descriptor capacity preflight",
    )
    require(capacity, "run_private_tree_closure_from_descriptor --check-descriptor-budget", "host descriptor budget")
    forbid(capacity, "docker", "container capacity surrogate")

    owner_fixture = section(
        build,
        "verify_private_tree_owner_removal() {",
        "\n}\n\nverify_private_tree_cleanup_preflight() {",
        "owner-removal behavior fixture",
    )
    require_order(
        owner_fixture,
        (
            'install -d -m 0700 "$fixture"',
            'chmod 0000 "$fixture/owner-entry"',
            'chmod 0500 "$fixture/locked"',
            'remove_owned_tree_contents "$fixture" "$fixture_id"',
            '--remove-empty-private-root "$fixture"',
            '[ ! -e "$fixture" ] && [ ! -L "$fixture" ]',
        ),
        "real current-user cleanup fixture",
    )
    forbid(owner_fixture, "docker", "Docker cleanup fixture")

    child_runner = section(build, "run_child() {", "\n}\n\nrun_verification() {", "child runner")
    require(child_runner, "/usr/bin/env -i", "empty child environment")
    for token in ("DOCKER_HOST=", "DOCKER_CONFIG=", "LOCAL_DOCKER_"):
        forbid(child_runner, token, "parent Docker state in child")
    target = section(build, "invoke_target() {", "\n}\n\nbuild_snapshot() {", "target dispatch")
    require(target, 'RELEASE_DOCKER_IMAGE_ID="$DEBIAN_IMAGE_ID"', "Debian pinned ID handoff")
    require(target, 'RELEASE_DOCKER_IMAGE_ID="$ANDROID_IMAGE_ID"', "Android pinned ID handoff")

    cleanup = section(build, "cleanup_release_workspace() {", "\n}\n\nrelease_preflight() {", "release cleanup")
    require_order(
        cleanup,
        (
            "reconcile_final_publication",
            '[ -n "$PRIVATE_TREE_CLOSURE_FD" ] || cleanup_failed=1',
            'remove_owned_tree_contents "$WORKSPACE" "$WORKSPACE_ID"',
            '--remove-empty-private-root "$WORKSPACE"',
            "close_private_tree_closure_execution",
            '[ "$status" -eq 0 ] && [ -n "$RELEASE_SUCCESS_MESSAGE" ]',
        ),
        "preservation-first terminal cleanup",
    )
    for token in ("docker", "rm -rf", "chmod -R", "find "):
        forbid(cleanup, token, "cleanup fallback")
    require(cleanup, "cleanup failed; recorded private workspace state is %s", "visible cleanup failure")

    reset_fixture = section(
        build,
        "run_reset_self_test() {",
        "\n}\n\nrun_cleanup_missing_self_test() {",
        "reset behavior fixture",
    )
    for value in (
        "external-hardlink rejection fixture",
        'chmod 0000 "$SOURCE_A/target/reset-proof/locked/marker"',
        'chmod 0500 "$SOURCE_A/target/reset-proof/locked"',
        'normalize_owned_tree_modes "$SOURCE_A" "$source_identity"',
        'reset_snapshot_build_state "$SOURCE_A"',
    ):
        require(reset_fixture, value, "reset behavior")
    forbid(reset_fixture, "docker", "Docker reset fixture")

    for platform, child in children.items():
        require(child, "verify-vm-entry-preflight.sh", f"{platform} VM admission")
        forbid(child, "/var/run/docker.sock", f"{platform} host socket")
        forbid(child, "local_docker", f"{platform} host Docker wrapper")

    require(
        verify,
        "python3 -I -S scripts/verify-release-parent-authority.py --repo .",
        "focused gate wiring",
    )
    forbid(verify, "verify-release-parent-docker-authority.py", "retired checker wiring")
    require(
        build,
        "RELEASE_PARENT_VM_AUTHORITY=pass uid=%s gid=%s network=none channel=guest-unix parent_docker=absent cleanup=descriptor-bound children=vm-only",
        "runtime authority receipt",
    )
    for value in (
        'readonly RELEASE_PARENT_SOURCE="$SCRIPT_DIR/build-release.sh"',
        'readonly FORK_VERSION_SOURCE="$SCRIPT_DIR/fork-version.sh"',
        '"repo/scripts/build-release.sh=$RELEASE_PARENT_SOURCE"',
        '"repo/scripts/fork-version.sh=$FORK_VERSION_SOURCE"',
        "VERIFIER_VM_RELEASE_PARENT_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused parent_docker=absent cleanup=descriptor-bound children=vm-only",
    ):
        require(vm_outer, value, "outer VM release-parent probe")
    for value in (
        'readonly RELEASE_PARENT_SCRIPT="$VERIFY_REPO/scripts/build-release.sh"',
        '/bin/bash "$RELEASE_PARENT_SCRIPT" --self-test-vm-authority',
        '/usr/sbin/useradd --uid "$principal" --gid "$principal"',
        "setpriv --reuid=4001 --regid=4001 --clear-groups",
        "setpriv --reuid=4000 --regid=4000 --clear-groups",
        "RELEASE_PARENT_VM_AUTHORITY=pass uid=4000 gid=4000 network=none channel=guest-unix parent_docker=absent cleanup=descriptor-bound children=vm-only",
        "VERIFIER_VM_RELEASE_PARENT_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused parent_docker=absent cleanup=descriptor-bound children=vm-only",
    ):
        require(vm_guest, value, "guest release-parent runtime probe")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=".")
    arguments = parser.parse_args()
    try:
        validate(Path(arguments.repo).resolve())
    except (OSError, UnicodeError, VerificationError) as error:
        raise SystemExit(f"release-parent authority verification: FAIL: {error}") from error
    print(
        "release-parent authority verification: PASS "
        "(Docker-free parent; descriptor-bound current-user cleanup; VM-only build children)"
    )


if __name__ == "__main__":
    main()
