#!/usr/bin/env python3
"""Validate the Debian builder's private-source and confined-container authority."""

import argparse
import pathlib
from typing import Dict, NamedTuple, Tuple


class AuthorityError(Exception):
    pass


class Mutation(NamedTuple):
    source: str
    old: str
    new: str
    label: str


def require(source: str, token: str, label: str) -> None:
    if token not in source:
        raise AuthorityError("missing {}".format(label))


def require_count(source: str, token: str, count: int, label: str) -> None:
    observed = source.count(token)
    if observed != count:
        raise AuthorityError("{} count is {}, expected {}".format(label, observed, count))


def forbid(source: str, token: str, label: str) -> None:
    if token in source:
        raise AuthorityError("forbidden {}".format(label))


def validate(sources: Dict[str, str]) -> None:
    build = sources["build"]

    for token, label in (
        ("set -euo pipefail\numask 077", "private host-created state umask"),
        ("readonly DOCKER_BIN=/usr/bin/docker", "fixed Docker client"),
        ("GIT_CONFIG_NOSYSTEM=1 \\\n    GIT_CONFIG_GLOBAL=/dev/null \\\n"
         "    GIT_CONFIG_SYSTEM=/dev/null \\\n    GIT_TERMINAL_PROMPT=0 \\\n"
         "    GIT_NO_REPLACE_OBJECTS=1", "closed Git configuration and replacement authority"),
        ('SOURCE_COMMIT="$current"', "exact source commit capture"),
        (
            '[ -z "${DOCKER_CONFIG+x}" ] \\\n'
            '        || die "DOCKER_CONFIG must not influence a direct or release-child Debian build"',
            "inherited Docker-configuration refusal",
        ),
        (
            "mktemp -d /tmp/rustdesk-debian-build.XXXXXXXXXX",
            "private direct-or-release workspace",
        ),
        (
            'install -d -m 0700 "$OWNED_WORKSPACE/docker-config"',
            "private direct-or-release Docker configuration",
        ),
        (
            'export DOCKER_CONFIG="$OWNED_WORKSPACE/docker-config"',
            "build-owned Docker configuration selection",
        ),
        ("prepare_direct_build_source() {", "private direct-source constructor"),
        ('clone --quiet --no-hardlinks --no-checkout --reject-shallow "$REPO_ROOT" "$source"',
         "non-hardlinked private Git clone"),
        ('checkout --quiet --detach "$SOURCE_COMMIT"', "detached exact-commit checkout"),
        ('remote remove origin', "private clone remote removal"),
        ('fsck --full --strict --no-reflogs', "private object-database verification"),
        ('BUILD_SOURCE_ROOT="$REPO_ROOT"', "release-snapshot source selection"),
        ('prepare_direct_build_source "$label"', "direct-build private-source selection"),
        ('[ "$common" = "$path/.git" ]', "private Git-directory ownership"),
        ('$common/objects/info/alternates" ] && [ ! -L "$common/objects/info/alternates"',
         "Git-alternate refusal"),
        ('for-each-ref --format=\'%(refname)\' refs/replace', "replacement-ref refusal"),
        ('status --porcelain=v1 --untracked-files=no', "tracked-state comparison"),
        ('diff --quiet --no-ext-diff HEAD --', "worktree exact-commit comparison"),
        ('diff --cached --quiet --no-ext-diff HEAD --', "index exact-commit comparison"),
        ('BUILD_SOURCE_ID="$(stat -c \'%d:%i\'', "source root identity capture"),
        ('[ "$observed" = "$BUILD_SOURCE_ID" ]', "source root identity postcondition"),
        ('verify_build_source_postcondition "failed Debian $profile build"',
         "failed-build source postcondition"),
        ('verify_build_source_postcondition "completed Debian $profile build"',
         "successful-build source postcondition"),
        ('release child requires outer independent snapshots and DOUBLE_BUILD=0',
         "release outer-snapshot reproducibility ownership"),
        ("activate_build_source pass-a", "first private direct build source"),
        ("activate_build_source pass-b", "second independent direct build source"),
        ('"$DOCKER_BIN" run --rm --pull=never', "immutable no-pull container launch"),
        ("--network=none", "networkless compile container"),
        ("--read-only", "read-only container root"),
        ('--user "$BUILD_UID:$BUILD_GID"', "numeric nonroot identity"),
        ("--cap-drop=ALL", "complete capability drop"),
        ("--security-opt=no-new-privileges", "no-new-privileges boundary"),
        ("--pids-limit=1024", "PID ceiling"),
        ("--memory=16g", "memory ceiling"),
        ("--memory-swap=16g", "no-swap expansion"),
        ("--cpus=4", "CPU ceiling"),
        ("--tmpfs /tmp:rw,exec,nosuid,nodev,mode=1777,size=12g",
         "bounded executable scratch"),
        ('--mount "type=bind,source=$BUILD_SOURCE_ROOT,target=/src"',
         "private writable build-source mount"),
        ("--tmpfs /src/.git:ro,noexec,nosuid,nodev,mode=0555,size=1m",
         "empty read-only nested Git-authority shield"),
        ('--mount "type=bind,source=$ONLINE_DIR,target=/online,readonly"',
         "read-only private online-input mount"),
        ('deb="$(ls -1 "$BUILD_SOURCE_ROOT"/rustdesk-*.deb',
         "artifact selection confined to private source"),
        ('--repo "$BUILD_SOURCE_ROOT" --deb', "artifact validation against exact source"),
    ):
        require(build, token, label)

    require_count(build, 'BUILD_SOURCE_ROOT="$REPO_ROOT"', 1, "release-source assignment")
    require_count(build, 'prepare_direct_build_source "$label"', 1, "direct-source selection")
    require_count(build, '"$DOCKER_BIN" run', 1, "sole Debian compiler container launch")
    require_count(build, "--cap-drop=ALL", 1, "sole compile capability policy")
    require_count(build, "--security-opt=no-new-privileges", 1, "sole privilege policy")
    require_count(build, "/src/.git:ro,noexec,nosuid,nodev,mode=0555,size=1m", 1,
                  "sole nested Git shield")
    require_count(build, "target=/online,readonly", 1, "sole online-input mount")

    release_assignment = build.index('BUILD_SOURCE_ROOT="$REPO_ROOT"')
    release_branch = build.rfind('if [ "$RELEASE_CHILD" -eq 1 ]', 0, release_assignment)
    direct_selection = build.index('prepare_direct_build_source "$label"', release_assignment)
    if release_branch < 0 or not release_branch < release_assignment < direct_selection:
        raise AuthorityError("release and direct source selection are not one closed branch")
    release_contract = build.index('if [ -n "${RELEASE_SRC_COMMIT:-}" ]')
    docker_contract = build.index(
        'install -d -m 0700 "$OWNED_WORKSPACE/docker-config"'
    )
    if docker_contract >= release_contract:
        raise AuthorityError(
            "Debian release child does not own its private Docker configuration"
        )

    launch_tokens = (
        '"$DOCKER_BIN" run --rm --pull=never',
        "--network=none",
        "--read-only",
        '--user "$BUILD_UID:$BUILD_GID"',
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--pids-limit=1024",
        "--memory=16g",
        "--memory-swap=16g",
        "--cpus=4",
        "--tmpfs /tmp:rw,exec,nosuid,nodev,mode=1777,size=12g",
        'target=/src"',
        "/src/.git:ro,noexec,nosuid,nodev,mode=0555,size=1m",
        "target=/online,readonly",
        "-w /src",
        '"$IMAGE_ID"',
    )
    positions = tuple(build.index(token, build.index('"$DOCKER_BIN" run')) for token in launch_tokens)
    if positions != tuple(sorted(positions)) or len(set(positions)) != len(positions):
        raise AuthorityError("Debian compile-container authority is incomplete or misordered")

    for token, label in (
        ('$REPO_ROOT:/src', "real repository short bind"),
        ('source=$REPO_ROOT,target=/src', "real repository direct mount"),
        ("--name ", "daemon-global container name"),
        ("--privileged", "privileged container"),
        ("--cap-add", "added capability"),
        ("--network=host", "host network namespace"),
        ("--pid=host", "host PID namespace"),
        ("--ipc=host", "host IPC namespace"),
        ("--uts=host", "host UTS namespace"),
        ("/var/run/docker.sock:/var/run/docker.sock", "Docker socket volume"),
        ("source=/var/run/docker.sock", "Docker socket mount"),
        ("docker build", "image build fallback"),
        ("docker pull", "image pull fallback"),
    ):
        forbid(build, token, label)

    require(
        sources["verify"],
        "python3 scripts/verify-debian-builder-authority.py --repo . --self-test",
        "shared focused-verifier wiring",
    )
    require(sources["requirements"], '<span class="id">R-S11cf</span>', "R-S11cf requirement")
    require(sources["requirements"], "<tr><td>225</td>", "Appendix C #225 disposition")
    require(
        sources["hardening"],
        "R-S11cf/R-S11e-98 — Debian builder private-source and container authority",
        "hardening-ledger disposition",
    )
    require(
        sources["requirements"],
        '<span class="id">R-S11dj</span>',
        "R-S11dj release-child Docker isolation requirement",
    )
    require(
        sources["hardening"],
        "R-S11dj/R-S11e-128 — Android artifact-builder Docker client, daemon, and configuration authority",
        "release-child Docker isolation hardening ledger",
    )
    require(
        sources["workspace"],
        '"debian_builder_authority_verifier"',
        "workspace-verifier source ownership",
    )
    require(
        sources["workspace"],
        "Debian builder focused authority verifier",
        "workspace-verifier semantic binding",
    )


MUTATIONS: Tuple[Mutation, ...] = (
    Mutation("build", "set -euo pipefail\numask 077", "set -euo pipefail\numask 022",
             "private host-created state umask"),
    Mutation("build", "readonly DOCKER_BIN=/usr/bin/docker", "DOCKER_BIN=docker", "fixed Docker client"),
    Mutation("build", "GIT_CONFIG_NOSYSTEM=1 \\\n    GIT_CONFIG_GLOBAL=/dev/null",
             "GIT_CONFIG_NOSYSTEM=0 \\\n    GIT_CONFIG_GLOBAL=/hostile/gitconfig",
             "closed Git configuration authority"),
    Mutation(
        "build",
        '[ -z "${DOCKER_CONFIG+x}" ] \\\n'
        '        || die "DOCKER_CONFIG must not influence a direct or release-child Debian build"',
        "true # inherited Docker configuration accepted",
        "inherited Docker-configuration refusal",
    ),
    Mutation(
        "build",
        'install -d -m 0700 "$OWNED_WORKSPACE/docker-config"',
        'mkdir -p "$OWNED_WORKSPACE/docker-config"',
        "private direct-or-release Docker configuration",
    ),
    Mutation(
        "build",
        'export DOCKER_CONFIG="$OWNED_WORKSPACE/docker-config"',
        "true # ambient Docker configuration retained",
        "build-owned Docker configuration selection",
    ),
    Mutation("build", "--no-hardlinks", "--local", "non-hardlinked private clone"),
    Mutation("build", 'checkout --quiet --detach "$SOURCE_COMMIT"', 'checkout --quiet master',
             "detached exact-commit checkout"),
    Mutation("build", "remote remove origin", "remote -v", "private clone remote removal"),
    Mutation("build", "fsck --full --strict --no-reflogs", "status --short",
             "private object-database verification"),
    Mutation("build", 'prepare_direct_build_source "$label"', 'BUILD_SOURCE_ROOT="$REPO_ROOT"',
             "direct private-source selection"),
    Mutation("build",
             '$common/objects/info/alternates" ] && [ ! -L "$common/objects/info/alternates"',
             '$common/objects/info/alternates" ] && [ ! -L "$common/objects/info/alternate-disabled"',
             "Git-alternate refusal"),
    Mutation("build", 'status --porcelain=v1 --untracked-files=no', 'status --porcelain=v1',
             "tracked-state comparison"),
    Mutation("build", 'diff --quiet --no-ext-diff HEAD --', 'diff --quiet --no-ext-diff --',
             "worktree exact-commit comparison"),
    Mutation("build", '[ "$observed" = "$BUILD_SOURCE_ID" ]', "true",
             "source root identity postcondition"),
    Mutation("build", 'verify_build_source_postcondition "completed Debian $profile build"',
             'true # completed-build source proof removed', "successful-build source postcondition"),
    Mutation("build", "release child requires outer independent snapshots and DOUBLE_BUILD=0",
             "release child accepted an inner warm rebuild", "release outer-snapshot ownership"),
    Mutation("build", "activate_build_source pass-b", "true # reused pass-a source",
             "independent direct second source"),
    Mutation("build", '"$DOCKER_BIN" run --rm --pull=never', '"$DOCKER_BIN" run --rm',
             "no-pull launch"),
    Mutation("build", "        --network=none \\\n        --read-only",
             "        --network=bridge \\\n        --read-only", "networkless compile"),
    Mutation("build", "--read-only", "--read-write", "read-only root"),
    Mutation("build", '--user "$BUILD_UID:$BUILD_GID"', "--user 0:0", "numeric nonroot identity"),
    Mutation("build", "--cap-drop=ALL", "--cap-drop=NET_RAW", "complete capability drop"),
    Mutation("build", "--security-opt=no-new-privileges", "--security-opt=seccomp=unconfined",
             "no-new-privileges boundary"),
    Mutation("build", "--pids-limit=1024", "--pids-limit=-1", "PID ceiling"),
    Mutation("build", "--memory=16g", "--memory=0", "memory ceiling"),
    Mutation("build", "--memory-swap=16g", "--memory-swap=-1", "no-swap expansion"),
    Mutation("build", "--cpus=4", "--cpus=0", "CPU ceiling"),
    Mutation("build", "size=12g", "size=120g", "bounded scratch"),
    Mutation("build", "/src/.git:ro,noexec,nosuid,nodev,mode=0555,size=1m",
             "/src/.git:rw,exec,suid,dev,mode=0777,size=1g",
             "empty read-only Git-authority shield"),
    Mutation("build", "target=/online,readonly", "target=/online", "read-only online input"),
    Mutation("verify", "python3 scripts/verify-debian-builder-authority.py --repo . --self-test",
             "true # Debian builder verifier removed", "shared focused-verifier wiring"),
    Mutation("requirements", '<span class="id">R-S11cf</span>',
             '<span class="id">R-S11cf-disabled</span>', "R-S11cf requirement"),
    Mutation("requirements", "<tr><td>225</td>", "<tr><td>225-disabled</td>",
             "Appendix C #225 disposition"),
    Mutation("hardening", "R-S11cf/R-S11e-98 — Debian builder private-source and container authority",
             "R-S11cf/R-S11e-98 — Debian builder ambient authority",
             "hardening-ledger disposition"),
    Mutation("requirements", '<span class="id">R-S11dj</span>',
             '<span class="id">R-S11dj-disabled</span>',
             "R-S11dj release-child Docker isolation requirement"),
    Mutation(
        "hardening",
        "R-S11dj/R-S11e-128 — Android artifact-builder Docker client, daemon, and configuration authority",
        "R-S11dj/R-S11e-XXX — release-child Docker isolation deferred",
        "release-child Docker isolation hardening ledger",
    ),
)


def load_sources(repo: pathlib.Path) -> Dict[str, str]:
    return {
        "build": (repo / "scripts/build-debian.sh").read_text(encoding="utf-8"),
        "verify": (repo / "scripts/verify.sh").read_text(encoding="utf-8"),
        "requirements": (repo / "requirements.html").read_text(encoding="utf-8"),
        "hardening": (repo / "HARDENING_STATUS.md").read_text(encoding="utf-8"),
        "workspace": (repo / "scripts/verify-verifier-workspace.py").read_text(encoding="utf-8"),
    }


def run_mutations(sources: Dict[str, str]) -> None:
    for mutation in MUTATIONS:
        original = sources[mutation.source]
        if original.count(mutation.old) != 1:
            raise AuthorityError(
                "mutation target for {} occurs {} times".format(
                    mutation.label, original.count(mutation.old)
                )
            )
        changed = dict(sources)
        changed[mutation.source] = original.replace(mutation.old, mutation.new, 1)
        try:
            validate(changed)
        except AuthorityError:
            continue
        raise AuthorityError("mutation was accepted: {}".format(mutation.label))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=pathlib.Path, default=pathlib.Path("."))
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    sources = load_sources(args.repo.resolve())
    validate(sources)
    if args.self_test:
        run_mutations(sources)
    print(
        "verify-debian-builder-authority: OK"
        + (" ({} mutations)".format(len(MUTATIONS)) if args.self_test else "")
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AuthorityError, OSError) as error:
        print("verify-debian-builder-authority: {}".format(error))
        raise SystemExit(1)
