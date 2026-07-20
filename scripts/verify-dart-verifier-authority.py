#!/usr/bin/env python3
"""Bind the Dart/FRB verifier to its non-root disposable-snapshot contract."""

import argparse
import re
from pathlib import Path
from typing import Dict, Iterable, NamedTuple


class ContractError(RuntimeError):
    pass


class Mutation(NamedTuple):
    source: str
    old: str
    new: str
    label: str


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def require_once(source: str, token: str, label: str) -> None:
    count = source.count(token)
    require(count == 1, f"{label}: expected one exact occurrence, found {count}")


def require_all(source: str, tokens: Iterable[str], label: str) -> None:
    for token in tokens:
        require(token in source, f"{label}: missing {token!r}")


def docker_run_block(source: str, label: str) -> str:
    require(source.count("docker run ") == 1, f"{label}: expected exactly one Docker launch")
    start = source.index("docker run ")
    match = re.search(r"\n\s+bash -euo pipefail -c '\n", source[start:])
    require(match is not None, f"{label}: Docker launch has no exact fail-closed shell boundary")
    return source[start : start + match.end()]


def validate_docker_block(block: str, label: str, source_mount: str, online_mount: str) -> None:
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
            "--pids-limit=512",
            "--memory=12g",
            "--memory-swap=12g",
            "--cpus=4",
            "--tmpfs /tmp:rw,exec,nosuid,nodev,mode=1777,size=10g",
            source_mount,
            online_mount,
        ),
        label,
    )
    require(block.index(source_mount) < block.index(online_mount), f"{label}: mount order drifted")
    require(block.count("--mount ") == 2, f"{label}: expected exactly two bind mounts")
    forbidden = (
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
        "--net=host",
        "--net host",
        "--publish",
        "--expose",
        "--volume",
        "source=$REPO_ROOT",
        "source=$SOURCE_SNAPSHOT",
        "-v ",
    )
    for token in forbidden:
        require(token not in block, f"{label}: forbidden Docker authority {token!r}")
    require(
        re.search(r"(?:^|\s)-p(?:\s|=)", block) is None,
        f"{label}: a Docker port publication flag is present",
    )


def validate_contract(sources: Dict[str, str]) -> None:
    dart = sources["dart"]
    frb = sources["frb"]
    verify = sources["verify"]
    requirements = sources["requirements"]
    hardening = sources["hardening"]

    require_all(
        dart,
        (
            '[ "$(id -u)" -ne 0 ] || die "dart-verify refuses host or container-root execution"',
            '[ "$(id -g)" -ne 0 ] || die "dart-verify refuses a root primary group"',
            'IMAGE_ID="$DEB_BUILDER_IMAGE_ID"',
            'require_pinned_builder_image deb-builder "$IMAGE_ID"',
            'WORKSPACE="$(umask 077 && mktemp -d /tmp/rustdesk-dart-verify.XXXXXXXXXX)"',
            '[ "$(stat -c \'%u:%g:%a\' "$WORKSPACE")" = "$(id -u):$(id -g):700" ]',
            'create_private_online_snapshot "$ONLINE_SNAPSHOT_PARENT"',
            'ONLINE_SNAPSHOT="$ONLINE_SNAPSHOT_PARENT/online"',
            'archive_current_source >"$SOURCE_ARCHIVE"',
            'SOURCE_DIGEST="$(sha256sum "$SOURCE_ARCHIVE" | awk \'{print $1}\')"',
            'chmod -R a-w "$SOURCE_SNAPSHOT"',
            'FRB_IMAGE_ID="$IMAGE_ID"',
            '--source-root "$SOURCE_SNAPSHOT"',
            '--online-root "$ONLINE_SNAPSHOT"',
            '--output-root "$FRB_OUTPUT"',
            'cp -a --reflink=auto "$SOURCE_SNAPSHOT/." "$ANALYSIS_ROOT/"',
            'cp -a "$FRB_OUTPUT/." "$ANALYSIS_ROOT/"',
            '    dart pub get --offline >/dev/null',
            'if [ "$lock_before" != "$lock_after" ]; then',
            'flutter analyze --no-pub --no-fatal-infos --no-fatal-warnings lib/',
            'analyze_status=$?',
            'if [ "$analyze_status" -ne 0 ] || [ "$errs" != "0" ]; then',
            'flutter test --no-pub test/address_validator_test.dart',
            'SOURCE_DIGEST_AFTER="$(archive_current_source | sha256sum | awk \'{print $1}\')"',
            '[ "$SOURCE_DIGEST_AFTER" = "$SOURCE_DIGEST" ]',
        ),
        "dart verifier authority",
    )
    require(
        dart.count('verify_private_online_snapshot "$ONLINE_SNAPSHOT_PARENT"') == 2,
        "dart verifier must verify its private online snapshot before and after use",
    )
    require(
        dart.index('create_private_online_snapshot "$ONLINE_SNAPSHOT_PARENT"')
        < dart.index('FRB_IMAGE_ID="$IMAGE_ID"'),
        "dart verifier consumes the online tree before snapshot creation",
    )
    require(
        dart.index('SOURCE_DIGEST="$(sha256sum "$SOURCE_ARCHIVE"')
        < dart.index("docker run "),
        "dart verifier records source identity after container execution",
    )
    require(
        dart.rindex('verify_private_online_snapshot "$ONLINE_SNAPSHOT_PARENT"')
        < dart.index('SOURCE_DIGEST_AFTER="$(archive_current_source'),
        "dart verifier final online/source checks are not ordered",
    )
    for forbidden in (
        "docker build",
        "docker volume",
        "rd-fluttercheck",
        "rd-devcheck",
        "rd-pub-cache",
        "rd-cargo-cache",
        "rd-git-cache",
        "rd-verify-target",
        "/root/.pub-cache",
        "frb_log=/tmp/",
        "build_runner build --delete-conflicting-outputs",
        "|| true\n    if ! flutter_rust_bridge_codegen",
        '-v "$PWD:/work:rw"',
    ):
        require(forbidden not in dart, f"dart verifier retained forbidden legacy authority {forbidden!r}")

    dart_block = docker_run_block(dart, "dart analyzer container")
    validate_docker_block(
        dart_block,
        "dart analyzer container",
        '--mount "type=bind,source=$ANALYSIS_ROOT,target=/src"',
        '--mount "type=bind,source=$ONLINE_SNAPSHOT,target=/online,readonly"',
    )
    require(
        '--workdir /src "$IMAGE_ID"' in dart_block,
        "dart analyzer does not execute the immutable pinned image in its private source",
    )

    require_all(
        frb,
        (
            '[ "$(id -u)" -ne 0 ] || die "FRB code generation refuses host or container-root execution"',
            '[ "$(id -g)" -ne 0 ] || die "FRB code generation refuses a root primary group"',
            '[[ "$IMAGE_ID" =~ ^sha256:[0-9a-f]{64}$ ]]',
            '[ "$IMAGE_ID" = "${DEB_BUILDER_IMAGE_ID:-}" ]',
            'require_pinned_builder_image deb-builder "$IMAGE_ID"',
        ),
        "FRB generator authority",
    )
    frb_block = docker_run_block(frb, "FRB generator container")
    validate_docker_block(
        frb_block,
        "FRB generator container",
        '--mount "type=bind,source=$WORK_SOURCE,target=/src"',
        '--mount "type=bind,source=$ONLINE_DIR,target=/online,readonly"',
    )
    require(
        '--workdir /src "$IMAGE_ID"' in frb_block,
        "FRB generator does not execute the immutable pinned image in its private source",
    )

    require_once(
        verify,
        "python3 scripts/verify-dart-verifier-authority.py",
        "shared verifier wiring",
    )
    require(
        '<span class="id">R-S11bc</span>' in requirements,
        "requirements are missing R-S11bc",
    )
    require(
        "<tr><td>180</td>" in requirements,
        "requirements are missing Appendix C #180",
    )
    require(
        "R-S11bc/R-S11e-69" in hardening,
        "hardening ledger is missing the Dart verifier authority closure",
    )


def mutate_once(sources: Dict[str, str], mutation: Mutation) -> Dict[str, str]:
    source = sources[mutation.source]
    count = source.count(mutation.old)
    require(count == 1, f"self-test fixture {mutation.label!r} matched {count} times")
    changed = dict(sources)
    changed[mutation.source] = source.replace(mutation.old, mutation.new, 1)
    return changed


MUTATIONS = (
    Mutation("dart", '[ "$(id -u)" -ne 0 ]', '[ "$(id -u)" -ge 0 ]', "dart uid-root refusal"),
    Mutation("dart", '[ "$(id -g)" -ne 0 ]', '[ "$(id -g)" -ge 0 ]', "dart gid-root refusal"),
    Mutation("dart", 'IMAGE_ID="$DEB_BUILDER_IMAGE_ID"', 'IMAGE_ID=rd-fluttercheck', "mutable Dart image"),
    Mutation(
        "dart",
        '[ "$(stat -c \'%u:%g:%a\' "$WORKSPACE")" = "$(id -u):$(id -g):700" ]',
        '[ -d "$WORKSPACE" ]',
        "private workspace identity",
    ),
    Mutation("dart", 'create_private_online_snapshot "$ONLINE_SNAPSHOT_PARENT"\n', "", "online snapshot creation"),
    Mutation(
        "dart",
        'cd "$REPO_ROOT"\nverify_private_online_snapshot "$ONLINE_SNAPSHOT_PARENT"',
        'cd "$REPO_ROOT"\ntrue # private snapshot final proof disabled',
        "final online proof",
    ),
    Mutation("dart", 'archive_current_source >"$SOURCE_ARCHIVE"\n', "", "source snapshot identity"),
    Mutation("dart", 'chmod -R a-w "$SOURCE_SNAPSHOT"', 'chmod -R u+w "$SOURCE_SNAPSHOT"', "read-only source snapshot"),
    Mutation("dart", '--pull=never', '--pull=always', "Dart pull refusal"),
    Mutation("dart", '--network=none', '--network=bridge', "Dart network isolation"),
    Mutation("dart", '--read-only', '--hostname=dart-verify', "Dart read-only root"),
    Mutation("dart", '--user "$(id -u):$(id -g)"', '--user 0:0', "Dart numeric non-root user"),
    Mutation("dart", '--cap-drop=ALL', '--cap-add=SYS_ADMIN', "Dart capability drop"),
    Mutation("dart", '--security-opt=no-new-privileges', '--security-opt=label=disable', "Dart no-new-privileges"),
    Mutation("dart", '--pids-limit=512', '--pids-limit=-1', "Dart pid bound"),
    Mutation("dart", '--memory=12g', '--memory=0', "Dart memory bound"),
    Mutation("dart", '--memory-swap=12g', '--memory-swap=-1', "Dart no-swap bound"),
    Mutation("dart", '--cpus=4', '--cpuset-cpus=0-255', "Dart cpu bound"),
    Mutation(
        "dart",
        '--tmpfs /tmp:rw,exec,nosuid,nodev,mode=1777,size=10g',
        '--tmpfs /tmp:rw,exec,mode=1777',
        "Dart temporary-storage bound",
    ),
    Mutation("dart", 'source=$ANALYSIS_ROOT,target=/src', 'source=$REPO_ROOT,target=/src', "Dart private source mount"),
    Mutation(
        "dart",
        '--mount "type=bind,source=$ANALYSIS_ROOT,target=/src"',
        '--mount "type=bind,source=$ANALYSIS_ROOT,target=/src" --mount "type=bind,source=/var/run/docker.sock,target=/var/run/docker.sock"',
        "Dart complete mount inventory",
    ),
    Mutation("dart", 'source=$ONLINE_SNAPSHOT,target=/online,readonly', 'source=$ONLINE_DIR,target=/online', "Dart immutable online mount"),
    Mutation(
        "dart",
        '    dart pub get --offline >/dev/null',
        '    dart pub get >/dev/null',
        "offline Pub resolution",
    ),
    Mutation(
        "dart",
        'if [ "$lock_before" != "$lock_after" ]; then',
        'if false; then',
        "Pub lock preservation",
    ),
    Mutation(
        "dart",
        'if [ "$analyze_status" -ne 0 ] || [ "$errs" != "0" ]; then',
        'if [ "$errs" != "0" ]; then',
        "analyzer exit finality",
    ),
    Mutation(
        "dart",
        'flutter test --no-pub test/address_validator_test.dart',
        'true # focused direct-address test disabled',
        "focused Dart regression",
    ),
    Mutation("dart", 'SOURCE_DIGEST_AFTER="$(archive_current_source', 'SOURCE_DIGEST_AFTER="$(printf stale |', "final source proof"),
    Mutation("frb", '[ "$(id -u)" -ne 0 ]', '[ "$(id -u)" -ge 0 ]', "FRB uid-root refusal"),
    Mutation("frb", '[ "$(id -g)" -ne 0 ]', '[ "$(id -g)" -ge 0 ]', "FRB gid-root refusal"),
    Mutation(
        "frb",
        'require_pinned_builder_image deb-builder "$IMAGE_ID"',
        'true # image provenance disabled',
        "FRB image provenance",
    ),
    Mutation("frb", '--pull=never', '--pull=missing', "FRB pull refusal"),
    Mutation("frb", '--network=none', '--network=host', "FRB network isolation"),
    Mutation("frb", '--read-only', '--hostname=frb-codegen', "FRB read-only root"),
    Mutation("frb", '--user "$(id -u):$(id -g)"', '--user 0:0', "FRB numeric non-root user"),
    Mutation("frb", '--cap-drop=ALL', '--cap-add=SYS_ADMIN', "FRB capability drop"),
    Mutation("frb", '--security-opt=no-new-privileges', '--security-opt=label=disable', "FRB no-new-privileges"),
    Mutation("frb", '--pids-limit=512', '--pids-limit=-1', "FRB pid bound"),
    Mutation("frb", '--memory=12g', '--memory=0', "FRB memory bound"),
    Mutation("frb", '--memory-swap=12g', '--memory-swap=-1', "FRB no-swap bound"),
    Mutation("frb", '--cpus=4', '--cpuset-cpus=0-255', "FRB cpu bound"),
    Mutation(
        "frb",
        '--tmpfs /tmp:rw,exec,nosuid,nodev,mode=1777,size=10g',
        '--tmpfs /tmp:rw,exec,mode=1777',
        "FRB temporary-storage bound",
    ),
    Mutation("frb", 'source=$WORK_SOURCE,target=/src', 'source=$SOURCE_ROOT,target=/src', "FRB private source mount"),
    Mutation(
        "frb",
        '--mount "type=bind,source=$WORK_SOURCE,target=/src"',
        '--mount "type=bind,source=$WORK_SOURCE,target=/src" --mount "type=bind,source=/var/run/docker.sock,target=/var/run/docker.sock"',
        "FRB complete mount inventory",
    ),
    Mutation(
        "frb",
        'source=$ONLINE_DIR,target=/online,readonly',
        'source=$ONLINE_DIR,target=/online',
        "FRB immutable online mount",
    ),
    Mutation(
        "verify",
        "python3 scripts/verify-dart-verifier-authority.py --repo . --self-test \\\n",
        "",
        "shared gate wiring",
    ),
    Mutation("requirements", '<span class="id">R-S11bc</span>', '<span class="id">R-S11bc-broken</span>', "normative requirement"),
    Mutation("requirements", "<tr><td>180</td>", "<tr><td>180-broken</td>", "Appendix disposition"),
    Mutation("hardening", "R-S11bc/R-S11e-69", "R-S11bc/R-S11e-XX", "hardening ledger"),
)


def load_sources(repo: Path) -> Dict[str, str]:
    paths = {
        "dart": repo / "scripts/dart-verify.sh",
        "frb": repo / "scripts/frb-codegen.sh",
        "verify": repo / "scripts/verify.sh",
        "requirements": repo / "requirements.html",
        "hardening": repo / "HARDENING_STATUS.md",
    }
    return {name: path.read_text(encoding="utf-8") for name, path in paths.items()}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    sources = load_sources(args.repo.resolve())
    validate_contract(sources)
    if args.self_test:
        for mutation in MUTATIONS:
            mutated = mutate_once(sources, mutation)
            try:
                validate_contract(mutated)
            except ContractError:
                continue
            raise ContractError(f"self-test mutation was accepted: {mutation.label}")
        print(f"verify-dart-verifier-authority: ok ({len(MUTATIONS)} mutations rejected)")
    else:
        print("verify-dart-verifier-authority: ok")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ContractError as error:
        raise SystemExit(f"verify-dart-verifier-authority: {error}")
