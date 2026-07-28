#!/usr/bin/env python3
"""Validate exact Android SDK acquisition, extraction, and publication authority."""

from __future__ import annotations

import argparse
import ast
import pathlib
import re
from dataclasses import dataclass
from typing import Dict, Tuple


class AuthorityError(RuntimeError):
    pass


@dataclass(frozen=True)
class Mutation:
    source: str
    old: str
    new: str
    label: str


def require(source: str, token: str, label: str) -> None:
    if token not in source:
        raise AuthorityError("missing {}: {!r}".format(label, token))


def forbid(source: str, token: str, label: str) -> None:
    if token in source:
        raise AuthorityError("forbidden {} remains: {!r}".format(label, token))


def require_count(source: str, token: str, expected: int, label: str) -> None:
    actual = source.count(token)
    if actual != expected:
        raise AuthorityError(
            "{} count is {}, expected {}: {!r}".format(
                label,
                actual,
                expected,
                token,
            )
        )


def require_order(source: str, tokens: Tuple[str, ...], label: str) -> None:
    position = -1
    for token in tokens:
        found = source.find(token, position + 1)
        if found < 0:
            raise AuthorityError(
                "{} is missing ordered token {!r}".format(label, token)
            )
        position = found


def extract(source: str, start: str, end: str, label: str) -> str:
    if source.count(start) != 1:
        raise AuthorityError("{} start cardinality differs".format(label))
    begin = source.index(start)
    finish = source.find(end, begin + len(start))
    if finish < 0:
        raise AuthorityError("{} end is absent".format(label))
    return source[begin:finish]


def pin_value(source: str, name: str) -> str:
    match = re.search(
        r'^{}="([0-9a-f]{{64}})"'.format(re.escape(name)),
        source,
        re.MULTILINE,
    )
    if match is None:
        raise AuthorityError("{} is not one canonical SHA-256 pin".format(name))
    return match.group(1)


PIN_VALUES = {
    "SHA256_ANDROID_CMDLINE_TOOLS":
        "a66d5ef0238fc0162e9c1446602ce0dd41702d4dd7a94d2ce42d12b7f80baf7e",
    "SHA256_ANDROID_BUILD_TOOLS_30_0_3":
        "24593500aa95d2f99fb4f10658aae7e65cb519be6cd33fa164f15f27f3c4a2d6",
    "SHA256_ANDROID_BUILD_TOOLS_34_0_0":
        "e858c4b60069d0431051b225d384413b1643e1289b00a4825aed347f25bd510f",
    "SHA256_ANDROID_PLATFORM_31":
        "1d69fe1d7f9788d82ff3a374faf4f6ccc9d1d372aa84a86b5bcfb517523b0b3f",
    "SHA256_ANDROID_PLATFORM_32":
        "01d8da1c900e70fcf5da39767d5444e39928935b1a5927055ce749fc348ca7ae",
    "SHA256_ANDROID_PLATFORM_33":
        "b32b10f787867987f03ae8e101d217e053a9065b7136379fb353b388379aed1d",
    "SHA256_ANDROID_PLATFORM_34":
        "16fdb74c55e59ae3ef52def135aec713508467bd56d7dabcd8c9be31fa8b20f3",
}


def validate(sources: Dict[str, str]) -> None:
    shell = sources["shell"]
    helper = sources["helper"]
    pins = sources["pins"]
    try:
        ast.parse(helper)
    except SyntaxError as error:
        raise AuthorityError(
            "Android SDK output helper does not parse: {}".format(error)
        ) from error

    for name, expected in PIN_VALUES.items():
        if pin_value(pins, name) != expected:
            raise AuthorityError("{} changed from its audited value".format(name))

    funnel = extract(
        shell,
        "online_docker_run_archive_acquisition() {",
        '        "$@"\n}',
        "archive acquisition launch funnel",
    )
    for token, label in (
        ("online_docker run --rm", "ephemeral container"),
        ("--pull=never", "no-pull execution"),
        ("--network=bridge", "isolated acquisition egress"),
        ("--read-only", "read-only root"),
        ('--user "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID"', "numeric nonroot identity"),
        ("--cap-drop=ALL", "zero capabilities"),
        ("--security-opt=no-new-privileges", "no-new-privileges"),
        ("--pids-limit=256", "PID bound"),
        ("--memory=4g --memory-swap=4g --cpus=2", "resource bounds"),
        (
            "--tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777,size=256m",
            "bounded non-executable scratch",
        ),
    ):
        require(funnel, token, label)
    for token, label in (
        ("--privileged", "privileged execution"),
        ("--cap-add", "added capability"),
        ("--network=host", "host network"),
        ("--pid=host", "host PID namespace"),
        ("--ipc=host", "host IPC namespace"),
        ("--uts=host", "host UTS namespace"),
        ("--publish", "published port"),
        ("--expose", "exposed port"),
        ("--device", "host device"),
        ("docker.sock", "Docker socket"),
        ("rw,exec", "executable scratch"),
    ):
        forbid(funnel, token, label)

    stage = extract(
        shell,
        "stage_android_sdk() {",
        "\n}\n\n# ── The warm gradle cache",
        "Android SDK transaction",
    )
    for token, label in (
        ('local builder="$ANDROID_BUILDER_IMAGE_ID"', "immutable builder"),
        ("require_online_fetch_builder_image android-builder", "image verification"),
        ("verify_sha256 \"$cmdline_archive\"", "command-line-tools input check"),
        ('"$FLOCK_BIN" --exclusive --nonblock "$lock_fd"', "exclusive transaction"),
        ("recover_android_sdk_output_staging", "stale-state recovery"),
        ("android_sdk_output_tool check-complete", "existing-output validation"),
        ('"$ONLINE_DIR/.rustdesk-android-sdk.XXXXXXXXXX"', "private staging"),
        ("android_sdk_output_tool prepare", "state preparation"),
        ("online_docker_run_archive_acquisition", "constrained producer funnel"),
        (
            "source=$cmdline_archive,target=/inputs/android-cmdline-tools.zip,readonly",
            "exact archive input",
        ),
        (
            "source=$SCRIPT_DIR/online-android-sdk-output.py,"
            "target=/authority/online-android-sdk-output.py,readonly",
            "exact helper input",
        ),
        (
            "source=$staging/downloads,target=/outputs/downloads",
            "private download output",
        ),
        (
            "source=$staging/output,target=/outputs/sdk",
            "private SDK output",
        ),
        ("android_sdk_output_tool verify", "host output postcondition"),
        ("android_sdk_output_tool publish", "checked publication"),
        ("retire_android_sdk_output_staging", "private retirement"),
        (
            '[ "$status" -eq 0 ] && [ "$output_status" -eq 0 ]',
            "producer/output publication barrier",
        ),
    ):
        require(stage, token, label)
    require_count(stage, "--mount ", 4, "SDK producer mount inventory")
    forbid(stage, "target=/online", "online namespace mount")
    forbid(stage, "target=/src", "repository mount")
    forbid(stage, "sdkmanager", "moving SDK package resolver")
    forbid(stage, '"platform-tools"', "moving platform-tools package")
    forbid(stage, "rm -rf /online/android-sdk", "destructive final replacement")
    forbid(stage, "cp -a /tmp/sdk /online/android-sdk", "direct final publication")
    require_order(
        stage,
        (
            '"$FLOCK_BIN" --exclusive --nonblock "$lock_fd"',
            "recover_android_sdk_output_staging",
            "android_sdk_output_tool check-complete",
            "android_sdk_output_tool prepare",
            "online_docker_run_archive_acquisition",
            "Android command-line-tools archive changed during acquisition",
            "android_sdk_output_tool verify",
            "android_sdk_output_tool publish",
            "retire_android_sdk_output_staging",
            '"$FLOCK_BIN" --unlock "$lock_fd"',
        ),
        "Android SDK transaction order",
    )

    for token, label in (
        ('STATE_NAME = ".rustdesk-android-sdk-output-state-v1"', "state record"),
        ("STATE_VERSION = 1", "state schema version"),
        ('DOWNLOAD_BASE = "https://dl.google.com/android/repository/"', "fixed origin"),
        ("MAX_ARCHIVE_BYTES = 256 * 1024 * 1024", "archive bound"),
        ("MAX_DOWNLOAD_BYTES = 700 * 1024 * 1024", "download bound"),
        ("MAX_ENTRIES = 60000", "entry bound"),
        ("MAX_DIRECTORIES = 12000", "directory bound"),
        ("MAX_FILES = 50000", "file bound"),
        ("MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024", "expanded byte bound"),
        (
            '"build-tools_r30.0.3-linux.zip",\n        53134793',
            "build-tools 30 archive",
        ),
        ('"build-tools_r34-linux.zip",\n        61224257', "build-tools 34 archive"),
        ('"platform-31_r01.zip",\n        56475526', "platform 31 archive"),
        ('"platform-32_r01.zip",\n        66108299', "platform 32 archive"),
        ('"platform-33-ext3_r03.zip",\n        67334237', "platform 33 archive"),
        ('"platform-34-ext7_r03.zip",\n        63180081', "platform 34 archive"),
        (
            '"031dedf9f4bd8eda3fa0ed24903d94d640607c8e805ba9f044ea8fcbddd91403"',
            "independent tree digest",
        ),
        ("EXPECTED_TREE_FILES = 43468", "exact file count"),
        ("EXPECTED_TREE_DIRECTORIES = 11293", "exact directory count"),
        ("EXPECTED_TREE_BYTES = 876007562", "exact expanded bytes"),
        ("response.status != 200", "HTTP status check"),
        ("response.geturl() != url", "redirect rejection"),
        ('response.headers.get("Content-Encoding")', "content encoding check"),
        ('response.headers.get("Content-Length")', "content length check"),
        ("digest.hexdigest() != pins[spec.key]", "download digest check"),
        ("os.O_EXCL", "exclusive file creation"),
        ("os.O_NOFOLLOW", "no-follow file handling"),
        ("stable_metadata(before) != stable_metadata(after)", "stable archive read"),
        (
            "or before.st_nlink != 1\n"
            "            or before.st_size != spec.size",
            "archive hardlink rejection",
        ),
        ("info.orig_filename != info.filename", "NUL truncation rejection"),
        ("info.create_system != 3", "Unix type authority"),
        ("info.flag_bits not in spec.allowed_flags", "ZIP flag closure"),
        ("archive contains a special member", "special-member rejection"),
        ("archive member escapes its exact root", "path traversal rejection"),
        ("repeats one member path", "duplicate-path rejection"),
        ("packages collide at", "cross-package collision rejection"),
        (
            "if relative in files or relative in directories:\n"
            '                    fail(f"Android SDK packages collide at {relative}")',
            "file/package collision rejection",
        ),
        ("output bytes differ from the pinned archive", "byte-for-byte comparison"),
        ("output inventory differs from the pinned archives", "exact inventory"),
        ("output has foreign ownership", "owner rejection"),
        ("output crosses a filesystem", "filesystem closure"),
        ("output file is not exact, private, and regular", "hardlink/type rejection"),
        ("carries extended attributes", "xattr rejection"),
        ("reject_mount_at_or_below(root)", "descendant-mount rejection"),
        (
            'validate_absolute(root, "Android SDK output")\n'
            "    reject_mount_at_or_below(root)\n"
            "    files, directories = compose_manifest(manifests)",
            "raw-output mount closure",
        ),
        ("seal_and_sync_tree", "sealed durable tree"),
        ("transition_directory_mode", "descriptor-bound root mode transition"),
        (
            "if mode == 0o700:\n"
            '        downloads = staging / "downloads"',
            "post-rename recovery completion",
        ),
        (
            "self-test did not complete post-rename SDK publication",
            "post-rename recovery fixture",
        ),
        ("validate_required_summary", "independent closure check"),
        (
            "validate_required_summary(summary)\n"
            "        validate_semantics(candidate)\n"
            "        candidate_identity = identity(os.lstat(candidate))",
            "pre-seal whole-tree closure",
        ),
        ("validate_semantics", "SDK consumer semantics"),
        ("write_state(staging, payload)", "durable verification state"),
        ("RENAME_NOREPLACE = 1", "no-clobber primitive"),
        (
            'renameat2(\n            output_fd,\n            "android-sdk",',
            "descriptor-relative publication",
        ),
        ("publication rollback also failed", "rollback path"),
        ('return "verified-unpublished"', "unpublished recovery"),
        ('return "published"', "published recovery"),
        ("state is incoherent and was preserved", "ambiguous-state refusal"),
        ("transaction self-test refuses root UID or GID", "root self-test refusal"),
        ("self-test accepted changed Android SDK output bytes", "tamper fixture"),
        ("self-test accepted an extra Android SDK output", "extra fixture"),
        (
            "self-test accepted externally hardlinked Android SDK output",
            "hardlink fixture",
        ),
        (
            "self-test accepted an occupied Android SDK destination",
            "no-clobber fixture",
        ),
        ("self-test accepted a wrong Android SDK archive digest", "digest fixture"),
        ("self-test accepted Android SDK archive path traversal", "path fixture"),
    ):
        require(helper, token, label)
    for token, label in (
        ("extractall(", "bulk ZIP extraction"),
        ("unpack_archive(", "general archive extraction"),
        ("subprocess", "child process execution"),
        ("os.system(", "shell execution"),
        ("platform-tools", "unused moving platform-tools"),
        ("urllib.request.urlretrieve", "unbounded URL retrieval"),
        ("os.chmod(destination", "post-publication mode mutation"),
    ):
        forbid(helper, token, label)

    require(
        sources["verify"],
        "/usr/bin/python3 -I -S "
        "scripts/verify-online-fetch-android-sdk-output-authority.py "
        "--repo . --self-test",
        "shared focused gate",
    )
    require(
        sources["requirements"],
        '<span class="id">R-S11cr</span>',
        "R-S11cr requirement",
    )
    require(
        sources["requirements"],
        "<tr><td>245</td>",
        "Appendix C #245",
    )
    require(
        sources["hardening"],
        "R-S11cr/R-S11e-110 — exact Android SDK acquisition and publication authority",
        "hardening disposition",
    )
    require(
        sources["hardening"],
        "R-S11cr/R-S11e-110 archive-specific PID mutation authority",
        "archive-specific PID mutation disposition",
    )
    require(
        sources["workspace"],
        '"online_fetch_android_sdk_output_authority_verifier"',
        "workspace source ownership",
    )
    require(
        sources["workspace"],
        "Online-fetch Android SDK output authority focused verifier",
        "workspace semantic binding",
    )


MUTATIONS: Tuple[Mutation, ...] = (
    Mutation("pins", "SHA256_ANDROID_BUILD_TOOLS_30_0_3=",
             "SHA256_ANDROID_BUILD_TOOLS_30_0_3_DISABLED=", "build-tools 30 pin"),
    Mutation("pins", "SHA256_ANDROID_BUILD_TOOLS_34_0_0=",
             "SHA256_ANDROID_BUILD_TOOLS_34_0_0_DISABLED=", "build-tools 34 pin"),
    Mutation("pins", "SHA256_ANDROID_PLATFORM_31=",
             "SHA256_ANDROID_PLATFORM_31_DISABLED=", "platform 31 pin"),
    Mutation("pins", "SHA256_ANDROID_PLATFORM_34=",
             "SHA256_ANDROID_PLATFORM_34_DISABLED=", "platform 34 pin"),
    Mutation(
        "shell",
        "online_docker_run_archive_acquisition() {\n"
        "    online_docker run --rm --pull=never --network=bridge --read-only",
        "online_docker_run_archive_acquisition() {\n"
        "    online_docker run --rm --pull=always --network=bridge --read-only",
        "no-pull acquisition",
    ),
    Mutation(
        "shell",
        "online_docker_run_archive_acquisition() {\n"
        "    online_docker run --rm --pull=never --network=bridge --read-only \\\n"
        '        --user "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID" \\\n'
        "        --cap-drop=ALL --security-opt=no-new-privileges \\\n"
        "        --pids-limit=256 --memory=4g",
        "online_docker_run_archive_acquisition() {\n"
        "    online_docker run --rm --pull=never --network=bridge --read-only \\\n"
        '        --user "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID" \\\n'
        "        --cap-drop=ALL --security-opt=no-new-privileges \\\n"
        "        --pids-limit=-1 --memory=4g",
        "archive-acquisition PID bound",
    ),
    Mutation(
        "shell",
        "online_docker_run_archive_acquisition() {\n"
        "    online_docker run --rm --pull=never --network=bridge --read-only \\\n"
        '        --user "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID" \\\n'
        "        --cap-drop=ALL --security-opt=no-new-privileges \\\n"
        "        --pids-limit=256 --memory=4g --memory-swap=4g --cpus=2 \\\n"
        "        --tmpfs /tmp:rw,noexec,nosuid,nodev",
        "online_docker_run_archive_acquisition() {\n"
        "    online_docker run --rm --pull=never --network=bridge --read-only \\\n"
        '        --user "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID" \\\n'
        "        --cap-drop=ALL --security-opt=no-new-privileges \\\n"
        "        --pids-limit=256 --memory=4g --memory-swap=4g --cpus=2 \\\n"
        "        --tmpfs /tmp:rw,exec,nosuid,nodev",
        "non-executable scratch",
    ),
    Mutation(
        "shell",
        "source=$cmdline_archive,target=/inputs/android-cmdline-tools.zip,readonly",
        "source=$ONLINE_DIR,target=/inputs/android-cmdline-tools.zip",
        "narrow command-line input",
    ),
    Mutation(
        "shell",
        "source=$staging/downloads,target=/outputs/downloads",
        "source=$ONLINE_DIR,target=/outputs/downloads",
        "narrow download output",
    ),
    Mutation(
        "shell",
        "source=$staging/output,target=/outputs/sdk",
        "source=$ONLINE_DIR,target=/outputs/sdk",
        "narrow SDK output",
    ),
    Mutation(
        "shell",
        "recover_android_sdk_output_staging \"$builder\"",
        "true # stale SDK state ignored",
        "preflight recovery",
    ),
    Mutation("shell", "android_sdk_output_tool verify \\\n",
             "android_sdk_output_tool accept \\\n", "host output postcondition"),
    Mutation(
        "shell",
        '[ "$status" -eq 0 ] && [ "$output_status" -eq 0 ]; then\n'
        "        android_sdk_output_tool publish",
        '[ "$status" -eq 0 ]; then\n'
        "        android_sdk_output_tool publish",
        "publication barrier",
    ),
    Mutation("helper", "response.status != 200", "False", "HTTP status check"),
    Mutation("helper", "response.geturl() != url", "False", "redirect rejection"),
    Mutation("helper", 'response.headers.get("Content-Length")',
             '"ignored"', "content length check"),
    Mutation("helper", "digest.hexdigest() != pins[spec.key]",
             "False", "download digest check"),
    Mutation(
        "helper",
        "or before.st_nlink != 1\n"
        "            or before.st_size != spec.size",
        "or before.st_nlink < 1\n"
        "            or before.st_size != spec.size",
        "archive hardlink rejection",
    ),
    Mutation("helper", "info.orig_filename != info.filename",
             "False", "NUL truncation rejection"),
    Mutation("helper", "info.create_system != 3",
             "False", "Unix archive type"),
    Mutation("helper", "info.flag_bits not in spec.allowed_flags",
             "False", "ZIP flag closure"),
    Mutation("helper", "archive contains a special member",
             "archive special member accepted", "special member rejection"),
    Mutation("helper", "archive member escapes its exact root",
             "archive traversal accepted", "path traversal rejection"),
    Mutation("helper", "repeats one member path",
             "duplicate path accepted", "duplicate rejection"),
    Mutation(
        "helper",
        "if relative in files or relative in directories:\n"
        '                    fail(f"Android SDK packages collide at {relative}")',
        "if relative in files or relative in directories:\n"
        '                    fail(f"Android SDK package collision accepted at {relative}")',
        "package collision rejection",
    ),
    Mutation("helper", "output bytes differ from the pinned archive",
             "output mismatch accepted", "output byte comparison"),
    Mutation("helper", "output inventory differs from the pinned archives",
             "output inventory accepted", "output inventory"),
    Mutation("helper", "output has foreign ownership",
             "foreign owner accepted", "owner rejection"),
    Mutation("helper", "carries extended attributes",
             "extended attributes accepted", "xattr rejection"),
    Mutation(
        "helper",
        'validate_absolute(root, "Android SDK output")\n'
        "    reject_mount_at_or_below(root)\n"
        "    files, directories = compose_manifest(manifests)",
        'validate_absolute(root, "Android SDK output")\n'
        "    # descendant mount accepted\n"
        "    files, directories = compose_manifest(manifests)",
        "mount closure",
    ),
    Mutation(
        "helper",
        "validate_required_summary(summary)\n"
        "        validate_semantics(candidate)\n"
        "        candidate_identity = identity(os.lstat(candidate))",
        "pass # independent summary omitted\n"
        "        validate_semantics(candidate)\n"
        "        candidate_identity = identity(os.lstat(candidate))",
        "whole-tree closure",
    ),
    Mutation(
        "helper",
        "if mode == 0o700:\n"
        '        downloads = staging / "downloads"',
        "if False:\n"
        '        downloads = staging / "downloads"',
        "post-rename recovery completion",
    ),
    Mutation(
        "helper",
        'renameat2(\n            output_fd,\n            "android-sdk",',
        'os.rename(\n            output_fd,\n            "android-sdk",',
        "no-clobber publication",
    ),
    Mutation(
        "verify",
        "/usr/bin/python3 -I -S "
        "scripts/verify-online-fetch-android-sdk-output-authority.py "
        "--repo . --self-test",
        "true # Android SDK authority gate removed",
        "shared gate",
    ),
    Mutation(
        "requirements",
        '<span class="id">R-S11cr</span>',
        '<span class="id">R-S11cr-disabled</span>',
        "R-S11cr requirement",
    ),
    Mutation(
        "requirements",
        "<tr><td>245</td>",
        "<tr><td>245-disabled</td>",
        "Appendix C #245",
    ),
    Mutation(
        "hardening",
        "R-S11cr/R-S11e-110 — exact Android SDK acquisition and publication authority",
        "R-S11cr/R-S11e-110 — ambient Android SDK authority",
        "hardening disposition",
    ),
    Mutation(
        "hardening",
        "R-S11cr/R-S11e-110 archive-specific PID mutation authority",
        "R-S11cr/R-S11e-110 global PID mutation authority",
        "archive-specific PID mutation disposition",
    ),
)


def load_sources(repo: pathlib.Path) -> Dict[str, str]:
    return {
        "shell": (repo / "scripts/online-fetch.sh").read_text(encoding="utf-8"),
        "helper": (repo / "scripts/online-android-sdk-output.py").read_text(
            encoding="utf-8"
        ),
        "pins": (repo / "scripts/pins.env").read_text(encoding="utf-8"),
        "verify": (repo / "scripts/verify.sh").read_text(encoding="utf-8"),
        "requirements": (repo / "requirements.html").read_text(encoding="utf-8"),
        "hardening": (repo / "HARDENING_STATUS.md").read_text(encoding="utf-8"),
        "workspace": (repo / "scripts/verify-verifier-workspace.py").read_text(
            encoding="utf-8"
        ),
    }


def run_mutations(sources: Dict[str, str]) -> None:
    for mutation in MUTATIONS:
        original = sources[mutation.source]
        count = original.count(mutation.old)
        if count != 1:
            raise AuthorityError(
                "mutation target for {} occurs {} times".format(
                    mutation.label,
                    count,
                )
            )
        changed = dict(sources)
        changed[mutation.source] = original.replace(
            mutation.old,
            mutation.new,
            1,
        )
        try:
            validate(changed)
        except AuthorityError:
            continue
        raise AuthorityError("mutation was accepted: {}".format(mutation.label))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=pathlib.Path, default=pathlib.Path("."))
    parser.add_argument("--self-test", action="store_true")
    arguments = parser.parse_args()
    sources = load_sources(arguments.repo.resolve())
    validate(sources)
    if arguments.self_test:
        run_mutations(sources)
    print(
        "verify-online-fetch-android-sdk-output-authority: PASS"
        + (
            " ({} mutations rejected)".format(len(MUTATIONS))
            if arguments.self_test
            else ""
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, AuthorityError) as error:
        raise SystemExit(
            "verify-online-fetch-android-sdk-output-authority: {}".format(error)
        )
