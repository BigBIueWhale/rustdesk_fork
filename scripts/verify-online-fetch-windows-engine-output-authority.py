#!/usr/bin/env python3
"""Gate the Windows Flutter-engine acquisition-output authority boundary."""

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
        raise AuthorityError(f"missing {label}: {token!r}")


def require_absent(source: str, token: str, label: str) -> None:
    if token in source:
        raise AuthorityError(f"forbidden {label} remains: {token!r}")


def require_count(source: str, token: str, expected: int, label: str) -> None:
    actual = source.count(token)
    if actual != expected:
        raise AuthorityError(
            f"{label} count is {actual}, expected {expected}: {token!r}"
        )


def require_order(source: str, tokens: Tuple[str, ...], label: str) -> None:
    position = -1
    for token in tokens:
        found = source.find(token, position + 1)
        if found < 0:
            raise AuthorityError(f"{label} is missing ordered token {token!r}")
        position = found


def extract_between(source: str, start: str, end: str, label: str) -> str:
    if source.count(start) != 1:
        raise AuthorityError(f"{label} start cardinality differs")
    begin = source.index(start)
    finish = source.find(end, begin + len(start))
    if finish < 0:
        raise AuthorityError(f"{label} end is absent")
    return source[begin:finish]


def pin_value(source: str, name: str) -> str:
    match = re.search(
        rf'^{re.escape(name)}="([^"]+)"',
        source,
        re.MULTILINE,
    )
    if match is None:
        raise AuthorityError(f"{name} is not one canonical quoted pin")
    return match.group(1)


def validate(sources: Dict[str, str]) -> None:
    shell = sources["shell"]
    helper = sources["helper"]
    pins = sources["pins"]
    verify = sources["verify"]
    requirements = sources["requirements"]
    hardening = sources["hardening"]
    workspace = sources["workspace"]
    focused = sources["focused"]
    try:
        ast.parse(helper)
        focused_module = ast.parse(focused)
    except SyntaxError as error:
        raise AuthorityError(f"Windows-engine Python source does not parse: {error}")
    if not any(
        isinstance(node, ast.FunctionDef) and node.name == "mutations"
        for node in focused_module.body
    ):
        raise AuthorityError("focused mutation inventory is absent")

    output_sha256 = pin_value(pins, "SHA256_FLUTTER_WIN_ENGINE")
    output_size = pin_value(pins, "SIZE_FLUTTER_WIN_ENGINE")
    source_sha256 = pin_value(pins, "SHA256_FLUTTER_3_24_5")
    builder = pin_value(pins, "ANDROID_BUILDER_IMAGE_ID")
    if output_sha256 != (
        "413c7117cc60545629367f73545aa5b3720687eddc77d7d48f93477e4f05440e"
    ):
        raise AuthorityError("Windows-engine SHA-256 differs from the reviewed pin")
    if output_size != "207343264":
        raise AuthorityError("Windows-engine compressed size differs from the reviewed pin")
    if re.fullmatch(r"[0-9a-f]{64}", source_sha256) is None:
        raise AuthorityError("Flutter source SHA-256 is malformed")
    if re.fullmatch(r"sha256:[0-9a-f]{64}", builder) is None:
        raise AuthorityError("Android builder is not one immutable image content ID")
    lifecycle = extract_between(
        shell,
        "stage_windows_engine() {",
        "\n}\n\n# ── The Windows flutter_tools Pub cache",
        "Windows-engine output lifecycle",
    )
    online_profile = extract_between(
        shell,
        "online_docker_run() {",
        "\n}\n\n# Host-side archive expansion",
        "networked acquisition profile",
    )
    offline_profile = extract_between(
        shell,
        "online_docker_run_offline() {",
        "\n}\n\n# Offline Cargo resolution",
        "networkless semantic profile",
    )
    for token, label in (
        ("--pull=never --network=bridge --read-only", "isolated networked profile"),
        ('--user "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID"', "numeric non-root identity"),
        ("--cap-drop=ALL --security-opt=no-new-privileges", "privilege removal"),
        ("--pids-limit=2048 --memory=16g --memory-swap=16g --cpus=4",
         "networked resource ceiling"),
        ("--tmpfs /tmp:rw,exec,nosuid,nodev,mode=1777,size=12g",
         "networked scratch ceiling"),
    ):
        require(online_profile, token, label)
    for token, label in (
        ("--pull=never --network=none --read-only", "networkless semantic profile"),
        ('--user "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID"',
         "semantic numeric non-root identity"),
        ("--cap-drop=ALL --security-opt=no-new-privileges",
         "semantic privilege removal"),
        ("--pids-limit=512 --memory=4g --memory-swap=4g --cpus=2",
         "semantic resource ceiling"),
        ("--tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777,size=256m",
         "semantic bounded scratch"),
    ):
        require(offline_profile, token, label)

    for token, label in (
        ("windows_engine_output_tool() {", "fixed transaction helper"),
        ("windows_engine_output_args() {", "closed contract mapper"),
        ("verify_windows_engine_source() {", "source byte postcondition"),
        ("retire_windows_engine_staging() {", "private staging retirement"),
        ("recover_windows_engine_staging() {", "restart recovery"),
    ):
        require(shell, token, label)
    for token, label in (
        ('local builder="$ANDROID_BUILDER_IMAGE_ID"', "immutable producer"),
        ('"$FLOCK_BIN" --exclusive --nonblock "$lock_fd"', "exclusive transaction"),
        ('"$ONLINE_DIR/.rustdesk-windows-engine.XXXXXXXXXX"',
         "unpredictable same-filesystem staging"),
        ("windows_engine_output_tool prepare", "transaction preparation"),
        (
            "source=$source,target=/inputs/flutter.tar.xz,readonly,bind-recursive=disabled",
            "exact read-only source mount",
        ),
        (
            "source=$staging/output,target=/outputs/engine.tar.gz",
            "sole writable output inode",
        ),
        ("GIT_CONFIG_GLOBAL=/dev/null", "closed Git global configuration"),
        (
            "PATH=/tmp/toolchain/flutter/bin:/tmp/toolchain/flutter/bin/cache/dart-sdk/bin:/usr/bin:/bin",
            "closed executable search path",
        ),
        ("flutter precache --windows", "exact acquisition command"),
        (
            "bin/cache/artifacts/engine/windows-x64-profile",
            "exact profile-engine projection",
        ),
        (
            "bin/cache/artifacts/engine/windows-x64-release",
            "exact release-engine projection",
        ),
        ("bin/cache/libimobiledevice.stamp", "exact libimobiledevice stamp"),
        ("bin/cache/usbmuxd.stamp", "exact usbmuxd stamp"),
        ("bin/cache/windows-sdk.stamp", "exact Windows SDK stamp"),
        (
            '$(/usr/bin/wc -l < /tmp/stage.txt)" -eq 73',
            "exact producer inventory count",
        ),
        ("-exec /usr/bin/chmod 0666 {} +", "ordinary-file mode normalization"),
        ("/usr/bin/chmod 0644 \\", "snapshot/stamp mode normalization"),
        ("written + len(block) > limit", "producer output byte ceiling"),
        ("windows_engine_output_tool verify", "independent structural verdict"),
        ("online_docker_run_offline", "networkless semantic replay"),
        ("verify-archive", "closed archive semantic command"),
        ("windows_engine_output_tool publish", "checked publication"),
        ("retire_windows_engine_staging", "reconciled retirement"),
    ):
        require(lifecycle, token, label)
    require_count(lifecycle, "online_docker_run \\", 1, "networked producer")
    require_count(
        lifecycle,
        "online_docker_run_offline \\",
        1,
        "networkless semantic replay",
    )
    for token, label in (
        ("target=/online", "online-root mount"),
        ("source=$ONLINE_DIR,target=/online", "broad online-root authority"),
        ("> /online/flutter-windows-engine.tar.gz", "direct final write"),
        ('git config --global --add safe.directory "*"', "wildcard Git trust"),
        ('[ -f "$out" ] &&', "presence-only reuse"),
        ("-newer /tmp/marker", "cache-wide timestamp inference"),
        ("/tmp/before.txt", "cache-wide before/after inference"),
        ("rm -f \"$destination\"", "destructive final cleanup"),
        ("mv \"$staging/output\"", "unchecked shell publication"),
    ):
        require_absent(lifecycle, token, label)
    require_order(
        lifecycle,
        (
            "verify_windows_engine_source \"before Windows-engine transaction\"",
            '"$FLOCK_BIN" --exclusive --nonblock "$lock_fd"',
            "recover_windows_engine_staging",
            "check-complete",
            "/usr/bin/mktemp -d",
            "windows_engine_output_tool prepare",
            "online_docker_run \\",
            "verify_windows_engine_source \"after Windows-engine producer\"",
            "windows_engine_output_tool verify",
            "online_docker_run_offline \\",
            "verify_windows_engine_source \"after Windows-engine semantic validation\"",
            "windows_engine_output_tool publish",
            "retire_windows_engine_staging",
            '"$FLOCK_BIN" --unlock "$lock_fd"',
        ),
        "validate-seal-replay-publish lifecycle",
    )

    for token, label in (
        ('STATE_NAME = ".rustdesk-windows-engine-state-v1"',
         "bounded transaction state"),
        ('DESTINATION = "flutter-windows-engine.tar.gz"', "fixed final name"),
        ("MAX_ARCHIVE_BYTES = 256 * 1024 * 1024", "archive byte bound"),
        ("PRODUCTION_CONTRACT = ArchiveContract(", "closed semantic contract"),
        ("total_bytes=817_399_293", "exact uncompressed bytes"),
        ("if uid <= 0 or gid <= 0:", "non-root transaction identity"),
        ("reject_mount_at_or_below(staging)", "nested mount refusal"),
        ("os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW", "no-follow reads"),
        ("if metadata.st_nlink != 1:", "external-hardlink refusal"),
        ("if list_xattrs(archive):", "archive xattr refusal"),
        ("digest != expected_sha256", "exact archive digest"),
        ("member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE)",
         "regular-member-only contract"),
        ("if archive.pax_headers:", "global PAX refusal"),
        ("if member.pax_headers:", "member PAX refusal"),
        ("if member.mtime != ARCHIVE_MTIME:", "fixed archive time"),
        ("if names != contract.names:", "exact member inventory"),
        ("if total_bytes != contract.total_bytes:", "exact uncompressed size"),
        ("historical root-owned Windows engine archive is not mode 0644",
         "closed historical compatibility"),
        ("os.fchmod(descriptor, 0o400)", "candidate sealing"),
        ("RENAME_NOREPLACE = 1", "no-clobber primitive"),
        ("renameat2(staging_fd, \"output\", online_fd, DESTINATION)",
         "descriptor-relative publication"),
        ("Windows engine archive publication rollback also failed",
         "rollback-failure preservation"),
        ('return "unpublished-destination-occupied"',
         "destination-race recovery"),
        ('return "published"', "completed recovery"),
        ("self-test accepted a semantically wrong Windows-engine archive",
         "semantic negative fixture"),
        ("self-test accepted a hardlinked Windows-engine output",
         "hardlink negative fixture"),
        ("self-test accepted a symlinked Windows-engine output",
         "symlink negative fixture"),
        ("self-test accepted xattrs on Windows-engine output",
         "xattr negative fixture"),
        ("online-windows-engine-output: PASS", "runtime fixture result"),
    ):
        require(helper, token, label)

    for token, label in (
        (
            "/usr/bin/python3 -I -S scripts/online-windows-engine-output.py self-test",
            "transaction self-test wiring",
        ),
        (
            "/usr/bin/python3 -I -S scripts/verify-online-fetch-windows-engine-output-authority.py --repo . --self-test",
            "focused mutation gate wiring",
        ),
    ):
        require(verify, token, label)
    require(
        requirements,
        '<span class="id">R-S11cx</span>',
        "Windows-engine normative requirement",
    )
    require(
        requirements,
        "<tr><td>251</td>",
        "Windows-engine Appendix C row",
    )
    require(
        hardening,
        "R-S11cx/R-S11e-116 — exact Windows Flutter-engine acquisition-output authority",
        "Windows-engine hardening ledger",
    )
    for token, label in (
        (
            "validate_online_fetch_windows_engine_output_authority_contract(sources)",
            "workspace contract dispatch",
        ),
        (
            '"online_windows_engine_output_helper"',
            "workspace helper source binding",
        ),
        (
            '"online_fetch_windows_engine_output_authority_verifier"',
            "workspace focused-verifier binding",
        ),
    ):
        require(workspace, token, label)


def mutations() -> Tuple[Mutation, ...]:
    return (
        Mutation(
            "focused",
            "def " + "mutations() -> Tuple[Mutation, ...]:",
            "def disabled_mutations() -> Tuple[Mutation, ...]:",
            "focused mutation inventory",
        ),
        Mutation(
            "shell",
            "source=$source,target=/inputs/flutter.tar.xz,readonly,bind-recursive=disabled\" \\\n"
            "        --mount \"type=bind,source=$staging/output,target=/outputs/engine.tar.gz",
            "source=$ONLINE_DIR,target=/inputs/flutter.tar.xz\" \\\n"
            "        --mount \"type=bind,source=$staging/output,target=/outputs/engine.tar.gz",
            "exact read-only source mount",
        ),
        Mutation(
            "shell",
            "source=$staging/output,target=/outputs/engine.tar.gz",
            "source=$ONLINE_DIR,target=/outputs/engine.tar.gz",
            "sole writable output",
        ),
        Mutation(
            "shell",
            "online_docker run --rm --pull=never --network=none --read-only",
            "online_docker run --rm --pull=always --network=bridge",
            "networkless semantic profile",
        ),
        Mutation(
            "shell",
            "written + len(block) > limit",
            "False",
            "producer output byte bound",
        ),
        Mutation(
            "shell",
            '$(/usr/bin/wc -l < /tmp/stage.txt)" -eq 73',
            '$(/usr/bin/wc -l < /tmp/stage.txt)" -gt 0',
            "exact producer inventory count",
        ),
        Mutation(
            "shell",
            "-exec /usr/bin/chmod 0666 {} +",
            "-exec /usr/bin/chmod 0644 {} +",
            "ordinary-file mode normalization",
        ),
        Mutation(
            "shell",
            "windows_engine_output_tool publish",
            "true # Windows-engine publication removed",
            "checked publication",
        ),
        Mutation(
            "helper",
            "if uid <= 0 or gid <= 0:",
            "if False:",
            "non-root transaction identity",
        ),
        Mutation(
            "helper",
            "if metadata.st_nlink != 1:",
            "if False:",
            "archive hardlink refusal",
        ),
        Mutation(
            "helper",
            "if list_xattrs(archive):",
            "if False:",
            "archive xattr refusal",
        ),
        Mutation(
            "helper",
            "member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE)",
            "False",
            "regular-member contract",
        ),
        Mutation(
            "helper",
            "if names != contract.names:",
            "if False:",
            "exact archive inventory",
        ),
        Mutation(
            "helper",
            "if total_bytes != contract.total_bytes:",
            "if False:",
            "exact archive byte count",
        ),
        Mutation(
            "helper",
            "RENAME_NOREPLACE = 1",
            "RENAME_NOREPLACE = 0",
            "no-clobber publication",
        ),
        Mutation(
            "verify",
            "/usr/bin/python3 -I -S scripts/verify-online-fetch-windows-engine-output-authority.py --repo . --self-test",
            "true # Windows-engine focused gate removed",
            "focused verifier wiring",
        ),
        Mutation(
            "requirements",
            '<span class="id">R-S11cx</span>',
            '<span class="id">R-S11cx-disabled</span>',
            "normative requirement",
        ),
        Mutation(
            "requirements",
            "<tr><td>251</td>",
            "<tr><td>251-disabled</td>",
            "Appendix C row",
        ),
        Mutation(
            "hardening",
            "R-S11cx/R-S11e-116 — exact Windows Flutter-engine acquisition-output authority",
            "R-S11cx/R-S11e-116 — ambient Windows-engine output authority",
            "hardening ledger",
        ),
    )


def load_sources(repo: pathlib.Path) -> Dict[str, str]:
    return {
        "shell": (repo / "scripts/online-fetch.sh").read_text(encoding="utf-8"),
        "helper": (
            repo / "scripts/online-windows-engine-output.py"
        ).read_text(encoding="utf-8"),
        "pins": (repo / "scripts/pins.env").read_text(encoding="utf-8"),
        "verify": (repo / "scripts/verify.sh").read_text(encoding="utf-8"),
        "requirements": (repo / "requirements.html").read_text(encoding="utf-8"),
        "hardening": (repo / "HARDENING_STATUS.md").read_text(encoding="utf-8"),
        "workspace": (
            repo / "scripts/verify-verifier-workspace.py"
        ).read_text(encoding="utf-8"),
        "focused": pathlib.Path(__file__).read_text(encoding="utf-8"),
    }


def run_mutations(sources: Dict[str, str]) -> None:
    checked = 0
    for mutation in mutations():
        original = sources[mutation.source]
        if mutation.old not in original:
            raise AuthorityError(
                f"mutation source is absent for {mutation.label}: {mutation.old!r}"
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
            checked += 1
        else:
            raise AuthorityError(f"mutation survived: {mutation.label}")
    if checked != len(mutations()):
        raise AuthorityError("not every Windows-engine mutation was exercised")
    print(f"verify-online-fetch-windows-engine-output-authority: {checked} mutations rejected")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=".", type=pathlib.Path)
    parser.add_argument("--self-test", action="store_true")
    arguments = parser.parse_args()
    repo = arguments.repo.resolve()
    try:
        sources = load_sources(repo)
        validate(sources)
        if arguments.self_test:
            run_mutations(sources)
    except (OSError, UnicodeError, AuthorityError) as error:
        print(
            f"verify-online-fetch-windows-engine-output-authority: FAIL: {error}"
        )
        return 1
    print("verify-online-fetch-windows-engine-output-authority: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
