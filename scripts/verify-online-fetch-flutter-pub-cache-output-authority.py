#!/usr/bin/env python3
"""Gate the Windows flutter_tools Pub-cache acquisition-output boundary."""

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
        raise AuthorityError(
            f"Flutter Pub-cache Python source does not parse: {error}"
        )
    if not any(
        isinstance(node, ast.FunctionDef) and node.name == "mutations"
        for node in focused_module.body
    ):
        raise AuthorityError("focused mutation inventory is absent")

    output_sha256 = pin_value(pins, "SHA256_FLUTTER_PUB_CACHE")
    output_size = pin_value(pins, "SIZE_FLUTTER_PUB_CACHE")
    flutter_sha256 = pin_value(pins, "SHA256_FLUTTER_3_24_5")
    tools_lock = pin_value(pins, "SHA256_FLUTTER_TOOLS_LOCK")
    builder = pin_value(pins, "ANDROID_BUILDER_IMAGE_ID")
    if output_sha256 != (
        "69db14598f59440d4c2b16e017b2266f3b011cd1cc6854c65b6caaea8db946ae"
    ):
        raise AuthorityError("Flutter Pub-cache SHA-256 differs from the reviewed pin")
    if output_size != "18771131":
        raise AuthorityError("Flutter Pub-cache size differs from the reviewed pin")
    if tools_lock != (
        "66955192347d2d4eb24476745462c80a11d9bbf19a461f3504bbbd86e366ee8e"
    ):
        raise AuthorityError("flutter_tools lock SHA-256 differs from the reviewed pin")
    if re.fullmatch(r"[0-9a-f]{64}", flutter_sha256) is None:
        raise AuthorityError("Flutter source SHA-256 is malformed")
    if re.fullmatch(r"sha256:[0-9a-f]{64}", builder) is None:
        raise AuthorityError("Android builder is not one immutable image content ID")

    lifecycle = extract_between(
        shell,
        "stage_flutter_pub_cache() {",
        "\n}\n\n# ── The exact signed WiX",
        "Flutter Pub-cache output lifecycle",
    )
    semantic_profile = extract_between(
        shell,
        "online_docker_run_pub_semantic() {",
        "\n}\n\n# Exact archive acquisition",
        "offline Pub semantic profile",
    )
    semantic_replay = extract_between(
        shell,
        "verify_flutter_pub_cache_archive_resolution() {",
        "\n}\n\n# Flutter's Windows SDK",
        "Flutter Pub-cache semantic replay",
    )
    for token, label in (
        ("--pull=never --network=none --read-only", "network removal"),
        ('--user "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID"', "numeric non-root identity"),
        ("--cap-drop=ALL --security-opt=no-new-privileges", "privilege removal"),
        (
            "--pids-limit=512 --memory=8g --memory-swap=8g --cpus=4",
            "resource ceiling",
        ),
        (
            "--tmpfs /tmp:rw,exec,nosuid,nodev,mode=1777,size=5g",
            "bounded executable scratch",
        ),
    ):
        require(semantic_profile, token, f"offline Pub semantic {label}")

    for token, label in (
        ("flutter_pub_cache_output_tool() {", "fixed transaction helper"),
        ("flutter_pub_cache_output_args() {", "closed contract mapper"),
        ("verify_flutter_pub_cache_source() {", "source-tree validator"),
        (
            "verify_flutter_pub_cache_flutter_source() {",
            "Flutter archive validator",
        ),
        (
            "verify_flutter_pub_cache_archive_resolution() {",
            "offline semantic replay",
        ),
        (
            'if [[ "$receipt" =~ ^sha256=([0-9a-f]{64})$ ]]; then\n'
            '        printf \'%s\\n\' "${BASH_REMATCH[1]}"',
            "exact source receipt",
        ),
        ("retire_flutter_pub_cache_staging() {", "staging retirement"),
        ("recover_flutter_pub_cache_staging() {", "restart recovery"),
    ):
        require(shell, token, label)
    for token, label in (
        ('local builder="$ANDROID_BUILDER_IMAGE_ID"', "reproducible builder"),
        ('"$FLOCK_BIN" --exclusive --nonblock "$lock_fd"', "exclusive transaction"),
        (
            '"$ONLINE_DIR/.rustdesk-flutter-pub-cache.XXXXXXXXXX"',
            "unpredictable same-filesystem staging",
        ),
        ("verify_flutter_pub_cache_source", "source receipt"),
        ("flutter_pub_cache_output_tool prepare", "transaction preparation"),
        (
            "source=$ONLINE_DIR/pub-cache,target=/inputs/pub-cache,readonly,bind-recursive=disabled",
            "exact read-only cache source",
        ),
        (
            "source=$source,target=/inputs/flutter.tar.xz,readonly,bind-recursive=disabled",
            "exact producer Flutter source",
        ),
        (
            "source=$staging/output,target=/outputs/pub-cache.tar.gz",
            "sole writable output inode",
        ),
        (
            "RUSTDESK_FLUTTER_TOOLS_LOCK_SHA256=$SHA256_FLUTTER_TOOLS_LOCK",
            "producer lockfile contract",
        ),
        (
            "write-projection-manifest",
            "lock-derived projection",
        ),
        (
            "--null --verbatim-files-from --no-recursion",
            "exact nonrecursive manifest consumption",
        ),
        ("--hard-dereference", "regular-file archive projection"),
        ('--mode="u+rwX,go+rX,go-w"', "mode normalization"),
        ("normalize-tar", "exact historical mode normalization"),
        ("write-bounded", "bounded output writer"),
        ("flutter_pub_cache_output_tool verify", "independent archive verdict"),
        (
            "verify_flutter_pub_cache_archive_resolution",
            "networkless semantic replay",
        ),
        ("flutter_pub_cache_output_tool publish", "checked publication"),
        ("retire_flutter_pub_cache_staging", "reconciled retirement"),
    ):
        require(lifecycle, token, label)
    require_count(
        lifecycle,
        "online_docker_run_offline \\",
        1,
        "offline packager launch",
    )
    for token, label in (
        ("online_docker_run_pub_semantic", "shared semantic profile"),
        (
            "source=$source,target=/inputs/flutter.tar.xz,readonly,bind-recursive=disabled",
            "exact Flutter source mount",
        ),
        (
            "source=$archive,target=/inputs/pub-cache.tar.gz,readonly,bind-recursive=disabled",
            "exact archive mount",
        ),
        ("verify-archive", "complete archive validation"),
        ("--no-same-owner --no-same-permissions", "bounded extraction metadata"),
        ("dart pub get --offline --enforce-lockfile", "exact offline resolver"),
        (
            "RUSTDESK_FLUTTER_TOOLS_LOCK_SHA256=$SHA256_FLUTTER_TOOLS_LOCK",
            "lockfile contract",
        ),
    ):
        require(semantic_replay, token, label)
    for token, label in (
        ('local builder="$DEB_BUILDER_IMAGE_ID"', "non-reproducible Debian builder"),
        ("target=/online", "broad online mount"),
        ("source=$ONLINE_DIR,target=/online", "online-root authority"),
        ("> /online/flutter-pub-cache.tar.gz", "direct final write"),
        ('[ -f "$out" ]', "presence-only reuse"),
        ("zcat \"$out\"", "single-member archive check"),
        ("grep -q 'hosted/pub.dev/test-1.25.7", "single-member archive verdict"),
        ("rm -f \"$destination\"", "destructive final cleanup"),
        ("mv \"$staging/output\"", "unchecked shell publication"),
    ):
        require_absent(lifecycle, token, label)
    require_order(
        lifecycle,
        (
            "prepare_gradle_source",
            "retire_gradle_source_build",
            "verify_flutter_pub_cache_flutter_source",
            '"$FLOCK_BIN" --exclusive --nonblock "$lock_fd"',
            "verify_flutter_pub_cache_source",
            "recover_flutter_pub_cache_staging",
            "check-complete",
            "/usr/bin/mktemp -d",
            "flutter_pub_cache_output_tool prepare",
            "online_docker_run_offline \\",
            "verify_flutter_pub_cache_source",
            "flutter_pub_cache_output_tool verify",
            "verify_flutter_pub_cache_archive_resolution",
            "verify_flutter_pub_cache_source",
            "flutter_pub_cache_output_tool publish",
            "retire_flutter_pub_cache_staging",
            '"$FLOCK_BIN" --unlock "$lock_fd"',
        ),
        "validate-package-replay-publish lifecycle",
    )

    for token, label in (
        (
            'STATE_NAME = ".rustdesk-flutter-pub-cache-state-v1"',
            "bounded transaction state",
        ),
        ('DESTINATION = "flutter-pub-cache.tar.gz"', "fixed final name"),
        ("MAX_ARCHIVE_BYTES = 256 * 1024 * 1024", "archive byte bound"),
        ("HOSTED_LOCK_RECORDS = 95", "exact hosted lock record count"),
        ("PRODUCTION_CONTRACT = ArchiveContract(", "logical archive contract"),
        ("member_count=7_778", "exact member count"),
        ("directory_count=1_054", "exact directory count"),
        ("file_count=6_724", "exact regular-file count"),
        ("total_bytes=86_925_556", "exact uncompressed bytes"),
        (
            '"fa1189aa532a4444dcd2c0643030e7a41dae0421968843fa2ee48c258ac69c80"',
            "exact metadata digest",
        ),
        (
            '"d9b7aa737bea93d62fb46cfa1e2a49339040f8f594c8ac1d61459b3e895106e8"',
            "name-bound payload digest",
        ),
        (
            "def parse_flutter_tools_lock(",
            "exact flutter_tools lock parser",
        ),
        (
            "def write_projection_manifest(",
            "minimal projection manifest",
        ),
        (
            "if hash_bytes != record.sha256.encode(\"ascii\"):",
            "lock-to-cache hash equality",
        ),
        (
            'paths = {"hosted", "hosted/pub.dev", "hosted-hashes", "hosted-hashes/pub.dev"}',
            "metadata-free projection roots",
        ),
        (
            "if uid <= 0 or gid <= 0:\n"
            '        fail("Flutter Pub-cache transaction refuses UID or primary GID zero")',
            "non-root transaction identity",
        ),
        ("reject_mount_at_or_below(staging)", "nested mount refusal"),
        ("os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW", "no-follow reads"),
        ("if metadata.st_nlink != 1:", "external-hardlink refusal"),
        ("if list_xattrs(archive):", "archive xattr refusal"),
        ("if digest != expected_sha256:", "exact archive digest"),
        ("if archive.pax_headers:", "global PAX refusal"),
        ("if member.pax_headers:", "member PAX refusal"),
        ("elif member.isfile():", "regular-member contract"),
        ("member.mtime != ARCHIVE_MTIME", "fixed member time"),
        ("actual != expected", "complete logical contract comparison"),
        (
            "historical root-owned Flutter Pub-cache archive is not mode 0644",
            "closed historical compatibility",
        ),
        ("mutable[100:108] = b\"0000754\\0\"", "exact 0754 raw-tar repair"),
        ("if zero_blocks < 2:", "raw-tar terminal validation"),
        ("if patched != SPECIAL_MODES:", "both special members required"),
        (
            "if total + len(block) > expected_size:",
            "producer byte ceiling",
        ),
        ("os.fchmod(descriptor, 0o400)", "candidate sealing"),
        ("RENAME_NOREPLACE = 1", "no-clobber primitive"),
        (
            'renameat2(staging_fd, "output", online_fd, DESTINATION)',
            "descriptor-relative publication",
        ),
        (
            "Flutter Pub-cache publication rollback also failed",
            "rollback-failure preservation",
        ),
        ('return "unpublished-destination-occupied"', "destination-race recovery"),
        ('return "published"', "completed recovery"),
        (
            "self-test accepted a semantically wrong Flutter Pub-cache archive",
            "semantic negative fixture",
        ),
        (
            "self-test accepted a raw tar missing one special-mode member",
            "raw normalization negative fixture",
        ),
        (
            "self-test did not emit the exact lock-derived projection manifest",
            "projection manifest fixture",
        ),
        (
            "self-test accepted a projection hash that differs from the lock",
            "projection hash negative fixture",
        ),
        ("online-flutter-pub-cache-output: PASS", "runtime fixture result"),
    ):
        require(helper, token, label)

    for token, label in (
        (
            "/usr/bin/python3 -I -S scripts/online-flutter-pub-cache-output.py self-test",
            "transaction self-test wiring",
        ),
        (
            "/usr/bin/python3 -I -S scripts/verify-online-fetch-flutter-pub-cache-output-authority.py --repo . --self-test",
            "focused mutation gate wiring",
        ),
    ):
        require(verify, token, label)
    require(
        requirements,
        '<span class="id">R-S11cy</span>',
        "Flutter Pub-cache normative requirement",
    )
    require(requirements, "<tr><td>252</td>", "Flutter Pub-cache Appendix C row")
    require(
        hardening,
        "R-S11cy/R-S11e-117 — exact Windows flutter_tools Pub-cache acquisition-output authority",
        "Flutter Pub-cache hardening ledger",
    )
    for token, label in (
        (
            "validate_online_fetch_flutter_pub_cache_output_authority_contract(sources)",
            "workspace contract dispatch",
        ),
        (
            '"online_flutter_pub_cache_output_helper"',
            "workspace helper source binding",
        ),
        (
            '"online_fetch_flutter_pub_cache_output_authority_verifier"',
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
            "source=$ONLINE_DIR/pub-cache,target=/inputs/pub-cache,readonly,bind-recursive=disabled",
            "source=$ONLINE_DIR,target=/inputs/pub-cache",
            "exact read-only source",
        ),
        Mutation(
            "shell",
            'if [[ "$receipt" =~ ^sha256=([0-9a-f]{64})$ ]]; then\n'
            '        printf \'%s\\n\' "${BASH_REMATCH[1]}"',
            'if [[ -n "$receipt" ]]; then\n'
            '        printf \'%s\\n\' "${receipt}"',
            "exact source receipt",
        ),
        Mutation(
            "shell",
            "source=$staging/output,target=/outputs/pub-cache.tar.gz",
            "source=$ONLINE_DIR,target=/outputs/pub-cache.tar.gz",
            "sole writable output",
        ),
        Mutation(
            "shell",
            "source=$ONLINE_DIR/pub-cache,target=/inputs/pub-cache,readonly,bind-recursive=disabled\" \\\n"
            "        --mount \"type=bind,source=$source,target=/inputs/flutter.tar.xz,readonly,bind-recursive=disabled",
            "source=$ONLINE_DIR/pub-cache,target=/inputs/pub-cache,readonly,bind-recursive=disabled\" \\\n"
            "        --mount \"type=bind,source=$ONLINE_DIR,target=/inputs/flutter.tar.xz",
            "exact producer Flutter source",
        ),
        Mutation(
            "shell",
            "online_docker_run_pub_semantic() {\n"
            "    online_docker run --rm --pull=never --network=none --read-only",
            "online_docker_run_pub_semantic() {\n"
            "    online_docker run --rm --pull=always --network=bridge",
            "networkless semantic profile",
        ),
        Mutation(
            "shell",
            "source=$source,target=/inputs/flutter.tar.xz,readonly,bind-recursive=disabled\" \\\n"
            "        --mount \"type=bind,source=$archive,target=/inputs/pub-cache.tar.gz",
            "source=$ONLINE_DIR,target=/inputs/flutter.tar.xz\" \\\n"
            "        --mount \"type=bind,source=$archive,target=/inputs/pub-cache.tar.gz",
            "exact Flutter source mount",
        ),
        Mutation(
            "shell",
            "source=$archive,target=/inputs/pub-cache.tar.gz,readonly,bind-recursive=disabled",
            "source=$ONLINE_DIR,target=/inputs/pub-cache.tar.gz",
            "exact semantic archive mount",
        ),
        Mutation(
            "shell",
            'stage_flutter_pub_cache() {\n'
            '    local builder="$ANDROID_BUILDER_IMAGE_ID"',
            'stage_flutter_pub_cache() {\n'
            '    local builder="$DEB_BUILDER_IMAGE_ID"',
            "reproducible builder",
        ),
        Mutation(
            "shell",
            '--mode="u+rwX,go+rX,go-w"',
            '--mode="a=rX"',
            "historical mode normalization",
        ),
        Mutation(
            "shell",
            "--null --verbatim-files-from --no-recursion",
            "--null --verbatim-files-from",
            "nonrecursive projection manifest",
        ),
        Mutation(
            "shell",
            "--hard-dereference",
            "--no-recursion",
            "regular-file archive projection",
        ),
        Mutation(
            "shell",
            "flutter_pub_cache_output_tool publish",
            "true # Flutter Pub-cache publication removed",
            "checked publication",
        ),
        Mutation(
            "helper",
            "if uid <= 0 or gid <= 0:\n"
            '        fail("Flutter Pub-cache transaction refuses UID or primary GID zero")',
            "if False:\n"
            '        fail("Flutter Pub-cache transaction refuses UID or primary GID zero")',
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
            "if member.pax_headers:",
            "if False:",
            "member PAX refusal",
        ),
        Mutation(
            "helper",
            "if actual != expected:",
            "if False:",
            "complete logical contract",
        ),
        Mutation(
            "helper",
            "HOSTED_LOCK_RECORDS = 95",
            "HOSTED_LOCK_RECORDS = 94",
            "exact hosted lock record count",
        ),
        Mutation(
            "helper",
            'if hash_bytes != record.sha256.encode("ascii"):',
            "if False:",
            "lock-to-cache hash equality",
        ),
        Mutation(
            "helper",
            'paths = {"hosted", "hosted/pub.dev", "hosted-hashes", "hosted-hashes/pub.dev"}',
            'paths = {"hosted", "hosted/pub.dev", "hosted/pub.dev/.cache", "hosted-hashes", "hosted-hashes/pub.dev"}',
            "metadata-free projection roots",
        ),
        Mutation(
            "helper",
            'mutable[100:108] = b"0000754\\0"',
            'mutable[100:108] = b"0000755\\0"',
            "special archive modes",
        ),
        Mutation(
            "helper",
            "if patched != SPECIAL_MODES:",
            "if False:",
            "complete special-mode inventory",
        ),
        Mutation(
            "helper",
            "if total + len(block) > expected_size:",
            "if False:",
            "bounded writer ceiling",
        ),
        Mutation(
            "helper",
            "RENAME_NOREPLACE = 1",
            "RENAME_NOREPLACE = 0",
            "no-clobber publication",
        ),
        Mutation(
            "pins",
            'SIZE_FLUTTER_PUB_CACHE="18771131"',
            'SIZE_FLUTTER_PUB_CACHE="18771132"',
            "exact compressed size",
        ),
        Mutation(
            "verify",
            "/usr/bin/python3 -I -S scripts/verify-online-fetch-flutter-pub-cache-output-authority.py --repo . --self-test",
            "true # Flutter Pub-cache focused gate removed",
            "focused verifier wiring",
        ),
        Mutation(
            "requirements",
            '<span class="id">R-S11cy</span>',
            '<span class="id">R-S11cy-disabled</span>',
            "normative requirement",
        ),
        Mutation(
            "requirements",
            "<tr><td>252</td>",
            "<tr><td>252-disabled</td>",
            "Appendix C row",
        ),
        Mutation(
            "hardening",
            "R-S11cy/R-S11e-117 — exact Windows flutter_tools Pub-cache acquisition-output authority",
            "R-S11cy/R-S11e-117 — ambient Flutter Pub-cache output authority",
            "hardening ledger",
        ),
    )


def load_sources(repo: pathlib.Path) -> Dict[str, str]:
    return {
        "shell": (repo / "scripts/online-fetch.sh").read_text(encoding="utf-8"),
        "helper": (
            repo / "scripts/online-flutter-pub-cache-output.py"
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
        if original.count(mutation.old) != 1:
            raise AuthorityError(
                f"mutation source cardinality differs for {mutation.label}"
            )
        changed = dict(sources)
        changed[mutation.source] = original.replace(mutation.old, mutation.new, 1)
        try:
            validate(changed)
        except AuthorityError:
            checked += 1
        else:
            raise AuthorityError(f"mutation survived: {mutation.label}")
    if checked != len(mutations()):
        raise AuthorityError("not every Flutter Pub-cache mutation was exercised")
    print(
        "verify-online-fetch-flutter-pub-cache-output-authority: "
        f"{checked} mutations rejected"
    )


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
            "verify-online-fetch-flutter-pub-cache-output-authority: "
            f"FAIL: {error}"
        )
        return 1
    print("verify-online-fetch-flutter-pub-cache-output-authority: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
