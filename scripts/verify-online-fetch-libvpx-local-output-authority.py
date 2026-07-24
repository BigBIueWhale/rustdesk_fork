#!/usr/bin/env python3
"""Bind committed libvpx patch/native-key source and publication authority."""

from __future__ import annotations

import argparse
import copy
import re
from pathlib import Path
from typing import Mapping, Tuple


class VerificationError(RuntimeError):
    pass


def require_text(source: str, text: str, label: str) -> None:
    if text not in source:
        raise VerificationError(f"{label}: required contract is absent")


def require_absent(source: str, text: str, label: str) -> None:
    if text in source:
        raise VerificationError(f"{label}: forbidden legacy authority remains")


def require_exact_count(source: str, text: str, count: int, label: str) -> None:
    actual = source.count(text)
    if actual != count:
        raise VerificationError(f"{label}: expected {count}, got {actual}")


def require_order(source: str, tokens: Tuple[str, ...], label: str) -> None:
    cursor = 0
    for token in tokens:
        position = source.find(token, cursor)
        if position < 0:
            raise VerificationError(f"{label}: ordered token is absent: {token}")
        cursor = position + len(token)


def extract_between(source: str, start: str, end: str, label: str) -> str:
    begin = source.find(start)
    if begin < 0:
        raise VerificationError(f"{label}: start anchor is absent")
    finish = source.find(end, begin + len(start))
    if finish < 0:
        raise VerificationError(f"{label}: end anchor is absent")
    return source[begin:finish]


def validate(sources: Mapping[str, str]) -> None:
    online = sources["online"]
    helper = sources["helper"]
    verify = sources["verify"]
    requirements = sources["requirements"]
    hardening = sources["hardening"]

    for text, label in (
        (
            "online_source_git rev-parse --git-path info/grafts",
            "Git graft-state authority",
        ),
        (
            "if [ -e \"$grafts\" ] || [ -L \"$grafts\" ]; then",
            "Git graft-state refusal",
        ),
        (
            "online_source_git for-each-ref --format='%(refname)' refs/replace",
            "Git replacement-ref authority",
        ),
        (
            "Git replacement refs are forbidden",
            "Git replacement-ref refusal",
        ),
    ):
        require_text(online, text, label)

    source_authority = extract_between(
        online,
        "libvpx_live_native_key() {",
        "\n}\n\nvcpkg_native_output_key()",
        "committed libvpx source authority",
    )
    for text, label in (
        (
            "online_source_git ls-tree -rz --full-tree",
            "committed subtree enumeration",
        ),
        (
            "online_source_git cat-file blob",
            "committed blob-byte hashing",
        ),
        (
            "committed libvpx source contains a symlink, submodule, or special entry",
            "committed tree type closure",
        ),
        (
            "verify_clean_live_checkout_state",
            "clean committed checkout proof",
        ),
        (
            "online_source_git hash-object --no-filters",
            "worktree-to-blob equality",
        ),
        (
            "LIBVPX_SOURCE_AUTHORITY_NATIVE_KEY",
            "retained exact native key",
        ),
        (
            "verify_libvpx_source_authority() {",
            "source postcondition function",
        ),
        (
            "live libvpx input key changed",
            "whole-subtree postcondition",
        ),
    ):
        require_text(source_authority, text, label)
    require_exact_count(
        source_authority,
        "verify_clean_live_checkout_state",
        2,
        "clean committed checkout proof",
    )
    require_order(
        source_authority,
        (
            "verify_clean_live_checkout_state",
            "online_source_git ls-tree --full-tree",
            "online_source_git hash-object --no-filters",
            "libvpx_native_key_for_commit",
            "libvpx_live_native_key",
        ),
        "committed source derivation order",
    )

    lifecycle = extract_between(
        online,
        "stage_libvpx_distfiles() {",
        "\n}\n\nlibyuv_distfile_output_tool()",
        "libvpx local-output lifecycle",
    )
    require_order(
        lifecycle,
        (
            "stage_vcpkg_fixed_archives",
            "prepare_libvpx_source_authority",
            '"$FLOCK_BIN" --exclusive --nonblock "$lock_fd"',
            '"$LIBVPX_LOCAL_OUTPUT_HELPER" publish',
            '"$FLOCK_BIN" --unlock "$lock_fd"',
            "verify_libvpx_source_authority",
            "require_libvpx_distfiles",
        ),
        "libvpx local-output lifecycle order",
    )
    for text, label in (
        (
            "--source-patch "
            '"$REPO_ROOT/res/vcpkg/libvpx/0005-cve-2026-1861.patch"',
            "exact committed patch source",
        ),
        ("--patch-sha512", "patch publisher hash"),
        ("--native-key", "native-key publisher input"),
        ("--source-commit", "publisher source commit"),
        ("--source-tree", "publisher source tree"),
        ("--source-blob", "publisher patch blob"),
        ("complete | published", "closed helper dispositions"),
    ):
        require_text(lifecycle, text, label)
    for text, label in (
        (".patch.part", "predictable patch temporary"),
        ("libvpx-native-key.txt.part", "predictable key temporary"),
        ('cp "$committed_patch"', "path-copy publisher"),
        ('mv "$vpx_dir/', "overwrite-capable publisher"),
    ):
        require_absent(lifecycle, text, label)

    consumer = extract_between(
        online,
        "require_libvpx_distfiles() {",
        "\n}\n\nrequire_libyuv_distfile()",
        "libvpx local-output consumer",
    )
    require_order(
        consumer,
        (
            "verify_libvpx_source_authority",
            '"$LIBVPX_LOCAL_OUTPUT_HELPER" check',
        ),
        "consumer source and output proof",
    )
    require_absent(consumer, "cat \"$dir/libvpx-native-key", "path-read key verdict")
    require_absent(
        consumer,
        'sha512sum "$dir/libvpx-${LIBVPX_FIX_COMMIT}.patch"',
        "path-read patch verdict",
    )

    for function, label in (
        ("stage_vcpkg_natives() {", "x64-linux source postcondition"),
        ("stage_vcpkg_natives_arm64() {", "arm64-android source postcondition"),
    ):
        block = extract_between(
            online,
            function,
            "\n}\n",
            label,
        )
        require_text(
            block,
            "local status=0 source_status=0 output_status=0 publication_status=0",
            f"{label} status",
        )
        require_order(
            block,
            (
                "online_docker_run",
                "verify_libvpx_source_authority",
                "vcpkg_native_output_tool verify",
                'if [ "$status" -eq 0 ] && [ "$source_status" -eq 0 ]',
                "vcpkg_native_output_tool publish",
            ),
            f"{label} publication barrier",
        )

    for text, label in (
        ('FORMAT = "rustdesk-libvpx-local-output-v1"', "state format"),
        (
            'PATCH_SOURCE_RELATIVE = Path("res/vcpkg/libvpx/0005-cve-2026-1861.patch")',
            "exact source path",
        ),
        (
            'if uid == 0 or gid == 0 or (os.geteuid(), os.getegid()) != (uid, gid):',
            "non-root exact identity",
        ),
        (
            "descriptor = os.open(\n"
            "        source_patch,\n"
            "        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,",
            "no-follow descriptor policy",
        ),
        (
            "descriptor = os.open(\n"
            "            name,\n"
            "            os.O_WRONLY | os.O_CREAT | os.O_EXCL | "
            "os.O_CLOEXEC | os.O_NOFOLLOW,",
            "exclusive candidate creation",
        ),
        ("stable_file_metadata(before)", "stable descriptor read"),
        (
            "if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:",
            "external-hardlink refusal",
        ),
        ("os.listxattr(descriptor)", "file xattr refusal"),
        ("reject_mount_at_or_below(staging)", "staging mount closure"),
        ("RENAME_NOREPLACE = 1", "no-clobber primitive"),
        ("os.fsync(staging_fd)", "staging durability"),
        ("os.fsync(distfiles_fd)", "destination durability"),
        (
            'if [record["kind"] for record in records] != ["patch", "key"]:',
            "patch-before-key state order",
        ),
        ("for record in records:\n                    publish_record(", "patch-before-key publication"),
        ("recover_staging(", "restart reconciliation"),
        (
            "reserved libvpx local-output staging remains unreconciled",
            "read-only consumer ambiguity refusal",
        ),
        (
            'state["source_commit"] != source_commit',
            "recorded source-authority equality",
        ),
        (
            "without_identity != expected_without_identity",
            "recorded byte-authority equality",
        ),
        (
            "current_state, current_identity = read_state(staging_fd)",
            "stable state retirement recheck",
        ),
        (
            "or edge.st_nlink != 1",
            "retirement hardlink recheck",
        ),
        (
            "self-test overwrote an occupied wrong libvpx destination",
            "wrong-destination no-clobber fixture",
        ),
        (
            "self-test accepted a symlinked stale local-output entry",
            "symlinked-staging fixture",
        ),
        (
            "self-test accepted externally hardlinked stale local-output state",
            "hardlink-staging fixture",
        ),
        (
            "self-test accepted a symlinked committed patch source",
            "symlinked-source fixture",
        ),
        (
            "self-test replaced an exact occupied libvpx local output",
            "exact-reuse inode fixture",
        ),
        (
            "self-test accepted unreconciled state in the read-only consumer",
            "read-only unresolved-state fixture",
        ),
        (
            "self-test accepted recorded staging from a different source authority",
            "recorded source-authority fixture",
        ),
    ):
        require_text(helper, text, label)
    require_exact_count(
        helper,
        "RENAME_NOREPLACE = 1",
        1,
        "sole no-clobber flag definition",
    )
    require_exact_count(
        helper,
        "reject_mount_at_or_below(staging)",
        2,
        "staging mount closure",
    )
    require_absent(helper, "os.replace(", "overwrite-capable helper publication")
    require_absent(helper, "shutil.copy", "path-copy helper publication")

    for text, label in (
        (
            "/usr/bin/python3 -I -S scripts/online-libvpx-local-output.py self-test",
            "transaction self-test wiring",
        ),
        (
            "/usr/bin/python3 -I -S "
            "scripts/verify-online-fetch-libvpx-local-output-authority.py "
            "--repo . --self-test",
            "focused verifier wiring",
        ),
    ):
        require_text(verify, text, label)
    require_text(
        requirements,
        '<span class="id">R-S11cv</span>',
        "normative local-output requirement",
    )
    require_text(
        requirements,
        "<tr><td>249</td>",
        "local-output Appendix C row",
    )
    require_text(
        hardening,
        "R-S11cv/R-S11e-114 — committed libvpx patch and native-key publication authority",
        "local-output hardening ledger",
    )


Mutation = Tuple[str, str, str, str]
MUTATIONS: Tuple[Mutation, ...] = (
    (
        "online",
        "online_source_git cat-file blob",
        "online_source_git show",
        "committed blob-byte hashing",
    ),
    (
        "online",
        'verify_clean_live_checkout_state "before committed libvpx local publication"',
        'true # clean source proof removed "before committed libvpx local publication"',
        "clean committed checkout proof",
    ),
    (
        "online",
        "online_source_git rev-parse --git-path info/grafts",
        "true # Git graft authority removed",
        "Git graft-state authority",
    ),
    (
        "online",
        "online_source_git for-each-ref --format='%(refname)' refs/replace",
        "true # Git replacement-ref authority removed",
        "Git replacement-ref authority",
    ),
    (
        "online",
        "online_source_git hash-object --no-filters",
        "online_source_git hash-object",
        "committed source derivation order",
    ),
    (
        "online",
        '"$FLOCK_BIN" --exclusive --nonblock "$lock_fd" \\\n'
        '        || die "another online-output transaction already owns the online root"',
        "true # libvpx local-output lock removed",
        "libvpx local-output lifecycle order",
    ),
    (
        "online",
        '"$LIBVPX_LOCAL_OUTPUT_HELPER" publish',
        '"$LIBVPX_LOCAL_OUTPUT_HELPER" check',
        "libvpx local-output lifecycle order",
    ),
    (
        "online",
        "verify_libvpx_source_authority \"after committed libvpx local publication\"",
        "true # committed source postcondition removed",
        "libvpx local-output lifecycle order",
    ),
    (
        "online",
        '"$LIBVPX_LOCAL_OUTPUT_HELPER" check',
        "true # local-output consumer gate removed",
        "consumer source and output proof",
    ),
    (
        "online",
        "local status=0 source_status=0 output_status=0 publication_status=0",
        "local status=0 output_status=0 publication_status=0",
        "x64-linux source postcondition status",
    ),
    (
        "online",
        "verify_libvpx_source_authority \"after arm64-android vcpkg native production\"",
        "true # arm64 source postcondition removed",
        "arm64-android source postcondition publication barrier",
    ),
    (
        "helper",
        'FORMAT = "rustdesk-libvpx-local-output-v1"',
        'FORMAT = "ambient-libvpx-output"',
        "state format",
    ),
    (
        "helper",
        "descriptor = os.open(\n"
        "        source_patch,\n"
        "        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,",
        "descriptor = os.open(\n"
        "        source_patch,\n"
        "        os.O_RDONLY | os.O_CLOEXEC,",
        "no-follow descriptor policy",
    ),
    (
        "helper",
        "descriptor = os.open(\n"
        "            name,\n"
        "            os.O_WRONLY | os.O_CREAT | os.O_EXCL | "
        "os.O_CLOEXEC | os.O_NOFOLLOW,",
        "descriptor = os.open(\n"
        "            name,\n"
        "            os.O_WRONLY | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW,",
        "exclusive candidate creation",
    ),
    (
        "helper",
        "if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:",
        "if not stat.S_ISREG(metadata.st_mode):",
        "external-hardlink refusal",
    ),
    (
        "helper",
        "reject_mount_at_or_below(staging)",
        "None # mount closure removed",
        "staging mount closure",
    ),
    (
        "helper",
        "RENAME_NOREPLACE = 1",
        "RENAME_NOREPLACE = 0",
        "no-clobber primitive",
    ),
    (
        "helper",
        'if [record["kind"] for record in records] != ["patch", "key"]:',
        'if [record["kind"] for record in records] != ["key", "patch"]:',
        "patch-before-key state order",
    ),
    (
        "helper",
        "reserved libvpx local-output staging remains unreconciled",
        "reserved state ignored",
        "read-only consumer ambiguity refusal",
    ),
    (
        "helper",
        'state["source_commit"] != source_commit',
        "False",
        "recorded source-authority equality",
    ),
    (
        "helper",
        "current_state, current_identity = read_state(staging_fd)",
        "current_state, current_identity = state, state_identity",
        "stable state retirement recheck",
    ),
    (
        "helper",
        "self-test overwrote an occupied wrong libvpx destination",
        "wrong destination accepted",
        "wrong-destination no-clobber fixture",
    ),
    (
        "helper",
        "self-test accepted a symlinked stale local-output entry",
        "symlinked state accepted",
        "symlinked-staging fixture",
    ),
    (
        "helper",
        "self-test accepted externally hardlinked stale local-output state",
        "hardlinked state accepted",
        "hardlink-staging fixture",
    ),
    (
        "helper",
        "self-test accepted recorded staging from a different source authority",
        "mismatched source authority accepted",
        "recorded source-authority fixture",
    ),
    (
        "verify",
        "/usr/bin/python3 -I -S scripts/online-libvpx-local-output.py self-test",
        "true # local-output transaction self-test removed",
        "transaction self-test wiring",
    ),
    (
        "requirements",
        '<span class="id">R-S11cv</span>',
        '<span class="id">R-S11cv-disabled</span>',
        "normative local-output requirement",
    ),
    (
        "requirements",
        "<tr><td>249</td>",
        "<tr><td>249-disabled</td>",
        "local-output Appendix C row",
    ),
    (
        "hardening",
        "R-S11cv/R-S11e-114 — committed libvpx patch and native-key publication authority",
        "R-S11cv/R-S11e-114 — ambient local publication authority",
        "local-output hardening ledger",
    ),
)


def run_mutations(sources: Mapping[str, str]) -> None:
    for key, old, new, expected in MUTATIONS:
        count = sources[key].count(old)
        if count < 1:
            raise VerificationError(
                f"mutation fixture source is absent for {expected}: {old}"
            )
        mutated = copy.copy(dict(sources))
        mutated[key] = sources[key].replace(old, new, 1)
        try:
            validate(mutated)
        except VerificationError as error:
            if expected not in str(error):
                raise VerificationError(
                    f"mutation for {expected} failed at the wrong contract: {error}"
                ) from error
        else:
            raise VerificationError(f"mutation escaped validation: {expected}")


def read_sources(repo: Path) -> dict[str, str]:
    return {
        "online": (repo / "scripts/online-fetch.sh").read_text(encoding="utf-8"),
        "helper": (
            repo / "scripts/online-libvpx-local-output.py"
        ).read_text(encoding="utf-8"),
        "verify": (repo / "scripts/verify.sh").read_text(encoding="utf-8"),
        "requirements": (repo / "requirements.html").read_text(encoding="utf-8"),
        "hardening": (repo / "HARDENING_STATUS.md").read_text(encoding="utf-8"),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path("."))
    parser.add_argument("--self-test", action="store_true")
    arguments = parser.parse_args()
    repo = arguments.repo.resolve()
    sources = read_sources(repo)
    validate(sources)
    if arguments.self_test:
        run_mutations(sources)
    print("verify-online-fetch-libvpx-local-output-authority: PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, UnicodeError, VerificationError) as error:
        print(f"FAIL: {error}")
        raise SystemExit(1)
