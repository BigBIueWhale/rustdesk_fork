#!/usr/bin/env python3
"""Validate the networked Gradle warmer's output/publication authority."""

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


def require_absent(source: str, token: str, label: str) -> None:
    if token in source:
        raise AuthorityError("forbidden {} remains: {!r}".format(label, token))


def require_count(source: str, token: str, expected: int, label: str) -> None:
    actual = source.count(token)
    if actual != expected:
        raise AuthorityError(
            "{} count is {}, expected {}: {!r}".format(label, actual, expected, token)
        )


def require_order(source: str, tokens: Tuple[str, ...], label: str) -> None:
    position = -1
    for token in tokens:
        found = source.find(token, position + 1)
        if found < 0:
            raise AuthorityError("{} is missing ordered token {!r}".format(label, token))
        position = found


def extract_between(source: str, start: str, end: str, label: str) -> str:
    begin = source.find(start)
    if begin < 0:
        raise AuthorityError("{} start is absent".format(label))
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


def validate(sources: Dict[str, str]) -> None:
    shell = sources["shell"]
    helper = sources["helper"]
    android = sources["android"]
    pins = sources["pins"]
    wrapper = sources["wrapper"]
    verify = sources["verify"]
    requirements = sources["requirements"]
    hardening = sources["hardening"]
    workspace = sources["workspace"]
    try:
        ast.parse(helper)
    except SyntaxError as error:
        raise AuthorityError("Gradle output helper does not parse: {}".format(error)) from error

    for token, label in (
        ("readonly FLOCK_BIN=/usr/bin/flock", "fixed transaction-lock client"),
        ('/usr/bin/chmod 0700 "$ONLINE_DIR"', "existing online-root normalization"),
        ('/usr/bin/install -d -m 0700 "$ONLINE_DIR"', "new online-root construction"),
        ('"$ONLINE_FETCH_UID:$ONLINE_FETCH_GID:700"', "private online-root postcondition"),
        ("gradle_output_tool() {", "exact-source output helper"),
        ("recover_gradle_output_staging() {", "reserved-state recovery"),
        ("prepare_gradle_output_staging() {", "same-filesystem staging preparation"),
        ('"$ONLINE_DIR/.rustdesk-gradle-warm.XXXXXXXXXX"', "unpredictable staging namespace"),
        ("restore_gradle_output_traversal() {", "private output traversal restoration"),
        ('"$FLOCK_BIN" --exclusive --nonblock "$lock_fd"', "exclusive output transaction"),
        ("--env RUSTDESK_GRADLE_WARM_HOME=/outputs/gradle-home", "exact Gradle output"),
        ("--env RUSTDESK_ANDROID_SDK_HOME=/outputs/android-sdk", "exact SDK output"),
        ("target=/online,readonly,bind-recursive=disabled", "read-only nonrecursive input"),
        ('source=$GRADLE_OUTPUT_STAGING/gradle-home,target=/outputs/gradle-home',
         "narrow Gradle writable mount"),
        ('source=$GRADLE_OUTPUT_STAGING/android-sdk,target=/outputs/android-sdk',
         "narrow SDK writable mount"),
        ("gradle_output_tool verify", "output postcondition"),
        ("gradle_output_tool publish", "checked output publication"),
        ("retire_gradle_output_staging", "private output retirement"),
        ('[ "$status" -eq 0 ] && [ "$source_status" -eq 0 ] && [ "$output_status" -eq 0 ]',
         "three-verdict publication barrier"),
    ):
        require(shell, token, label)
    stage = extract_between(
        shell,
        "stage_gradle() {",
        "\n}\n\n# ── The windows flutter ENGINE",
        "Gradle output lifecycle",
    )
    require_count(stage, "target=/online", 1, "Gradle online input mount")
    require_count(stage, "target=/outputs/gradle-home", 1, "Gradle cache output mount")
    require_count(stage, "target=/outputs/android-sdk", 1, "Android SDK output mount")
    require_absent(
        stage,
        'source=$ONLINE_DIR,target=/online"',
        "broad writable online mount",
    )
    require_order(
        stage,
        (
            '"$FLOCK_BIN" --exclusive --nonblock "$lock_fd"',
            "prepare_gradle_source",
            "recover_gradle_output_staging",
            "check-complete",
            "prepare_gradle_output_staging",
            "online_docker_run",
            "(verify_gradle_source_unchanged) || source_status=$?",
            "restore_gradle_output_traversal",
            "gradle_output_tool verify",
            "gradle_output_tool publish",
            "retire_gradle_output_staging",
            '"$FLOCK_BIN" --unlock "$lock_fd"',
        ),
        "Gradle output transaction",
    )

    for token, label in (
        ('[ "${RUSTDESK_GRADLE_WARM_HOME:-}" = /outputs/gradle-home ]',
         "warm Gradle output contract"),
        ('[ "${RUSTDESK_ANDROID_SDK_HOME:-}" = /outputs/android-sdk ]',
         "warm SDK output contract"),
        ('[ -z "${RUSTDESK_GRADLE_WARM_HOME+x}" ]',
         "non-warm Gradle output rejection"),
        ('[ -z "${RUSTDESK_ANDROID_SDK_HOME+x}" ]',
         "non-warm SDK output rejection"),
        ('ANDROID_BUILD_SDK="$RUSTDESK_ANDROID_SDK_HOME"',
         "warm SDK selection"),
        ("ANDROID_BUILD_SDK=/online/android-sdk", "read-only ordinary SDK selection"),
        ('export GRADLE_USER_HOME="$RUSTDESK_GRADLE_WARM_HOME"',
         "private Gradle user home"),
        ('export ANDROID_SDK_ROOT="$ANDROID_BUILD_SDK" ANDROID_HOME="$ANDROID_BUILD_SDK"',
         "private SDK environment"),
        ("export PUB_CACHE=/online/pub-cache", "read-only Pub input"),
    ):
        require(android, token, label)

    wrapper_pin = pin_value(pins, "SHA256_ANDROID_GRADLE_WRAPPER_ALL")
    wrapper_matches = re.findall(r"^distributionSha256Sum=([0-9a-f]{64})$", wrapper, re.MULTILINE)
    if wrapper_matches != [wrapper_pin]:
        raise AuthorityError("Gradle wrapper property does not exactly match its independent pin")
    require(
        wrapper,
        "distributionUrl=https\\://services.gradle.org/distributions/gradle-7.6.4-all.zip",
        "pinned complete Gradle distribution URL",
    )

    for token, label in (
        ("STATE_NAME = \".rustdesk-gradle-output-state-v1\"", "bounded transaction record"),
        ("GRADLE_LIMITS = (100_000, 100_000, 12 * 1024**3, 2 * 1024**3)",
         "Gradle output bounds"),
        ("SDK_LIMITS = (100_000, 100_000, 4 * 1024**3, 2 * 1024**3)",
         "SDK output bounds"),
        ("reject_descendant_mounts(canonical)", "descendant-mount rejection"),
        ("os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW", "no-follow file reads"),
        ("stable_metadata(before) != stable_metadata(after)", "stable file read"),
        ("if metadata.st_nlink != 1:\n"
         '                    fail(f"output file is multiply linked: {child_relative}")',
         "external-hardlink rejection"),
        ("output tree contains a symlink", "symlink rejection"),
        ("output tree contains a special file", "special-file rejection"),
        ("output tree has foreign ownership", "owner rejection"),
        ("output file is group/world writable", "writable-file rejection"),
        ("sdk_source_digest", "live SDK digest binding"),
        ("live Android SDK changed while the networked producer ran",
         "live SDK postcondition"),
        ("Gradle dependency module cache is absent", "dependency-cache semantic gate"),
        ("exactly one pinned distribution archive", "single wrapper archive"),
        ("if digest.hexdigest() != gradle_sha256:",
         "publisher checksum comparison"),
        ("publisher pin", "publisher checksum gate"),
        ('for name in ("aapt2", "apksigner", "zipalign"):\n'
         "        require_file(tools / name, executable=True, nonempty=True)",
         "SDK build-tools gate"),
        ('require_file(platform / "android.jar", nonempty=True)',
         "compile SDK gate"),
        ("sync_tree(staging / \"android-sdk\")", "SDK durability barrier"),
        ("sync_tree(staging / \"gradle-home\")", "Gradle durability barrier"),
        ("RENAME_EXCHANGE = 2", "atomic SDK exchange"),
        ("RENAME_NOREPLACE = 1", "no-clobber Gradle publication"),
        ("rollback_publication(online_fd, staging_fd, sdk_swapped, gradle_moved)",
         "publication rollback"),
        ('return "sdk-rolled-back"', "SDK-only restart rollback"),
        ('return "published"', "completed restart classification"),
        ("state is incoherent and was preserved", "ambiguous-state refusal"),
        ("self-test did not roll back an SDK-only publication",
         "SDK-only recovery fixture"),
        ("self-test accepted an occupied Gradle publication destination",
         "destination-race fixture"),
        ("self-test accepted a wrong Gradle distribution checksum",
         "checksum negative fixture"),
        ("self-test accepted a symlinked output", "symlink negative fixture"),
    ):
        require(helper, token, label)
    require_order(
        helper,
        (
            "verify_staged(",
            'sync_tree(staging / "android-sdk")',
            'renameat2(staging_fd, "android-sdk", online_fd, "android-sdk", RENAME_EXCHANGE)',
            'renameat2(staging_fd, "gradle-home", online_fd, "gradle-home", RENAME_NOREPLACE)',
            "published Android SDK identity postcondition failed",
            "published Gradle identity postcondition failed",
            "validate_semantics(",
        ),
        "checked two-name publication",
    )

    require(
        verify,
        "/usr/bin/python3 -I -S scripts/verify-online-fetch-gradle-output-authority.py --repo . --self-test",
        "shared focused-verifier wiring",
    )
    require(requirements, '<span class="id">R-S11cl</span>', "R-S11cl requirement")
    require(requirements, "<tr><td>231</td>", "Appendix C #231 disposition")
    require(
        hardening,
        "R-S11cl/R-S11e-104 — networked Gradle acquisition-output authority",
        "hardening-ledger disposition",
    )
    require(
        workspace,
        '"online_fetch_gradle_output_authority_verifier"',
        "workspace-verifier source ownership",
    )
    require(
        workspace,
        "Online-fetch Gradle output authority focused verifier",
        "workspace-verifier semantic binding",
    )


MUTATIONS: Tuple[Mutation, ...] = (
    Mutation("shell", '/usr/bin/chmod 0700 "$ONLINE_DIR"',
             '/usr/bin/chmod 0775 "$ONLINE_DIR"', "private online root"),
    Mutation(
        "shell",
        '"$FLOCK_BIN" --exclusive --nonblock "$lock_fd" \\\n'
        '        || die "another Gradle output transaction already owns the online root"',
        "true # Gradle output transaction unlocked",
        "exclusive transaction lock",
    ),
    Mutation(
        "shell",
        '--mount "type=bind,source=$ONLINE_DIR,target=/online,readonly,bind-recursive=disabled" \\\n'
        '        --mount "type=bind,source=$GRADLE_OUTPUT_STAGING/gradle-home,target=/outputs/gradle-home"',
        '--mount "type=bind,source=$ONLINE_DIR,target=/online" \\\n'
        '        --mount "type=bind,source=$GRADLE_OUTPUT_STAGING/gradle-home,target=/outputs/gradle-home"',
        "read-only online input",
    ),
    Mutation("shell", 'source=$GRADLE_OUTPUT_STAGING/gradle-home,target=/outputs/gradle-home',
             'source=$ONLINE_DIR,target=/outputs/gradle-home', "narrow Gradle output"),
    Mutation("shell", 'source=$GRADLE_OUTPUT_STAGING/android-sdk,target=/outputs/android-sdk',
             'source=$ONLINE_DIR,target=/outputs/android-sdk', "narrow SDK output"),
    Mutation("shell", "recover_gradle_output_staging\n    mapfile",
             "true # stale state ignored\n    mapfile", "preflight recovery"),
    Mutation("shell", "gradle_output_tool verify \\\n",
             "gradle_output_tool accept \\\n", "output postcondition"),
    Mutation("shell",
             '[ "$status" -eq 0 ] && [ "$source_status" -eq 0 ] && [ "$output_status" -eq 0 ]',
             '[ "$status" -eq 0 ]', "publication barrier"),
    Mutation("android", '[ "${RUSTDESK_GRADLE_WARM_HOME:-}" = /outputs/gradle-home ]',
             '[ -n "${RUSTDESK_GRADLE_WARM_HOME:-}" ]', "exact warm Gradle output"),
    Mutation("android", '[ "${RUSTDESK_ANDROID_SDK_HOME:-}" = /outputs/android-sdk ]',
             '[ -n "${RUSTDESK_ANDROID_SDK_HOME:-}" ]', "exact warm SDK output"),
    Mutation("android", '[ -z "${RUSTDESK_ANDROID_SDK_HOME+x}" ]',
             "true # non-warm SDK override accepted", "non-warm override rejection"),
    Mutation("wrapper", "distributionSha256Sum=", "disabledDistributionSha256Sum=",
             "wrapper publisher checksum"),
    Mutation("pins", "SHA256_ANDROID_GRADLE_WRAPPER_ALL=",
             "SHA256_ANDROID_GRADLE_WRAPPER_DISABLED=", "independent wrapper pin"),
    Mutation("helper", "reject_descendant_mounts(canonical)",
             "return # descendant mounts accepted", "mount-closure enforcement"),
    Mutation(
        "helper",
        "if metadata.st_nlink != 1:\n"
        '                    fail(f"output file is multiply linked: {child_relative}")',
        "if metadata.st_nlink < 1:\n"
        '                    fail(f"output file is multiply linked: {child_relative}")',
        "hardlink rejection",
    ),
    Mutation("helper", "output tree contains a symlink",
             "symlinked output accepted", "symlink rejection"),
    Mutation("helper", "output tree contains a special file",
             "special output accepted", "special-file rejection"),
    Mutation("helper", "live Android SDK changed while the networked producer ran",
             "live SDK mutation accepted", "live input postcondition"),
    Mutation("helper", "digest.hexdigest() != gradle_sha256",
             "False", "publisher checksum validation"),
    Mutation(
        "helper",
        'for name in ("aapt2", "apksigner", "zipalign"):\n'
        "        require_file(tools / name, executable=True, nonempty=True)",
        'for name in ("aapt2",):\n'
        "        require_file(tools / name, executable=True, nonempty=True)",
        "SDK semantic closure",
    ),
    Mutation("helper", 'sync_tree(staging / "android-sdk")',
             "pass # SDK not synchronized", "SDK durability barrier"),
    Mutation("helper", 'sync_tree(staging / "gradle-home")',
             "pass # Gradle not synchronized", "Gradle durability barrier"),
    Mutation(
        "helper",
        'renameat2(staging_fd, "android-sdk", online_fd, "android-sdk", RENAME_EXCHANGE)\n'
        "        sdk_swapped = True",
        'os.replace(staging / "android-sdk", online / "android-sdk")\n'
        "        sdk_swapped = True",
        "atomic SDK exchange",
    ),
    Mutation("helper", 'renameat2(staging_fd, "gradle-home", online_fd, "gradle-home", RENAME_NOREPLACE)',
             'os.replace(staging / "gradle-home", online / "gradle-home")',
             "no-clobber Gradle publication"),
    Mutation("helper", "rollback_publication(online_fd, staging_fd, sdk_swapped, gradle_moved)",
             "pass # rollback omitted", "publication rollback"),
    Mutation("helper", 'return "sdk-rolled-back"', 'return "published"',
             "SDK-only restart rollback"),
    Mutation("verify",
             "/usr/bin/python3 -I -S scripts/verify-online-fetch-gradle-output-authority.py --repo . --self-test",
             "true # Gradle output authority gate removed", "shared verifier wiring"),
    Mutation("requirements", '<span class="id">R-S11cl</span>',
             '<span class="id">R-S11cl-disabled</span>', "R-S11cl requirement"),
    Mutation("requirements", "<tr><td>231</td>", "<tr><td>231-disabled</td>",
             "Appendix C #231 disposition"),
    Mutation("hardening",
             "R-S11cl/R-S11e-104 — networked Gradle acquisition-output authority",
             "R-S11cl/R-S11e-104 — ambient Gradle output authority",
             "hardening disposition"),
)


def load_sources(repo: pathlib.Path) -> Dict[str, str]:
    return {
        "shell": (repo / "scripts/online-fetch.sh").read_text(encoding="utf-8"),
        "helper": (repo / "scripts/online-gradle-output.py").read_text(encoding="utf-8"),
        "android": (repo / "scripts/android-apk-build.sh").read_text(encoding="utf-8"),
        "pins": (repo / "scripts/pins.env").read_text(encoding="utf-8"),
        "wrapper": (
            repo / "flutter/android/gradle/wrapper/gradle-wrapper.properties"
        ).read_text(encoding="utf-8"),
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
                "mutation target for {} occurs {} times".format(mutation.label, count)
            )
        changed = dict(sources)
        changed[mutation.source] = original.replace(mutation.old, mutation.new, 1)
        try:
            validate(changed)
        except AuthorityError:
            continue
        raise AuthorityError("mutation was accepted: {}".format(mutation.label))


def main() -> int:
    value = argparse.ArgumentParser()
    value.add_argument("--repo", type=pathlib.Path, default=pathlib.Path("."))
    value.add_argument("--self-test", action="store_true")
    arguments = value.parse_args()
    sources = load_sources(arguments.repo.resolve())
    validate(sources)
    if arguments.self_test:
        run_mutations(sources)
        print(
            "verify-online-fetch-gradle-output-authority: PASS "
            "({} mutations rejected)".format(len(MUTATIONS))
        )
    else:
        print("verify-online-fetch-gradle-output-authority: PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, AuthorityError) as error:
        raise SystemExit("verify-online-fetch-gradle-output-authority: {}".format(error))
