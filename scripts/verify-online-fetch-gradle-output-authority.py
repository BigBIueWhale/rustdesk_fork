#!/usr/bin/env python3
"""Validate the networked Gradle warmer's single-output authority."""

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


def extract_between(source: str, start: str, end: str, label: str) -> str:
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


def validate(sources: Dict[str, str]) -> None:
    shell = sources["shell"]
    helper = sources["helper"]
    android = sources["android"]
    pins = sources["pins"]
    wrapper = sources["wrapper"]
    projector = sources["projector"]
    try:
        ast.parse(helper)
    except SyntaxError as error:
        raise AuthorityError(
            "Gradle output helper does not parse: {}".format(error)
        ) from error

    publication = extract_between(
        helper,
        "def publish(",
        "\ndef optional_identity(",
        "Gradle one-name publication helper",
    )
    replacement = extract_between(
        helper,
        "def replace(",
        "\ndef validate_sdk_state(",
        "Gradle replacement helper",
    )
    replacement_finish = extract_between(
        helper,
        "def finish_promoted_replacement(",
        "\ndef replace(",
        "Gradle replacement finisher",
    )

    stage = extract_between(
        shell,
        "stage_gradle() {",
        "\n}\n\n# ── The windows flutter ENGINE",
        "Gradle output lifecycle",
    )
    for token, label in (
        ("readonly FLOCK_BIN=/usr/bin/flock", "fixed transaction-lock client"),
        ('/usr/bin/chmod 0700 "$ONLINE_DIR"', "private existing online root"),
        ('/usr/bin/install -d -m 0700 "$ONLINE_DIR"', "private new online root"),
        ("gradle_output_tool() {", "exact-source Gradle output helper"),
        ("recover_gradle_output_staging() {", "reserved-state recovery"),
        ("prepare_gradle_output_staging() {", "private staging preparation"),
        ('"$ONLINE_DIR/.rustdesk-gradle-warm.XXXXXXXXXX"', "unpredictable staging"),
        ("restore_gradle_output_traversal() {", "private traversal restoration"),
        ('"$FLOCK_BIN" --exclusive --nonblock "$lock_fd"', "exclusive transaction"),
        ("android_sdk_output_tool check-complete", "exact SDK precondition"),
        ("--env RUSTDESK_GRADLE_WARM_HOME=/outputs/gradle-home", "one exact output"),
        ("target=/online,readonly,bind-recursive=disabled", "read-only online input"),
        (
            "source=$GRADLE_OUTPUT_STAGING/gradle-home,target=/outputs/gradle-home",
            "narrow Gradle output",
        ),
        ("gradle_output_tool verify", "output postcondition"),
        ("gradle_output_tool publish", "checked publication"),
        ("gradle_output_tool replace", "checked stale-output replacement"),
        ("gradle_output_tool archive-replaced", "replacement-record archival"),
        ("prepare_retired_online_input_root", "retired-record root preparation"),
        ('--expected-digest "$digest"', "verified candidate digest binding"),
        (
            '            replace_existing=1\n'
            '            log "existing Gradle cache is stale or semantically incomplete; '
            'preparing one verified replacement"',
            "stale-cache replacement selection",
        ),
        (
            '    if [[ "$receipt" =~ ^sha256=([0-9a-f]{64})$ ]]; then\n'
            '        digest="${BASH_REMATCH[1]}"\n'
            '    else\n'
            '        output_status=1\n'
            '    fi',
            "candidate digest receipt",
        ),
        ("retire_gradle_output_staging", "private staging retirement"),
        (
            '[ "$status" -eq 0 ] && [ "$source_status" -eq 0 ] && '
            '[ "$output_status" -eq 0 ]',
            "three-verdict publication barrier",
        ),
    ):
        require(shell, token, label)
    require_count(stage, "target=/online", 1, "Gradle online input mount")
    require(
        stage,
        "--env RUSTDESK_GRADLE_WARM_HOME=/outputs/gradle-home \\\n"
        "        --mount "
        '"type=bind,source=$GRADLE_SOURCE_BUILD,target=/src" \\\n'
        "        --mount "
        '"type=bind,source=$GRADLE_SOURCE_AUTHORITY/scripts/'
        "android-apk-build.sh,target=/authority/android-apk-build.sh,readonly"
        '" \\\n'
        "        --mount "
        '"type=bind,source=$ONLINE_DIR,target=/online,readonly,'
        'bind-recursive=disabled"',
        "Gradle read-only input topology",
    )
    require_count(
        stage,
        "target=/outputs/gradle-home",
        1,
        "Gradle writable output mount",
    )
    forbid(stage, "target=/outputs/android-sdk", "writable Android SDK mount")
    forbid(stage, "--env RUSTDESK_ANDROID_SDK_HOME", "Android SDK redirection")
    forbid(stage, 'source=$ONLINE_DIR,target=/online"', "broad writable online mount")
    require_order(
        stage,
        (
            '"$FLOCK_BIN" --exclusive --nonblock "$lock_fd"',
            "prepare_gradle_source",
            "recover_gradle_output_staging",
            "android_sdk_output_tool check-complete",
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
        (
            '[ "${RUSTDESK_GRADLE_WARM_HOME:-}" = /outputs/gradle-home ]',
            "exact warm Gradle home",
        ),
        (
            '[ -z "${RUSTDESK_ANDROID_SDK_HOME+x}" ]',
            "SDK redirection rejection",
        ),
        (
            '[ -z "${RUSTDESK_ANDROID_SDK_HOME+x}" ] \\\n'
            '        || { echo "[FATAL] warm builds may not redirect the '
            'read-only Android SDK" >&2; exit 1; }',
            "warm SDK redirection rejection",
        ),
        ("ANDROID_BUILD_SDK=/online/android-sdk", "read-only SDK selection"),
        (
            'read-only Android SDK" >&2; exit 1; }\n'
            "    ANDROID_BUILD_SDK=/online/android-sdk\n"
            "else",
            "warm read-only SDK selection",
        ),
        (
            'export GRADLE_USER_HOME="$RUSTDESK_GRADLE_WARM_HOME"',
            "private Gradle home selection",
        ),
        (
            'export ANDROID_SDK_ROOT="$ANDROID_BUILD_SDK" '
            'ANDROID_HOME="$ANDROID_BUILD_SDK"',
            "read-only SDK environment",
        ),
        ("export PUB_CACHE=/online/pub-cache", "read-only Pub input"),
    ):
        require(android, token, label)
    forbid(
        android,
        'ANDROID_BUILD_SDK="$RUSTDESK_ANDROID_SDK_HOME"',
        "warm writable SDK selection",
    )

    wrapper_pin = pin_value(pins, "SHA256_ANDROID_GRADLE_WRAPPER_ALL")
    matches = re.findall(
        r"^distributionSha256Sum=([0-9a-f]{64})$",
        wrapper,
        re.MULTILINE,
    )
    if matches != [wrapper_pin]:
        raise AuthorityError(
            "Gradle wrapper checksum does not exactly match its independent pin"
        )
    for token, label in (
        ("SOURCE_DIRECTORY_MODE = 0o500", "offline seed directory mode"),
        ("SOURCE_FILE_MODES = {0o400, 0o500}", "offline seed file modes"),
    ):
        require(projector, token, label)
    require(
        wrapper,
        "distributionUrl=https\\://services.gradle.org/distributions/"
        "gradle-8.7-all.zip",
        "pinned complete Gradle distribution",
    )

    for token, label in (
        ('STATE_NAME = ".rustdesk-gradle-output-state-v3"', "current state schema"),
        ('LEGACY_STATE_NAME = ".rustdesk-gradle-output-state-v2"', "legacy state schema"),
        ("STATE_VERSION = 3", "state version"),
        ("LEGACY_STATE_VERSION = 2", "legacy state version"),
        (
            "GRADLE_LIMITS = (100_000, 100_000, 12 * 1024**3, 2 * 1024**3)",
            "Gradle output bounds",
        ),
        (
            "SDK_LIMITS = (100_000, 100_000, 4 * 1024**3, 2 * 1024**3)",
            "SDK input bounds",
        ),
        ("set(value) != current_keys", "closed current state schema"),
        ("set(value) != legacy_keys", "closed legacy state schema"),
        ("reject_descendant_mounts(canonical)", "descendant-mount rejection"),
        ("os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW", "no-follow reads"),
        ("stable_metadata(before) != stable_metadata(after)", "stable reads"),
        ("output file is multiply linked", "external-hardlink rejection"),
        ("output tree contains a symlink", "symlink rejection"),
        ("output tree contains a special file", "special-file rejection"),
        ("output tree has foreign ownership", "owner rejection"),
        ("output file is group/world writable", "mode rejection"),
        ("sdk_source_digest", "SDK content binding"),
        (
            "live Android SDK changed while the networked producer ran",
            "post-producer SDK content check",
        ),
        (
            "read-only Android SDK content postcondition failed",
            "post-publication SDK content check",
        ),
        (
            '    if summary.digest != state.get("sdk_source_digest"):\n'
            '        fail("Android SDK changed during Gradle output recovery")',
            "current recovery SDK content check",
        ),
        ("Gradle dependency module cache is absent", "module-cache semantics"),
        ("exactly one pinned distribution archive", "single wrapper archive"),
        ("digest.hexdigest() != gradle_sha256", "publisher checksum"),
        (
            'for name in ("aapt2", "apksigner", "zipalign")',
            "SDK build-tools semantics",
        ),
        (
            'require_property(tools / "source.properties", '
            '"Pkg.Revision", build_tools)\n'
            '    for name in ("aapt2", "apksigner", "zipalign"):\n'
            "        require_file(tools / name, executable=True, nonempty=True)",
            "SDK build-tools semantic closure",
        ),
        ('require_file(platform / "android.jar", nonempty=True)', "platform semantics"),
        ('sync_tree(staging / "gradle-home")', "Gradle durability"),
        (
            'sealed_summary = inspect_tree(\n'
            '        staging / "gradle-home",\n'
            '        owners={(uid, gid)},\n'
            '        limits=GRADLE_LIMITS,\n'
            '        hash_contents=True,\n'
            '        seal=True,\n'
            '        seal_root=False,',
            "sealed descendants before namespace publication",
        ),
        (
            'transition_root_mode(\n'
            '            online_fd,\n'
            '            "gradle-home",\n'
            '            staged_gradle_identity,\n'
            '            uid,\n'
            '            gid,\n'
            '            {0o700},\n'
            '            0o500,\n'
            '            "published Gradle",',
            "descriptor-bound published-root sealing",
        ),
        (
            'fail("published sealed Gradle tree postcondition failed")',
            "sealed published-tree postcondition",
        ),
        (
            'fail("Gradle publication candidate root is not mode 0700")',
            "renameable candidate-root policy",
        ),
        (
            'fail("self-test accepted a writable Gradle seed directory")',
            "writable seed-directory rejection fixture",
        ),
        (
            'fail("self-test accepted a writable Gradle seed file")',
            "writable seed-file rejection fixture",
        ),
        (
            'fail("self-test did not recover the post-rename/pre-root-seal state")',
            "interrupted root-seal recovery fixture",
        ),
        (
            'fail("self-test rollback did not restore unpublished transaction state")',
            "sealed-root rollback fixture",
        ),
        ("RENAME_NOREPLACE = 1", "no-clobber primitive"),
        ("RENAME_EXCHANGE = 2", "same-parent exchange primitive"),
        (
            '        "replaced_gradle_digest": replaced.digest,',
            "displaced full-content digest binding",
        ),
        (
            '            renameat2(\n'
            '                online_fd,\n'
            '                replacement_name,\n'
            '                online_fd,\n'
            '                "gradle-home",\n'
            '                RENAME_EXCHANGE,\n'
            '            )\n'
            '            exchanged = True',
            "same-parent replacement exchange",
        ),
        (
            '            renameat2(\n'
            '                online_fd,\n'
            '                "gradle-home",\n'
            '                online_fd,\n'
            '                replacement_name,\n'
            '                RENAME_EXCHANGE,\n'
            '            )',
            "old-first replacement rollback",
        ),
        (
            '        hash_contents=True,\n'
            '        expected_identity=expected_identity,\n'
            '    )\n'
            '    if summary.files == 0:',
            "displaced full-content validation",
        ),
        (
            '        renameat2(\n'
            '            online_fd,\n'
            '            staging.name,\n'
            '            retired_fd,\n'
            '            archive_name,\n'
            '            RENAME_NOREPLACE,\n'
            '        )',
            "replacement journal archival",
        ),
        (
            'renameat2(staging_fd, "gradle-home", online_fd, '
            '"gradle-home", RENAME_NOREPLACE)',
            "no-clobber publication",
        ),
        (
            "rollback_publication(\n"
            "                    online_fd,\n"
            "                    staging_fd,",
            "publication rollback",
        ),
        ('return "unpublished"', "unpublished recovery"),
        ('return "published"', "published recovery"),
        ('return "replacement-prepared"', "prepared replacement recovery"),
        ('return "replaced"', "completed replacement recovery"),
        (
            "state is incoherent and was preserved",
            "ambiguous-state refusal",
        ),
        (
            "self-test accepted a changed read-only Android SDK",
            "SDK mutation fixture",
        ),
        (
            "self-test accepted an occupied Gradle publication destination",
            "destination-race fixture",
        ),
        (
            "self-test accepted a wrong Gradle distribution checksum",
            "checksum fixture",
        ),
        ("self-test accepted a symlinked output", "symlink fixture"),
        (
            "self-test did not recover a promoted Gradle replacement",
            "promotion-crash recovery fixture",
        ),
        (
            "self-test did not recover a prepared Gradle replacement",
            "prepared-journal recovery fixture",
        ),
        (
            "self-test did not recover an exchanged Gradle replacement",
            "exchange-before-seal recovery fixture",
        ),
        (
            "self-test Gradle replacement rollback did not restore prepared state",
            "sealed-candidate rollback fixture",
        ),
        (
            "self-test replacement changed the displaced Gradle output",
            "displaced-output preservation fixture",
        ),
        (
            "retired Gradle archive identity postcondition failed",
            "replacement journal archival",
        ),
        (
            "previous_umask = os.umask(0o077)\n"
            "        try:\n"
            '            create_fake_sdk(online / "android-sdk", '
            "build_tools, compile_sdk)\n"
            "        finally:\n"
            "            os.umask(previous_umask)",
            "private SDK fixture umask scope",
        ),
    ):
        require(helper, token, label)
    require_count(
        helper,
        "require_sealed=True,",
        5,
        "complete/published/recovery sealed-tree checks",
    )
    require_count(
        helper,
        "seal_root=False,",
        5,
        "prepublication and recovery root-mode exceptions",
    )
    require_count(
        helper,
        "if sealed_summary.digest != expected_digest:",
        2,
        "sealed candidate digest checks",
    )
    for token, label in (
        ("staged_sdk_identity", "staged SDK identity"),
        ('sync_tree(staging / "android-sdk")', "SDK publication durability"),
        ('renameat2(staging_fd, "android-sdk"', "SDK publication"),
        ('require_file(sdk / "platform-tools" / "adb"', "unused adb requirement"),
        ("copy_tree(", "SDK cloning"),
        ("FICLONE", "SDK reflink cloning"),
    ):
        forbid(helper, token, label)
    require_order(
        publication,
        (
            "verify_staged(",
            'sealed_summary = inspect_tree(',
            'seal=True,',
            'if sealed_summary.digest != expected_digest:',
            'validate_semantics(',
            'sync_tree(staging / "gradle-home")',
            'fsync_directory(staging)',
            'state = record_new_publication(',
            'renameat2(staging_fd, "gradle-home", online_fd, '
            '"gradle-home", RENAME_NOREPLACE)',
            'transition_root_mode(',
            "read-only Android SDK identity postcondition failed",
            "read-only Android SDK content postcondition failed",
            "published Gradle identity postcondition failed",
            "validate_semantics(",
        ),
        "checked one-name publication",
    )
    require_order(
        replacement,
        (
            "verify_staged(",
            "validate_displaced_output(destination, uid, gid)",
            "validate_retired_root(online, retired_root, uid, gid)",
            "sealed_summary = inspect_tree(",
            "seal=True,",
            "if sealed_summary.digest != expected_digest:",
            "validate_semantics(",
            "sync_tree(output)",
            "fsync_directory(staging)",
            "state = record_replacement_publication(",
            "validate_displaced_output(\n        destination,",
            'fail("reserved replacement Gradle name is already occupied")',
            "validate_sdk_state(online, state, uid, gid)",
            "online_fd = open_directory(online)",
            "RENAME_NOREPLACE,",
            "finish_promoted_replacement(",
        ),
        "checked stale-output replacement",
    )
    require_count(
        replacement,
        "validate_sdk_state(online, state, uid, gid)",
        1,
        "replacement SDK full-content precondition",
    )
    require_count(
        replacement_finish,
        "validate_sdk_state(online, state, uid, gid)",
        1,
        "replacement SDK full-content postcondition",
    )
    require_order(
        replacement_finish,
        (
            "if not exchanged:",
            "RENAME_EXCHANGE,",
            '"replacement Gradle",',
            "validate_candidate_output(",
            "validate_displaced_output(",
            "validate_sdk_state(online, state, uid, gid)",
        ),
        "replacement SDK pre/post full-content closure",
    )

    require(
        sources["verify"],
        "/usr/bin/python3 -I -S "
        "scripts/verify-online-fetch-gradle-output-authority.py --repo . --self-test",
        "shared focused-verifier wiring",
    )
    require(
        sources["requirements"],
        '<span class="id">R-S11cl</span>',
        "R-S11cl requirement",
    )
    require(
        sources["requirements"],
        '<span class="id">R-S11cr</span>',
        "R-S11cr SDK requirement",
    )
    require(
        sources["requirements"],
        '<span class="id">R-S11fv</span>',
        "R-S11fv immutable Gradle seed requirement",
    )
    require(
        sources["requirements"],
        '<span class="id">R-S11fz</span>',
        "R-S11fz stale Gradle replacement requirement",
    )
    require(
        sources["requirements"],
        "<tr><td>245</td>",
        "Appendix C #245 disposition",
    )
    require(
        sources["requirements"],
        "<tr><td>330</td>",
        "Appendix C #330 disposition",
    )
    require(
        sources["requirements"],
        "<tr><td>334</td>",
        "Appendix C #334 disposition",
    )
    require(
        sources["hardening"],
        "R-S11cr/R-S11e-110 — exact Android SDK acquisition and publication authority",
        "hardening-ledger disposition",
    )
    require(
        sources["hardening"],
        "R-S11cl/R-S11e-104 umask-independent Gradle SDK fixture authority",
        "private SDK fixture correction ledger",
    )
    require(
        sources["hardening"],
        "R-S11fv/R-S11e-208 — Gradle publication/offline-seed mode closure",
        "Gradle seed mode-closure ledger",
    )
    require(
        sources["hardening"],
        "R-S11fz/R-S11e-212 — stale canonical Gradle-cache replacement authority",
        "stale Gradle replacement ledger",
    )
    require(
        sources["workspace"],
        '"online_fetch_gradle_output_authority_verifier"',
        "workspace source ownership",
    )
    require(
        sources["workspace"],
        "Online-fetch Gradle output authority focused verifier",
        "workspace semantic binding",
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
        "android_sdk_output_tool check-complete \\\n"
        '        --online "$ONLINE_DIR" "${sdk_args[@]}"',
        "true # exact SDK precondition omitted",
        "exact SDK precondition",
    ),
    Mutation(
        "shell",
        "--env RUSTDESK_GRADLE_WARM_HOME=/outputs/gradle-home \\\n"
        "        --mount "
        '"type=bind,source=$GRADLE_SOURCE_BUILD,target=/src" \\\n'
        "        --mount "
        '"type=bind,source=$GRADLE_SOURCE_AUTHORITY/scripts/'
        "android-apk-build.sh,target=/authority/android-apk-build.sh,readonly"
        '" \\\n'
        "        --mount "
        '"type=bind,source=$ONLINE_DIR,target=/online,readonly,'
        'bind-recursive=disabled"',
        "--env RUSTDESK_GRADLE_WARM_HOME=/outputs/gradle-home \\\n"
        "        --mount "
        '"type=bind,source=$GRADLE_SOURCE_BUILD,target=/src" \\\n'
        "        --mount "
        '"type=bind,source=$GRADLE_SOURCE_AUTHORITY/scripts/'
        "android-apk-build.sh,target=/authority/android-apk-build.sh,readonly"
        '" \\\n'
        "        --mount "
        '"type=bind,source=$ONLINE_DIR,target=/online"',
        "read-only online input",
    ),
    Mutation(
        "shell",
        "source=$GRADLE_OUTPUT_STAGING/gradle-home,target=/outputs/gradle-home",
        "source=$ONLINE_DIR,target=/outputs/gradle-home",
        "narrow Gradle output",
    ),
    Mutation(
        "shell",
        "recover_gradle_output_staging\n    mapfile",
        "true # stale Gradle output ignored\n    mapfile",
        "preflight recovery",
    ),
    Mutation("shell", "gradle_output_tool verify \\\n",
             "gradle_output_tool accept \\\n", "output postcondition"),
    Mutation(
        "shell",
        '            replace_existing=1\n'
        '            log "existing Gradle cache is stale or semantically incomplete; '
        'preparing one verified replacement"',
        '            die "stale Gradle cache cannot be replaced"',
        "stale-cache replacement selection",
    ),
    Mutation(
        "shell",
        '    if [[ "$receipt" =~ ^sha256=([0-9a-f]{64})$ ]]; then\n'
        '        digest="${BASH_REMATCH[1]}"\n'
        '    else\n'
        '        output_status=1\n'
        '    fi',
        '    digest="0" # unchecked producer receipt',
        "candidate digest receipt",
    ),
    Mutation(
        "shell",
        "            gradle_output_tool replace \\\n",
        "            gradle_output_tool publish \\\n",
        "checked replacement dispatch",
    ),
    Mutation(
        "shell",
        "            gradle_output_tool archive-replaced \\\n",
        "            gradle_output_tool recover \\\n",
        "replacement-record archival",
    ),
    Mutation(
        "shell",
        '[ "$status" -eq 0 ] && [ "$source_status" -eq 0 ] && '
        '[ "$output_status" -eq 0 ]',
        '[ "$status" -eq 0 ]',
        "publication barrier",
    ),
    Mutation(
        "android",
        '[ "${RUSTDESK_GRADLE_WARM_HOME:-}" = /outputs/gradle-home ]',
        '[ -n "${RUSTDESK_GRADLE_WARM_HOME:-}" ]',
        "exact warm Gradle home",
    ),
    Mutation(
        "android",
        '[ -z "${RUSTDESK_ANDROID_SDK_HOME+x}" ] \\\n'
        '        || { echo "[FATAL] warm builds may not redirect the '
        'read-only Android SDK" >&2; exit 1; }',
        "true # writable SDK redirection accepted",
        "SDK redirection rejection",
    ),
    Mutation(
        "android",
        'read-only Android SDK" >&2; exit 1; }\n'
        "    ANDROID_BUILD_SDK=/online/android-sdk\n"
        "else",
        'read-only Android SDK" >&2; exit 1; }\n'
        '    ANDROID_BUILD_SDK="$RUSTDESK_ANDROID_SDK_HOME"\n'
        "else",
        "read-only SDK selection",
    ),
    Mutation("wrapper", "distributionSha256Sum=",
             "disabledDistributionSha256Sum=", "wrapper checksum"),
    Mutation("pins", "SHA256_ANDROID_GRADLE_WRAPPER_ALL=",
             "SHA256_ANDROID_GRADLE_WRAPPER_DISABLED=", "wrapper pin"),
    Mutation(
        "projector",
        "SOURCE_DIRECTORY_MODE = 0o500",
        "SOURCE_DIRECTORY_MODE = 0o700",
        "offline seed directory mode",
    ),
    Mutation(
        "projector",
        "SOURCE_FILE_MODES = {0o400, 0o500}",
        "SOURCE_FILE_MODES = {0o600, 0o700}",
        "offline seed file modes",
    ),
    Mutation("helper", "STATE_VERSION = 3", "STATE_VERSION = 1", "state version"),
    Mutation("helper", "set(value) != current_keys", "False", "closed state schema"),
    Mutation(
        "helper",
        "RENAME_EXCHANGE = 2",
        "RENAME_EXCHANGE = 0",
        "same-parent exchange primitive",
    ),
    Mutation(
        "helper",
        '        "replaced_gradle_digest": replaced.digest,',
        '        "replaced_gradle_digest": expected_digest,',
        "displaced full-content digest binding",
    ),
    Mutation(
        "helper",
        '            renameat2(\n'
        '                online_fd,\n'
        '                replacement_name,\n'
        '                online_fd,\n'
        '                "gradle-home",\n'
        '                RENAME_EXCHANGE,\n'
        '            )\n'
        '            exchanged = True',
        '            exchanged = True # same-parent exchange omitted',
        "replacement exchange",
    ),
    Mutation(
        "helper",
        '            renameat2(\n'
        '                online_fd,\n'
        '                "gradle-home",\n'
        '                online_fd,\n'
        '                replacement_name,\n'
        '                RENAME_EXCHANGE,\n'
        '            )',
        "            pass # old live name not restored",
        "old-first replacement rollback",
    ),
    Mutation(
        "helper",
        '        hash_contents=True,\n'
        '        expected_identity=expected_identity,\n'
        '    )\n'
        '    if summary.files == 0:',
        '        hash_contents=False,\n'
        '        expected_identity=expected_identity,\n'
        '    )\n'
        '    if summary.files == 0:',
        "displaced full-content validation",
    ),
    Mutation(
        "helper",
        '        renameat2(\n'
        '            online_fd,\n'
        '            staging.name,\n'
        '            retired_fd,\n'
        '            archive_name,\n'
        '            RENAME_NOREPLACE,\n'
        '        )',
        "        pass # replacement journal not archived",
        "replacement journal archival",
    ),
    Mutation(
        "helper",
        "reject_descendant_mounts(canonical)",
        "return # descendant mounts accepted",
        "mount closure",
    ),
    Mutation("helper", "output file is multiply linked",
             "multiply linked output accepted", "hardlink rejection"),
    Mutation("helper", "output tree contains a symlink",
             "symlinked output accepted", "symlink rejection"),
    Mutation("helper", "output tree contains a special file",
             "special output accepted", "special-file rejection"),
    Mutation(
        "helper",
        "live Android SDK changed while the networked producer ran",
        "live Android SDK mutation accepted",
        "post-producer SDK check",
    ),
    Mutation(
        "helper",
        "read-only Android SDK content postcondition failed",
        "read-only Android SDK content accepted",
        "post-publication SDK check",
    ),
    Mutation(
        "helper",
        '    if summary.digest != state.get("sdk_source_digest"):\n'
        '        fail("Android SDK changed during Gradle output recovery")',
        "    pass # current recovery SDK mutation accepted",
        "recovery SDK check",
    ),
    Mutation("helper", "digest.hexdigest() != gradle_sha256",
             "False", "publisher checksum"),
    Mutation(
        "helper",
        'require_property(tools / "source.properties", '
        '"Pkg.Revision", build_tools)\n'
        '    for name in ("aapt2", "apksigner", "zipalign"):\n'
        "        require_file(tools / name, executable=True, nonempty=True)",
        'require_property(tools / "source.properties", '
        '"Pkg.Revision", build_tools)\n'
        '    for name in ("aapt2",):\n'
        "        require_file(tools / name, executable=True, nonempty=True)",
        "SDK semantic closure",
    ),
    Mutation(
        "helper",
        'sync_tree(staging / "gradle-home")\n'
        "    fsync_directory(staging)\n"
        "    state = record_new_publication(staging, state, expected_digest)\n"
        "    online_fd = open_directory(online)\n"
        "    staging_fd = open_directory(staging)\n"
        "    gradle_moved = False",
        "pass # Gradle output not synchronized\n"
        "    fsync_directory(staging)\n"
        "    state = record_new_publication(staging, state, expected_digest)\n"
        "    online_fd = open_directory(online)\n"
        "    staging_fd = open_directory(staging)\n"
        "    gradle_moved = False",
        "durability",
    ),
    Mutation(
        "helper",
        '    sync_tree(staging / "gradle-home")\n'
        "    fsync_directory(staging)\n"
        "    state = record_new_publication(staging, state, expected_digest)",
        "    state = record_new_publication(staging, state, expected_digest)\n"
        '    sync_tree(staging / "gradle-home")\n'
        "    fsync_directory(staging)",
        "publication journal after durable candidate",
    ),
    Mutation(
        "helper",
        "    sync_tree(output)\n"
        "    fsync_directory(staging)\n"
        "    state = record_replacement_publication(",
        "    state = record_replacement_publication(",
        "replacement journal after durable candidate",
    ),
    Mutation(
        "helper",
        '    if replacement.exists() or replacement.is_symlink():\n'
        '        fail("reserved replacement Gradle name is already occupied")\n'
        "    validate_sdk_state(online, state, uid, gid)\n"
        "    online_fd = open_directory(online)",
        '    if replacement.exists() or replacement.is_symlink():\n'
        '        fail("reserved replacement Gradle name is already occupied")\n'
        "    online_fd = open_directory(online)",
        "replacement SDK precondition",
    ),
    Mutation(
        "helper",
        "        validate_displaced_output(\n"
        "            replacement,\n"
        "            uid,\n"
        "            gid,\n"
        "            replaced_identity,\n"
        "            replaced_digest,\n"
        "        )\n"
        "        validate_sdk_state(online, state, uid, gid)",
        "        validate_displaced_output(\n"
        "            replacement,\n"
        "            uid,\n"
        "            gid,\n"
        "            replaced_identity,\n"
        "            replaced_digest,\n"
        "        )",
        "replacement SDK postcondition",
    ),
    Mutation(
        "helper",
        "        seal=True,\n        seal_root=False,\n"
        "        expected_identity=decode_identity(\n"
        '            state.get("staged_gradle_identity"), "staged Gradle"\n'
        "        ),\n    )\n"
        "    if sealed_summary.digest != expected_digest:\n"
        '        fail("sealed Gradle candidate digest changed")\n'
        "    validate_semantics(",
        "        seal=False,\n        seal_root=False,\n"
        "        expected_identity=decode_identity(\n"
        '            state.get("staged_gradle_identity"), "staged Gradle"\n'
        "        ),\n    )\n"
        "    if sealed_summary.digest != expected_digest:\n"
        '        fail("sealed Gradle candidate digest changed")\n'
        "    validate_semantics(",
        "prepublication descendant sealing",
    ),
    Mutation(
        "helper",
        '            0o500,\n            "published Gradle",',
        '            0o700,\n            "published Gradle",',
        "published root sealing",
    ),
    Mutation(
        "helper",
        "        require_sealed=True,\n    )\n    validate_semantics(\n"
        "        sdk,\n        gradle,",
        "        require_sealed=False,\n    )\n    validate_semantics(\n"
        "        sdk,\n        gradle,",
        "complete sealed-tree check",
    ),
    Mutation(
        "helper",
        'renameat2(staging_fd, "gradle-home", online_fd, '
        '"gradle-home", RENAME_NOREPLACE)',
        'os.replace(staging / "gradle-home", online / "gradle-home")',
        "no-clobber publication",
    ),
    Mutation(
        "helper",
        "rollback_publication(\n"
        "                    online_fd,\n"
        "                    staging_fd,",
        "pass # rollback omitted\n"
        "                if False:\n"
        "                    staging_fd,",
        "publication rollback",
    ),
    Mutation(
        "helper",
        "previous_umask = os.umask(0o077)\n"
        "        try:\n"
        '            create_fake_sdk(online / "android-sdk", '
        "build_tools, compile_sdk)\n"
        "        finally:\n"
        "            os.umask(previous_umask)",
        "previous_umask = os.umask(0o002)\n"
        "        try:\n"
        '            create_fake_sdk(online / "android-sdk", '
        "build_tools, compile_sdk)\n"
        "        finally:\n"
        "            os.umask(previous_umask)",
        "private SDK fixture umask",
    ),
    Mutation(
        "helper",
        "previous_umask = os.umask(0o077)\n"
        "        try:\n"
        '            create_fake_sdk(online / "android-sdk", '
        "build_tools, compile_sdk)\n"
        "        finally:\n"
        "            os.umask(previous_umask)",
        "previous_umask = os.umask(0o077)\n"
        "        try:\n"
        '            create_fake_sdk(online / "android-sdk", '
        "build_tools, compile_sdk)\n"
        "        finally:\n"
        "            os.umask(0o077)",
        "SDK fixture umask restoration",
    ),
    Mutation(
        "verify",
        "/usr/bin/python3 -I -S "
        "scripts/verify-online-fetch-gradle-output-authority.py --repo . --self-test",
        "true # Gradle output authority gate removed",
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
        '<span class="id">R-S11fv</span>',
        '<span class="id">R-S11fv-disabled</span>',
        "R-S11fv requirement",
    ),
    Mutation(
        "requirements",
        '<span class="id">R-S11fz</span>',
        '<span class="id">R-S11fz-disabled</span>',
        "R-S11fz requirement",
    ),
    Mutation(
        "requirements",
        "<tr><td>245</td>",
        "<tr><td>245-disabled</td>",
        "Appendix C #245",
    ),
    Mutation(
        "requirements",
        "<tr><td>330</td>",
        "<tr><td>330-disabled</td>",
        "Appendix C #330",
    ),
    Mutation(
        "requirements",
        "<tr><td>334</td>",
        "<tr><td>334-disabled</td>",
        "Appendix C #334",
    ),
    Mutation(
        "hardening",
        "R-S11cr/R-S11e-110 — exact Android SDK acquisition and publication authority",
        "R-S11cr/R-S11e-110 — ambient Android SDK authority",
        "hardening disposition",
    ),
    Mutation(
        "hardening",
        "R-S11cl/R-S11e-104 umask-independent Gradle SDK fixture authority",
        "R-S11cl/R-S11e-104 ambient Gradle SDK fixture authority",
        "private SDK fixture correction ledger",
    ),
    Mutation(
        "hardening",
        "R-S11fv/R-S11e-208 — Gradle publication/offline-seed mode closure",
        "R-S11fv/R-S11e-208 — writable Gradle publication mode",
        "Gradle seed mode-closure ledger",
    ),
    Mutation(
        "hardening",
        "R-S11fz/R-S11e-212 — stale canonical Gradle-cache replacement authority",
        "R-S11fz/R-S11e-212 — destructive Gradle-cache replacement authority",
        "stale Gradle replacement ledger",
    ),
)


def load_sources(repo: pathlib.Path) -> Dict[str, str]:
    return {
        "shell": (repo / "scripts/online-fetch.sh").read_text(encoding="utf-8"),
        "helper": (repo / "scripts/online-gradle-output.py").read_text(
            encoding="utf-8"
        ),
        "android": (repo / "scripts/android-apk-build.sh").read_text(
            encoding="utf-8"
        ),
        "pins": (repo / "scripts/pins.env").read_text(encoding="utf-8"),
        "wrapper": (
            repo / "flutter/android/gradle/wrapper/gradle-wrapper.properties"
        ).read_text(encoding="utf-8"),
        "projector": (repo / "scripts/android-gradle-cache.py").read_text(
            encoding="utf-8"
        ),
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
        "verify-online-fetch-gradle-output-authority: PASS"
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
            "verify-online-fetch-gradle-output-authority: {}".format(error)
        )
