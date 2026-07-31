#!/usr/bin/env python3
"""Validate checked publication of the network-acquired Dart/Flutter Pub cache."""

from __future__ import annotations

import argparse
import ast
from dataclasses import dataclass
import pathlib
import re
from typing import Dict, Tuple


class AuthorityError(RuntimeError):
    pass


@dataclass(frozen=True)
class Mutation:
    source: str
    old: str
    new: str
    label: str


GIT_SPECS = (
    (
        "dash_chat_2",
        "bd6b5b41254e57c5bcece202ebfb234de63e6487",
        ".",
        "https://github.com/rustdesk-org/Dash-Chat-2",
    ),
    (
        "desktop_multi_window",
        "b47e8385e5a75d38319ad706a64b0ead3108b093",
        ".",
        "https://github.com/rustdesk-org/rustdesk_desktop_multi_window",
    ),
    (
        "dynamic_layouts",
        "24cb88413fa5181d949ddacbb30a65d5c459e7d9",
        ".",
        "https://github.com/rustdesk-org/dynamic_layouts.git",
    ),
    (
        "uni_links",
        "f416118d843a7e9ed117c7bb7bdc2deda5a9e86f",
        "uni_links",
        "https://github.com/rustdesk-org/uni_links",
    ),
    (
        "window_manager",
        "85789bfe6e4cfaf4ecc00c52857467fdb7f26879",
        ".",
        "https://github.com/rustdesk-org/window_manager",
    ),
    (
        "window_size",
        "eb3964990cf19629c89ff8cb4a37640c7b3d5601",
        "plugins/window_size",
        "https://github.com/google/flutter-desktop-embedding.git",
    ),
)


def require(source: str, token: str, label: str) -> None:
    if token not in source:
        raise AuthorityError("missing {}: {!r}".format(label, token))


def require_absent(source: str, token: str, label: str) -> None:
    if token in source:
        raise AuthorityError("forbidden {} remains: {!r}".format(label, token))


def require_count(source: str, token: str, expected: int, label: str) -> None:
    observed = source.count(token)
    if observed != expected:
        raise AuthorityError(
            "{} count is {}, expected {}: {!r}".format(
                label,
                observed,
                expected,
                token,
            )
        )


def require_order(source: str, tokens: Tuple[str, ...], label: str) -> None:
    position = -1
    for token in tokens:
        found = source.find(token, position + 1)
        if found < 0:
            raise AuthorityError("{} is missing ordered token {!r}".format(label, token))
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
        r'^{}="([^"]+)"'.format(re.escape(name)),
        source,
        re.MULTILINE,
    )
    if match is None:
        raise AuthorityError("{} is not one canonical quoted pin".format(name))
    return match.group(1)


def lock_package_block(lock: str, package: str) -> str:
    match = re.search(
        r"^  {}:\n(?P<body>.*?)(?=^  [A-Za-z0-9_]+:\n|\Z)".format(
            re.escape(package)
        ),
        lock,
        re.MULTILINE | re.DOTALL,
    )
    if match is None:
        raise AuthorityError("Pub lock lacks Git package {}".format(package))
    return match.group("body")


def validate_git_specs(semantic: str, lock: str) -> None:
    require_count(semantic, '|https://github.com/', 6, "closed Git semantic mapping")
    require_count(lock, "    source: git\n", 6, "locked Git package set")
    for package, resolved, package_path, url in GIT_SPECS:
        require(
            semantic,
            '"{}|{}|{}|{}"'.format(package, resolved, package_path, url),
            "{} semantic mapping".format(package),
        )
        block = lock_package_block(lock, package)
        for token, label in (
            ("      path: ", "package path"),
            ("      resolved-ref: ", "resolved ref"),
            ('      url: "{}"'.format(url), "repository URL"),
            ("    source: git", "Git source kind"),
        ):
            require(block, token, "{} {}".format(package, label))
        path_match = re.search(r"^      path: \"?([^\"\n]+)\"?$", block, re.MULTILINE)
        resolved_match = re.search(
            r"^      resolved-ref: \"?([0-9a-f]{40})\"?$",
            block,
            re.MULTILINE,
        )
        if path_match is None or path_match.group(1) != package_path:
            raise AuthorityError("{} package path differs from semantic mapping".format(package))
        if resolved_match is None or resolved_match.group(1) != resolved:
            raise AuthorityError("{} resolved ref differs from semantic mapping".format(package))


def validate_consumers(sources: Dict[str, str]) -> None:
    requirements = {
        "android": (
            "( cd flutter && dart pub get --offline --enforce-lockfile )",
            '( cd "$TC"/flutter/packages/flutter_tools && dart pub get --offline --enforce-lockfile )',
            '"$REAL_FLUTTER" pub get --offline --enforce-lockfile',
        ),
        "debian": (
            "( cd flutter && dart pub get --offline --enforce-lockfile )",
            '( cd "$TC"/flutter/packages/flutter_tools && dart pub get --offline --enforce-lockfile )',
            '"$REAL_FLUTTER" pub get --offline --enforce-lockfile',
        ),
        "windows": (
            "& dart pub get --offline --enforce-lockfile",
            "& flutter pub get --offline --enforce-lockfile",
        ),
        "dart": (
            '(cd "$toolchain/flutter/packages/flutter_tools" && dart pub get --offline --enforce-lockfile >/dev/null)',
            "    dart pub get --offline --enforce-lockfile >/dev/null",
        ),
        "shim": (
            "exec dart pub get --offline --enforce-lockfile",
        ),
        "frb": (
            "(cd flutter && dart pub get --offline --enforce-lockfile)",
            '(cd "$TC"/flutter/packages/flutter_tools && dart pub get --offline --enforce-lockfile)',
        ),
        "win_guest": (
            "'pub','get','--offline','--enforce-lockfile'",
        ),
        "macos": (
            "flutter pub get --enforce-lockfile",
        ),
    }
    for source_name, tokens in requirements.items():
        for token in tokens:
            require(
                sources[source_name],
                token,
                "{} enforced-lockfile consumer".format(source_name),
            )

def validate(sources: Dict[str, str]) -> None:
    shell = sources["shell"]
    helper = sources["helper"]
    pins = sources["pins"]
    verify = sources["verify"]
    requirements = sources["requirements"]
    hardening = sources["hardening"]
    workspace = sources["workspace"]
    try:
        ast.parse(helper)
    except SyntaxError as error:
        raise AuthorityError("Pub-cache output helper does not parse: {}".format(error)) from error

    if pin_value(pins, "FLUTTER_VERSION") != "3.24.5":
        raise AuthorityError("Pub-cache authority requires exact Flutter 3.24.5")
    if re.search(
        r'^SHA256_FLUTTER_3_24_5="[0-9a-f]{64}"',
        pins,
        re.MULTILINE,
    ) is None:
        raise AuthorityError("Flutter 3.24.5 archive lacks one canonical SHA-256 pin")

    for token, label in (
        ("readonly FLOCK_BIN=/usr/bin/flock", "fixed transaction-lock client"),
        ("pub_cache_output_tool() {", "fixed Pub-cache output helper"),
        ("pub_cache_provenance_args() {", "closed provenance mapper"),
        ("retire_pub_cache_output_staging() {", "private staging retirement"),
        ("recover_pub_cache_output_staging() {", "reserved-state recovery"),
        ("prepare_pub_cache_output_staging() {", "private staging preparation"),
        ("verify_pub_cache_resolution() {", "networkless semantic replay"),
        ("stage_pub_cache() {", "closed producer lifecycle"),
        ('"$FLOCK_BIN" --exclusive --nonblock "$lock_fd"', "exclusive transaction"),
        ('"$ONLINE_DIR/.rustdesk-pub-cache.XXXXXXXXXX"',
         "unpredictable same-filesystem staging"),
        ("prepare_gradle_source", "exact committed source construction"),
        ("verify_gradle_source_unchanged", "source postcondition"),
        ("retire_gradle_source_build", "source retirement"),
        ("pub_cache_output_tool prepare", "transaction preparation"),
        ("pub_cache_output_tool verify", "structural output verdict"),
        ("pub_cache_output_tool publish", "no-clobber publication"),
        ("pub_cache_output_tool check-complete", "existing-output revalidation"),
        ("retire_pub_cache_output_staging", "reconciled staging retirement"),
    ):
        require(shell, token, label)

    semantic = extract_between(
        shell,
        "verify_pub_cache_resolution() {",
        "\n}\n\nstage_pub_cache() {",
        "Pub-cache semantic replay",
    )
    semantic_profile = extract_between(
        shell,
        "online_docker_run_pub_semantic() {",
        "\n}\n\n# Exact archive acquisition",
        "Pub-cache semantic execution profile",
    )
    semantic_authority = semantic_profile + "\n" + semantic
    stage = extract_between(
        shell,
        "stage_pub_cache() {",
        "\n}\n\n# ── vcpkg overlay distfiles",
        "Pub-cache output lifecycle",
    )

    for token, label in (
        ("online_docker run --rm --pull=never --network=none --read-only",
         "offline immutable-container launch"),
        ('--user "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID"', "numeric non-root identity"),
        ("--cap-drop=ALL --security-opt=no-new-privileges", "privilege confinement"),
        ("--pids-limit=512 --memory=8g --memory-swap=8g --cpus=4",
         "bounded resources"),
        ('source=$ONLINE_DIR,target=/online,readonly,bind-recursive=disabled',
         "read-only online closure"),
        ('source=$cache,target=/online/pub-cache,readonly,bind-recursive=disabled',
         "read-only candidate at canonical path"),
        ('source=$GRADLE_SOURCE_AUTHORITY,target=/authority,readonly,bind-recursive=disabled',
         "read-only exact source authority"),
        ('"$builder" /bin/bash --noprofile --norc -euo pipefail',
         "immutable builder execution"),
        ("PUB_CACHE=/online/pub-cache", "canonical Pub cache path"),
        ("GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_OPTIONAL_LOCKS=0",
         "closed Git configuration"),
        ("dart pub get --offline --enforce-lockfile", "offline Dart lock enforcement"),
        ("flutter pub get --offline --enforce-lockfile",
         "offline Flutter lock enforcement"),
        ('authority_lock="$(sha256sum /authority/flutter/pubspec.lock',
         "offline project lock preimage"),
        ('[ "$authority_lock" = "$(sha256sum /tmp/project/pubspec.lock',
         "offline project lock postcondition"),
        ("tools_lock=", "flutter_tools lock preimage"),
        ("git_specs=(", "closed Git dependency map"),
        ('[ "${#git_specs[@]}" -eq 6 ]', "exact Git dependency count"),
        ('status --porcelain=v1 --untracked-files=all', "clean checkout proof"),
        ("diff --no-ext-diff --quiet --", "worktree index proof"),
        ("diff --cached --no-ext-diff --quiet --", "index HEAD proof"),
        ('config --path --get remote.origin.url', "canonical bare-cache path"),
        ('case "$remote" in /online/pub-cache/git/cache/*)',
         "bare-cache namespace restriction"),
        ("fsck --full --no-dangling --no-reflogs", "Git object closure"),
        ('cat-file -e "${resolved}^{commit}"', "locked commit availability"),
        ("mode not in (b'100644', b'100755', b'120000')",
         "Git tree mode closure"),
        ('grep -qE "^name:[[:space:]]*$package\\$"',
         "locked package identity"),
    ):
        require(semantic_authority, token, label)
    require(
        semantic,
        "online_docker_run_pub_semantic \\",
        "shared Pub semantic profile use",
    )
    validate_git_specs(semantic, sources["pub_lock"])

    require_count(
        semantic_profile,
        "--network=none",
        1,
        "offline semantic network removal",
    )
    require_count(
        semantic,
        "dart pub get --offline --enforce-lockfile",
        2,
        "offline Dart lockfile replays",
    )
    require_count(
        semantic,
        "fsck --full --no-dangling --no-reflogs",
        2,
        "checkout and bare-cache Git object checks",
    )
    require_count(
        semantic,
        'source=$cache,target=/online/pub-cache,readonly,bind-recursive=disabled',
        1,
        "semantic candidate mount",
    )
    require_order(
        semantic,
        (
            'authority_lock="$(sha256sum /authority/flutter/pubspec.lock',
            "(cd /tmp/project && dart pub get --offline --enforce-lockfile >/dev/null)",
            "(cd /tmp/project && flutter pub get --offline --enforce-lockfile >/dev/null)",
            '[ "$authority_lock" = "$(sha256sum /tmp/project/pubspec.lock',
        ),
        "offline project lock preimage, resolution, and postcondition",
    )
    require_count(stage, "online_docker_run ", 1, "networked Pub producer")
    require_count(
        stage,
        'source=$ONLINE_DIR,target=/online,readonly,bind-recursive=disabled',
        1,
        "producer online input mount",
    )
    require_count(
        stage,
        'source=$PUB_CACHE_OUTPUT_STAGING/output,target=/online/pub-cache',
        1,
        "producer output mount",
    )
    require_count(
        stage,
        'source=$GRADLE_SOURCE_BUILD/flutter,target=/project-source,readonly,bind-recursive=disabled',
        1,
        "producer source mount",
    )
    require_count(stage, "--enforce-lockfile", 2, "networked lock enforcement")
    require_count(
        stage,
        '"$ONLINE_DIR/flutter-${FLUTTER_VERSION}.tar.xz" "$SHA256_FLUTTER_3_24_5"',
        2,
        "pre/post Flutter archive verification",
    )

    for token, label in (
        ('source=$ONLINE_DIR,target=/online"', "broad writable online mount"),
        ('source=$REPO_ROOT/flutter', "live Flutter source mount"),
        ('target=/project"', "persistent writable source mount"),
        ("mkdir -p \"$PUB_CACHE\"", "direct final cache creation"),
        ("rm -rf \"$ONLINE_DIR/pub-cache\"", "destructive final replacement"),
        ("git config --global --add safe.directory \"*\"", "wildcard Git trust"),
        ("flutter pub get\n", "unenforced project resolution"),
    ):
        require_absent(stage, token, label)

    for token, label in (
        ('source=$ONLINE_DIR,target=/online,readonly,bind-recursive=disabled',
         "read-only online input"),
        ('source=$PUB_CACHE_OUTPUT_STAGING/output,target=/online/pub-cache',
         "single private durable output"),
        ('source=$GRADLE_SOURCE_BUILD/flutter,target=/project-source,readonly,bind-recursive=disabled',
         "read-only exact project input"),
        ("cp -a /project-source/. /tmp/project/", "disposable project copy"),
        ('project_lock="$(sha256sum /project-source/pubspec.lock',
         "networked project lock preimage"),
        ('[ "$project_lock" = "$(sha256sum /tmp/project/pubspec.lock',
         "networked project lock postcondition"),
        ("dart pub get --enforce-lockfile", "flutter_tools lock enforcement"),
        ("flutter pub get --enforce-lockfile", "project lock enforcement"),
        ('rm -rf -- "$PUB_CACHE/_temp" "$PUB_CACHE/log" "$PUB_CACHE/README.md"',
         "ephemeral top-level cleanup"),
        ('[[ "$receipt" =~ ^sha256=([0-9a-f]{64})$ ]]',
         "verified digest receipt"),
        ('--expected-digest "$digest"', "digest-bound publication"),
        ('[ "$status" -eq 0 ] && [ "$source_status" -eq 0 ]',
         "producer/source verdict barrier"),
        ('&& [ "$input_status" -eq 0 ] && [ "$output_status" -eq 0 ]',
         "input/output verdict barrier"),
        ('&& [ "$semantic_status" -eq 0 ]', "semantic verdict barrier"),
        ('[ "$publication_status" -eq 0 ]', "publication verdict"),
    ):
        require(stage, token, label)
    require_order(
        stage,
        (
            'project_lock="$(sha256sum /project-source/pubspec.lock',
            "(cd /tmp/project && flutter pub get --enforce-lockfile)",
            '[ "$project_lock" = "$(sha256sum /tmp/project/pubspec.lock',
        ),
        "networked project lock preimage, resolution, and postcondition",
    )
    require_order(
        stage,
        (
            '"$FLOCK_BIN" --exclusive --nonblock "$lock_fd"',
            "prepare_gradle_source",
            "verify_sha256",
            "recover_pub_cache_output_staging",
            "check-complete",
            "prepare_pub_cache_output_staging",
            "online_docker_run",
            "(verify_gradle_source_unchanged) || source_status=$?",
            "retire_gradle_source_build",
            "|| input_status=$?",
            "restore_pub_cache_output_traversal",
            "pub_cache_output_tool verify",
            "verify_pub_cache_resolution",
            "pub_cache_output_tool publish",
            "retire_pub_cache_output_staging",
            '"$FLOCK_BIN" --unlock "$lock_fd"',
        ),
        "Pub-cache checked transaction",
    )

    for token, label in (
        ('STATE_NAME = ".rustdesk-pub-cache-output-state-v1"',
         "bounded transaction record"),
        ("TREE_LIMITS = (100_000, 30_000, 4 * 1024**3, 256 * 1024**2, 32)",
         "closed output bounds"),
        ("EXPECTED_GIT_DEPENDENCIES = 6", "exact Git dependency count"),
        ('required = {"hosted", "hosted-hashes", "git"}',
         "exact required top-level trees"),
        ('ALLOWED_LEGACY_TOP_LEVEL = {"_temp", "log", "README.md"}',
         "bounded historical top-level allowance"),
        ("reject_descendant_mounts(canonical)", "descendant-mount rejection"),
        ("Pub cache crosses a filesystem", "filesystem closure"),
        ("Pub cache has mixed or foreign ownership", "owner closure"),
        ("Pub cache directory is group/world writable", "directory mode closure"),
        ("Pub cache file is group/world writable", "file mode closure"),
        ("Pub cache directory remains owner-writable", "published directory closure"),
        ("Pub cache file remains owner-writable", "published file closure"),
        ("if metadata.st_mode & FORBIDDEN_MODE_BITS:", "set-id/sticky rejection"),
        ("if attributes:", "extended-attribute rejection"),
        ("os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW", "no-follow reads"),
        ("stable_metadata(before_file) != stable_metadata(after_file)",
         "stable content reads"),
        ("Pub cache has a hardlink outside its closed output tree",
         "closed internal hardlinks"),
        ("Pub cache symlink escapes the cache root", "escaping-symlink rejection"),
        ("Pub cache symlink exists outside a Git checkout",
         "symlink namespace restriction"),
        ("Pub cache contains a special file", "special-file rejection"),
        ("Pub hosted package directories and content-hash records are not one exact set",
         "hosted/hash set equality"),
        ('for advisory in ("archive-advisories.json", "http-advisories.json")',
         "required advisory cache"),
        ("Pub cache does not contain the exact six locked Git dependencies",
         "Git inventory closure"),
        ("source_archive_sha256", "source archive provenance"),
        ("flutter_archive_sha256", "Flutter archive provenance"),
        ("sync_tree(output)", "content durability barrier"),
        ("RENAME_NOREPLACE = 1", "no-clobber rename primitive"),
        ('renameat2(staging_fd, "output", online_fd, "pub-cache", RENAME_NOREPLACE)',
         "descriptor-relative publication"),
        ("Pub-cache publication rollback also failed", "rollback preservation"),
        ('return "unpublished"', "unpublished recovery"),
        ('return "published"', "published recovery"),
        ("transaction state is incoherent and was preserved",
         "ambiguous recovery refusal"),
        ("self-test accepted an occupied Pub-cache destination",
         "destination-race fixture"),
        ("self-test accepted an escaping Pub-cache symlink",
         "escaping-symlink fixture"),
        ("self-test accepted a Pub-cache hardlink outside the output",
         "external-hardlink fixture"),
        ("self-test accepted a special file in Pub-cache output",
         "special-file fixture"),
        ("self-test accepted extended attributes in Pub-cache output",
         "extended-attribute fixture"),
    ):
        require(helper, token, label)
    require_order(
        helper,
        (
            "verify_staged(",
            "sync_tree(output)",
            'renameat2(staging_fd, "output", online_fd, "pub-cache", RENAME_NOREPLACE)',
            "published Pub-cache identity postcondition failed",
            "validate_shape(destination, strict_output=True)",
        ),
        "checked Pub-cache publication",
    )

    validate_consumers(sources)
    require(
        verify,
        "/usr/bin/python3 -I -S scripts/online-pub-cache-output.py self-test",
        "transaction self-test wiring",
    )
    require(
        verify,
        "/usr/bin/python3 -I -S scripts/verify-online-fetch-pub-cache-output-authority.py --repo . --self-test",
        "focused verifier wiring",
    )
    require(requirements, '<span class="id">R-S11cn</span>', "R-S11cn requirement")
    require(requirements, "<tr><td>233</td>", "Appendix C #233 disposition")
    require(
        hardening,
        "R-S11cn/R-S11e-106 — networked Pub-cache acquisition-output authority",
        "hardening-ledger disposition",
    )
    require(
        workspace,
        '"online_fetch_pub_cache_output_authority_verifier"',
        "workspace-verifier source ownership",
    )
    require(
        workspace,
        "Online-fetch Pub-cache output authority focused verifier",
        "workspace-verifier semantic binding",
    )


MUTATIONS: Tuple[Mutation, ...] = (
    Mutation(
        "shell",
        '"$FLOCK_BIN" --exclusive --nonblock "$lock_fd" \\\n'
        '        || die "another Pub-cache output transaction already owns the online root"',
        "true # Pub-cache transaction lock removed",
        "exclusive transaction lock",
    ),
    Mutation(
        "shell",
        'source=$ONLINE_DIR,target=/online,readonly,bind-recursive=disabled" \\\n'
        '            --mount "type=bind,source=$PUB_CACHE_OUTPUT_STAGING/output,'
        'target=/online/pub-cache',
        'source=$ONLINE_DIR,target=/online" \\\n'
        '            --mount "type=bind,source=$PUB_CACHE_OUTPUT_STAGING/output,'
        'target=/online/pub-cache',
        "read-only online input",
    ),
    Mutation(
        "shell",
        'source=$PUB_CACHE_OUTPUT_STAGING/output,target=/online/pub-cache',
        'source=$ONLINE_DIR,target=/online/pub-cache',
        "private writable output",
    ),
    Mutation(
        "shell",
        'source=$GRADLE_SOURCE_BUILD/flutter,target=/project-source,readonly,bind-recursive=disabled',
        'source=$REPO_ROOT/flutter,target=/project-source,readonly',
        "exact private source input",
    ),
    Mutation(
        "shell",
        "cp -a /project-source/. /tmp/project/",
        "cp -a /project-source/. /project/",
        "disposable project copy",
    ),
    Mutation(
        "shell",
        "dart pub get --enforce-lockfile",
        "dart pub get",
        "flutter_tools acquisition lock enforcement",
    ),
    Mutation(
        "shell",
        "flutter pub get --enforce-lockfile",
        "flutter pub get",
        "project acquisition lock enforcement",
    ),
    Mutation(
        "shell",
        '[ "$project_lock" = "$(sha256sum /tmp/project/pubspec.lock '
        '| awk "{print \\$1}")" ]',
        "true # networked project lock drift accepted",
        "networked project lock postcondition",
    ),
    Mutation(
        "shell",
        "online_docker_run_pub_semantic() {\n"
        "    online_docker run --rm --pull=never --network=none --read-only",
        "online_docker_run_pub_semantic() {\n"
        "    online_docker run --rm --pull=never --network=bridge --read-only",
        "networkless semantic replay",
    ),
    Mutation(
        "shell",
        "(cd /tmp/project && dart pub get --offline --enforce-lockfile >/dev/null)",
        "(cd /tmp/project && dart pub get --offline >/dev/null)",
        "offline Dart lock enforcement",
    ),
    Mutation(
        "shell",
        "flutter pub get --offline --enforce-lockfile",
        "flutter pub get --offline",
        "offline Flutter lock enforcement",
    ),
    Mutation(
        "shell",
        '[ "$authority_lock" = "$(sha256sum /tmp/project/pubspec.lock '
        '| awk "{print \\$1}")" ]',
        "true # offline project lock drift accepted",
        "offline project lock postcondition",
    ),
    Mutation(
        "shell",
        '/usr/bin/git -c safe.directory="$checkout" -C "$checkout" \\\n'
        "                fsck --full --no-dangling --no-reflogs >/dev/null",
        '/usr/bin/git -c safe.directory="$checkout" -C "$checkout" \\\n'
        "                status --porcelain >/dev/null",
        "Git object closure",
    ),
    Mutation(
        "shell",
        'case "$remote" in /online/pub-cache/git/cache/*)',
        'case "$remote" in /online/*)',
        "Git bare-cache namespace",
    ),
    Mutation(
        "shell",
        '"dash_chat_2|bd6b5b41254e57c5bcece202ebfb234de63e6487|.|'
        'https://github.com/rustdesk-org/Dash-Chat-2"',
        '"dash_chat_2|0000000000000000000000000000000000000000|.|'
        'https://github.com/rustdesk-org/Dash-Chat-2"',
        "locked Git mapping",
    ),
    Mutation(
        "shell",
        '[[ "$receipt" =~ ^sha256=([0-9a-f]{64})$ ]]; then\n'
        '            digest="${BASH_REMATCH[1]}"',
        '[[ -n "$receipt" ]]; then\n'
        '            digest="${BASH_REMATCH[1]}"',
        "verified digest receipt",
    ),
    Mutation(
        "shell",
        '--expected-digest "$digest"',
        '--expected-digest "$receipt"',
        "digest-bound publication",
    ),
    Mutation(
        "shell",
        '&& [ "$semantic_status" -eq 0 ]; then\n'
        "            pub_cache_output_tool publish",
        "; then # semantic verdict omitted\n"
        "            pub_cache_output_tool publish",
        "semantic publication barrier",
    ),
    Mutation(
        "helper",
        "reject_descendant_mounts(canonical)",
        "return # descendant mounts accepted",
        "mount closure",
    ),
    Mutation(
        "helper",
        "Pub cache has a hardlink outside its closed output tree",
        "Pub cache permits a hardlink outside its output tree",
        "hardlink closure",
    ),
    Mutation(
        "helper",
        "Pub cache symlink escapes the cache root",
        "Pub cache permits a symlink escape",
        "symlink closure",
    ),
    Mutation(
        "helper",
        "Pub cache contains a special file",
        "Pub cache permits a special file",
        "special-file closure",
    ),
    Mutation(
        "helper",
        "if metadata.st_mode & FORBIDDEN_MODE_BITS:",
        "if False:",
        "set-id/sticky rejection",
    ),
    Mutation(
        "helper",
        "if attributes:",
        "if False:",
        "extended-attribute rejection",
    ),
    Mutation(
        "helper",
        "EXPECTED_GIT_DEPENDENCIES = 6",
        "EXPECTED_GIT_DEPENDENCIES = 7",
        "Git inventory bound",
    ),
    Mutation(
        "helper",
        'required = {"hosted", "hosted-hashes", "git"}',
        'required = {"hosted", "git"}',
        "top-level inventory",
    ),
    Mutation(
        "helper",
        "Pub hosted package directories and content-hash records are not one exact set",
        "Pub hosted packages need not have matching hashes",
        "hosted/hash equality",
    ),
    Mutation(
        "helper",
        "sync_tree(output)",
        "pass # output not synchronized",
        "durability barrier",
    ),
    Mutation(
        "helper",
        'renameat2(staging_fd, "output", online_fd, "pub-cache", RENAME_NOREPLACE)',
        "os.replace(output, destination)",
        "no-clobber publication",
    ),
    Mutation(
        "helper",
        "transaction state is incoherent and was preserved",
        "transaction state was discarded",
        "ambiguous recovery",
    ),
    Mutation(
        "android",
        "( cd flutter && dart pub get --offline --enforce-lockfile )",
        "( cd flutter && dart pub get --offline )",
        "Android enforced lockfile",
    ),
    Mutation(
        "debian",
        '"$REAL_FLUTTER" pub get --offline --enforce-lockfile',
        '"$REAL_FLUTTER" pub get --offline',
        "Debian Flutter enforced lockfile",
    ),
    Mutation(
        "windows",
        "& flutter pub get --offline --enforce-lockfile",
        "& flutter pub get --offline",
        "Windows enforced lockfile",
    ),
    Mutation(
        "dart",
        "    dart pub get --offline --enforce-lockfile >/dev/null",
        "    dart pub get --offline >/dev/null",
        "Dart verifier enforced lockfile",
    ),
    Mutation(
        "shim",
        "exec dart pub get --offline --enforce-lockfile",
        "exec dart pub get --offline",
        "Flutter shim enforced lockfile",
    ),
    Mutation(
        "frb",
        "(cd flutter && dart pub get --offline --enforce-lockfile)",
        "(cd flutter && dart pub get --offline)",
        "FRB enforced lockfile",
    ),
    Mutation(
        "win_guest",
        "'pub','get','--offline','--enforce-lockfile'",
        "'pub','get','--offline'",
        "Windows guest enforced lockfile",
    ),
    Mutation(
        "macos",
        "flutter pub get --enforce-lockfile",
        "flutter pub get",
        "macOS enforced lockfile",
    ),
    Mutation(
        "verify",
        "/usr/bin/python3 -I -S scripts/verify-online-fetch-pub-cache-output-authority.py --repo . --self-test",
        "true # Pub-cache authority gate removed",
        "focused verifier wiring",
    ),
    Mutation(
        "requirements",
        '<span class="id">R-S11cn</span>',
        '<span class="id">R-S11cn-disabled</span>',
        "R-S11cn requirement",
    ),
    Mutation(
        "requirements",
        "<tr><td>233</td>",
        "<tr><td>233-disabled</td>",
        "Appendix C #233 disposition",
    ),
    Mutation(
        "hardening",
        "R-S11cn/R-S11e-106 — networked Pub-cache acquisition-output authority",
        "R-S11cn/R-S11e-106 — ambient Pub-cache output authority",
        "hardening disposition",
    ),
)


def load_sources(repo: pathlib.Path) -> Dict[str, str]:
    paths = {
        "shell": "scripts/online-fetch.sh",
        "helper": "scripts/online-pub-cache-output.py",
        "pins": "scripts/pins.env",
        "verify": "scripts/verify.sh",
        "requirements": "requirements.html",
        "hardening": "HARDENING_STATUS.md",
        "workspace": "scripts/verify-verifier-workspace.py",
        "pub_lock": "flutter/pubspec.lock",
        "android": "scripts/android-apk-build.sh",
        "debian": "scripts/build-debian.sh",
        "windows": "scripts/build-windows.ps1",
        "dart": "scripts/dart-verify.sh",
        "shim": "scripts/flutter-offline-shim.sh",
        "frb": "scripts/frb-codegen.sh",
        "win_guest": "scripts/win-guest-setup.ps1",
        "macos": "res/osx-dist.sh",
    }
    return {
        name: (repo / relative).read_text(encoding="utf-8")
        for name, relative in paths.items()
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
    arguments = parser.parse_args()
    sources = load_sources(arguments.repo.resolve())
    validate(sources)
    if arguments.self_test:
        run_mutations(sources)
        print(
            "verify-online-fetch-pub-cache-output-authority: PASS "
            "({} mutations rejected)".format(len(MUTATIONS))
        )
    else:
        print("verify-online-fetch-pub-cache-output-authority: PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, AuthorityError) as error:
        raise SystemExit(
            "verify-online-fetch-pub-cache-output-authority: {}".format(error)
        )
