#!/usr/bin/env python3
"""Validate the networked Gradle warmer's private source authority."""

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


def extract(source: str, start: str, end: str, label: str) -> str:
    if source.count(start) != 1:
        raise AuthorityError("{} start cardinality differs".format(label))
    begin = source.index(start)
    finish = source.find(end, begin + len(start))
    if finish < 0:
        raise AuthorityError("{} end is missing".format(label))
    return source[begin : finish + len(end)]


def require_order(source: str, tokens: Tuple[str, ...], label: str) -> None:
    position = -1
    for token in tokens:
        found = source.find(token, position + 1)
        if found < 0:
            raise AuthorityError("{} is missing ordered token {!r}".format(label, token))
        position = found


def validate(sources: Dict[str, str]) -> None:
    shell = sources["shell"]
    comparator = sources["comparator"]
    normalizer = sources["normalizer"]

    for token, label in (
        ("readonly GIT_BIN=/usr/bin/git", "fixed Git client"),
        ("readonly TAR_BIN=/usr/bin/tar", "fixed tar client"),
        ('[ "$(/usr/bin/stat -c \'%u:%g:%a:%h\' -- "$GIT_BIN")" = "0:0:755:1" ]',
         "Git client metadata proof"),
        ('[ "$(/usr/bin/stat -c \'%u:%g:%a:%h\' -- "$TAR_BIN")" = "0:0:755:1" ]',
         "tar client metadata proof"),
        ("online_source_git() {", "closed Git funnel"),
        ("prepare_gradle_source() {", "private source constructor"),
        ("verify_gradle_source_unchanged() {", "source postcondition"),
        ("retire_gradle_source_build() {", "private writable-source retirement"),
    ):
        require(shell, token, label)

    git = extract(
        shell,
        "online_source_git() {",
        '    return "$status"\n}',
        "Git source funnel",
    )
    for token, label in (
        ("assert_online_fetch_source_tools", "tool pre/postcondition"),
        ("/usr/bin/env -i", "fixed closed-environment launcher"),
        ("PATH=/usr/bin:/bin", "fixed command path"),
        ('HOME="$ONLINE_FETCH_TMP"', "private home"),
        ("GIT_CONFIG_NOSYSTEM=1", "system-config exclusion"),
        ("GIT_CONFIG_GLOBAL=/dev/null", "global-config exclusion"),
        ("GIT_ATTR_NOSYSTEM=1", "system-attribute exclusion"),
        ("GIT_NO_REPLACE_OBJECTS=1", "replacement-object exclusion"),
        ("GIT_OPTIONAL_LOCKS=0", "optional repository-write exclusion"),
        ('"$GIT_BIN"', "fixed Git execution"),
        ("-c core.hooksPath=/dev/null", "hook exclusion"),
        ("-c core.attributesFile=/dev/null", "ambient attribute exclusion"),
        ("-c core.fsmonitor=false", "filesystem-monitor exclusion"),
        ('-C "$REPO_ROOT"', "fixed repository"),
    ):
        require(git, token, "Git funnel {}".format(label))
    require_count(git, "assert_online_fetch_source_tools", 2, "Git tool proofs")

    checkout = extract(
        shell,
        "verify_gradle_live_checkout_state() {",
        '    return "$status"\n}',
        "live checkout verifier",
    )
    for token, label in (
        ("config --local --no-includes --bool core.sparseCheckout",
         "sparse-checkout rejection"),
        ("online_source_git ls-files -v", "index-flag inventory"),
        ('substr($0,1,1) != "H"', "canonical index flags"),
        ("diff --no-ext-diff --quiet --ignore-submodules=none --",
         "worktree-to-index comparison"),
        ("diff --cached --no-ext-diff --quiet --ignore-submodules=none --",
         "index-to-HEAD comparison"),
        ("status --porcelain=v1 --untracked-files=all",
         "stable all-untracked status"),
        ('return "$status"', "accumulated checkout verdict"),
    ):
        require(checkout, token, "live checkout {}".format(label))

    prepare = extract(
        shell,
        "prepare_gradle_source() {",
        "\n}\n\nverify_gradle_source_unchanged() {",
        "Gradle source constructor",
    )
    for token, label in (
        ("rev-parse --verify 'HEAD^{commit}'", "exact HEAD capture"),
        ('rev-parse --verify "${GRADLE_SOURCE_COMMIT}^{tree}"', "exact tree capture"),
        ('verify_gradle_live_checkout_state "before Gradle warming"',
         "canonical clean-checkout proof"),
        ("ls-tree -rz --full-tree", "commit entry inventory"),
        ('mode not in (b"100644", b"100755")', "regular/executable-only tree"),
        ("grep -q -E 'export-(ignore|subst)'", "archive-transforming attribute scan"),
        ('[ "$archive_attribute_status" -eq 1 ]',
         "archive-attribute no-match classification"),
        ('GRADLE_SOURCE_ARCHIVE="$ONLINE_FETCH_TMP/gradle-source.tar"',
         "private source archive"),
        ('GRADLE_SOURCE_AUTHORITY="$ONLINE_FETCH_TMP/gradle-source-authority"',
         "private read-only authority"),
        ('GRADLE_SOURCE_BUILD="$ONLINE_FETCH_TMP/gradle-source-build"',
         "private writable source"),
        ('online_source_git archive --format=tar "$GRADLE_SOURCE_COMMIT"',
         "commit-object archive"),
        ('/usr/bin/install -d -m 0700 "$GRADLE_SOURCE_AUTHORITY" '
         '"$GRADLE_SOURCE_BUILD"',
         "private extraction roots"),
        ('/usr/bin/chmod 0400 "$GRADLE_SOURCE_ARCHIVE"',
         "read-only source archive"),
        ('/usr/bin/chmod -R a=rX "$GRADLE_SOURCE_AUTHORITY"',
         "canonical read-only authority modes"),
        ('/usr/bin/chmod -R u=rwX,go=rX "$GRADLE_SOURCE_BUILD"',
         "canonical writable-copy modes"),
        ('GRADLE_SOURCE_BUILD_ID="$(/usr/bin/stat -c \'%d:%i\' -- '
         '"$GRADLE_SOURCE_BUILD")"',
         "writable-source identity"),
        ('--reference "$GRADLE_SOURCE_AUTHORITY" --candidate "$GRADLE_SOURCE_BUILD"',
         "initial exact-source comparison"),
    ):
        require(prepare, token, "source constructor {}".format(label))

    postcondition = extract(
        shell,
        "verify_gradle_source_unchanged() {",
        "\n}\n\nretire_gradle_source_build() {",
        "Gradle source postcondition",
    )
    for token, label in (
        ('local after_archive="$ONLINE_FETCH_TMP/gradle-source-after.tar" '
         "current status=0",
         "accumulating postcondition verdict"),
        ("if ! /usr/bin/python3 -I -S", "non-short-circuit input comparison"),
        ('--reference "$GRADLE_SOURCE_AUTHORITY" --candidate "$GRADLE_SOURCE_BUILD" --allow-extras',
         "post-build exact-input comparison"),
        ("networked Gradle warming changed a committed source input",
         "changed-input rejection"),
        ("rev-parse --verify 'HEAD^{commit}'", "live commit reproof"),
        ('[ "$current" != "$GRADLE_SOURCE_COMMIT" ]', "commit identity comparison"),
        ('[ "$current" != "$GRADLE_SOURCE_TREE" ]', "tree identity comparison"),
        ('verify_gradle_live_checkout_state "after Gradle warming"',
         "live canonical-checkout reproof"),
        ('online_source_git archive --format=tar "$GRADLE_SOURCE_COMMIT"',
         "commit rearchive"),
        ('[ "$(/usr/bin/sha256sum "$after_archive" | '
         "/usr/bin/awk '{print $1}')\" != "
         '"$GRADLE_SOURCE_ARCHIVE_SHA256" ]',
         "archive digest comparison"),
        ('return "$status"', "complete accumulated verdict"),
    ):
        require(postcondition, token, "source postcondition {}".format(label))

    retirement = extract(
        shell,
        "retire_gradle_source_build() {",
        "\n}\n\nstage_gradle() {",
        "Gradle source retirement",
    )
    for token, label in (
        ('[ "$(/usr/bin/stat -c \'%d:%i\' -- "$GRADLE_SOURCE_BUILD")" = '
         '"$GRADLE_SOURCE_BUILD_ID" ]',
         "writable-source identity reproof"),
        ('"$GRADLE_SOURCE_AUTHORITY/scripts/restore-private-directory-modes.py"',
         "read-only directory normalizer"),
        ('--expected-identity "$GRADLE_SOURCE_BUILD_ID"',
         "normalizer exact tree identity"),
        ('--owner "$ONLINE_FETCH_UID" --group "$ONLINE_FETCH_GID"',
         "normalizer exact tree principal"),
        ('--remove-private-root "$GRADLE_SOURCE_BUILD"', "descriptor-safe tree removal"),
        ('--expected-identity "$GRADLE_SOURCE_BUILD_ID"', "exact tree identity"),
        ("private Gradle writable source survived retirement", "removal postcondition"),
        ('GRADLE_SOURCE_BUILD=""', "retired-source invalidation"),
    ):
        require(retirement, token, "source retirement {}".format(label))

    stage = extract(
        shell,
        "stage_gradle() {",
        "\n}\n\n# ── The windows flutter ENGINE",
        "Gradle warmer",
    )
    for token, label in (
        ("local status=0", "captured container status"),
        ("source_status=0", "captured source-postcondition status"),
        ("prepare_gradle_source", "private-source construction"),
        ('source=$GRADLE_SOURCE_BUILD,target=/src"', "private writable source mount"),
        ('source=$GRADLE_SOURCE_AUTHORITY/scripts/android-apk-build.sh,'
         'target=/authority/android-apk-build.sh,readonly',
         "read-only inner-program authority"),
        ("/bin/bash --noprofile --norc /authority/android-apk-build.sh",
         "authority-script execution"),
        ("|| status=$?", "failure-preserving postcondition path"),
        ("(verify_gradle_source_unchanged) || source_status=$?",
         "failure-preserving source postcondition"),
        ("retire_gradle_source_build", "source retirement call"),
        ('[ "$source_status" -eq 0 ] || die "networked Gradle source postcondition failed"',
         "delayed source-postcondition failure"),
        ('[ "$status" -eq 0 ] || die "networked Gradle warming failed"',
         "delayed container failure"),
    ):
        require(stage, token, "Gradle warmer {}".format(label))
    require_order(
        stage,
        (
            "prepare_gradle_source",
            "online_docker_run",
            "|| status=$?",
            "(verify_gradle_source_unchanged) || source_status=$?",
            "retire_gradle_source_build\n    restore_gradle_output_traversal",
            '[ "$source_status" -eq 0 ] || die "networked Gradle source postcondition failed"',
            '[ "$status" -eq 0 ] || die "networked Gradle warming failed"',
        ),
        "Gradle source lifecycle",
    )

    require_count(
        shell,
        'source=$GRADLE_SOURCE_BUILD,target=/src"',
        1,
        "private Gradle source mount",
    )
    require_count(
        shell,
        "verify-android-build-source.py",
        2,
        "pre/post exact-input comparisons",
    )
    require_count(
        shell,
        'online_source_git archive --format=tar "$GRADLE_SOURCE_COMMIT"',
        2,
        "initial and final commit archives",
    )
    forbid(shell, 'source=$REPO_ROOT,target=/src"', "live repository container mount")
    forbid(shell, "/src/scripts/android-apk-build.sh", "writable inner-program execution")
    forbid(shell, "cp -a \"$REPO_ROOT", "live repository source copy")
    forbid(shell, "export PATH=/usr/bin:/bin", "script-wide command-path override")

    for token, label in (
        ('before.st_nlink != 1', "hardlink refusal"),
        ('identity_before != identity_after', "stable-read proof"),
        ('reference_digest != candidate_digest', "exact byte comparison"),
        ('candidate_mode != expected_candidate_mode', "exact mode comparison"),
        ('if not allow_extras:', "generated-output policy"),
        ('candidate source contains an extra input', "initial extra-input rejection"),
        ('candidate source is missing', "missing-input rejection"),
        ('expect_failure(reference, candidate, "hardlink substitution")',
         "hardlink negative test"),
        ('expect_failure(reference, candidate, "changed executable mode")',
         "mode negative test"),
    ):
        require(comparator, token, "source comparator {}".format(label))

    for token, label in (
        ("os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC",
         "no-follow path descriptors"),
        ("def open_root_path(path):", "component-wise root acquisition"),
        ('os.chmod("/proc/self/fd/{}".format(descriptor), mode)',
         "descriptor-bound mode restoration"),
        ('return os.open(\n        ".",\n        os.O_RDONLY | os.O_DIRECTORY | '
         "os.O_NOFOLLOW | os.O_CLOEXEC,\n        dir_fd=path_descriptor,",
         "descriptor-relative read traversal"),
        ("metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)",
         "no-follow child metadata"),
        ("if metadata.st_dev != device:", "filesystem-bound traversal"),
        ("descriptor_mount_id(child) != expected_mount", "mount-bound traversal"),
        ("descriptor_mount_id(path_descriptor)\n"
         "            != descriptor_mount_id(parent_descriptor)",
         "root-parent mount binding"),
        ("if stat.S_ISDIR(metadata.st_mode):", "directory-only normalization"),
        ("metadata.st_uid != owner or metadata.st_gid != group",
         "exact directory principal"),
        ("normalized_directory_mode(opened_path.st_mode)", "bounded directory modes"),
        ("elif not (\n            stat.S_ISREG(metadata.st_mode) or "
         "stat.S_ISLNK(metadata.st_mode)\n        ):",
         "exact regular/symlink classification"),
        ("private-tree directory restoration found a special file",
         "special-file rejection"),
        ("ENTRY_LIMIT = 524288", "entry bound"),
        ("DEPTH_LIMIT = 128", "depth bound"),
        ('if stat.S_IMODE(os.stat(external).st_mode) != 0o640:',
         "hardlinked-file mode preservation self-test"),
        ('raise RestoreError("self-test changed a cross-mount directory mode")',
         "pre-chmod mount rejection self-test"),
        ('raise RestoreError("self-test changed a symlink-parent directory mode")',
         "component-symlink rejection self-test"),
        ('expect_failure(', "negative self-test"),
    ):
        require(normalizer, token, "directory normalizer {}".format(label))

    require(
        sources["verify"],
        "/usr/bin/python3 -I -S scripts/verify-online-fetch-gradle-source-authority.py --repo . --self-test",
        "shared focused-verifier wiring",
    )
    require(
        sources["verify"],
        "/usr/bin/python3 -I -S scripts/restore-private-directory-modes.py --self-test",
        "directory-normalizer self-test wiring",
    )
    require(
        sources["requirements"],
        '<span class="id">R-S11ck</span>',
        "R-S11ck requirement",
    )
    require(
        sources["requirements"],
        "<tr><td>230</td>",
        "Appendix C #230 disposition",
    )
    require(
        sources["hardening"],
        "R-S11ck/R-S11e-103 — networked Gradle warmer source authority",
        "hardening-ledger disposition",
    )
    require(
        sources["workspace"],
        '"online_fetch_gradle_source_authority_verifier"',
        "workspace-verifier source ownership",
    )
    require(
        sources["workspace"],
        "Online-fetch Gradle source authority focused verifier",
        "workspace-verifier semantic binding",
    )


MUTATIONS: Tuple[Mutation, ...] = (
    Mutation(
        "shell",
        "assert_online_fetch_source_tools\n    /usr/bin/env -i \\\n"
        "        PATH=/usr/bin:/bin \\\n"
        '        HOME="$ONLINE_FETCH_TMP"',
        "assert_online_fetch_source_tools\n    /usr/bin/env -i \\\n"
        '        PATH="$PATH" \\\n'
        '        HOME="$ONLINE_FETCH_TMP"',
        "closed Git command path",
    ),
    Mutation("shell", "readonly GIT_BIN=/usr/bin/git", "GIT_BIN=git",
             "fixed Git client"),
    Mutation("shell", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_NOSYSTEM=0",
             "system Git config exclusion"),
    Mutation("shell", "GIT_NO_REPLACE_OBJECTS=1",
             "GIT_REPLACE_REF_BASE=refs/replace",
             "replacement-object exclusion"),
    Mutation("shell", "GIT_OPTIONAL_LOCKS=0", "GIT_OPTIONAL_LOCKS=1",
             "optional repository-write exclusion"),
    Mutation("shell", "-c core.fsmonitor=false", "-c core.fsmonitor=true",
             "filesystem-monitor exclusion"),
    Mutation(
        "shell",
        "prepare_gradle_source() {\n"
        "    local archive_attribute_status=0 invalid_tree_entry\n"
        "    GRADLE_SOURCE_COMMIT=\"$(online_source_git rev-parse --verify 'HEAD^{commit}')\"",
        "prepare_gradle_source() {\n"
        "    local archive_attribute_status=0 invalid_tree_entry\n"
        "    GRADLE_SOURCE_COMMIT=\"$(online_source_git rev-parse --verify 'HEAD^{tree}')\"",
        "exact source commit capture",
    ),
    Mutation(
        "shell",
        "status --porcelain=v1 --untracked-files=all",
        "status --porcelain=v1 --untracked-files=no",
        "clean source state",
    ),
    Mutation(
        "shell",
        'substr($0,1,1) != "H"',
        'substr($0,1,1) == "H"',
        "canonical index flags",
    ),
    Mutation("shell", 'mode not in (b"100644", b"100755")',
             'mode not in (b"100644", b"100755", b"120000")',
             "nonregular tree rejection"),
    Mutation(
        "shell",
        "grep -q -E 'export-(ignore|subst)'",
        "grep -q -E 'archive-attributes-accepted'",
        "archive-transforming attribute rejection",
    ),
    Mutation("shell", '/usr/bin/chmod -R a=rX "$GRADLE_SOURCE_AUTHORITY"',
             '/usr/bin/chmod -R u+rwX "$GRADLE_SOURCE_AUTHORITY"',
             "read-only source authority"),
    Mutation("shell", '/usr/bin/chmod -R u=rwX,go=rX "$GRADLE_SOURCE_BUILD"',
             '/usr/bin/chmod -R a+rwx "$GRADLE_SOURCE_BUILD"',
             "canonical writable-source modes"),
    Mutation(
        "shell",
        '--reference "$GRADLE_SOURCE_AUTHORITY" --candidate "$GRADLE_SOURCE_BUILD" \\\n'
        '        || die "Gradle writable source does not match its exact commit authority"',
        'true \\\n        || die "Gradle writable source does not match its exact commit authority"',
        "initial exact-source comparison",
    ),
    Mutation("shell", "networked Gradle warming changed a committed source input",
             "networked Gradle warming may change committed source inputs",
             "post-build exact-source comparison"),
    Mutation("shell", '[ "$current" != "$GRADLE_SOURCE_COMMIT" ]',
             "true # live commit accepted", "live commit reproof"),
    Mutation(
        "shell",
        'verify_gradle_live_checkout_state "after Gradle warming"',
        "true # live checkout accepted",
        "live canonical-checkout reproof",
    ),
    Mutation(
        "shell",
        '[ "$(/usr/bin/sha256sum "$after_archive" | '
        "/usr/bin/awk '{print $1}')\" != "
        '"$GRADLE_SOURCE_ARCHIVE_SHA256" ]',
        '[ "$(/usr/bin/sha256sum "$after_archive" | '
        "/usr/bin/awk '{print $1}')\" = "
        '"$GRADLE_SOURCE_ARCHIVE_SHA256" ]',
        "commit archive reproof",
    ),
    Mutation(
        "shell",
        "if ! /usr/bin/python3 -I -S \\\n"
        '        "$GRADLE_SOURCE_AUTHORITY/scripts/verify-android-build-source.py"',
        "if false && /usr/bin/python3 -I -S \\\n"
        '        "$GRADLE_SOURCE_AUTHORITY/scripts/verify-android-build-source.py"',
        "non-short-circuit source comparison",
    ),
    Mutation("shell", 'source=$GRADLE_SOURCE_BUILD,target=/src"',
             'source=$REPO_ROOT,target=/src"', "private source mount"),
    Mutation(
        "shell",
        'source=$GRADLE_SOURCE_AUTHORITY/scripts/android-apk-build.sh,'
        'target=/authority/android-apk-build.sh,readonly',
        'source=$GRADLE_SOURCE_BUILD/scripts/android-apk-build.sh,'
        'target=/authority/android-apk-build.sh',
        "read-only inner-program authority",
    ),
    Mutation("shell", "/bin/bash --noprofile --norc /authority/android-apk-build.sh",
             "/bin/bash --noprofile --norc /src/scripts/android-apk-build.sh",
             "authority-script execution"),
    Mutation(
        "shell",
        '[ "$(/usr/bin/stat -c \'%d:%i\' -- "$GRADLE_SOURCE_BUILD")" = '
        '"$GRADLE_SOURCE_BUILD_ID" ]',
        "true # writable source identity accepted",
        "writable-source retirement identity",
    ),
    Mutation(
        "normalizer",
        "metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)",
        "metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=True)",
        "no-follow directory restoration",
    ),
    Mutation(
        "normalizer",
        'os.chmod("/proc/self/fd/{}".format(descriptor), mode)',
        "os.chmod(root, mode)",
        "descriptor-bound mode restoration",
    ),
    Mutation(
        "normalizer",
        "descriptor_mount_id(child) != expected_mount",
        "False",
        "mount-bound directory restoration",
    ),
    Mutation(
        "normalizer",
        "descriptor_mount_id(path_descriptor)\n"
        "            != descriptor_mount_id(parent_descriptor)",
        "False",
        "root-parent mount binding",
    ),
    Mutation(
        "normalizer",
        "metadata.st_uid != owner or metadata.st_gid != group",
        "False",
        "directory restoration principal",
    ),
    Mutation(
        "normalizer",
        "stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)",
        "stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or stat.S_ISFIFO(metadata.st_mode)",
        "directory restoration special-file rejection",
    ),
    Mutation("shell", "retire_gradle_source_build\n    restore_gradle_output_traversal",
             "true # source retained\n    restore_gradle_output_traversal",
             "private source retirement"),
    Mutation(
        "verify",
        "/usr/bin/python3 -I -S scripts/verify-online-fetch-gradle-source-authority.py --repo . --self-test",
        "true # online-fetch Gradle source gate removed",
        "shared focused-verifier wiring",
    ),
    Mutation("requirements", '<span class="id">R-S11ck</span>',
             '<span class="id">R-S11ck-disabled</span>', "R-S11ck requirement"),
    Mutation("requirements", "<tr><td>230</td>", "<tr><td>230-disabled</td>",
             "Appendix C #230 disposition"),
    Mutation(
        "hardening",
        "R-S11ck/R-S11e-103 — networked Gradle warmer source authority",
        "R-S11ck/R-S11e-103 — networked Gradle live-source authority",
        "hardening-ledger disposition",
    ),
)


def load_sources(repo: pathlib.Path) -> Dict[str, str]:
    return {
        "shell": (repo / "scripts/online-fetch.sh").read_text(encoding="utf-8"),
        "comparator": (repo / "scripts/verify-android-build-source.py").read_text(
            encoding="utf-8"
        ),
        "normalizer": (repo / "scripts/restore-private-directory-modes.py").read_text(
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
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=pathlib.Path, default=pathlib.Path("."))
    parser.add_argument("--self-test", action="store_true")
    arguments = parser.parse_args()
    sources = load_sources(arguments.repo.resolve())
    validate(sources)
    if arguments.self_test:
        run_mutations(sources)
    print(
        "verify-online-fetch-gradle-source-authority: OK"
        + (" ({} mutations)".format(len(MUTATIONS)) if arguments.self_test else "")
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AuthorityError, OSError, ValueError) as error:
        print("verify-online-fetch-gradle-source-authority: {}".format(error))
        raise SystemExit(1)
