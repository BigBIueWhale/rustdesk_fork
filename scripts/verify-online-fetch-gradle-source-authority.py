#!/usr/bin/env python3
"""Guard the Gradle warmer's exact private source topology.

This is deliberately a compact, source-only invariant. It does not execute
Gradle, mutate source text, or treat requirement/ledger wording as evidence.
Runtime acceptance requires the real stage_gradle transaction in the
authenticated online-acquisition VM, including failure and cleanup cases.
"""

import argparse
import pathlib


class AuthorityError(Exception):
    pass


def require(source: str, token: str, label: str) -> None:
    if token not in source:
        raise AuthorityError("missing {}".format(label))


def forbid(source: str, token: str, label: str) -> None:
    if token in source:
        raise AuthorityError("forbidden {}".format(label))


def require_count(source: str, token: str, count: int, label: str) -> None:
    observed = source.count(token)
    if observed != count:
        raise AuthorityError(
            "{} count is {}, expected {}".format(label, observed, count)
        )


def extract(source: str, start: str, end: str, label: str) -> str:
    if source.count(start) != 1:
        raise AuthorityError("{} start cardinality differs".format(label))
    begin = source.index(start)
    finish = source.find(end, begin + len(start))
    if finish < 0:
        raise AuthorityError("{} end is absent".format(label))
    return source[begin:finish]


def require_order(source: str, tokens: tuple[str, ...], label: str) -> None:
    position = -1
    for token in tokens:
        position = source.find(token, position + 1)
        if position < 0:
            raise AuthorityError(
                "{} is missing ordered token {!r}".format(label, token)
            )


def validate(repo: pathlib.Path) -> None:
    shell = (repo / "scripts/online-fetch.sh").read_text(encoding="utf-8")

    require_order(
        shell,
        (
            'if [ "${RUSTDESK_ONLINE_FETCH_VM_GUEST:-}" != 1 ]; then',
            'exec "$SCRIPT_DIR/online-fetch-vm.sh" "$@"',
            '"$SCRIPT_DIR/verify-online-fetch-vm-entry.sh"',
            "readonly DOCKER_BIN=/usr/bin/docker",
        ),
        "VM-only acquisition entry",
    )
    for token, label in (
        ("readonly GIT_RUNTIME_ROOT=/opt/rustdesk-online-fetch-git",
         "authenticated Git runtime root"),
        ("readonly GIT_BIN=$GIT_RUNTIME_ROOT/usr/bin/git",
         "authenticated Git binary"),
        ("readonly GIT_EXEC_PATH=$GIT_RUNTIME_ROOT/usr/lib/git-core",
         "authenticated Git executable closure"),
        ("readonly GIT_TEMPLATE_DIR=$GIT_RUNTIME_ROOT/usr/share/git-core/templates",
         "authenticated Git template closure"),
        ('[ "$(/usr/bin/stat -c \'%u:%g:%a\' -- "$GIT_RUNTIME_ROOT")" = "0:0:555" ]',
         "root-owned read-only Git runtime"),
        ('"0:0:555:1:$SIZE_VERIFIER_VM_GIT_BINARY"',
         "Git binary metadata pin"),
        ('"$SHA256_VERIFIER_VM_GIT_BINARY"',
         "Git binary digest pin"),
        ('[ -d "$GIT_EXEC_PATH" ] && [ ! -L "$GIT_EXEC_PATH" ]',
         "Git executable-directory closure"),
        ('[ -d "$GIT_TEMPLATE_DIR" ] && [ ! -L "$GIT_TEMPLATE_DIR" ]',
         "Git template-directory closure"),
        ("readonly TAR_BIN=/usr/bin/tar", "fixed tar binary"),
    ):
        require(shell, token, label)

    git = extract(
        shell,
        "online_source_git() {",
        '\n}\n\nverify_gradle_live_checkout_state() {',
        "closed Git funnel",
    )
    for token, label in (
        ("assert_online_fetch_source_tools", "tool identity replay"),
        ("/usr/bin/env -i", "empty Git environment"),
        ("PATH=/usr/bin:/bin", "fixed Git command path"),
        ('HOME="$ONLINE_FETCH_TMP"', "private Git home"),
        ("GIT_CONFIG_NOSYSTEM=1", "system-config exclusion"),
        ("GIT_CONFIG_GLOBAL=/dev/null", "global-config exclusion"),
        ("GIT_ATTR_NOSYSTEM=1", "system-attribute exclusion"),
        ('GIT_EXEC_PATH="$GIT_EXEC_PATH"', "Git executable closure"),
        ('GIT_TEMPLATE_DIR="$GIT_TEMPLATE_DIR"', "Git template closure"),
        ("GIT_ALLOW_PROTOCOL=file", "non-file protocol exclusion"),
        ("GIT_NO_REPLACE_OBJECTS=1", "replacement-object exclusion"),
        ("GIT_OPTIONAL_LOCKS=0", "optional-lock exclusion"),
        ('"$GIT_BIN"', "authenticated Git execution"),
        ("-c core.hooksPath=/dev/null", "hook exclusion"),
        ("-c core.attributesFile=/dev/null", "global-attribute exclusion"),
        ("-c core.fsmonitor=false", "filesystem-monitor exclusion"),
        ('-C "$REPO_ROOT"', "fixed source repository"),
        ('return "$status"', "Git verdict propagation"),
    ):
        require(git, token, label)
    require_count(git, "assert_online_fetch_source_tools", 2, "Git identity replay")

    checkout = extract(
        shell,
        "verify_gradle_live_checkout_state() {",
        "\n}\n\nverify_clean_live_checkout_state() {",
        "tracked checkout verifier",
    )
    for token, label in (
        ("config --local --no-includes --bool core.sparseCheckout",
         "sparse-checkout refusal"),
        ("online_source_git ls-files -v", "index-flag inventory"),
        ('substr($0,1,1) != "H"', "noncanonical index-flag refusal"),
        ("diff --no-ext-diff --quiet --ignore-submodules=none --",
         "worktree-to-index comparison"),
        ("diff --cached --no-ext-diff --quiet --ignore-submodules=none --",
         "index-to-HEAD comparison"),
        ("status --porcelain=v1 --untracked-files=all",
         "nonignored untracked inventory"),
        ('return "$status"', "accumulated checkout verdict"),
    ):
        require(checkout, token, label)

    closure = extract(
        shell,
        "verify_clean_live_checkout_state() {",
        "\n}\n\n# Online acquisition intentionally retains outbound bridge networking.",
        "repository-metadata closure",
    )
    for token, label in (
        ('verify_gradle_live_checkout_state "$phase" || status=$?',
         "tracked checkout composition"),
        ("rev-parse --git-path info/attributes",
         "repository-local archive-attribute refusal"),
        ("repository-local Git attributes are forbidden",
         "archive-attribute failure"),
        ("rev-parse --git-path info/grafts", "graft refusal"),
        ("Git graft state is forbidden", "graft failure"),
        ("for-each-ref --format='%(refname)' refs/replace",
         "replacement-ref inventory"),
        ("Git replacement refs are forbidden", "replacement-ref failure"),
        ('return "$status"', "complete metadata verdict"),
    ):
        require(closure, token, label)

    prepare = extract(
        shell,
        "prepare_gradle_source() {",
        "\n}\n\nverify_gradle_source_unchanged() {",
        "private source construction",
    )
    for token, label in (
        ('if [ -n "${GRADLE_SOURCE_AUTHORITY:-}" ]; then',
         "retained-authority branch"),
        ('verify_clean_live_checkout_state "before exact-source reuse"',
         "retained-source metadata reproof"),
        ('[ "$current" = "$GRADLE_SOURCE_COMMIT" ]',
         "retained commit reproof"),
        ('[ "$current" = "$GRADLE_SOURCE_TREE" ]',
         "retained tree reproof"),
        ('= "$GRADLE_SOURCE_ARCHIVE_SHA256" ]',
         "retained archive reproof"),
        ("recreated exact source contains a symlink or special entry",
         "recreated-source type closure"),
        ("recreated writable source does not match its exact commit authority",
         "recreated-source comparison"),
        ('GRADLE_SOURCE_COMMIT="$(online_source_git rev-parse --verify \'HEAD^{commit}\')"',
         "exact commit capture"),
        ('rev-parse --verify "${GRADLE_SOURCE_COMMIT}^{tree}"',
         "exact tree capture"),
        ('verify_clean_live_checkout_state "before Gradle warming"',
         "initial source metadata proof"),
        ("ls-tree -rz --full-tree", "committed-entry inventory"),
        ('mode not in (b"100644", b"100755")',
         "regular/executable-only source"),
        ("grep -q -E 'export-(ignore|subst)'",
         "committed archive-transform refusal"),
        ('GRADLE_SOURCE_ARCHIVE="$ONLINE_FETCH_TMP/gradle-source.tar"',
         "private source archive"),
        ('GRADLE_SOURCE_AUTHORITY="$ONLINE_FETCH_TMP/gradle-source-authority"',
         "read-only authority root"),
        ('GRADLE_SOURCE_BUILD="$ONLINE_FETCH_TMP/gradle-source-build"',
         "writable build root"),
        ('online_source_git archive --format=tar "$GRADLE_SOURCE_COMMIT"',
         "exact commit archive"),
        ('/usr/bin/chmod -R a=rX "$GRADLE_SOURCE_AUTHORITY"',
         "read-only authority modes"),
        ('/usr/bin/chmod -R u=rwX,go=rX "$GRADLE_SOURCE_BUILD"',
         "writable-copy modes"),
        ("Gradle writable source does not match its exact commit authority",
         "initial source comparison"),
    ):
        require(prepare, token, label)

    postcondition = extract(
        shell,
        "verify_gradle_source_unchanged() {",
        "\n}\n\nretire_gradle_source_build() {",
        "source postcondition",
    )
    for token, label in (
        ("current status=0", "accumulated source status"),
        ('--candidate "$GRADLE_SOURCE_BUILD" --allow-extras',
         "post-build exact-input comparison"),
        ("networked Gradle warming changed a committed source input",
         "changed-input refusal"),
        ('[ "$current" != "$GRADLE_SOURCE_COMMIT" ]',
         "live commit reproof"),
        ('[ "$current" != "$GRADLE_SOURCE_TREE" ]',
         "live tree reproof"),
        ('verify_clean_live_checkout_state "after Gradle warming"',
         "post-build repository-metadata proof"),
        ('online_source_git archive --format=tar "$GRADLE_SOURCE_COMMIT"',
         "repeat commit archive"),
        ("Gradle source commit archive changed during warming",
         "repeat-archive comparison"),
        ('return "$status"', "complete source verdict"),
    ):
        require(postcondition, token, label)

    retirement = extract(
        shell,
        "retire_gradle_source_build() {",
        "\n}\n\ngradle_output_tool() {",
        "private source retirement",
    )
    for token, label in (
        ('[ "$(/usr/bin/stat -c \'%d:%i\' -- "$GRADLE_SOURCE_BUILD")" = '
         '"$GRADLE_SOURCE_BUILD_ID" ]',
         "writable-tree identity reproof"),
        ('"$GRADLE_SOURCE_AUTHORITY/scripts/restore-private-directory-modes.py"',
         "descriptor-safe directory restoration"),
        ('--expected-identity "$GRADLE_SOURCE_BUILD_ID"',
         "exact retirement identity"),
        ('--owner "$ONLINE_FETCH_UID" --group "$ONLINE_FETCH_GID"',
         "retirement principal"),
        ('--remove-private-root "$GRADLE_SOURCE_BUILD"',
         "inode-closed removal"),
        ("private Gradle writable source survived retirement",
         "retirement postcondition"),
        ('GRADLE_SOURCE_BUILD=""', "retired-source invalidation"),
    ):
        require(retirement, token, label)

    stage = extract(
        shell,
        "stage_gradle() {",
        "\n}\n\n# ── The windows flutter ENGINE",
        "Gradle producer transaction",
    )
    for token, label in (
        ("local status=0 source_status=0", "separate producer/source verdicts"),
        ("prepare_gradle_source", "private-source preparation"),
        ('source=$GRADLE_SOURCE_BUILD,target=/src"',
         "private writable source mount"),
        ('source=$GRADLE_SOURCE_AUTHORITY/scripts/android-apk-build.sh,'
         'target=/authority/android-apk-build.sh,readonly',
         "read-only authority-program mount"),
        ("/bin/bash --noprofile --norc /authority/android-apk-build.sh",
         "authority-program execution"),
        ("|| status=$?", "producer failure capture"),
        ("(verify_gradle_source_unchanged) || source_status=$?",
         "failure-preserving source postcondition"),
        ("retire_gradle_source_build", "exact source retirement"),
        ('[ "$status" -eq 0 ] && [ "$source_status" -eq 0 ]',
         "publication source barrier"),
        ('[ "$source_status" -eq 0 ] || die "networked Gradle source postcondition failed"',
         "source finality"),
    ):
        require(stage, token, label)
    require_order(
        stage,
        (
            "prepare_gradle_source",
            "online_docker_run",
            "|| status=$?",
            "(verify_gradle_source_unchanged) || source_status=$?",
            "retire_gradle_source_build\n    restore_gradle_output_traversal",
            "gradle_output_tool verify",
            '[ "$status" -eq 0 ] && [ "$source_status" -eq 0 ]',
            "retire_gradle_output_staging",
            '[ "$source_status" -eq 0 ] || die "networked Gradle source postcondition failed"',
        ),
        "source verification and retirement before publication finality",
    )

    require_count(
        shell,
        "verify-android-build-source.py",
        3,
        "initial/recreated/post-build comparisons",
    )
    require_count(
        shell,
        'online_source_git archive --format=tar "$GRADLE_SOURCE_COMMIT"',
        2,
        "initial and repeat commit archives",
    )
    require_count(
        stage,
        'source=$GRADLE_SOURCE_BUILD,target=/src"',
        1,
        "private Gradle source mount",
    )
    forbid(stage, 'source=$REPO_ROOT,target=/src"', "live repository mount")
    forbid(stage, "/src/scripts/android-apk-build.sh",
           "writable source-program execution")
    forbid(shell, 'cp -a "$REPO_ROOT', "live repository source copy")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=pathlib.Path, default=pathlib.Path("."))
    arguments = parser.parse_args()
    validate(arguments.repo.resolve())
    print(
        "verify-online-fetch-gradle-source-authority: PASS "
        "(source topology only; real VM/Gradle execution remains required)"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AuthorityError, OSError, ValueError) as error:
        raise SystemExit(
            "verify-online-fetch-gradle-source-authority: {}".format(error)
        )
