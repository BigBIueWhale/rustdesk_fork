#!/usr/bin/env python3
import argparse
import ast
import json
import os
import re
import selectors
import signal
import shlex
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path


WORKSPACE_BLOCKS = (
    (
        "workspace cleanup",
        (
            'VERIFY_TMP=""',
            'VERIFY_TMP_ID=""',
            'VERIFY_SUCCESS_MESSAGE=""',
            "cleanup_verify_tmp() {",
            "  local status=$? cleanup_failed=0",
            "  trap - EXIT",
            "  trap '' HUP INT TERM",
        ),
    ),
    (
        "workspace signal handling",
        (
            "trap cleanup_verify_tmp EXIT",
            "trap 'exit 129' HUP",
            "trap 'exit 130' INT",
            "trap 'exit 143' TERM",
        ),
    ),
    (
        "workspace creation",
        (
            "VERIFY_TMP=$(umask 077 && mktemp -d /tmp/rustdesk-verify.XXXXXXXXXX)",
            'VERIFY_TMP_ID="$(stat -c \'%d:%i\' -- "$VERIFY_TMP")"',
            "readonly VERIFY_TMP VERIFY_TMP_ID",
        ),
    ),
    (
        "workspace metadata proof",
        (
            'if ! python3 - "$VERIFY_TMP" <<\'PY\'',
            "import os",
            "import stat",
            "import sys",
            "",
            "metadata = os.lstat(sys.argv[1])",
            "if (",
            "    not stat.S_ISDIR(metadata.st_mode)",
            "    or metadata.st_uid != os.geteuid()",
            "    or stat.S_IMODE(metadata.st_mode) != 0o700",
            "):",
            '    raise SystemExit("verify: private workspace is not a current-UID mode-0700 directory")',
            "PY",
            "then",
            "  exit 1",
            "fi",
        ),
    ),
)

OLD_SCRATCH_PREFIX = re.compile(r"/tmp/(?:rd_verify|r_s11b3|r_s11c23)")
PUBLIC_TMP_REDIRECTION = re.compile(r"\d*(?:>>?|<<?)\s*['\"]?/tmp/")
SHELL_COMMAND_SEPARATORS = {"|", "||", "&", "&&", ";"}


class VerificationError(RuntimeError):
    pass


class ManagedSignal(BaseException):
    def __init__(self, signum):
        super().__init__(signum)
        self.signum = signum


MANAGED_SIGNALS = (signal.SIGHUP, signal.SIGINT, signal.SIGTERM)
_MANAGED_SIGNAL_STATE = None


def require_text(source, text, label):
    if text not in source:
        raise VerificationError(f"{label}: required contract is absent")


def require_count(source, text, minimum, label):
    count = source.count(text)
    if count < minimum:
        raise VerificationError(f"{label}: expected at least {minimum} occurrences, found {count}")


def require_exact_count(source, text, expected, label):
    count = source.count(text)
    if count != expected:
        raise VerificationError(f"{label}: expected exactly {expected} occurrences, found {count}")


def require_order(source, tokens, label):
    positions = []
    cursor = 0
    for token in tokens:
        position = source.find(token, cursor)
        if position < 0:
            raise VerificationError(f"{label}: missing ordered stage {token!r}")
        positions.append(position)
        cursor = position + len(token)
    if len(set(positions)) != len(positions):
        raise VerificationError(f"{label}: stages are not strictly ordered")


def extract_between(source, start_token, end_token, label):
    start = source.find(start_token)
    if start < 0:
        raise VerificationError(f"{label}: opening token is absent")
    end = source.find(end_token, start + len(start_token))
    if end < 0:
        raise VerificationError(f"{label}: closing token is absent")
    return source[start:end]


def extract_through(source, start_token, end_token, label):
    start = source.find(start_token)
    if start < 0:
        raise VerificationError(f"{label}: opening token is absent")
    end = source.find(end_token, start + len(start_token))
    if end < 0:
        raise VerificationError(f"{label}: closing token is absent")
    return source[start : end + len(end_token)]


def validate_popen_finally_ownership(source, function_name, cleanup_name, reaped_name, label):
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        raise VerificationError(f"{label}: Python source does not parse: {exc}") from exc
    functions = [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == function_name
    ]
    if len(functions) != 1:
        raise VerificationError(f"{label}: expected one {function_name} function")
    function = functions[0]
    owner_tries = [statement for statement in function.body if isinstance(statement, ast.Try)]
    if len(owner_tries) != 1:
        raise VerificationError(f"{label}: Popen is not covered by one top-level teardown try")
    owner_try = owner_tries[0]
    owner_body = ast.Module(body=owner_try.body, type_ignores=[])
    popen_assignments = [
        node
        for node in ast.walk(owner_body)
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "process" for target in node.targets)
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Attribute)
        and isinstance(node.value.func.value, ast.Name)
        and node.value.func.value.id == "subprocess"
        and node.value.func.attr == "Popen"
    ]
    all_popen_calls = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "subprocess"
        and node.func.attr == "Popen"
    ]
    if len(popen_assignments) != 1 or len(all_popen_calls) != 1:
        raise VerificationError(f"{label}: Popen assignment escapes the teardown-owning try")
    cleanup_ifs = [
        node
        for statement in owner_try.finalbody
        for node in ast.walk(statement)
        if isinstance(node, ast.If)
        and any(
            isinstance(descendant, ast.Call)
            and isinstance(descendant.func, ast.Name)
            and descendant.func.id == cleanup_name
            for descendant in ast.walk(node)
        )
    ]
    if len(cleanup_ifs) != 1:
        raise VerificationError(f"{label}: teardown finally does not conditionally call {cleanup_name}")
    expected_condition = ast.parse(f"process is not None and not {reaped_name}", mode="eval").body
    if ast.dump(cleanup_ifs[0].test) != ast.dump(expected_condition):
        raise VerificationError(f"{label}: teardown finally has the wrong ownership condition")


def find_unique_line(lines, expected, label):
    matches = [index for index, line in enumerate(lines) if line == expected]
    if len(matches) != 1:
        raise VerificationError(f"{label}: expected one exact line, found {len(matches)}")
    return matches[0]


def find_unique_block(lines, block, label):
    width = len(block)
    matches = [
        index
        for index in range(len(lines) - width + 1)
        if tuple(lines[index : index + width]) == block
    ]
    if len(matches) != 1:
        raise VerificationError(f"{label}: expected one exact block, found {len(matches)}")
    return matches[0]


def has_fixed_string_self_check(line):
    if "grep" not in line or "scripts/verify.sh" not in line:
        return False
    try:
        lexer = shlex.shlex(line, posix=True, punctuation_chars="|&;")
        lexer.whitespace_split = True
        lexer.commenters = ""
        tokens = list(lexer)
    except ValueError as exc:
        raise VerificationError(f"cannot parse potential verify.sh self-check: {exc}") from exc
    for index, token in enumerate(tokens):
        if token != "grep":
            continue
        command = []
        for argument in tokens[index + 1 :]:
            if argument in SHELL_COMMAND_SEPARATORS:
                break
            command.append(argument)
        fixed = any(
            argument == "--fixed-strings"
            or argument.startswith("--fixed-strings=")
            or (argument.startswith("-") and not argument.startswith("--") and "F" in argument[1:])
            for argument in command
        )
        if fixed and "scripts/verify.sh" in command:
            return True
    return False


def validate_verify_workspace(source):
    lines = source.splitlines()
    cleanup = extract_between(
        source,
        "cleanup_verify_tmp() {",
        "\n}\n",
        "verify workspace cleanup",
    )
    root_index = find_unique_line(lines, 'cd "$(dirname "$0")/.."', "repository-root selection")
    version_index = find_unique_line(lines, "source scripts/fork-version.sh", "fork-version loading")
    positions = {}
    previous_end = root_index
    for label, block in WORKSPACE_BLOCKS:
        start = find_unique_block(lines, block, label)
        if start <= previous_end:
            raise VerificationError(f"{label}: block is outside the ordered startup sequence")
        positions[label] = start
        previous_end = start + len(block) - 1
    if previous_end >= version_index:
        raise VerificationError("workspace setup must finish before fork-version loading")
    for text, label in (
        ('[ -z "$VERIFY_TMP_ID" ]', "workspace recorded identity requirement"),
        ('"$(stat -c \'%d:%i\' -- "$VERIFY_TMP"', "workspace live identity proof"),
        ('scripts/verify-private-tree-closure.py --mount-root "$VERIFY_TMP"', "workspace mount closure"),
        ('rm -rf -- "$VERIFY_TMP"', "workspace removal"),
        ('[ -e "$VERIFY_TMP" ] || [ -L "$VERIFY_TMP" ]', "workspace removal postcondition"),
        ('trap \'\' HUP INT TERM', "workspace cleanup signal exclusion"),
        ('echo "$VERIFY_SUCCESS_MESSAGE"', "deferred verify success output"),
    ):
        require_text(cleanup, text, label)
    require_order(
        cleanup,
        (
            "trap '' HUP INT TERM",
            '"$(stat -c \'%d:%i\' -- "$VERIFY_TMP"',
            'scripts/verify-private-tree-closure.py --mount-root "$VERIFY_TMP"',
            'rm -rf -- "$VERIFY_TMP"',
            'echo "$VERIFY_SUCCESS_MESSAGE"',
            'exit "$status"',
        ),
        "verify success-after-cleanup ordering",
    )
    require_exact_count(
        source,
        'VERIFY_SUCCESS_MESSAGE="VERIFY: all required source, behavior, compile, policy, inventory, and excision gates green"',
        1,
        "deferred verify completion marker",
    )
    if 'echo "VERIFY: all required source, behavior, compile, policy, inventory, and excision gates green"' in source:
        raise VerificationError("verify completion marker bypasses workspace cleanup")
    require_text(source, "--self-test-workspace-missing", "missing-workspace behavioral test mode")
    require_text(
        source,
        'echo "verify workspace missing self-test: REACHED" >&2',
        "verify missing-workspace reached marker",
    )
    require_text(
        source,
        'native_watch_log=$(mktemp "$VERIFY_TMP/native-watch.XXXXXXXXXX")',
        "native watch log workspace ownership",
    )
    for line_number, line in enumerate(lines, 1):
        if OLD_SCRATCH_PREFIX.search(line):
            raise VerificationError(f"line {line_number}: predictable public scratch prefix is present")
        if PUBLIC_TMP_REDIRECTION.search(line):
            raise VerificationError(f"line {line_number}: direct public-/tmp redirection is present")
        if has_fixed_string_self_check(line):
            raise VerificationError(f"line {line_number}: fixed-string self-inspection is present")
    return lines, positions


def validate_build_release(source):
    normalizer = extract_between(
        source,
        "offline_normalize_exact_tree() {",
        "\n}\n\nnormalize_snapshot_access() {",
        "private-tree normalizer",
    )
    snapshot_normalizer = extract_between(
        source,
        "normalize_snapshot_access() {",
        "\n}\n\nnormalize_workspace_access() {",
        "snapshot normalizer",
    )
    worktree_cleanup = extract_between(
        source,
        "query_git_worktree_registry() {",
        "\n}\n\nprepare_existing_dist_removal() {",
        "registered-worktree cleanup",
    )
    worktree_query = extract_between(
        source,
        "query_git_worktree_registry() {",
        "\n}\n\nremove_snapshot_worktree_if_registered() {",
        "registered-worktree registry query",
    )
    registry_python = extract_between(
        worktree_query,
        "<<'PY'\n",
        "\nPY",
        "embedded Git worktree registry parser",
    ).split("\n", 1)[1]
    validate_popen_finally_ownership(
        registry_python,
        "inspect_registry",
        "stop_and_reap",
        "producer_reaped",
        "Git worktree registry teardown ownership",
    )
    worktree_registration_predicate = extract_between(
        source,
        "worktree_path_is_registered() {",
        "\n}\n\nassert_no_stale_release_worktrees() {",
        "exact worktree registration predicate",
    )
    invalid_registration_inspection = extract_between(
        source,
        "assert_snapshot_worktree_not_registered() {",
        "\n}\n\nprepare_existing_dist_removal() {",
        "invalid-workspace registration inspection",
    )
    unprivileged_workspace_cleanup = extract_between(
        source,
        "prepare_unprivileged_workspace_removal() {",
        "\n}\n\nquery_git_worktree_registry() {",
        "unprivileged workspace cleanup",
    )
    cleanup = extract_between(
        source,
        "cleanup_release_workspace() {",
        "\n}\n\nrelease_preflight() {",
        "release cleanup",
    )
    create_snapshot = extract_between(
        source,
        "create_snapshot() {",
        "\n}\n\nreset_snapshot_build_state() {",
        "release snapshot creation",
    )
    reset = extract_between(
        source,
        "reset_snapshot_build_state() {",
        "\n}\n\nrun_child() {",
        "generated-state reset",
    )
    verification = extract_between(
        source,
        "run_verification() {",
        "\n}\n\ncopy_artifact() {",
        "release verification consumer",
    )
    build_snapshot = extract_between(
        source,
        "build_snapshot() {",
        "\n}\n\nassert_exact_set() {",
        "snapshot build loop",
    )
    reset_self_test = extract_between(
        source,
        "run_reset_self_test() {",
        "\n}\n\nrun_self_test() {",
        "root-owned reset self-test",
    )
    publication_self_test = extract_between(
        source,
        "run_publication_reconciliation_self_test() {",
        "\n}\n\nrun_self_test() {",
        "publication reconciliation self-test",
    )
    create_workspace = extract_between(
        source,
        "create_workspace() {",
        "\n}\n\nassert_release_online_snapshot() {",
        "release workspace creation",
    )
    publication = extract_between(
        source,
        "assert_single_writer_publication_parent() {",
        "\n}\n\nwrite_fixture_target() {",
        "final-dist transaction",
    )
    existing_dist = extract_between(
        source,
        "prepare_existing_dist_removal() {",
        "\n}\n\ncleanup_release_workspace() {",
        "existing-dist inspection",
    )
    exchange = extract_between(
        publication,
        "atomic_exchange_or_install() {",
        "\n}\n\npath_identity() {",
        "atomic exchange helper",
    )
    publication_parent = extract_between(
        publication,
        "assert_single_writer_publication_parent() {",
        "\n}\n\natomic_exchange_or_install() {",
        "single-writer publication parent",
    )
    directory_sync = extract_between(
        publication,
        "sync_exact_directory() {",
        "\n}\n\natomic_exchange_or_install() {",
        "exact directory synchronization helper",
    )
    transaction_removal = extract_between(
        publication,
        "commit_registered_final_transaction_discard() {",
        "\n}\n\nreconcile_final_publication() {",
        "registered-transaction removal",
    )
    record_writer = extract_between(
        publication,
        "write_publication_record() {",
        "\n}\n\nread_publication_record() {",
        "durable publication record writer",
    )
    published_proof = extract_between(
        publication,
        "prove_recorded_published_dist() {",
        "\n}\n\nprove_published_dist() {",
        "record-bound published-set proof",
    )
    payload_sync = extract_between(
        publication,
        "sync_staged_publication_payload() {",
        "\n}\n\nsync_publication_directories() {",
        "staged publication durability proof",
    )
    publication_sync = extract_between(
        publication,
        "sync_publication_directories() {",
        "\n}\n\nwrite_publication_record() {",
        "post-exchange publication durability proof",
    )
    record_reader = extract_between(
        publication,
        "read_publication_record() {",
        "\n}\n\ncommit_registered_final_transaction_discard() {",
        "durable publication record reader",
    )
    reconciliation = extract_between(
        publication,
        "reconcile_final_publication() {",
        "\n}\n\nrecover_pending_publications() {",
        "publication reconciliation",
    )
    recovery = extract_between(
        publication,
        "recover_pending_publications() {",
        "\n}\n\natomic_install_dist() {",
        "restartable publication recovery",
    )
    atomic_install = extract_between(
        publication,
        "atomic_install_dist() {",
        "\n}",
        "atomic final-dist installation",
    )
    main = extract_between(source, "main() {", "\n}\n\nmain\n", "release main transaction")
    inspector_header = extract_through(
        normalizer,
        "docker_local run --rm --pull=never --network=none --read-only --user 0:0 \\",
        '"$DEBIAN_IMAGE_ID" /usr/bin/python3 /probe.py --inode-root /inspect',
        "read-only inode-closure inspector",
    )
    mutator_header = extract_through(
        normalizer[normalizer.find(inspector_header) + len(inspector_header) :],
        "docker_local run --rm --pull=never --network=none --read-only --user 0:0 \\",
        '"$DEBIAN_IMAGE_ID" /bin/sh -ceu \'',
        "private-tree ownership mutator",
    )
    require_text(
        source,
        "#!/usr/bin/env -S -i /usr/bin/bash --noprofile --norc",
        "release empty-environment entrypoint",
    )
    require_text(source, 'readonly FINAL_OUT_DIR="$REPO_ROOT/dist"', "non-overridable final dist")
    if "readonly RELEASE_SRC_COMMIT ANDROID_KEY_ALIAS OUT_DIR" in source:
        raise VerificationError("fatal readonly OUT_DIR assignment remains")
    for variable in (
        "BASH_ENV",
        "PYTHONPATH",
        "HARNESS_PREFIX",
        "GIT_*",
        "DOCKER_*",
        "SOURCE_DATE_EPOCH",
        "DOUBLE_BUILD",
        "OUT_DIR",
        "WINDOWS_*",
        "RELEASE_*",
    ):
        require_text(source, variable, f"closed inherited environment {variable}")
    require_text(
        source,
        "run_child() {\n    assert_release_docker_config\n    /usr/bin/env -i",
        "child environment allowlist",
    )
    require_text(source, 'DOCKER_HOST_URI=unix:///var/run/docker.sock', "local Docker socket binding")
    require_text(source, 'DOCKER_CONFIG_DIR="$WORKSPACE/docker-config"', "private Docker config")
    require_text(source, 'ONLINE_SNAPSHOT_PARENT="$WORKSPACE/online-input"', "single online snapshot location")
    require_text(
        source,
        "require_cmd cmp git docker python3 sha256sum stat readlink install find date flock /usr/bin/grep",
        "release host-tool preflight",
    )
    require_text(
        source,
        'run_child /usr/bin/bash --noprofile --norc "$REPO_ROOT/scripts/verify-release.sh" --preflight',
        "release source-gate preflight",
    )
    require_order(
        source,
        (
            'require_cmd cmp git docker python3 sha256sum stat readlink install find date flock /usr/bin/grep',
            "acquire_publication_lock\n",
            'CANONICAL_PUBLICATION_PARENT_ID="$(assert_single_writer_publication_parent "$REPO_ROOT")"',
            'recover_pending_publications "$REPO_ROOT" "$FINAL_OUT_DIR"',
            "clear_final_publication_state\n",
            "assert_no_stale_release_worktrees\n",
            'run_child /usr/bin/bash --noprofile --norc "$REPO_ROOT/scripts/verify-release.sh" --preflight',
            "require_online_complete\n",
            "create_release_online_snapshot\n",
        ),
        "release preflight ordering",
    )
    if source.count('create_private_online_snapshot "$ONLINE_SNAPSHOT_PARENT"') != 1:
        raise VerificationError("release transaction must create exactly one private online snapshot")
    if "HOST_ONLINE_DIR" in source:
        raise VerificationError("release transaction retains the mutable canonical-online child path")
    require_text(source, "run_snapshot_consumer() {", "online snapshot consumer wrapper")
    require_exact_count(source, "run_snapshot_consumer ", 6, "before/after online snapshot consumption")
    require_text(
        source,
        'assert_release_online_snapshot "before final dist installation"',
        "pre-publication online snapshot proof",
    )
    require_text(source, "verify_all_release_builder_images", "pinned builder provenance checks")
    require_text(source, 'require_pinned_builder_image "$role" "$image_id"', "builder image helper contract")
    for mutable_name in (
        "rustdesk-fork-harness-deb-builder",
        "rustdesk-fork-harness-android-builder",
        "rustdesk-fork-harness-win-helper",
    ):
        if mutable_name in source:
            raise VerificationError(f"release transaction retains mutable image name {mutable_name}")
    require_text(source, 'create_snapshot A "$SOURCE_A"', "snapshot A creation")
    require_text(source, 'create_snapshot B "$SOURCE_B"', "snapshot B creation")
    require_text(source, 'worktree add --quiet --detach "$source" "$PINNED_HEAD"', "detached exact-commit worktrees")
    require_text(create_snapshot, 'chmod 0700 "$source"', "private release snapshot mode")
    require_text(
        create_snapshot,
        '[ "$(stat -c \'%u:%a\' "$source")" = "$(id -u):700" ]',
        "private release snapshot metadata proof",
    )
    require_text(reset, 'normalize_snapshot_access "$source" "$label"', "snapshot-scoped ownership reset")
    if 'normalize_snapshot_access "$WORKSPACE"' in reset:
        raise VerificationError("generated-state reset broadens ownership authority to the whole workspace")
    require_order(
        reset,
        (
            'normalize_snapshot_access "$source" "$label"',
            '"$PRIVATE_TREE_CLOSURE_PROBE" --mount-root "$source"',
            'git_closed -C "$source" clean -ffdx',
            'git_closed -C "$source" clean -nffdx',
            'assert_snapshot_exact "$source" "$label after generated-state reset"',
        ),
        "generated-state reset ordering",
    )
    expected_inspector_header = """docker_local run --rm --pull=never --network=none --read-only --user 0:0 \\
            --cap-drop=ALL --cap-add=DAC_READ_SEARCH \\
            --security-opt no-new-privileges \\
            --mount "type=bind,src=$path,dst=/inspect,readonly,bind-recursive=disabled" \\
            --mount "type=bind,src=$PRIVATE_TREE_CLOSURE_PROBE,dst=/probe.py,readonly" \\
            "$DEBIAN_IMAGE_ID" /usr/bin/python3 /probe.py --inode-root /inspect"""
    if inspector_header != expected_inspector_header:
        raise VerificationError("inode-closure inspector command is not the exact authority allowlist")
    expected_mutator_header = """docker_local run --rm --pull=never --network=none --read-only --user 0:0 \\
            --cap-drop=ALL --cap-add=CHOWN \\
            --security-opt no-new-privileges \\
            --mount "type=bind,src=$path,dst=/cleanup,bind-recursive=disabled" \\
            "$DEBIAN_IMAGE_ID" /bin/sh -ceu '"""
    if mutator_header != expected_mutator_header:
        raise VerificationError("private-tree mutator command is not the exact authority allowlist")
    for text, label in (
        ("--pull=never", "normalizer no-pull policy"),
        ("--network=none", "normalizer network isolation"),
        ("--read-only", "normalizer immutable container root"),
        ("--user 0:0", "normalizer root identity"),
        ("--cap-drop=ALL", "normalizer capability reset"),
        ("--cap-add=DAC_READ_SEARCH", "normalizer read-only inspection capability"),
        ("--cap-add=CHOWN", "normalizer chown capability"),
        ("--security-opt no-new-privileges", "normalizer privilege ceiling"),
        ('"$DEBIAN_IMAGE_ID" /bin/sh -ceu', "content-ID normalizer image"),
        ("/bin/chown --no-dereference 0:0 /cleanup", "normalizer process-owned root transition"),
        ("/usr/bin/find -P /cleanup -type d", "normalizer physical directory walk"),
        ("-exec /bin/chown --no-dereference 0:0 {}", "normalizer parent-first ownership transition"),
        ("-exec /bin/chmod u+rwx,go-w {}", "normalizer directory access repair"),
        ("/usr/bin/find -P /cleanup ! -type d ! -type l", "normalizer physical non-directory walk"),
        ("/usr/bin/find -P /cleanup -type l", "normalizer physical symlink walk"),
        ("/usr/bin/find -P /cleanup -depth -type d", "normalizer depth-first ownership restoration"),
        ('"$PRIVATE_TREE_CLOSURE_PROBE" --mount-root "$path"', "normalizer mount closure proof"),
        ('/probe.py --inode-root /inspect', "normalizer inode closure proof"),
        ("bind-recursive=disabled", "normalizer recursive-bind exclusion"),
        ('[ "$observed" = "$expected_identity" ]', "normalizer identity postcondition"),
        ('! -uid "$uid" -o ! -gid "$gid"', "normalizer ownership postcondition"),
        ('! -type l -perm /022', "normalizer non-writable postcondition"),
        ('-type d ! -perm -0700', "normalizer owner-access postcondition"),
    ):
        require_text(normalizer, text, label)
    if re.findall(r"--cap-add=([A-Z_]+)", normalizer) != ["DAC_READ_SEARCH", "CHOWN"]:
        raise VerificationError("normalizer capability partitions are not exact")
    if re.findall(r"--cap-add=([A-Z_]+)", reset_self_test) != ["CHOWN"]:
        raise VerificationError("reset fixture capability set is not exactly CHOWN")
    require_exact_count(normalizer, "bind-recursive=disabled", 2, "normalizer recursive-bind exclusions")
    require_exact_count(normalizer, '"$PRIVATE_TREE_CLOSURE_PROBE" --mount-root "$path"', 3, "normalizer mount closure stages")
    require_exact_count(normalizer, '[ "$observed" = "$expected_identity" ]', 3, "normalizer identity stages")
    require_text(
        normalizer,
        'if ! (verify_release_builder_image deb-builder "$DEBIAN_IMAGE_ID"); then\n'
        '        warn "$role normalization image failed provenance verification"\n'
        "        return 1\n"
        "    fi",
        "normalizer live image provenance",
    )
    require_order(
        normalizer,
        (
            '[ "$resolved" = "$path" ]',
            '[ "$observed" = "$expected_identity" ]',
            '"$PRIVATE_TREE_CLOSURE_PROBE" --mount-root "$path"',
            'verify_release_builder_image deb-builder "$DEBIAN_IMAGE_ID"',
            "--cap-add=DAC_READ_SEARCH",
            "disappeared after closure inspection",
            "identity changed after closure inspection",
            "gained a mount boundary after closure inspection",
            "--cap-add=CHOWN",
            "disappeared after normalization",
            "identity changed during normalization",
            "gained a mount boundary during normalization",
            "retains foreign ownership after normalization",
            "retains group/world-writable state after normalization",
            "retains an owner-inaccessible directory after normalization",
        ),
        "private-tree authority ordering",
    )
    for forbidden in (
        "--privileged",
        "--cap-add=ALL",
        "--device",
        "--pid=host",
        "--ipc=host",
        "--uts=host",
        "--userns=host",
        "--cgroupns=host",
        "--network=host",
        "--volume",
        "--mount=",
        "/var/run/docker.sock",
        "--entrypoint",
        "seccomp=unconfined",
        "apparmor=unconfined",
    ):
        if forbidden in normalizer:
            raise VerificationError(f"private-tree normalizer retains forbidden Docker authority: {forbidden}")
    require_text(snapshot_normalizer, '"$SOURCE_A"|"$SOURCE_B"', "snapshot normalizer scope")
    require_text(
        snapshot_normalizer,
        'offline_normalize_exact_tree "$source" "$expected" "$phase snapshot"',
        "snapshot normalizer exact-tree call",
    )
    require_text(snapshot_normalizer, 'chmod 0700 "$source"', "snapshot root mode restoration")
    require_text(snapshot_normalizer, '"$expected:$(id -u):$(id -g):700"', "snapshot root metadata proof")
    require_order(
        cleanup,
        (
            'if [ "$WINDOWS_UNSAFE" -eq 1 ] || [ "$KEEP_WORKSPACE" -eq 1 ]',
            "normalize_workspace_access",
            'remove_snapshot_worktree_if_registered "$SOURCE_A" "snapshot A"',
            'remove_snapshot_worktree_if_registered "$SOURCE_B" "snapshot B"',
            'rm -rf -- "$WORKSPACE"',
        ),
        "whole-workspace cleanup ordering",
    )
    require_text(
        cleanup,
        "cleanup failed; recorded private workspace state is %s",
        "cleanup failure preservation",
    )
    require_text(cleanup, "workspace_state=absent", "missing-workspace failure state")
    require_text(cleanup, "workspace_state=invalid", "changed-workspace failure state")
    require_text(cleanup, 'elif [ ! -e "$WORKSPACE" ] && [ ! -L "$WORKSPACE" ]', "missing workspace detection")
    require_exact_count(
        cleanup,
        '"$PRIVATE_TREE_CLOSURE_PROBE" --mount-root "$WORKSPACE"',
        2,
        "workspace cleanup mount closure",
    )
    require_order(
        cleanup,
        (
            "workspace_state=invalid",
            'if [ "$worktrees_safe" -eq 0 ]; then',
            'assert_snapshot_worktree_not_registered "$SOURCE_A" "snapshot A"',
            'assert_snapshot_worktree_not_registered "$SOURCE_B" "snapshot B"',
        ),
        "invalid-workspace registration inspection",
    )
    if 'elif [ -n "$DEBIAN_IMAGE_ID" ]' in cleanup:
        raise VerificationError("workspace cleanup can delete without an installed closure probe")
    if "chmod -R" in cleanup:
        raise VerificationError("workspace cleanup changes non-directory metadata recursively")
    for text, label in (
        ('[ "$(stat -c \'%d:%i\' -- "$WORKSPACE"', "unprivileged workspace identity proof"),
        ('"$PRIVATE_TREE_CLOSURE_PROBE" --mount-root "$WORKSPACE"', "unprivileged workspace mount closure"),
        ('find -P "$WORKSPACE" -type d', "unprivileged physical directory walk"),
        ('! -uid "$(id -u)" -o ! -gid "$(id -g)"', "unprivileged directory ownership proof"),
        ('-exec chmod u+rwx,go-w {} +', "directory-only removal access"),
        ('"$WORKSPACE_ID:$(id -u):$(id -g):700"', "unprivileged workspace root postcondition"),
    ):
        require_text(unprivileged_workspace_cleanup, text, label)
    require_exact_count(
        unprivileged_workspace_cleanup,
        '"$PRIVATE_TREE_CLOSURE_PROBE" --mount-root "$WORKSPACE"',
        2,
        "unprivileged workspace mount closure",
    )
    if "chmod -R" in unprivileged_workspace_cleanup or "! -type d" in unprivileged_workspace_cleanup:
        raise VerificationError("unprivileged workspace cleanup changes non-directory metadata")
    require_order(
        create_workspace,
        ("trap cleanup_release_workspace EXIT", 'mktemp -d /tmp/rustdesk-release.', 'chmod 0700 "$WORKSPACE"'),
        "workspace trap installation",
    )
    require_order(
        create_workspace,
        (
            'PRIVATE_TREE_CLOSURE_PROBE="$WORKSPACE/private-tree-closure.py"',
            'install -m 0500 "$PRIVATE_TREE_CLOSURE_SOURCE" "$PRIVATE_TREE_CLOSURE_PROBE"',
            '"$PINNED_HEAD:scripts/verify-private-tree-closure.py"',
            '[ "$private_hash" = "$commit_hash" ]',
            'DOCKER_CONFIG_DIR="$WORKSPACE/docker-config"',
        ),
        "private closure-probe installation",
    )
    require_text(cleanup, "trap '' HUP INT TERM", "cleanup signal exclusion")
    require_exact_count(cleanup, '[ "$status" -ne 0 ] || status=1', 1, "cleanup original-status preservation")
    require_order(
        cleanup,
        (
            "trap '' HUP INT TERM",
            'rm -rf -- "$WORKSPACE"',
            'sync_exact_directory "$REPO_ROOT" "$CANONICAL_PUBLICATION_PARENT_ID"',
            '[ "$status" -eq 0 ] && [ -n "$RELEASE_SUCCESS_MESSAGE" ]',
            'log "$RELEASE_SUCCESS_MESSAGE"',
            'exit "$status"',
        ),
        "success-after-cleanup finalization",
    )
    for marker in (
        'log "RELEASE OK:',
        'log "DOCTOR OK:',
        'log "build-release self-test: OK"',
        'log "build-release root-owned reset self-test: OK"',
    ):
        if marker in source:
            raise VerificationError("a build-release success marker bypasses final cleanup")
    for marker in (
        'RELEASE_SUCCESS_MESSAGE="RELEASE OK:',
        'RELEASE_SUCCESS_MESSAGE="DOCTOR OK:',
        'RELEASE_SUCCESS_MESSAGE="build-release self-test: OK"',
        'RELEASE_SUCCESS_MESSAGE="build-release root-owned reset self-test: OK"',
    ):
        require_text(source, marker, "deferred build-release success marker")
    for text, label in (
        ('"worktree",\n        "list",\n        "--porcelain",\n        "-z"', "exact Git worktree registry query"),
        ('process = subprocess.Popen(', "streamed Git worktree registry query"),
        ('stdout=subprocess.PIPE', "Git worktree registry output pipe"),
        ('MAX_WORKTREE_FIELD_BYTES = 65536', "bounded Git worktree registry field"),
        ('MAX_WORKTREE_TOTAL_BYTES = 4 * 1024 * 1024', "Git worktree registry total-byte bound"),
        ('MAX_WORKTREE_FIELDS = 65536', "Git worktree registry field-count bound"),
        ('QUERY_TIMEOUT_SECONDS = 15.0', "Git worktree registry deadline"),
        ('deadline = time.monotonic() + timeout_seconds', "Git worktree registry deadline derivation"),
        ('delimiter = pending.find(b"\\0", start)', "incremental NUL-delimited registry parser"),
        ('del pending[:start]', "bounded registry buffer compaction"),
        ('if len(pending) > MAX_WORKTREE_FIELD_BYTES:', "unterminated registry field bound"),
        ('if field_count > MAX_WORKTREE_FIELDS:', "Git worktree registry field-count enforcement"),
        ('if total_bytes > MAX_WORKTREE_TOTAL_BYTES:', "Git worktree registry byte-count enforcement"),
        ('chunk = os.read(stream.fileno(), READ_SIZE)', "bounded Git worktree registry read"),
        ('if not selector.select(remaining):', "Git worktree registry read deadline"),
        ('returncode = process.wait(timeout=remaining)', "Git worktree registry producer deadline"),
        ('process.terminate()', "Git worktree registry timeout termination"),
        ('process.kill()', "Git worktree registry timeout kill"),
        ('process.kill()\n        process.wait()', "Git worktree registry post-kill reap"),
        ('process = None', "pre-spawn Git producer ownership"),
        ('producer_reaped = False', "Git worktree registry producer ownership"),
        (
            'if process is not None and not producer_reaped:\n            stop_and_reap(process)',
            "unexpected registry exception reap",
        ),
        (
            'if returncode != 0:\n            raise RegistryQueryError(',
            "Git worktree registry producer-status rejection",
        ),
        (
            'if matches > 1:\n                raise RegistryQueryError(',
            "duplicate exact worktree rejection",
        ),
        ('needle = b"worktree " + os.fsencode(source)', "byte-exact worktree path match"),
        ('stale = None', "bounded stale-worktree result"),
        ('partial output followed by producer failure', "partial-output registry fixture"),
        ('an oversized field', "oversized registry-field fixture"),
        ('an unterminated field', "unterminated registry-field fixture"),
        ('duplicate exact worktree paths', "duplicate registry-path fixture"),
        ('a field count above the total-work bound', "registry field-count fixture"),
        ('a byte count above the total-work bound', "registry byte-count fixture"),
        ('a nonterminating producer', "registry deadline fixture"),
        ('a SIGTERM-ignoring producer', "registry forced-kill fixture"),
        ('os.waitpid(process.pid, os.WNOHANG)', "forced-kill already-reaped proof"),
        ('except ChildProcessError:', "forced-kill reaped result"),
        ('registry parser self-test missed a late stale worktree', "multi-chunk stale registry fixture"),
        ('except BaseException as exc:', "unexpected registry exception classification"),
        ('exit_status = 2', "unexpected registry exception status"),
        ('print("present" if result else "absent")', "explicit exact registry result token"),
        ('return 3', "post-spawn retained-producer fixture failure status"),
    ):
        require_text(worktree_query, text, label)
    require_text(source, "query_git_worktree_registry self-test", "worktree registry parser fixture dispatch")
    require_text(
        source,
        "query_git_worktree_registry self-test-unexpected >/dev/null 2>&1 || query_status=$?",
        "unexpected registry exception fixture dispatch",
    )
    require_text(
        source,
        "query_git_worktree_registry self-test-unexpected-after-spawn",
        "post-spawn unexpected registry exception fixture dispatch",
    )
    require_order(
        worktree_query,
        (
            'needle = b"worktree " + os.fsencode(source)',
            'stale_pattern = re.compile(',
            'process = None',
            'producer_reaped = False',
            'process = subprocess.Popen(',
            'if after_spawn is not None:',
            'after_spawn(process)',
        ),
        "pre-spawn registry setup and immediate producer ownership",
    )
    require_text(worktree_cleanup, 'present) return 0', "registered worktree token classification")
    require_text(worktree_cleanup, 'absent) return 1', "absent worktree token classification")
    for text, label in (
        ('result="$(query_git_worktree_registry exact "$source")" || return 2', "exact query failure propagation"),
        ('present) return 0', "registered worktree token classification"),
        ('absent) return 1', "absent worktree token classification"),
        ('*) return 2', "unexpected worktree token rejection"),
    ):
        require_text(worktree_registration_predicate, text, label)
    require_text(
        invalid_registration_inspection,
        '*) warn "$role registration cannot be inspected"; return 1',
        "invalid-workspace operational-error rejection",
    )
    for text, label in (
        ('worktree remove --force --force "$source"', "locked registered snapshot removal"),
        ('assert_no_stale_release_worktrees() {', "interrupted release worktree rejection"),
        ('assert_snapshot_worktree_not_registered() {', "invalid-workspace read-only registration inspection"),
    ):
        require_text(worktree_cleanup, text, label)
    if "worktree prune" in source:
        raise VerificationError("cleanup mutates unrelated worktree registrations")
    for forbidden in ('subprocess.run(', '.split(b"\\0")', "stale = []"):
        if forbidden in worktree_query:
            raise VerificationError("worktree registry query retains whole-registry buffering")
    if '.git-worktree-registry"\n    git_closed' in worktree_cleanup:
        raise VerificationError("worktree registry query materializes a followable workspace file")
    require_exact_count(
        worktree_cleanup,
        'worktree remove --force --force "$source"',
        2,
        "present and absent locked-worktree removal",
    )
    require_text(
        source,
        '--mount "type=bind,src=$SOURCE_A,dst=/fixture,bind-recursive=disabled"',
        "reset fixture recursive-bind exclusion",
    )
    require_text(
        source,
        'run_invalid_workspace_registration_self_test \\\n'
        '        || die "reset self-test did not inspect registration under an invalid workspace root"',
        "invalid-workspace registration fixture dispatch",
    )
    require_text(
        source,
        "invalid-workspace fixture accepted a surviving exact registration",
        "invalid-workspace surviving-registration fixture",
    )
    require_text(
        source,
        "printf 'build-release cleanup-missing self-test: REACHED\\n' >&2",
        "release missing-workspace reached marker",
    )
    require_order(
        create_snapshot,
        (
            'worktree add --quiet --detach "$source" "$PINNED_HEAD"',
            'chmod 0700 "$source"',
            'identity="$(stat -c \'%d:%i\' "$source")"',
            'assert_snapshot_exact "$source" "snapshot $label creation"',
        ),
        "snapshot registration and identity ordering",
    )
    for stale_state in (
        "SOURCE_A_ADD_PENDING",
        "SOURCE_B_ADD_PENDING",
        "SOURCE_A_REGISTERED",
        "SOURCE_B_REGISTERED",
    ):
        if stale_state in source:
            raise VerificationError("release cleanup retains unused in-memory worktree state")
    require_order(
        verification,
        (
            'reset_snapshot_build_state "$source" "$label before verification"',
            'run_snapshot_consumer "$label complete release verification"',
            'reset_snapshot_build_state "$source" "$label after verification"',
        ),
        "verification reset envelope",
    )
    require_order(
        build_snapshot,
        (
            'run_verification "$source" "$label"',
            'invoke_target "$label" "$target"',
            'reset_snapshot_build_state "$source" "$label after $target"',
            "verify_all_release_builder_images",
        ),
        "post-target reset ordering",
    )
    require_exact_count(source, "DOUBLE_BUILD=0", 3, "single target invocation per outer snapshot")
    require_text(source, 'build_snapshot A "$SOURCE_A"', "snapshot A target execution")
    require_text(source, 'build_snapshot B "$SOURCE_B"', "snapshot B target execution")
    require_text(source, "independent snapshot mismatch for $name", "all-artifact A/B comparison")
    require_text(source, "# reproducibility: independent-snapshots-a-equals-b", "manifest reproducibility identity")
    require_text(source, "renameat2 = libc.renameat2", "atomic final-dist exchange")
    if "normalize_final_dist_access" in source:
        raise VerificationError("final-dist transaction retains privileged destination normalization")
    if "chmod" in existing_dist:
        raise VerificationError("existing dist is weakened before the publication commit point")
    pre_exchange = atomic_install[: atomic_install.find("atomic_exchange_or_install")]
    if re.search(r"chmod[^\n]*\$destination", pre_exchange):
        raise VerificationError("existing dist is weakened before the publication commit point")
    require_text(exchange, "release staging identity changed before exchange", "exchange source identity proof")
    require_text(exchange, "release destination identity changed before exchange", "exchange destination identity proof")
    require_text(exchange, "installed release identity differs after exchange", "exchange installed identity proof")
    require_text(exchange, "os.fsync(destination_parent_fd)", "exchange destination-parent durability proof")
    require_text(exchange, "os.fsync(source_parent_fd)", "exchange transaction durability proof")
    require_text(
        exchange,
        "source_parent_fd, source_name, destination_parent_fd, destination_name, 1",
        "first-publication kernel no-clobber",
    )
    if "os.rename(\n            source_name" in exchange:
        raise VerificationError("first publication can replace a destination after its absence check")
    for text, label in (
        ("metadata.st_uid != uid", "publication parent owner proof"),
        ("stat.S_IWOTH", "publication parent world-writer rejection"),
        ("stat.S_IWGRP", "publication parent group-writer proof"),
        ("pwd.getpwall()", "publication parent primary-group enumeration"),
        ("grp.getgrgid", "publication parent supplementary-group enumeration"),
        ("system.posix_acl_access", "publication parent ACL rejection"),
    ):
        require_text(publication_parent, text, label)
    for text, label in (
        ("os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW", "directory-sync no-follow descriptor"),
        ("metadata = os.fstat(descriptor)", "directory-sync descriptor metadata"),
        ("(metadata.st_dev, metadata.st_ino) != expected", "directory-sync inode identity proof"),
        ("os.fsync(descriptor)", "directory-sync durability syscall"),
    ):
        require_text(directory_sync, text, label)
    require_order(
        directory_sync,
        (
            "descriptor = os.open(",
            "metadata = os.fstat(descriptor)",
            "(metadata.st_dev, metadata.st_ino) != expected",
            "os.fsync(descriptor)",
        ),
        "identity-bound directory synchronization",
    )
    require_order(
        exchange,
        (
            "source_parent_fd = os.open(source_parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)",
            "destination_parent_fd = os.open(",
            "source_parent_stat = os.fstat(source_parent_fd)",
            "release transaction identity changed before exchange",
            "destination_parent_stat = os.fstat(destination_parent_fd)",
            "release parent identity changed before exchange",
            "identity(source_parent_fd, source_name)",
            "renameat2(",
            "source_parent_fd, source_name, destination_parent_fd, destination_name, 1",
            "source_parent_fd, source_name, destination_parent_fd, destination_name, 2",
            "identity(destination_parent_fd, destination_name)",
            "os.fsync(destination_parent_fd)",
            "os.fsync(source_parent_fd)",
        ),
        "dirfd-bound final exchange",
    )
    for text, label in (
        ("rustdesk-release-transaction-v1", "versioned publication record"),
        ("transaction_id=", "record transaction identity"),
        ("payload_id=", "record payload identity"),
        ("old_id=", "record prior-destination identity"),
        ("manifest_sha256=", "record manifest digest"),
        ("os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW", "exclusive no-follow record creation"),
        ("os.fsync(record_fd)", "publication record durability"),
        ("os.rename(temporary, record", "atomic publication record commit"),
        ("os.fsync(transaction_fd)", "transaction-directory record durability"),
        ("os.fsync(parent_fd)", "publication-parent record durability"),
    ):
        require_text(record_writer, text, label)
    for text, label in (
        ("os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW", "payload root no-follow descriptor"),
        ("stat.S_IMODE(directory.st_mode) != 0o700", "exchange-capable payload root mode"),
        ("metadata.st_nlink != 1", "payload hardlink rejection"),
        ("stat.S_IMODE(metadata.st_mode) != 0o444", "payload immutable-file mode proof"),
        ("os.fsync(descriptor)", "payload file durability"),
        ("os.fsync(directory_fd)", "payload directory durability"),
        ("payload_metadata = os.stat", "payload name identity proof"),
        ("os.fsync(transaction_fd)", "payload-name parent durability"),
    ):
        require_text(payload_sync, text, label)
    require_order(
        payload_sync,
        (
            "os.fsync(descriptor)",
            "os.fsync(directory_fd)",
            "transaction_fd = os.open(",
            'payload_metadata = os.stat("payload"',
            "os.fsync(transaction_fd)",
        ),
        "payload-name-before-record durability",
    )
    require_order(
        atomic_install,
        (
            'strict_manifest_proof "$FINAL_STAGE"',
            "sync_staged_publication_payload",
            'write_publication_record "$manifest_hash"',
        ),
        "payload-before-record durability ordering",
    )
    for text, label in (
        ("record_metadata.st_nlink != 1", "record hardlink rejection"),
        ("len(contents) > 4096", "record size bound"),
        ('lines[0] != "rustdesk-release-transaction-v1"', "record version proof"),
        ('values["transaction_id"] != transaction_identity', "record inode binding"),
        ('values["destination"] != expected_destination', "record destination binding"),
        ('values["parent_id"] != expected_parent', "record parent binding"),
        ('re.fullmatch(r"[0-9a-f]{64}", values["manifest_sha256"])', "record manifest validation"),
    ):
        require_text(record_reader, text, label)
    for text, label in (
        ('os.open("record", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=transaction_fd)', "record dirfd/no-follow open"),
        ("record_metadata = os.fstat(record_fd)", "opened-record metadata proof"),
        ("chunks.append(chunk)", "complete bounded record read"),
    ):
        require_text(record_reader, text, label)
    for text, label in (
        ("published_fd = os.open(destination, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)", "published root descriptor"),
        ("published release identity changed before recovery sync", "published root identity proof"),
        ("os.fsync(published_fd)", "published root durability"),
        ("os.fsync(transaction_fd)", "post-exchange transaction durability"),
        ("os.fsync(destination_fd)", "post-exchange parent durability"),
    ):
        require_text(publication_sync, text, label)
    for text, label in (
        ('chmod 0555 "$destination"', "post-exchange immutable-root finalization"),
        ('"$root_identity:$(id -u):$(id -g):555"', "published-root identity/mode postcondition"),
        ("published dist identity changed before root sync", "finalized-root identity reproof"),
        ("os.fsync(descriptor)", "finalized-root durability"),
    ):
        require_text(published_proof, text, label)
    require_text(
        transaction_removal,
        'os.rename(source_name, destination_name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)',
        "durable active-to-discard transition",
    )
    require_text(transaction_removal, "os.fsync(parent_fd)", "discard-transition durability")
    require_text(
        transaction_removal,
        '"$PRIVATE_TREE_CLOSURE_PROBE" --mount-root "$FINAL_TRANSACTION"',
        "transaction mount closure",
    )
    require_text(
        transaction_removal,
        '"$(path_identity "$FINAL_TRANSACTION")" = "$expected_identity"',
        "transaction identity reproof",
    )
    require_text(
        transaction_removal,
        'find -P "$FINAL_TRANSACTION" -type d -exec chmod u+rwx,go-w {} +',
        "transaction directory-only removal access",
    )
    if 'chmod -R' in transaction_removal or '! -type d' in transaction_removal:
        raise VerificationError("transaction removal changes non-directory metadata")
    require_order(
        transaction_removal,
        (
            'rm -rf -- "$FINAL_TRANSACTION"',
            "publication parent identity changed before discard-removal sync",
            "os.fsync(descriptor)",
            'FINAL_TRANSACTION=""',
        ),
        "durable discard removal",
    )
    require_text(
        reconciliation,
        '"$FINAL_DESTINATION" "$commit" "$version" "$epoch" "$manifest_hash"',
        "record-bound published-set proof",
    )
    require_text(reconciliation, "sync_publication_directories", "post-exchange durability recovery")
    require_text(reconciliation, 'FINAL_PUBLICATION_STATE=published', "publication commit state")
    require_text(
        reconciliation,
        '[ "$FINAL_PUBLICATION_STATE" = idle ] || [ "$FINAL_PUBLICATION_STATE" = published ]',
        "terminal publication cleanup state",
    )
    require_text(
        reconciliation,
        'remove_registered_final_transaction "$FINAL_TRANSACTION_ID"',
        "post-commit transaction removal",
    )
    require_exact_count(
        reconciliation,
        'remove_registered_final_transaction "$FINAL_TRANSACTION_ID"',
        3,
        "post-commit transaction removal",
    )
    require_order(
        reconciliation,
        (
            '[ "$destination_identity" = "$FINAL_STAGE_ID" ]',
            "prove_recorded_published_dist",
            "sync_publication_directories",
            "FINAL_PUBLICATION_STATE=published",
            'remove_registered_final_transaction "$FINAL_TRANSACTION_ID"',
        ),
        "publication proof before displaced-set removal",
    )
    for text, label in (
        ('discards=("$parent/.$base-release-discard."*)', "restart discard discovery"),
        ('transactions=("$parent/.$base-release-transaction."*)', "restart active-transaction discovery"),
        ('[ "${#transactions[@]}" -le 1 ]', "ambiguous transaction-count rejection"),
        ('read_publication_record "$transaction" "$base" "$parent_id"', "restart record proof"),
        ("reconcile_final_publication || return 1", "restart identity reconciliation"),
        ('sync_exact_directory "$parent" "$parent_id" "publication recovery parent"', "empty recovery parent sync"),
    ):
        require_text(recovery, text, label)
    require_exact_count(
        recovery,
        'sync_exact_directory "$parent" "$parent_id" "publication recovery parent"',
        2,
        "recovery parent synchronization stages",
    )
    require_order(
        recovery,
        (
            'remove_registered_final_transaction "$transaction_id"',
            'sync_exact_directory "$parent" "$parent_id" "publication recovery parent"',
            '[ "${#transactions[@]}" -le 1 ]',
            'if [ "${#transactions[@]}" -eq 0 ]',
        ),
        "durable empty-recovery observation",
    )
    if "FINAL_PRESERVE_STATE" in source:
        raise VerificationError("publication still relies on process-local preservation state")
    require_order(
        atomic_install,
        (
            'recover_pending_publications "$parent" "$destination"',
            'prepare_existing_dist_removal "$destination"',
            'FINAL_OLD_ID="$(stat -c',
            "FINAL_PUBLICATION_STATE=transaction-initializing",
            'FINAL_TRANSACTION="$(umask 077 && mktemp',
            'FINAL_STAGE="$FINAL_TRANSACTION/payload"',
            'strict_manifest_proof "$FINAL_STAGE"',
            'write_publication_record "$manifest_hash"',
            'read_publication_record "$FINAL_TRANSACTION"',
            'FINAL_PUBLICATION_STATE=exchange-pending',
            'atomic_exchange_or_install "$FINAL_STAGE"',
            "reconcile_final_publication",
            '[ "$FINAL_PUBLICATION_STATE" = published ]',
            "clear_final_publication_state",
        ),
        "failure-atomic final-dist installation",
    )
    if 'chmod 0555 "$FINAL_STAGE"' in atomic_install:
        raise VerificationError("cross-parent publication payload is made non-writable before exchange")
    require_order(
        atomic_install,
        (
            'if [ "$atomic_status" -ne 0 ]',
            "reconcile_final_publication",
            "clear_final_publication_state",
            'die "atomic final-dist installation failed"',
        ),
        "conclusive failed-exchange cleanup",
    )
    require_order(
        cleanup,
        (
            "reconcile_final_publication",
            "normalize_workspace_access",
            'rm -rf -- "$WORKSPACE"',
        ),
        "publication reconciliation before workspace cleanup",
    )
    require_text(source, "git --no-replace-objects", "Git replacement-object suppression")
    require_text(source, "Git grafts are forbidden for release builds", "Git graft rejection")
    require_text(source, "Git object alternates are forbidden for release builds", "Git alternate rejection")
    require_text(source, "Git replacement refs are forbidden for release builds", "Git replacement-ref rejection")
    require_text(source, "GIT_NO_REPLACE_OBJECTS=1", "child replacement-object suppression")
    for text, label in (
        ('exec {PUBLICATION_LOCK_FD}< "$common_dir"', "repository-directory publication lock descriptor"),
        ('flock -n "$PUBLICATION_LOCK_FD"', "exclusive publication lock"),
        ('"/proc/self/fd/$PUBLICATION_LOCK_FD"', "publication lock descriptor identity proof"),
        ('CANONICAL_PUBLICATION_PARENT_ID="$(assert_single_writer_publication_parent "$REPO_ROOT")"', "canonical parent identity capture"),
        ('sync_exact_directory "$REPO_ROOT" "$CANONICAL_PUBLICATION_PARENT_ID"', "final parent durability barrier"),
    ):
        require_text(source, text, label)
    require_text(source, '--verify-apk "$SET_A/rustdesk-arm64.apk"', "staged final APK certificate proof")
    require_text(source, "WINDOWS_UNSAFE=1", "Windows-owned state guard")
    require_text(source, "workspace retained because VM ownership is unresolved", "Windows failure retention")
    require_text(source, "run_self_test()", "release behavioral fixture")
    require_text(source, "release self-test did not execute exactly six target commands", "target execution fixture")
    require_text(source, "release self-test did not use two independent snapshots", "snapshot independence fixture")
    require_text(source, "release self-test target outputs are not distinct", "output isolation fixture")
    for text, label in (
        ("verify_release_builder_image deb-builder", "reset fixture image provenance"),
        ("negative control removed inaccessible root-owned state", "reset fixture negative control"),
        ('reset_snapshot_build_state "$SOURCE_A" "root-owned reset self-test"', "reset fixture production-call proof"),
        ("external symlink target", "reset fixture no-follow proof"),
        ("accepted an inode linked outside the snapshot", "reset fixture external-hardlink rejection"),
        ("internal-a", "reset fixture closed internal hardlink"),
        ("both root-owned mode-0000 directories", "reset fixture dual hostile-mode proof"),
        ("hostile Flutter directory", "reset fixture dual negative control"),
        ("worktree query followed its hostile fixed-name symlink", "registry-query no-follow fixture"),
        ("present locked worktree", "present locked-worktree fixture"),
        ("absent locked worktree", "absent locked-worktree fixture"),
        ("build-release root-owned reset self-test: OK", "reset fixture success marker"),
    ):
        require_text(reset_self_test, text, label)
    require_text(
        reset_self_test,
        'if git_closed -C "$SOURCE_A" clean -ffdx >/dev/null 2>"$WORKSPACE/negative-clean.log"; then',
        "reset fixture live negative control",
    )
    require_text(
        reset_self_test,
        "metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0",
        "reset fixture live hostile-mode predicate",
    )
    require_text(
        reset_self_test,
        'assert_release_source_state "reset self-test"',
        "reset fixture clean exact-HEAD caller",
    )
    require_text(
        create_workspace,
        'if [ "$SELF_TEST" -eq 0 ]; then',
        "reset fixture pinned closure-probe provenance",
    )
    require_order(
        reset_self_test,
        (
            'offline_normalize_exact_tree "$SOURCE_A" "$source_identity" "external-hardlink rejection fixture"',
            'rm -rf -- "$SOURCE_A/target"',
            'docker_local run --rm --pull=never',
            "for path in sys.argv[1:]",
            'check-ignore -q target/reset-proof/locked',
            'if git_closed -C "$SOURCE_A" clean -ffdx',
            "negative control did not preserve the hostile directory",
            "negative control did not preserve the hostile Flutter directory",
            'reset_snapshot_build_state "$SOURCE_A" "root-owned reset self-test"',
            '[ ! -e "$SOURCE_A/target/reset-proof" ]',
            '[ ! -e "$SOURCE_A/flutter/.dart_tool/reset-proof" ]',
            "external symlink target",
        ),
        "reset fixture adversarial ordering",
    )
    require_text(
        main,
        'if [ "$SELF_TEST_RESET" -eq 1 ]; then\n        run_reset_self_test\n        return 0',
        "reset fixture main dispatch",
    )
    for text, label in (
        ("first-publication fixture", "no-prior-destination fixture"),
        ("no-clobber fixture", "first-publication no-clobber fixture"),
        ("incomplete transaction restart fixture", "record-initialization restart fixture"),
        ("pre-exchange restart fixture", "pre-exchange restart fixture"),
        ("post-exchange restart fixture", "post-exchange restart fixture"),
        ("discard restart fixture", "terminal-discard restart fixture"),
        ("discard-removal gap restart", "post-removal parent-sync restart fixture"),
        ("combined restart fixture", "stale-worktree plus publication fixture"),
        ("forget_final_publication_fixture_state", "process-memory loss fixture"),
        ('recover_pending_publications "$parent" "$destination"', "on-disk restart recovery fixture"),
        ('atomic_exchange_or_install "$FINAL_STAGE" "$destination"', "post-exchange fixture production helper"),
        ("prove_published_dist", "post-exchange fixture published proof"),
    ):
        require_text(publication_self_test, text, label)
    require_order(
        publication_self_test,
        (
            "FINAL_PUBLICATION_STATE=transaction-initializing",
            "forget_final_publication_fixture_state",
            "incomplete transaction restart fixture could not recover",
            "clear_final_publication_fixture_state",
            'stage_publication_fixture "$source" "$destination"',
            "forget_final_publication_fixture_state",
            "pre-exchange restart fixture could not recover",
            "clear_final_publication_fixture_state",
            'stage_publication_fixture "$source" "$destination"',
            'atomic_exchange_or_install "$FINAL_STAGE" "$destination"',
            "forget_final_publication_fixture_state",
            "post-exchange restart fixture could not recover",
            "clear_final_publication_fixture_state",
            'stage_publication_fixture "$source" "$destination"',
            "commit_registered_final_transaction_discard",
            "forget_final_publication_fixture_state",
            "discard restart fixture could not recover",
        ),
        "publication restart fixture ordering",
    )
    require_text(
        source,
        'run_publication_reconciliation_self_test "$SET_A"',
        "publication reconciliation fixture dispatch",
    )
    require_text(
        source,
        'assert_single_writer_publication_parent "$REPO_ROOT" >/dev/null',
        "canonical publication-parent fixture",
    )
    require_exact_count(main, "compare_snapshots\n", 1, "release transaction")
    require_order(
        main,
        (
            'prepare_release_snapshots\n',
            'build_snapshot A "$SOURCE_A"',
            'build_snapshot B "$SOURCE_B"',
            'run_snapshot_consumer "final APK certificate proof"',
            'reset_snapshot_build_state "$SOURCE_A" "after final APK certificate proof"',
            "compare_snapshots\n",
            'write_manifest "$SET_A"',
            'assert_release_source_state "before final dist installation"',
            'assert_live_origin_master "before final dist installation"',
            'atomic_install_dist "$SET_A"',
            'RELEASE_SUCCESS_MESSAGE="RELEASE OK:',
        ),
        "release transaction",
    )


def validate_target_scripts(debian, android, pins):
    for source, label, mismatch, role, pin in (
        (debian, "Debian", "double-build SHA mismatch", "deb-builder", "DEB_BUILDER_IMAGE_ID"),
        (
            android,
            "Android",
            "double-build APK SHA mismatch",
            "android-builder",
            "ANDROID_BUILDER_IMAGE_ID",
        ),
    ):
        require_text(source, 'if [ "${DOUBLE_BUILD:-1}" = "1" ]; then', f"{label} default double build")
        require_text(source, mismatch, f"{label} A/B mismatch rejection")
        require_text(source, '--user "$BUILD_UID:$BUILD_GID"', f"{label} user-mapped container")
        require_text(source, "RELEASE_DOCKER_IMAGE_ID", f"{label} content-ID image binding")
        require_text(source, "unix:///var/run/docker.sock", f"{label} local Docker binding")
        require_text(source, f'IMAGE_ID="${{{pin}:-}}"', f"{label} pinned image ID selection")
        require_text(
            source,
            f'require_pinned_builder_image {role} "$IMAGE_ID"',
            f"{label} builder provenance verification",
        )
        require_text(source, "RUSTDESK_RELEASE_ONLINE_SNAPSHOT", f"{label} release snapshot contract")
        require_text(source, 'create_private_online_snapshot "$ONLINE_SNAPSHOT_PARENT"', f"{label} direct snapshot")
        require_text(source, 'ONLINE_DIR="$ONLINE_SNAPSHOT_PARENT/online"', f"{label} snapshot-only consumption")
        require_count(source, "verify_active_online_snapshot", 4, f"{label} consumer snapshot checks")
        require_text(source, "current-UID mode-0700 directory", f"{label} snapshot owner/mode proof")
        if "IMAGE_NAME=" in source or "docker image inspect" in source:
            raise VerificationError(f"{label} target retains mutable builder tag resolution")
    require_text(pins, 'ANDROID_SIGNING_CERT_SHA256="1091322BA0425AFA1EB50DEEAE439A5FFFE2B1DD82C82B04515D9290A0CEEFA9"', "Android certificate pin")
    require_text(android, "assert_private_signing_files", "Android private signing-file proof")
    require_text(android, "mode 0600", "Android signing-file mode")
    require_text(android, "mode 0700", "Android signing-parent mode")
    require_count(android, "ANDROID_SIGNING_CERT_SHA256", 6, "Android certificate identity checks")
    require_text(android, "apksigner verify -Werr", "final APK signature verification")
    require_text(android, "--verify-apk", "standalone final APK identity proof")


def validate_publisher(source):
    require_text(
        source,
        "#!/usr/bin/env -S -i /usr/bin/bash --noprofile --norc",
        "publisher empty-environment entrypoint",
    )
    if re.search(r"^\s*--push\)", source, re.MULTILINE):
        raise VerificationError("publisher source-push mode is present")
    if "release delete" in source or "git push --delete" in source or re.search(r"\bgh(?:_closed)?\s+release\b", source):
        raise VerificationError("publisher contains uncertain-state cleanup")
    require_text(source, "EXPECTED_REPO_ID=1268555599", "numeric GitHub repository identity pin")
    require_text(source, "EXPECTED_PUBLISHER_ID=85248530", "numeric publisher identity pin")
    require_text(source, "one canonical https://github.com/OWNER/REPO.git URL", "canonical Git origin")
    require_text(source, "GH_CONFIG_DIR=\"$GH_CONFIG_SNAPSHOT\" GH_HOST=github.com", "closed GitHub CLI context")
    require_text(source, "X-GitHub-Api-Version: $GITHUB_API_VERSION", "pinned GitHub REST version")
    require_text(source, "authenticated GitHub principal is not the authorized publisher", "publisher principal proof")
    require_text(source, "authenticated publisher lacks repository push permission", "draft-visible push authority proof")
    require_text(source, "flock -n 9", "exclusive publication lock")
    require_text(source, "set -o noclobber", "non-clobbering publication lock creation")
    require_text(source, "snapshot_commit_file FORK_VERSION", "commit-sourced version metadata")
    require_text(source, "dist is not the exact five-file publication set", "exact source dist set")
    require_text(source, "dist/{name} is mutable, hardlinked, or empty", "descriptor-based dist snapshot")
    require_text(source, 'repos/$REPO_SLUG/releases?per_page=100', "paginated release inventory")
    require_text(source, 'repos/$REPO_SLUG/releases/$RELEASE_ID/assets?per_page=100', "paginated numeric asset inventory")
    require_exact_count(source, "--paginate", 4, "exhaustive REST inventory calls and stub enforcement")
    if "--exclude-drafts" in source:
        raise VerificationError("publisher excludes drafts from uniqueness")
    require_text(source, 'rev-parse --verify "refs/tags/$tag^{commit}"', "existing release tag-to-commit proof")
    require_text(source, 'push --atomic "$ORIGIN_URL"', "atomic remote uniqueness ref")
    require_text(
        source,
        'TAG="fork-version-$FORK_VER-commit-$HEAD_FULL"',
        "version-and-full-commit release tag",
    )
    if "VERSION_TAG" in source:
        raise VerificationError("publisher retains a mutable secondary version tag")
    require_text(
        source,
        'gh_api "repos/$REPO_SLUG/immutable-releases" --method GET',
        "repository immutable-release policy proof",
    )
    require_text(source, 'value["enabled"] is not True', "enabled immutable-release policy")
    require_text(
        source,
        'value["immutable"] is not (draft == "0")',
        "published release immutability proof",
    )
    require_exact_count(source, "parse_constant=reject_nonfinite", 7, "non-finite JSON rejection")
    require_text(source, 'gh_api "repos/$REPO_SLUG/releases" --method POST --input "$create_payload"', "numeric-ID draft creation")
    require_text(source, 'gh_api "repos/$REPO_SLUG/releases/$RELEASE_ID" --method PATCH', "numeric-ID publication")
    require_text(source, 'gh_api "repos/$REPO_SLUG/releases/assets/$asset_id" --method GET', "numeric-ID asset download")
    require_text(source, "final_publication_barrier() {", "final pre-publication barrier")
    require_text(source, 'strict_release_inventory "$RELEASE_ID" 1', "barrier release inventory")
    require_text(source, 'assert_github_identity "final pre-publication barrier"', "barrier repository identity")
    require_text(
        source,
        'assert_immutable_release_policy "final pre-publication barrier"',
        "barrier immutable-release policy",
    )
    require_text(source, "TRANSACTION_STATE=draft-create-requested", "uncertain draft mutation state")
    require_text(source, 'TRANSACTION_STATE="asset-upload-requested:$name"', "uncertain asset mutation state")
    require_text(source, 'TRANSACTION_STATE="publish-requested:$RELEASE_ID"', "uncertain publish mutation state")
    require_exact_count(source, "--no-replace-objects -c core.hooksPath=/dev/null", 2, "publisher Git replacement suppression")
    require_text(source, "Git grafts are forbidden for publication", "publisher Git graft rejection")
    require_text(source, "GitHub release field {key} has a hostile or missing type", "hostile schema rejection")
    require_text(source, "GitHub release asset size differs", "remote size proof")
    require_exact_count(source, "GitHub release asset server digest differs", 2, "server digest proof")
    require_text(source, "remote digest differs", "remote digest proof")
    require_text(source, "no remote object was deleted", "explicit failure reconciliation")
    require_text(source, "write_stub_gh", "stub GitHub fixture")
    require_text(source, "write_stub_git", "stub Git fixture")
    require_text(source, "publisher self-test accepted a hostile asset schema", "hostile fixture")
    require_text(source, "publisher self-test accepted a hostile server digest", "hostile digest fixture")
    require_text(source, "publisher self-test accepted a hostile numeric release ID", "hostile ID fixture")
    require_text(source, "publisher self-test accepted a non-finite JSON number", "non-finite fixture")
    require_text(source, "publisher self-test accepted hostile downloaded bytes", "hostile download fixture")
    require_order(
        source,
        (
            "TRANSACTION_STATE=draft-create-requested",
            'gh_api "repos/$REPO_SLUG/releases" --method POST',
            "view_and_validate_release draft-created 1 0",
            'for name in "${PUBLICATION_ASSETS[@]}"',
            "view_and_validate_release draft-uploaded 1 5",
            "download_and_verify_remote_assets draft",
            "final_publication_barrier",
            'gh_api "repos/$REPO_SLUG/releases/$RELEASE_ID" --method PATCH',
            "view_and_validate_release published 0 5",
            "download_and_verify_remote_assets published",
        ),
        "draft-first publication postconditions",
    )


def validate_fork_version(source):
    require_text(source, "fork_version_real_date() {", "real calendar validation")
    require_text(source, 'date -u -d "$value 00:00:00Z" +%F', "calendar normalization")
    require_text(source, "for heading in \"${release_headings[@]}\"", "all-heading validation")
    require_text(source, "duplicate release version", "duplicate release rejection")
    require_text(source, "must increment", "same-base exact increment")
    require_text(source, "must start at hardened.1", "base-transition reset")
    require_text(source, "fork_version_base_is_newer", "base ordering")
    require_text(source, "release dates must be newest-first", "date ordering")


def validate_docs(source):
    for text in (
        "two private mode-0700 detached exact-commit worktrees",
        "independent target, Flutter, generated, output, and Windows state",
        "atomically exchanged into `dist/`",
        "public certificate SHA-256 pinned in `scripts/pins.env`",
        "All five assets are uploaded to that draft",
        "never deletes uncertain remote state",
    ):
        require_text(source, text, "versioning transaction documentation")


def validate_scan_contract(scan, verify, apple, release):
    require_text(scan, "readonly VERIFY_SCAN_GREP=/usr/bin/grep", "fixed verifier scanner")
    require_text(scan, "metadata = os.lstat(path)", "scanner no-follow metadata proof")
    require_text(scan, "metadata.st_uid != 0", "scanner root-owner proof")
    require_text(scan, "metadata.st_mode & 0o022", "scanner write-mode proof")
    require_text(scan, 'else\n    status=$?\n  fi', "scanner status capture")
    require_text(scan, "if [ \"$status\" -eq 1 ]; then", "scanner no-match status")
    require_text(scan, "scanner failed with status", "scanner operational-failure diagnostic")
    require_text(scan, "exit 1", "scanner operational-failure termination")
    require_text(scan, "verify_scan_self_test() {", "scanner status self-test")
    for source, label, minimum in (
        (verify, "verify", 18),
        (apple, "Apple", 4),
    ):
        require_text(source, "source scripts/verify-scan.sh", f"{label} scanner loading")
        require_text(source, "verify_scan_preflight", f"{label} scanner preflight")
        require_text(source, "verify_scan_self_test", f"{label} scanner status self-test")
        require_count(source, "verify_scan_capture", minimum, f"{label} fail-loud scans")
        if re.search(r"(?:^|\W)rg(?:$|\W)", source):
            raise VerificationError(f"{label} retains an undeclared ripgrep dependency")
    require_text(release, "source scripts/verify-scan.sh", "release scanner loading")
    require_text(release, "verify_scan_preflight || exit 1", "release scanner preflight")
    require_text(release, "--preflight)", "release side-effect-free preflight mode")
    require_text(
        verify,
        "^[[:space:]]*virtual_display[[:space:]]*=",
        "anchored IDD dependency scan",
    )


def validate_smoke_contract(smoke):
    for text, label in (
        ('fixture=/tmp/rd-smoke-nonroot', "non-root fixture root"),
        ('install -d -o root -g "$gid" -m 0750 "$fixture" "$fixture/bin"', "protected fixture directories"),
        ('install -d -o rduser -g "$gid" -m 0700 "$fixture/home"', "private non-root home"),
        ('install -o root -g "$gid" -m 0550 target/debug/rustdesk "$fixture/bin/rustdesk"', "portable server fixture"),
        ('install -o root -g "$gid" -m 0550 target/debug/examples/seed_password "$fixture/bin/seed_password"', "password seeder fixture"),
        ('install -o root -g "$gid" -m 0550 target/debug/examples/probe_client "$fixture/bin/probe_client"', "probe client fixture"),
        ('install -o root -g "$gid" -m 0440 target/smoke-bind-loopback.so "$fixture/bin/smoke-bind-loopback.so"', "bind shim fixture"),
        ('su -s /bin/bash -c /tmp/rd-smoke-nonroot/run.sh rduser', "non-root runner dispatch"),
        ('echo SOURCE_BIND_UNCHANGED=yes', "source-bind postcondition"),
        ("SERVER_EXIT=0", "server reaping assertion"),
        ("SOURCE_BIND_UNCHANGED=yes", "source-bind assertion"),
    ):
        require_text(smoke, text, label)
    if smoke.count('install -o root -g "$gid"') != 4:
        raise VerificationError("non-root smoke fixture must stage exactly four root-owned runtime files")
    marker = 'cat > "$fixture/run.sh" <<"EOS"\n'
    start = smoke.find(marker)
    if start < 0:
        raise VerificationError("non-root smoke runner heredoc is absent")
    start += len(marker)
    end = smoke.find("\nEOS\n", start)
    if end < 0:
        raise VerificationError("non-root smoke runner heredoc is unterminated")
    runner = smoke[start:end]
    for forbidden in ("/work", "target/debug", "pkill"):
        if forbidden in runner:
            raise VerificationError(f"non-root smoke runner retains forbidden source/process authority: {forbidden}")
    require_text(runner, 'export HOME=/tmp/rd-smoke-nonroot/home', "fixture-owned runner home")
    require_text(runner, 'kill -TERM "$SRV"', "exact server stop")
    require_text(runner, 'wait "$SRV"', "exact server reap")
    require_text(runner, 'SERVICE_ROLE_MARKER=absent', "portable-role proof")


def validate_faillo_contract(source):
    output_contract = extract_between(
        source,
        "script_die_output_is_expected() {",
        "\n}\nrun_script_die() {",
        "fail-loud result classifier",
    )
    probe_cleanup = extract_between(
        source,
        "  cleanup_dirty_probe() {",
        "\n  }\n  trap cleanup_dirty_probe EXIT",
        "dirty-probe cleanup",
    )
    probe_lifecycle = extract_between(
        source,
        "run_with_dirty_probe() (",
        "\n)\n\nexercise_dirty_probe_cleanup_failure() (",
        "dirty-probe lifecycle",
    )
    reached_contract = extract_between(
        source,
        "reached_failure_is_expected() {",
        "\n}\nrun_script_die_reached_without_marker() {",
        "reached-state failure classifier",
    )
    require_text(source, "release source-gate preflight accepts the fixed scanner", "scanner preflight proof")
    require_text(source, "verifier scanner rejects an operational error", "scanner error proof")
    require_text(
        source,
        "pinned offline reset removes root-owned inaccessible generated state",
        "root-owned reset behavioral proof",
    )
    require_text(
        source,
        '"build-release root-owned reset self-test: OK"',
        "root-owned reset success marker",
    )
    require_text(
        source,
        'scripts/build-release.sh --self-test-reset',
        "root-owned reset exact command",
    )
    for text, label in (
        ("run_with_dirty_probe()", "exclusive dirty-probe lifecycle"),
        ('mktemp "$probe_parent/.faillo-${label}.XXXXXXXXXX"', "random exclusive dirty probe"),
        ("verify.sh emits success only after workspace removal", "verify cleanup success fixture"),
        ("verify.sh rejects a missing recorded workspace", "verify missing-workspace fixture"),
        ("build-release.sh rejects a missing recorded workspace", "release missing-workspace fixture"),
        ("run_script_die_reached_without_marker", "reached-state premature marker rejection"),
        ('[ "$observed" = "$probe_id" ] || cleanup_failed=1', "dirty-probe identity verification"),
        ('rm -f -- "$probe" || cleanup_failed=1', "dirty-probe exact removal"),
        ('[ ! -e "$probe" ] && [ ! -L "$probe" ] || cleanup_failed=1', "dirty-probe absence postcondition"),
        (
            "printf 'BUILD-FAILLO: DIRTY-PROBE-CLEANUP-FAILURE: %s\\n' \"$probe\" >&2",
            "dirty-probe cleanup failure marker emission",
        ),
        ("grep -qF 'BUILD-FAILLO: DIRTY-PROBE-CLEANUP-FAILURE:'", "dirty-probe cleanup rejection"),
        ('[ "$rc" -ne 125 ]', "dirty-probe cleanup status rejection"),
        ("status=125", "distinct dirty-probe cleanup status"),
        ("exercise_dirty_probe_cleanup_failure()", "dirty-probe cleanup behavioral fixture"),
        ('[ "$rc" -eq 125 ]', "dirty-probe fixture status proof"),
        ("dirty-probe cleanup failure cannot satisfy a fail-loud case", "dirty-probe fixture dispatch"),
        ("BUILD-FAILLO: DIRTY-PROBE-READY:", "dirty-probe reached-state marker"),
        ('grep -qF "$expected"', "exact fail-loud diagnostic classification"),
        ("verify workspace missing self-test: REACHED", "verify missing-workspace target-state proof"),
        ("build-release cleanup-missing self-test: REACHED", "release missing-workspace target-state proof"),
        ("exercise_reached_failure_classifier()", "reached-state classifier behavioral fixture"),
        ("reached-state classifier rejects every incomplete lifecycle result", "reached-state fixture dispatch"),
    ):
        require_text(source, text, label)
    require_text(
        output_contract,
        "grep -qF 'BUILD-FAILLO: DIRTY-PROBE-CLEANUP-FAILURE:'",
        "dirty-probe cleanup rejection",
    )
    require_text(output_contract, '[ "$rc" -ne 125 ]', "dirty-probe cleanup status rejection")
    require_text(
        probe_cleanup,
        "printf 'BUILD-FAILLO: DIRTY-PROBE-CLEANUP-FAILURE: %s\\n' \"$probe\" >&2",
        "dirty-probe cleanup failure marker emission",
    )
    require_text(probe_cleanup, "status=125", "distinct dirty-probe cleanup status")
    require_text(
        probe_lifecycle,
        "printf 'BUILD-FAILLO: DIRTY-PROBE-READY: %s\\n' \"$probe\" >&2",
        "dirty-probe reached-state marker",
    )
    require_order(
        reached_contract,
        (
            '[ "$rc" -ne 0 ] || return 1',
            'grep -qF "$reached"',
            'grep -qF "$expected"',
            '! printf \'%s\\n\' "$out" | grep -qF "$marker"',
        ),
        "reached-state failure classification",
    )
    if "grep -qiE 'FATAL|FAIL" in source or 'grep -qiE \'FATAL|FAIL' in source:
        raise VerificationError("fail-loud suite accepts a broad unrelated failure diagnostic")
    for forbidden in (".faillo_ct_probe", ".faillo_dirt_probe"):
        if forbidden in source:
            raise VerificationError("fail-loud suite retains a fixed followable dirty probe")
    if "every misconfiguration" in source:
        raise VerificationError("fail-loud suite overclaims every possible misconfiguration")


def validate_private_tree_closure(source):
    for text, label in (
        ("os.lstat(path)", "physical inode inspection"),
        ("followlinks=False", "symlink traversal exclusion"),
        ("metadata.st_nlink", "inode link-count proof"),
        ("count != expected", "external hardlink rejection"),
        ('mount_path.startswith(prefix)', "descendant mount rejection"),
        ('modes.add_argument("--self-test"', "closure behavioral self-test"),
        ("os.link(internal", "internally closed hardlink fixture"),
        ("os.link(external", "external hardlink fixture"),
        ("internal-symlink-b", "internally closed hardlinked-symlink fixture"),
        ("external-symlink-link", "external hardlinked-symlink fixture"),
        ("0:1 /bound", "same-filesystem descendant mount fixture"),
        ("space\\040tab\\011line\\012slash\\134", "complete mountinfo escape fixture"),
    ):
        require_text(source, text, label)
    if "os.stat(" in source or "followlinks=True" in source:
        raise VerificationError("private-tree closure probe follows filesystem aliases")


def validate_sources(sources):
    validate_verify_workspace(sources["verify"])
    validate_build_release(sources["build"])
    validate_target_scripts(sources["debian"], sources["android"], sources["pins"])
    validate_publisher(sources["publish"])
    validate_fork_version(sources["version"])
    validate_docs(sources["docs"])
    validate_scan_contract(sources["scan"], sources["verify"], sources["apple"], sources["release"])
    validate_smoke_contract(sources["smoke"])
    validate_faillo_contract(sources["faillo"])
    validate_private_tree_closure(sources["closure"])
    validate_workspace_verifier_self_contract(sources["workspace_verifier"])


def run_command(command, cwd, env=None):
    return subprocess.run(
        command,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=90,
    )


def handle_managed_signal(signum, frame):
    del frame
    state = _MANAGED_SIGNAL_STATE
    if state is None:
        raise ManagedSignal(signum)
    state["caught"] = True
    if state["acquiring_process"]:
        if state["pending_signum"] is None:
            state["pending_signum"] = signum
        return
    signal.pthread_sigmask(signal.SIG_BLOCK, MANAGED_SIGNALS)
    raise ManagedSignal(signum)


def enter_managed_signal_scope():
    global _MANAGED_SIGNAL_STATE
    if threading.current_thread() is not threading.main_thread():
        raise VerificationError("managed signal scope requires the main thread")
    entry_mask = signal.pthread_sigmask(signal.SIG_BLOCK, MANAGED_SIGNALS)
    if _MANAGED_SIGNAL_STATE is not None:
        return {"entry_mask": entry_mask, "outer": False}

    previous_handlers = {}
    try:
        for signum in MANAGED_SIGNALS:
            previous_handlers[signum] = signal.getsignal(signum)
            signal.signal(signum, handle_managed_signal)
        state = {
            "acquiring_process": False,
            "caught": False,
            "pending_signum": None,
            "previous_handlers": previous_handlers,
            "previous_mask": entry_mask,
        }
        _MANAGED_SIGNAL_STATE = state
    except BaseException:
        signal.pthread_sigmask(signal.SIG_BLOCK, MANAGED_SIGNALS)
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)
        _MANAGED_SIGNAL_STATE = None
        signal.pthread_sigmask(signal.SIG_SETMASK, entry_mask)
        raise
    return {"entry_mask": entry_mask, "outer": True}


def activate_managed_signal_scope(scope):
    signal.pthread_sigmask(signal.SIG_SETMASK, scope["entry_mask"])


def begin_managed_process_acquisition():
    state = _MANAGED_SIGNAL_STATE
    if state is None or state["acquiring_process"]:
        raise VerificationError("managed process acquisition ownership is unavailable")
    state["acquiring_process"] = True


def finish_managed_process_acquisition():
    state = _MANAGED_SIGNAL_STATE
    if state is None or not state["acquiring_process"]:
        raise VerificationError("managed process acquisition ownership is unavailable")
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, MANAGED_SIGNALS)
    state["acquiring_process"] = False
    pending_signum = state["pending_signum"]
    state["pending_signum"] = None
    if pending_signum is not None:
        raise ManagedSignal(pending_signum)
    signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)


def leave_managed_signal_scope(scope, finalization_mask):
    global _MANAGED_SIGNAL_STATE
    state = _MANAGED_SIGNAL_STATE
    if state is None:
        raise VerificationError("managed signal scope ownership is unavailable")
    if not scope["outer"]:
        signal.pthread_sigmask(signal.SIG_SETMASK, finalization_mask)
        return
    if state["acquiring_process"]:
        raise VerificationError("outer managed signal scope retained process acquisition")

    previous_handlers = state["previous_handlers"]
    previous_mask = state["previous_mask"]
    if state["caught"]:
        for signum in MANAGED_SIGNALS:
            signal.signal(signum, signal.SIG_IGN)
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        signal.pthread_sigmask(signal.SIG_BLOCK, MANAGED_SIGNALS)
    for signum, handler in previous_handlers.items():
        signal.signal(signum, handler)
    _MANAGED_SIGNAL_STATE = None
    signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)


def process_group_exists(process_group):
    try:
        os.killpg(process_group, 0)
    except ProcessLookupError:
        return False
    except PermissionError as exc:
        raise VerificationError(f"cannot inspect owned process group {process_group}") from exc
    return True


def wait_process_group_absent(process_group, timeout_seconds):
    deadline = time.monotonic() + timeout_seconds
    while process_group_exists(process_group):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(0.01, remaining))
    return True


def signal_process_group(process_group, signum):
    try:
        os.killpg(process_group, signum)
    except ProcessLookupError:
        pass


def close_process_pipes(process):
    for stream in (process.stdout, process.stderr):
        if stream is not None and not stream.closed:
            stream.close()


def terminate_and_reap_process_group(process, cleanup_grace_seconds, kill_grace_seconds):
    process_group = process.pid
    try:
        signal_process_group(process_group, signal.SIGTERM)
        try:
            process.wait(timeout=cleanup_grace_seconds)
        except subprocess.TimeoutExpired:
            signal_process_group(process_group, signal.SIGKILL)
            try:
                process.wait(timeout=kill_grace_seconds)
            except subprocess.TimeoutExpired as exc:
                raise VerificationError("cannot reap a hard-killed managed command") from exc
        if process_group_exists(process_group):
            signal_process_group(process_group, signal.SIGKILL)
            if not wait_process_group_absent(process_group, kill_grace_seconds):
                raise VerificationError(f"managed command retained process group {process_group} after SIGKILL")
    finally:
        close_process_pipes(process)


def run_managed_command(
    command,
    cwd,
    env=None,
    timeout_seconds=300,
    cleanup_grace_seconds=120,
    kill_grace_seconds=10,
    max_output_bytes=32 * 1024 * 1024,
):
    process = None
    process_reaped = False
    selector = None
    signal_scope = None
    try:
        signal_scope = enter_managed_signal_scope()
        activate_managed_signal_scope(signal_scope)
        begin_managed_process_acquisition()
        try:
            process = subprocess.Popen(
                command,
                cwd=cwd,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
        finally:
            finish_managed_process_acquisition()
        if process.stdout is None or process.stderr is None:
            raise VerificationError("managed command has no output streams")
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        output = {"stdout": bytearray(), "stderr": bytearray()}
        output_bytes = 0
        timed_out = False
        phase = "running"
        deadline = time.monotonic() + timeout_seconds

        def advance_timeout():
            nonlocal deadline, phase, timed_out
            if phase == "running":
                timed_out = True
                phase = "terminating"
                signal_process_group(process.pid, signal.SIGTERM)
                deadline = time.monotonic() + cleanup_grace_seconds
            elif phase == "terminating":
                phase = "killing"
                signal_process_group(process.pid, signal.SIGKILL)
                deadline = time.monotonic() + kill_grace_seconds
            else:
                raise VerificationError("cannot reap a hard-killed managed command process group")

        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                advance_timeout()
                continue
            events = selector.select(remaining)
            if not events:
                advance_timeout()
                continue
            for key, _ in events:
                chunk = os.read(key.fd, 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                output_bytes += len(chunk)
                if output_bytes > max_output_bytes:
                    raise VerificationError("managed command output exceeds its bound")
                output[key.data].extend(chunk)

        while process.poll() is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                advance_timeout()
                continue
            try:
                process.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                advance_timeout()
        process_reaped = True

        if process_group_exists(process.pid):
            signal_process_group(process.pid, signal.SIGKILL)
            if not wait_process_group_absent(process.pid, kill_grace_seconds):
                raise VerificationError(f"managed command retained process group {process.pid}")
            if not timed_out:
                raise VerificationError("managed command exited while descendants remained")

        stdout = output["stdout"].decode("utf-8", errors="surrogateescape")
        stderr = output["stderr"].decode("utf-8", errors="surrogateescape")
        if timed_out:
            stderr += "\nmanaged command exceeded its deadline"
        return subprocess.CompletedProcess(command, 124 if timed_out else process.returncode, stdout, stderr)
    finally:
        finalization_mask = signal.pthread_sigmask(signal.SIG_BLOCK, MANAGED_SIGNALS)
        try:
            try:
                if process is not None and not process_reaped:
                    terminate_and_reap_process_group(process, cleanup_grace_seconds, kill_grace_seconds)
            finally:
                if selector is not None:
                    selector.close()
        finally:
            if signal_scope is not None:
                leave_managed_signal_scope(signal_scope, finalization_mask)
            else:
                signal.pthread_sigmask(signal.SIG_SETMASK, finalization_mask)


def reserved_release_state(repo):
    result = run_managed_command(
        [
            "/usr/bin/git",
            "--no-replace-objects",
            "-c",
            "core.hooksPath=/dev/null",
            "-C",
            str(repo),
            "worktree",
            "list",
            "--porcelain",
            "-z",
        ],
        repo,
        timeout_seconds=30,
        cleanup_grace_seconds=5,
        kill_grace_seconds=2,
        max_output_bytes=8 * 1024 * 1024,
    )
    if result.returncode != 0:
        raise VerificationError("cannot snapshot Git worktrees around a stateful fixture")
    worktree_pattern = re.compile(r"\Aworktree (/tmp/rustdesk-release\.[A-Za-z0-9]{10}/[^\0]+)\Z")
    worktrees = set()
    for field in result.stdout.split("\0"):
        match = worktree_pattern.match(field)
        if match:
            if match.group(1) in worktrees:
                raise VerificationError("reserved release worktree registry contains a duplicate exact path")
            worktrees.add(match.group(1))

    directory_pattern = re.compile(r"\Arustdesk-release\.[A-Za-z0-9]{10}\Z")
    directories = {}
    with os.scandir("/tmp") as entries:
        for entry in entries:
            if not directory_pattern.match(entry.name):
                continue
            metadata = entry.stat(follow_symlinks=False)
            directories[entry.path] = (metadata.st_dev, metadata.st_ino, metadata.st_mode)
    return worktrees, directories


def assert_reserved_release_state_unchanged(before, cwd, execution_error=None):
    after = reserved_release_state(cwd)
    if after != before:
        before_worktrees, before_directories = before
        after_worktrees, after_directories = after
        detail = {
            "new_worktrees": sorted(after_worktrees - before_worktrees),
            "missing_worktrees": sorted(before_worktrees - after_worktrees),
            "new_directories": sorted(set(after_directories) - set(before_directories)),
            "missing_directories": sorted(set(before_directories) - set(after_directories)),
            "changed_directories": sorted(
                path
                for path in set(before_directories) & set(after_directories)
                if before_directories[path] != after_directories[path]
            ),
        }
        state_error = VerificationError(f"stateful fixture changed reserved release state: {detail}")
        if execution_error is not None:
            raise state_error from execution_error
        raise state_error


def run_stateful_command(
    command,
    cwd,
    env=None,
    timeout_seconds=300,
    cleanup_grace_seconds=120,
    kill_grace_seconds=10,
):
    signal_scope = None
    before = None
    result = None
    execution_error = None
    try:
        signal_scope = enter_managed_signal_scope()
        activate_managed_signal_scope(signal_scope)
        before = reserved_release_state(cwd)
        try:
            result = run_managed_command(
                command,
                cwd,
                env,
                timeout_seconds,
                cleanup_grace_seconds,
                kill_grace_seconds,
            )
        except BaseException as exc:
            execution_error = exc
        assert_reserved_release_state_unchanged(before, cwd, execution_error)
        if execution_error is not None:
            raise execution_error
        if result is None:
            raise VerificationError("stateful command produced no result")
        return result
    except ManagedSignal:
        if before is not None:
            assert_reserved_release_state_unchanged(before, cwd)
        raise
    finally:
        finalization_mask = signal.pthread_sigmask(signal.SIG_BLOCK, MANAGED_SIGNALS)
        if signal_scope is not None:
            leave_managed_signal_scope(signal_scope, finalization_mask)
        else:
            signal.pthread_sigmask(signal.SIG_SETMASK, finalization_mask)


def assert_process_absent(pid, label):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return
    except PermissionError as exc:
        raise VerificationError(f"{label} process ownership cannot be inspected") from exc
    raise VerificationError(f"{label} process remains after process-group cleanup: {pid}")


def run_stateful_timeout_fixtures(repo):
    injected_processes = []

    def inject_after_spawn(frame, event, argument):
        del argument
        if event == "line" and frame.f_code is run_managed_command.__code__:
            process = frame.f_locals.get("process")
            state = _MANAGED_SIGNAL_STATE
            if (
                isinstance(process, subprocess.Popen)
                and state is not None
                and not state["acquiring_process"]
            ):
                injected_processes.append(process.pid)
                raise RuntimeError("STATEFUL-POST-SPAWN-CLEANUP")
        return inject_after_spawn

    previous_trace = sys.gettrace()
    try:
        sys.settrace(inject_after_spawn)
        run_managed_command(
            ["/usr/bin/bash", "--noprofile", "--norc", "-c", "trap '' TERM; sleep 60"],
            repo,
            timeout_seconds=30,
            cleanup_grace_seconds=0.1,
            kill_grace_seconds=2,
        )
    except RuntimeError as exc:
        if str(exc) != "STATEFUL-POST-SPAWN-CLEANUP":
            raise
    else:
        raise VerificationError("stateful post-spawn exception fixture did not inject its failure")
    finally:
        sys.settrace(previous_trace)
    if len(injected_processes) != 1:
        raise VerificationError("stateful post-spawn exception fixture did not capture one process")
    assert_process_absent(injected_processes[0], "stateful post-spawn exception")
    if process_group_exists(injected_processes[0]):
        raise VerificationError("stateful post-spawn exception retained its process group")

    real_popen = subprocess.Popen
    pre_assignment_processes = []

    def signal_before_popen_return(*arguments, **keywords):
        process = real_popen(*arguments, **keywords)
        pre_assignment_processes.append(process)
        handle_managed_signal(signal.SIGTERM, None)
        return process

    subprocess.Popen = signal_before_popen_return
    try:
        try:
            run_managed_command(
                ["/usr/bin/bash", "--noprofile", "--norc", "-c", "trap '' TERM; sleep 60"],
                repo,
                timeout_seconds=30,
                cleanup_grace_seconds=0.1,
                kill_grace_seconds=2,
            )
        except ManagedSignal as exc:
            if exc.signum != signal.SIGTERM:
                raise
        else:
            raise VerificationError("pre-assignment managed signal fixture did not raise its recorded signal")
    finally:
        subprocess.Popen = real_popen
    if len(pre_assignment_processes) != 1:
        raise VerificationError("pre-assignment managed signal fixture did not capture one process")
    pre_assignment_process = pre_assignment_processes[0]
    pre_assignment_group_alive = process_group_exists(pre_assignment_process.pid)
    pre_assignment_leader_alive = pre_assignment_process.poll() is None
    if pre_assignment_group_alive or pre_assignment_leader_alive:
        signal_process_group(pre_assignment_process.pid, signal.SIGKILL)
        if pre_assignment_leader_alive:
            pre_assignment_process.wait(timeout=2)
        wait_process_group_absent(pre_assignment_process.pid, 2)
        close_process_pipes(pre_assignment_process)
        raise VerificationError("pre-assignment managed signal retained its process or process group")
    assert_process_absent(pre_assignment_process.pid, "pre-assignment managed signal")

    with tempfile.TemporaryDirectory(prefix="rustdesk-stateful-signal-") as directory:
        fixture_root = Path(directory)
        leader_file = fixture_root / "leader"
        descendant_file = fixture_root / "descendant"
        nested_program = r'''
import importlib.util
import sys
from pathlib import Path

module_path = Path(sys.argv[1])
repo = Path(sys.argv[2])
leader_file = sys.argv[3]
descendant_file = sys.argv[4]
spec = importlib.util.spec_from_file_location("nested_workspace_verifier", module_path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
command = [
    "/usr/bin/bash",
    "--noprofile",
    "--norc",
    "-c",
    "trap 'kill -TERM \"$child\" 2>/dev/null || true; wait \"$child\" 2>/dev/null || true; exit 143' TERM; "
    "printf '%s' \"$$\" >\"$1\"; sleep 60 & child=$!; printf '%s' \"$child\" >\"$2\"; wait \"$child\"",
    "_",
    leader_file,
    descendant_file,
]
try:
    module.run_stateful_command(
        command,
        repo,
        timeout_seconds=30,
        cleanup_grace_seconds=5,
        kill_grace_seconds=2,
    )
except module.ManagedSignal as exc:
    print(f"STATEFUL-PARENT-SIGNAL-STATE-CHECKED:{exc.signum}", flush=True)
    raise SystemExit(128 + exc.signum)
raise SystemExit("nested stateful signal fixture completed without its parent signal")
'''
        nested = subprocess.Popen(
            [
                sys.executable,
                "-c",
                nested_program,
                str(Path(__file__).resolve()),
                str(repo),
                str(leader_file),
                str(descendant_file),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        leader_pid = None
        descendant_pid = None
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if leader_file.exists() and descendant_file.exists():
                    leader_pid = int(leader_file.read_text(encoding="ascii"))
                    descendant_pid = int(descendant_file.read_text(encoding="ascii"))
                    break
                if nested.poll() is not None:
                    break
                time.sleep(0.01)
            if leader_pid is None or descendant_pid is None:
                raise VerificationError("stateful parent-signal fixture did not reach its managed descendant")
            os.kill(nested.pid, signal.SIGTERM)
            os.kill(nested.pid, signal.SIGTERM)
            try:
                stdout, stderr = nested.communicate(timeout=15)
            except subprocess.TimeoutExpired as exc:
                raise VerificationError("stateful parent-signal fixture did not terminate") from exc
            if nested.returncode != 143 or "STATEFUL-PARENT-SIGNAL-STATE-CHECKED:15" not in stdout:
                raise VerificationError(
                    f"stateful parent-signal fixture bypassed cleanup or state proof: {stdout}{stderr}"
                )
        finally:
            if nested.poll() is None:
                os.killpg(nested.pid, signal.SIGKILL)
                nested.wait(timeout=2)
            if leader_pid is not None and process_group_exists(leader_pid):
                signal_process_group(leader_pid, signal.SIGKILL)
                wait_process_group_absent(leader_pid, 2)
        assert_process_absent(leader_pid, "stateful parent-signal leader")
        assert_process_absent(descendant_pid, "stateful parent-signal descendant")
        if process_group_exists(leader_pid):
            raise VerificationError("stateful parent signal retained its managed process group")

    graceful = run_stateful_command(
        [
            "/usr/bin/bash",
            "--noprofile",
            "--norc",
            "-c",
            "trap 'kill -TERM \"$child\" 2>/dev/null || true; wait \"$child\" 2>/dev/null || true; "
            "echo STATEFUL-GRACEFUL-CLEANUP; exit 143' TERM; "
            "sleep 60 & child=$!; echo STATEFUL-CHILD:$child; wait \"$child\"",
        ],
        repo,
        timeout_seconds=0.1,
        cleanup_grace_seconds=5,
        kill_grace_seconds=2,
    )
    graceful_output = graceful.stdout + graceful.stderr
    match = re.search(r"STATEFUL-CHILD:(\d+)", graceful_output)
    if graceful.returncode != 124 or "STATEFUL-GRACEFUL-CLEANUP" not in graceful_output or match is None:
        raise VerificationError("stateful graceful-timeout fixture did not execute its cleanup trap")
    assert_process_absent(int(match.group(1)), "stateful graceful-timeout descendant")

    resistant = run_stateful_command(
        [
            "/usr/bin/bash",
            "--noprofile",
            "--norc",
            "-c",
            "trap '' TERM; /usr/bin/bash --noprofile --norc -c "
            "'trap \"\" TERM; sleep 60' & child=$!; echo STATEFUL-RESISTANT-CHILD:$child; wait \"$child\"",
        ],
        repo,
        timeout_seconds=0.1,
        cleanup_grace_seconds=0.1,
        kill_grace_seconds=2,
    )
    resistant_output = resistant.stdout + resistant.stderr
    match = re.search(r"STATEFUL-RESISTANT-CHILD:(\d+)", resistant_output)
    if resistant.returncode != 124 or match is None:
        raise VerificationError("stateful hard-timeout fixture did not reach its resistant descendant")
    assert_process_absent(int(match.group(1)), "stateful hard-timeout descendant")


def require_success(result, label, marker):
    output = result.stdout + result.stderr
    if result.returncode != 0 or marker not in output:
        raise VerificationError(f"{label} failed ({result.returncode}): {output[-2000:]}")


def run_transaction_fixtures(repo):
    poison = dict(os.environ)
    poison.update(
        {
            "GIT_CONFIG": "/hostile/git-config",
            "PYTHONPATH": "/hostile/python",
            "DOCKER_HOST": "tcp://hostile.invalid:2376",
            "HARNESS_PREFIX": "hostile",
            "OUT_DIR": "/hostile/out",
        }
    )
    for relative, marker, label in (
        ("scripts/build-release.sh", "build-release self-test: OK", "release transaction fixture"),
        (
            "scripts/build-release.sh",
            "build-release root-owned reset self-test: OK",
            "root-owned reset transaction fixture",
        ),
        (
            "scripts/publish-github-release.sh",
            "publish-github-release self-test: OK",
            "publisher transaction fixture",
        ),
    ):
        path = repo / relative
        mode = "--self-test-reset" if "root-owned reset" in label else "--self-test"
        result = run_stateful_command([str(path), mode], repo, poison)
        require_success(result, label, marker)
        bypass = run_command(
            ["/usr/bin/bash", "--noprofile", "--norc", str(path), mode],
            repo,
            poison,
        )
        if bypass.returncode == 0 or "forbidden inherited environment variable" not in (bypass.stdout + bypass.stderr):
            raise VerificationError(f"{label} accepted a poisoned environment through an explicit Bash bypass")


def run_target_contract_fixtures(sources):
    commit = "a" * 40
    image_ids = {
        "debian": "sha256:" + "d" * 64,
        "android": "sha256:" + "a" * 64,
    }
    roles = {"debian": "deb-builder", "android": "android-builder"}
    pin_names = {"debian": "DEB_BUILDER_IMAGE_ID", "android": "ANDROID_BUILDER_IMAGE_ID"}
    with tempfile.TemporaryDirectory(prefix="rustdesk-target-contract-") as directory:
        root = Path(directory)
        scripts = root / "scripts"
        tools = root / "bin"
        scripts.mkdir(mode=0o700)
        tools.mkdir(mode=0o700)
        for target in ("debian", "android"):
            path = scripts / f"build-{target}.sh"
            path.write_text(sources[target], encoding="utf-8")
            path.chmod(0o700)
        (scripts / "lib.sh").write_text(
            r'''set -euo pipefail
LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$LIB_DIR/.." && pwd)"
ONLINE_DIR="$REPO_ROOT/online"
DEFAULT_ANDROID_KEYSTORE="$REPO_ROOT/private/key.jks"
DEFAULT_ANDROID_KEYSTORE_PASS_FILE="$REPO_ROOT/private/pass"
SHA_PENDING="__PENDING_R_B12__"
die() { printf 'fixture:FATAL: %s\n' "$*" >&2; exit 1; }
log() { :; }
load_pins() {
    SOURCE_DATE_EPOCH_PIN=1700000000
    RUST_VERSION=1.75
    FLUTTER_VERSION=3.24.5
    LLVM_VERSION=15.0.6
    ANDROID_NDK_VERSION=r28c
    ANDROID_BUILD_TOOLS=34.0.0
    ANDROID_MIN_SDK=24
    SHA256_RUST_1_75=1
    SHA256_RUST_STD_ANDROID_1_75=2
    SHA256_FLUTTER_3_24_5=3
    SHA256_LLVM_15_0_6=4
    SHA256_ANDROID_NDK_R28C=5
    SHA256_ANDROID_CMDLINE_TOOLS=6
    SHA256_BASEIMAGE_UBUNTU_1804=sha256:7
    SHA256_BASEIMAGE_UBUNTU_2404=sha256:8
    ANDROID_SIGNING_CERT_SHA256=9
    DEB_BUILDER_IMAGE_ID="sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
    ANDROID_BUILDER_IMAGE_ID="sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    if [ "${FIXTURE_MISSING_IMAGE_PIN:-0}" = 1 ]; then
        DEB_BUILDER_IMAGE_ID=""
        ANDROID_BUILDER_IMAGE_ID=""
    fi
}
require_cmd() { :; }
assert_repo_state() { :; }
assert_clean_worktree() { :; }
assert_source_date_epoch() { [ "${SOURCE_DATE_EPOCH:-}" = 1700000000 ] || die "bad epoch"; }
require_online_complete() {
    [ "$(cat "$ONLINE_DIR/closure" 2>/dev/null)" = pinned ] || die "canonical online closure mismatch"
}
verify_online_shas() { :; }
require_pinned_builder_image() {
    local role="$1" image_id="$2" expected="" pin=""
    case "$role" in
        deb-builder) expected="$DEB_BUILDER_IMAGE_ID"; pin=DEB_BUILDER_IMAGE_ID ;;
        android-builder) expected="$ANDROID_BUILDER_IMAGE_ID"; pin=ANDROID_BUILDER_IMAGE_ID ;;
        *) die "unexpected builder role: $role" ;;
    esac
    [ -n "$expected" ] || die "pins.env is missing $pin"
    [ "$image_id" = "$expected" ] || die "builder image ID differs from $pin"
    printf '%s|%s\n' "$role" "$image_id" >> "$FIXTURE_LOG"
}
verify_private_online_snapshot() {
    [ "$(cat "$1/online/closure" 2>/dev/null)" = pinned ] || die "private online closure mismatch"
}
create_private_online_snapshot() {
    [ ! -e "$1" ] || die "snapshot destination exists"
    mkdir -m 0700 "$1"
    mkdir -m 0700 "$1/online"
    cp "$ONLINE_DIR/closure" "$1/online/closure"
    chmod 0400 "$1/online/closure"
    chmod 0500 "$1/online"
    verify_private_online_snapshot "$1"
}
''',
            encoding="utf-8",
        )
        (tools / "git").write_text(
            f"#!/usr/bin/env bash\nprintf '%s\\n' '{commit}'\n",
            encoding="utf-8",
        )
        (tools / "git").chmod(0o700)
        (tools / "docker").write_text(
            """#!/usr/bin/python3
import json
import os
import sys
with open(os.environ["FIXTURE_DOCKER_LOG"], "a", encoding="utf-8") as stream:
    stream.write(json.dumps(sys.argv[1:]) + "\\n")
if os.environ.get("FIXTURE_MUTATE_ONLINE") == "1":
    mounts = [value for value in sys.argv[1:] if value.endswith(":/online:ro")]
    if len(mounts) != 1:
        raise SystemExit(18)
    closure = os.path.join(mounts[0][:-len(":/online:ro")], "closure")
    os.chmod(closure, 0o600)
    with open(closure, "w", encoding="ascii") as stream:
        stream.write("consumer mutation\\n")
    os.chmod(closure, 0o400)
raise SystemExit(17)
""",
            encoding="utf-8",
        )
        (tools / "docker").chmod(0o700)

        online = root / "online"
        online.mkdir(mode=0o700)
        (online / "closure").write_text("pinned\n", encoding="ascii")
        snapshot = root / "release-online"
        snapshot.mkdir(mode=0o700)
        snapshot_online = snapshot / "online"
        snapshot_online.mkdir(mode=0o700)
        (snapshot_online / "closure").write_text("pinned\n", encoding="ascii")
        (snapshot_online / "closure").chmod(0o400)
        snapshot_online.chmod(0o500)
        docker_config = root / "docker-config"
        docker_config.mkdir(mode=0o700)
        (docker_config / "config.json").write_text("{}\n", encoding="ascii")
        (docker_config / "config.json").chmod(0o600)
        home = root / "home"
        home.mkdir(mode=0o700)
        apk = root / "app.apk"
        apk.write_bytes(b"fixture apk")
        output = root / "out"
        output.mkdir(mode=0o700)
        helper_log = root / "helper.log"
        docker_log = root / "docker.log"

        def invoke(target, *, release=True, supplied_snapshot=snapshot, extra_env=None):
            helper_log.write_text("", encoding="ascii")
            docker_log.write_text("", encoding="ascii")
            environment = {
                "HOME": str(home),
                "PATH": f"{tools}:/usr/bin:/bin",
                "LC_ALL": "C",
                "LANG": "C",
                "SOURCE_DATE_EPOCH": "1700000000",
                "DOCKER_HOST": "unix:///var/run/docker.sock",
                "FIXTURE_LOG": str(helper_log),
                "FIXTURE_DOCKER_LOG": str(docker_log),
                "OUT_DIR": str(output),
                "DOUBLE_BUILD": "0",
            }
            if release:
                environment.update(
                    {
                        "RELEASE_SRC_COMMIT": commit,
                        "RELEASE_DOCKER_IMAGE_ID": image_ids[target],
                        "DOCKER_CONFIG": str(docker_config),
                    }
                )
                if supplied_snapshot is not None:
                    environment["RUSTDESK_RELEASE_ONLINE_SNAPSHOT"] = str(supplied_snapshot)
            if extra_env:
                environment.update(extra_env)
            command = ["/usr/bin/bash", str(scripts / f"build-{target}.sh")]
            if target == "android":
                command.extend(("--verify-apk", str(apk)))
            return run_command(command, root, environment)

        def output_of(result):
            return result.stdout + result.stderr

        for target in ("debian", "android"):
            result = invoke(target)
            if result.returncode == 0:
                raise VerificationError(f"{target} target fixture unexpectedly completed a platform build")
            helper_lines = helper_log.read_text(encoding="ascii").splitlines()
            expected_helper = f"{roles[target]}|{image_ids[target]}"
            if helper_lines != [expected_helper]:
                raise VerificationError(f"{target} did not verify exactly its pinned builder image: {helper_lines}")
            docker_lines = docker_log.read_text(encoding="ascii").splitlines()
            if len(docker_lines) != 1:
                raise VerificationError(f"{target} did not make exactly one fixture Docker invocation")
            docker_arguments = json.loads(docker_lines[0])
            if image_ids[target] not in docker_arguments:
                raise VerificationError(f"{target} Docker invocation did not use the immutable image ID")
            mutable_images = {
                "rustdesk-fork-harness-deb-builder",
                "rustdesk-fork-harness-android-builder",
            }
            if any(argument in mutable_images for argument in docker_arguments):
                raise VerificationError(f"{target} Docker invocation retained a mutable image tag")
            expected_mount = f"{snapshot_online}:/online:ro"
            if expected_mount not in docker_arguments:
                raise VerificationError(f"{target} release child did not mount the supplied private snapshot")

            result = invoke(target, extra_env={"FIXTURE_MUTATE_ONLINE": "1"})
            (snapshot_online / "closure").chmod(0o600)
            (snapshot_online / "closure").write_text("pinned\n", encoding="ascii")
            (snapshot_online / "closure").chmod(0o400)
            if "private online closure mismatch" not in output_of(result):
                raise VerificationError(f"{target} did not verify the snapshot after a consuming Docker run")

            result = invoke(target, supplied_snapshot=None)
            if "release child requires RUSTDESK_RELEASE_ONLINE_SNAPSHOT" not in output_of(result):
                raise VerificationError(f"{target} release child fell back to the canonical online tree")
            if docker_log.read_text(encoding="ascii"):
                raise VerificationError(f"{target} reached Docker without a release snapshot")

            snapshot.chmod(0o755)
            result = invoke(target)
            snapshot.chmod(0o700)
            if "current-UID mode-0700 directory" not in output_of(result):
                raise VerificationError(f"{target} accepted a non-private snapshot parent")

            (docker_config / "config.json").write_text('{"currentContext":"hostile"}\n', encoding="ascii")
            result = invoke(target)
            (docker_config / "config.json").write_text("{}\n", encoding="ascii")
            if "empty canonical configuration" not in output_of(result):
                raise VerificationError(f"{target} accepted mutable Docker configuration bytes")

            (snapshot_online / "closure").chmod(0o600)
            (snapshot_online / "closure").write_text("mutated\n", encoding="ascii")
            (snapshot_online / "closure").chmod(0o400)
            result = invoke(target)
            (snapshot_online / "closure").chmod(0o600)
            (snapshot_online / "closure").write_text("pinned\n", encoding="ascii")
            (snapshot_online / "closure").chmod(0o400)
            if "private online closure mismatch" not in output_of(result):
                raise VerificationError(f"{target} accepted a snapshot with the wrong pinned closure")

            snapshot_link = root / f"{target}-snapshot-link"
            snapshot_link.symlink_to(snapshot, target_is_directory=True)
            result = invoke(target, supplied_snapshot=snapshot_link)
            snapshot_link.unlink()
            if "must be a real directory" not in output_of(result):
                raise VerificationError(f"{target} accepted a symlinked release snapshot")

            result = invoke(target, extra_env={"FIXTURE_MISSING_IMAGE_PIN": "1"})
            expected_missing = f"pins.env is missing {pin_names[target]}"
            if expected_missing not in output_of(result):
                raise VerificationError(f"{target} did not fail precisely for a missing builder image pin")

            result = invoke(target, release=False, extra_env={"ONLINE_DIR": str(online)})
            if "ONLINE_DIR is not an operator override" not in output_of(result):
                raise VerificationError(f"{target} accepted an ambient online path override")

            result = invoke(target, release=False)
            if result.returncode == 0:
                raise VerificationError(f"{target} direct fixture unexpectedly completed a platform build")
            docker_lines = docker_log.read_text(encoding="ascii").splitlines()
            if len(docker_lines) != 1:
                raise VerificationError(f"{target} direct invocation did not reach one Docker consumer")
            docker_arguments = json.loads(docker_lines[0])
            online_mounts = [argument for argument in docker_arguments if argument.endswith(":/online:ro")]
            if len(online_mounts) != 1 or online_mounts[0] == f"{online}:/online:ro":
                raise VerificationError(f"{target} direct invocation consumed the mutable canonical online tree")


def run_fork_version_fixture(version_source, fork_version, changelog, cargo="1.4.7", expected=True):
    with tempfile.TemporaryDirectory(prefix="rustdesk-version-fixture-") as directory:
        root = Path(directory)
        (root / "scripts").mkdir()
        (root / "scripts/fork-version.sh").write_text(version_source, encoding="utf-8")
        (root / "Cargo.toml").write_text(
            f'[package]\nname = "fixture"\nversion = "{cargo}"\n', encoding="utf-8"
        )
        (root / "FORK_VERSION").write_text(fork_version, encoding="utf-8")
        (root / "CHANGELOG.md").write_text(changelog, encoding="utf-8")
        result = run_command(["/usr/bin/bash", str(root / "scripts/fork-version.sh")], root)
        if (result.returncode == 0) != expected:
            raise VerificationError(
                f"fork-version fixture expected success={expected}, got {result.returncode}: {result.stderr.strip()}"
            )


def run_version_fixtures(version_source):
    valid = (
        "# Changelog\n\n"
        "## 1.4.7-hardened.6 - 2026-07-13\n\n"
        "## 1.4.7-hardened.5 — 2026-07-11\n\n"
        "## 1.4.7-hardened.4 - 2026-07-08\n"
    )
    run_fork_version_fixture(version_source, "1.4.7-hardened.6\n", valid)
    invalid = (
        ("1.4.7-hardened.6", valid, "1.4.7"),
        ("1.4.7-hardened.6\n", valid.replace("2026-07-13", "2026-02-30"), "1.4.7"),
        ("1.4.7-hardened.6\n", valid.replace("hardened.5 —", "hardened.5 /"), "1.4.7"),
        ("1.4.7-hardened.7\n", valid.replace("hardened.6", "hardened.7"), "1.4.7"),
        ("1.4.7-hardened.6\n", valid + "\n## 1.4.7-hardened.6 - 2026-01-01\n", "1.4.7"),
        ("1.4.7-hardened.6\n", valid.replace("2026-07-11", "2026-07-14"), "1.4.7"),
        ("1.4.7-hardened.06\n", valid, "1.4.7"),
    )
    for fork_version, changelog, cargo in invalid:
        run_fork_version_fixture(version_source, fork_version, changelog, cargo, expected=False)
    transition = (
        "# Changelog\n\n"
        "## 1.4.8-hardened.1 - 2026-07-14\n\n"
        "## 1.4.7-hardened.6 - 2026-07-13\n"
    )
    run_fork_version_fixture(version_source, "1.4.8-hardened.1\n", transition, "1.4.8")
    run_fork_version_fixture(
        version_source,
        "1.4.8-hardened.2\n",
        transition.replace("1.4.8-hardened.1", "1.4.8-hardened.2"),
        "1.4.8",
        expected=False,
    )


def expect_workspace_rejection(lines, expected):
    try:
        validate_verify_workspace("\n".join(lines) + "\n")
    except VerificationError as exc:
        if expected not in str(exc):
            raise VerificationError(f"workspace mutation rejected for {exc}, expected {expected}") from exc
        return
    raise VerificationError(f"workspace mutation was accepted: {expected}")


def run_workspace_mutations(lines, positions):
    for label, block in WORKSPACE_BLOCKS:
        start = positions[label]
        for offset, line in enumerate(block):
            if not line:
                continue
            mutated = list(lines)
            del mutated[start + offset]
            expect_workspace_rejection(mutated, label)
    expect_workspace_rejection(lines + ["printf x >/tmp/verify-probe"], "direct public-/tmp redirection")
    expect_workspace_rejection(lines + ["printf x >/tmp/rd_verify_probe.$$"], "predictable public scratch prefix")
    expect_workspace_rejection(
        lines + ["grep -qF 'readonly VERIFY_TMP' scripts/verify.sh"],
        "fixed-string self-inspection",
    )


def run_source_mutations(sources):
    mutations = (
        (
            "build",
            "run_child() {\n    assert_release_docker_config\n    /usr/bin/env -i",
            "run_child() {\n    assert_release_docker_config\n    /usr/bin/env",
            "child environment allowlist",
        ),
        ("build", 'create_snapshot B "$SOURCE_B"', 'true # snapshot B removed', "snapshot B creation"),
        (
            "build",
            'chmod 0700 "$source"',
            'chmod 0711 "$source"',
            "snapshot root mode restoration",
        ),
        (
            "build",
            'create_private_online_snapshot "$ONLINE_SNAPSHOT_PARENT"',
            'true # online snapshot removed',
            "exactly one private online snapshot",
        ),
        (
            "build",
            'assert_release_online_snapshot "before final dist installation"',
            'true # final online proof removed',
            "pre-publication online snapshot proof",
        ),
        (
            "build",
            "require_cmd cmp git docker python3 sha256sum stat readlink install find date flock /usr/bin/grep",
            "require_cmd cmp git docker python3 sha256sum stat readlink install find date /usr/bin/grep",
            "release host-tool preflight",
        ),
        (
            "build",
            'run_child /usr/bin/bash --noprofile --norc "$REPO_ROOT/scripts/verify-release.sh" --preflight',
            "true # release source-gate preflight removed",
            "release source-gate preflight",
        ),
        (
            "build",
            'normalize_snapshot_access "$source" "$label"',
            'true # snapshot normalization removed',
            "snapshot-scoped ownership reset",
        ),
        (
            "build",
            'normalize_snapshot_access "$source" "$label"',
            'normalize_snapshot_access "$WORKSPACE" "$label"',
            "snapshot-scoped ownership reset",
        ),
        (
            "build",
            "docker_local run --rm --pull=never --network=none --read-only --user 0:0",
            "docker_local run --rm --pull=never --network=bridge --read-only --user 0:0",
            "read-only inode-closure inspector",
        ),
        (
            "build",
            "--cap-drop=ALL --cap-add=CHOWN \\",
            "--cap-drop=ALL --cap-add=CHOWN --cap-add=FOWNER \\",
            "private-tree mutator command",
        ),
        (
            "build",
            "-exec /bin/chmod u+rwx,go-w {} \\;",
            "-print # directory access repair removed",
            "normalizer directory access repair",
        ),
        (
            "build",
            'normalize_workspace_access || cleanup_failed=1',
            'true # whole-workspace normalization removed',
            "whole-workspace cleanup ordering",
        ),
        (
            "build",
            'find -P "$WORKSPACE" -type d -exec chmod u+rwx,go-w {} +',
            'chmod -R u+rwX,go-w "$WORKSPACE"',
            "directory-only removal access",
        ),
        (
            "build",
            'trap cleanup_release_workspace EXIT\n    trap \'exit 129\' HUP',
            'true # workspace cleanup trap delayed\n    trap \'exit 129\' HUP',
            "workspace trap installation",
        ),
        (
            "build",
            '"worktree",\n        "list",\n        "--porcelain",\n        "-z",',
            '"worktree",\n        "list",\n        "--porcelain",',
            "exact Git worktree registry query",
        ),
        (
            "build",
            'worktree remove --force --force "$source"',
            'worktree remove --force "$source"',
            "present and absent locked-worktree removal",
        ),
        (
            "build",
            'chunk = os.read(stream.fileno(), READ_SIZE)',
            'chunk = os.read(stream.fileno(), MAX_WORKTREE_TOTAL_BYTES)',
            "bounded Git worktree registry read",
        ),
        (
            "build",
            'returncode = process.wait(timeout=remaining)',
            'returncode = process.wait()',
            "Git worktree registry producer deadline",
        ),
        (
            "build",
            'if returncode != 0:\n            raise RegistryQueryError(',
            'if False:\n            raise RegistryQueryError(',
            "Git worktree registry producer-status rejection",
        ),
        (
            "build",
            'if matches > 1:\n                raise RegistryQueryError(',
            'if matches > 1:\n                return True # duplicate accepted\n            if False:\n                raise RegistryQueryError(',
            "duplicate exact worktree rejection",
        ),
        (
            "build",
            'if field_count > MAX_WORKTREE_FIELDS:',
            'if False:',
            "Git worktree registry field-count enforcement",
        ),
        (
            "build",
            'if total_bytes > MAX_WORKTREE_TOTAL_BYTES:',
            'if False:',
            "Git worktree registry byte-count enforcement",
        ),
        (
            "build",
            'if not selector.select(remaining):',
            'if not selector.select(None):',
            "Git worktree registry read deadline",
        ),
        (
            "build",
            'deadline = time.monotonic() + timeout_seconds',
            'deadline = time.monotonic() + 3600.0',
            "Git worktree registry deadline derivation",
        ),
        (
            "build",
            'except BaseException as exc:\n    print(f"unexpected Git worktree registry query failure: {type(exc).__name__}: {exc}", file=sys.stderr)\n    exit_status = 2',
            'except BaseException as exc:\n    print(f"unexpected Git worktree registry query failure: {type(exc).__name__}: {exc}", file=sys.stderr)\n    exit_status = 1',
            "unexpected registry exception status",
        ),
        (
            "build",
            'if process is not None and not producer_reaped:\n            stop_and_reap(process)',
            'if False:\n            stop_and_reap(process)',
            "Git worktree registry teardown ownership",
        ),
        (
            "build",
            'process.kill()\n        process.wait()',
            'process.kill()\n        return',
            "Git worktree registry post-kill reap",
        ),
        (
            "build",
            'process = None\n    producer_reaped = False',
            'producer_reaped = False # pre-spawn process ownership removed',
            "pre-spawn Git producer ownership",
        ),
        (
            "build",
            '''    try:
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
        except OSError as exc:
            raise RegistryQueryError(f"cannot start Git worktree registry query: {exc}") from exc
        if after_spawn is not None:''',
            '''    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except OSError as exc:
        raise RegistryQueryError(f"cannot start Git worktree registry query: {exc}") from exc
    try:
        if after_spawn is not None:''',
            "Git worktree registry teardown ownership",
        ),
        (
            "build",
            'absent) return 1',
            'absent) return 0',
            "absent worktree token classification",
        ),
        (
            "build",
            'result="$(query_git_worktree_registry exact "$source")" || return 2',
            'result="$(query_git_worktree_registry exact "$source")" || return 1',
            "exact query failure propagation",
        ),
        (
            "build",
            'absent) return 1 ;;\n        *) return 2',
            'absent) return 1 ;;\n        *) return 1',
            "unexpected worktree token rejection",
        ),
        (
            "build",
            '*) warn "$role registration cannot be inspected"; return 1',
            '*) warn "$role registration cannot be inspected"; return 0',
            "invalid-workspace operational-error rejection",
        ),
        (
            "build",
            'query_git_worktree_registry self-test-unexpected >/dev/null 2>&1 || query_status=$?',
            'query_status=2 # unexpected-exception fixture removed',
            "unexpected registry exception fixture dispatch",
        ),
        (
            "build",
            'query_git_worktree_registry self-test-unexpected-after-spawn >/dev/null 2>&1 \\\n'
            '        || query_status=$?',
            'query_status=2 # post-spawn exception fixture removed',
            "post-spawn unexpected registry exception fixture dispatch",
        ),
        (
            "build",
            'print("post-spawn exception fixture retained its producer", file=sys.stderr)\n                return 3',
            'print("post-spawn exception fixture retained its producer", file=sys.stderr)\n                raise RuntimeError("retained producer")',
            "post-spawn retained-producer fixture failure status",
        ),
        (
            "build",
            '--mount "type=bind,src=$SOURCE_A,dst=/fixture,bind-recursive=disabled"',
            '--mount "type=bind,src=$SOURCE_A,dst=/fixture"',
            "reset fixture recursive-bind exclusion",
        ),
        (
            "build",
            'elif [ ! -e "$WORKSPACE" ] && [ ! -L "$WORKSPACE" ]; then',
            'elif false; then',
            "missing workspace detection",
        ),
        (
            "build",
            'if [ "$worktrees_safe" -eq 0 ]; then',
            'if false; then',
            "invalid-workspace registration inspection",
        ),
        (
            "build",
            'run_invalid_workspace_registration_self_test \\\n'
            '        || die "reset self-test did not inspect registration under an invalid workspace root"',
            'true # invalid-workspace registration fixture removed',
            "invalid-workspace registration fixture dispatch",
        ),
        (
            "build",
            'if [ "$SELF_TEST" -eq 0 ]; then',
            'if [ "$SELF_TEST" -eq 0 ] && [ "$SELF_TEST_RESET" -eq 0 ]; then',
            "reset fixture pinned closure-probe provenance",
        ),
        (
            "build",
            "trap '' HUP INT TERM",
            "trap - HUP INT TERM",
            "cleanup signal exclusion",
        ),
        (
            "build",
            '[ "$status" -ne 0 ] || status=1',
            "status=1 # original failure discarded",
            "cleanup original-status preservation",
        ),
        (
            "build",
            'reset_snapshot_build_state "$source" "$label before verification"',
            'true # pre-verification reset removed',
            "verification reset envelope",
        ),
        (
            "build",
            'reset_snapshot_build_state "$source" "$label after verification"',
            'assert_snapshot_exact "$source" "$label after verification"',
            "verification reset envelope",
        ),
        (
            "build",
            'reset_snapshot_build_state "$source" "$label after $target"',
            'assert_snapshot_exact "$source" "$label after $target"',
            "post-target reset ordering",
        ),
        (
            "build",
            'ignored="$(git_closed -C "$source" clean -nffdx 2>/dev/null)" \\\n'
            '        || die "$label: cannot prove generated-state removal"',
            'ignored="" # generated-state proof removed',
            "generated-state reset ordering",
        ),
        (
            "build",
            "--cap-drop=ALL --cap-add=DAC_READ_SEARCH \\",
            "--privileged --cap-drop=ALL --cap-add=DAC_READ_SEARCH \\",
            "inode-closure inspector command",
        ),
        (
            "build",
            '--mount "type=bind,src=$path,dst=/cleanup,bind-recursive=disabled"',
            '--mount "type=bind,src=$WORKSPACE,dst=/cleanup,bind-recursive=disabled"',
            "private-tree mutator command",
        ),
        (
            "build",
            'offline_normalize_exact_tree "$source" "$expected" "$phase snapshot"',
            'offline_normalize_exact_tree "$WORKSPACE" "$expected" "$phase snapshot"',
            "snapshot normalizer exact-tree call",
        ),
        (
            "build",
            '[ "$observed" = "$expected_identity" ] \\\n'
            '        || { warn "$role identity changed: $path"; return 1; }',
            'true # pre-normalization identity proof removed',
            "normalizer identity stages",
        ),
        (
            "build",
            'if ! (verify_release_builder_image deb-builder "$DEBIAN_IMAGE_ID"); then\n'
            '        warn "$role normalization image failed provenance verification"',
            'if false; then\n'
            '        warn "$role normalization image failed provenance verification"',
            "normalizer live image provenance",
        ),
        (
            "build",
            'if git_closed -C "$SOURCE_A" clean -ffdx >/dev/null 2>"$WORKSPACE/negative-clean.log"; then',
            'if false && git_closed -C "$SOURCE_A" clean -ffdx >/dev/null 2>"$WORKSPACE/negative-clean.log"; then',
            "reset fixture live negative control",
        ),
        (
            "build",
            'metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0',
            'False',
            "reset fixture live hostile-mode predicate",
        ),
        (
            "build",
            'if [ "$SELF_TEST_RESET" -eq 1 ]; then\n        run_reset_self_test',
            'if [ "$SELF_TEST_RESET" -eq 1 ]; then\n        return 0 # reset fixture bypassed',
            "reset fixture main dispatch",
        ),
        (
            "faillo",
            'scripts/build-release.sh --self-test-reset',
            '/bin/true',
            "root-owned reset exact command",
        ),
        (
            "closure",
            "if count != expected:",
            "if False:",
            "external hardlink rejection",
        ),
        (
            "build",
            'reset_snapshot_build_state "$SOURCE_A" "root-owned reset self-test"',
            'git_closed -C "$SOURCE_A" clean -ffdx',
            "reset fixture production-call proof",
        ),
        (
            "build",
            'install -m 0500 "$PRIVATE_TREE_CLOSURE_SOURCE" "$PRIVATE_TREE_CLOSURE_PROBE"',
            'cp "$PRIVATE_TREE_CLOSURE_SOURCE" "$PRIVATE_TREE_CLOSURE_PROBE"',
            "private closure-probe installation",
        ),
        (
            "build",
            "os.fsync(destination_parent_fd)",
            "true # destination parent durability proof removed",
            "exchange destination-parent durability proof",
        ),
        (
            "build",
            "source_parent_fd, source_name, destination_parent_fd, destination_name, 1",
            "source_parent_fd, source_name, destination_parent_fd, destination_name, 0",
            "first-publication kernel no-clobber",
        ),
        (
            "build",
            'payload_metadata = os.stat("payload", dir_fd=transaction_fd, follow_symlinks=False)',
            'payload_metadata = os.fstat(transaction_fd)',
            "payload name identity proof",
        ),
        (
            "build",
            'sync_exact_directory "$parent" "$parent_id" "publication recovery parent"',
            'true # empty recovery parent sync removed',
            "recovery parent synchronization stages",
        ),
        (
            "build",
            'raise SystemExit(f"{role} identity changed before synchronization")\n    os.fsync(descriptor)',
            'raise SystemExit(f"{role} identity changed before synchronization")\n    pass',
            "directory-sync durability syscall",
        ),
        (
            "build",
            'sync_exact_directory "$REPO_ROOT" "$CANONICAL_PUBLICATION_PARENT_ID"',
            'true # final publication parent sync removed',
            "success-after-cleanup finalization",
        ),
        (
            "build",
            "os.fsync(record_fd)",
            "true # durable record sync removed",
            "publication record durability",
        ),
        (
            "build",
            "record_metadata.st_nlink != 1",
            "False",
            "record hardlink rejection",
        ),
        (
            "build",
            'strict_manifest_proof "$FINAL_STAGE"\n    sync_staged_publication_payload',
            "true # staged payload durability removed",
            "payload-before-record durability ordering",
        ),
        (
            "build",
            "os.fsync(published_fd)",
            "true # published root sync removed",
            "published root durability",
        ),
        (
            "build",
            "publication parent identity changed before discard-removal sync",
            "discard removal parent identity unchecked",
            "durable discard removal",
        ),
        (
            "build",
            'transactions=("$parent/.$base-release-transaction."*)',
            "transactions=() # restart discovery removed",
            "restart active-transaction discovery",
        ),
        (
            "build",
            'flock -n "$PUBLICATION_LOCK_FD"',
            "true # publication lock removed",
            "exclusive publication lock",
        ),
        (
            "build",
            'RELEASE_SUCCESS_MESSAGE="RELEASE OK:',
            'log "RELEASE OK:',
            "a build-release success marker bypasses final cleanup",
        ),
        (
            "verify",
            'VERIFY_SUCCESS_MESSAGE="VERIFY: all required source, behavior, compile, policy, inventory, and excision gates green"',
            'echo "VERIFY: all required source, behavior, compile, policy, inventory, and excision gates green"',
            "deferred verify completion marker",
        ),
        (
            "verify",
            'native_watch_log=$(mktemp "$VERIFY_TMP/native-watch.XXXXXXXXXX")',
            'native_watch_log=$(mktemp)',
            "native watch log workspace ownership",
        ),
        (
            "verify",
            'echo "verify workspace missing self-test: REACHED" >&2',
            'true # verify missing-workspace reached marker removed',
            "verify missing-workspace reached marker",
        ),
        (
            "build",
            "printf 'build-release cleanup-missing self-test: REACHED\\n' >&2",
            'true # release missing-workspace reached marker removed',
            "release missing-workspace reached marker",
        ),
        (
            "faillo",
            '[ "$observed" = "$probe_id" ] || cleanup_failed=1',
            'true # dirty-probe identity verification removed',
            "dirty-probe identity verification",
        ),
        (
            "faillo",
            'rm -f -- "$probe" || cleanup_failed=1',
            'true # dirty-probe removal removed',
            "dirty-probe exact removal",
        ),
        (
            "faillo",
            '[ ! -e "$probe" ] && [ ! -L "$probe" ] || cleanup_failed=1',
            'true # dirty-probe absence proof removed',
            "dirty-probe absence postcondition",
        ),
        (
            "faillo",
            "grep -qF 'BUILD-FAILLO: DIRTY-PROBE-CLEANUP-FAILURE:'",
            "/bin/false # dirty-probe cleanup rejection removed",
            "dirty-probe cleanup rejection",
        ),
        (
            "faillo",
            "printf 'BUILD-FAILLO: DIRTY-PROBE-CLEANUP-FAILURE: %s\\n' \"$probe\" >&2",
            "true # dirty-probe cleanup marker emission removed",
            "dirty-probe cleanup failure marker emission",
        ),
        (
            "faillo",
            '[ "$rc" -ne 125 ]',
            'true # dirty-probe cleanup status accepted',
            "dirty-probe cleanup status rejection",
        ),
        (
            "faillo",
            "printf 'BUILD-FAILLO: DIRTY-PROBE-READY: %s\\n' \"$probe\" >&2",
            "true # dirty-probe reached-state marker removed",
            "dirty-probe reached-state marker",
        ),
        (
            "faillo",
            'grep -qF "$expected"',
            "grep -qiE 'FATAL|FAIL'",
            "fail-loud suite accepts a broad unrelated failure diagnostic",
        ),
        (
            "faillo",
            '[ "$rc" -ne 0 ] || return 1',
            'true # reached-state status check removed',
            "reached-state failure classification",
        ),
        (
            "faillo",
            '[ "$rc" -ne 0 ] || return 1\n  printf \'%s\\n\' "$out" | grep -qF "$reached"',
            '[ "$rc" -ne 0 ] || return 1\n  true # reached-state marker check removed',
            "reached-state failure classification",
        ),
        (
            "faillo",
            'printf \'%s\\n\' "$out" | grep -qF "$expected"',
            'true # reached-state diagnostic check removed',
            "reached-state failure classification",
        ),
        (
            "faillo",
            '! printf \'%s\\n\' "$out" | grep -qF "$marker"',
            'true # forbidden success marker check removed',
            "reached-state failure classification",
        ),
        (
            "workspace_verifier",
            "if threading.current_thread() is not threading.main_thread():",
            "if False:",
            "managed command signal ownership",
        ),
        (
            "workspace_verifier",
            "MANAGED_SIGNALS = (signal.SIGHUP, signal.SIGINT, signal.SIGTERM)",
            "MANAGED_SIGNALS = (signal.SIGINT, signal.SIGTERM)",
            "managed command signal ownership",
        ),
        (
            "workspace_verifier",
            'if state["acquiring_process"]:',
            "if False:",
            "managed command signal ownership",
        ),
        (
            "workspace_verifier",
            "signal.pthread_sigmask(signal.SIG_BLOCK, MANAGED_SIGNALS)\n    raise ManagedSignal(signum)",
            "raise ManagedSignal(signum) # repeated managed signals remain unblocked",
            "managed command signal ownership",
        ),
        (
            "workspace_verifier",
            "signal_scope = enter_managed_signal_scope()\n        activate_managed_signal_scope(signal_scope)",
            "signal_scope = None # managed signal handlers removed",
            "managed command process-group ownership",
        ),
        (
            "workspace_verifier",
            "begin_managed_process_acquisition()\n        try:\n            process = subprocess.Popen(",
            "try:\n            process = subprocess.Popen(",
            "managed command process-group ownership",
        ),
        (
            "workspace_verifier",
            "finally:\n            finish_managed_process_acquisition()",
            "finally:\n            pass # process acquisition handoff removed",
            "managed command process-group ownership",
        ),
        (
            "workspace_verifier",
            "leave_managed_signal_scope(signal_scope, finalization_mask)",
            "signal.pthread_sigmask(signal.SIG_SETMASK, finalization_mask)",
            "managed command process-group ownership",
        ),
        (
            "workspace_verifier",
            "signal_scope = enter_managed_signal_scope()\n        activate_managed_signal_scope(signal_scope)\n        before = reserved_release_state(cwd)",
            "signal_scope = None # state transaction signal scope removed\n        before = reserved_release_state(cwd)",
            "stateful release-state proof",
        ),
        (
            "workspace_verifier",
            "subprocess.Popen = signal_before_popen_return\n    try:",
            "subprocess.Popen = real_popen # pre-assignment fixture removed\n    try:",
            "pre-assignment managed signal fixture",
        ),
        (
            "workspace_verifier",
            "STATEFUL-PARENT-SIGNAL-STATE-CHECKED:{exc.signum}",
            "STATEFUL-PARENT-SIGNAL-CLEANUP-UNPROVEN:{exc.signum}",
            "external parent-signal cleanup fixture",
        ),
        (
            "workspace_verifier",
            "except ManagedSignal as exc:\n        print(f\"verify-verifier-workspace: interrupted by signal {exc.signum}\"",
            "except Exception as exc:\n        print(f\"verify-verifier-workspace: interrupted by signal {exc.signum}\"",
            "managed signal main classification",
        ),
        (
            "workspace_verifier",
            "start_new_session=True",
            "start_new_session=False",
            "managed command process-group ownership",
        ),
        (
            "workspace_verifier",
            "signal_process_group(process.pid, signal.SIGTERM)",
            "signal_process_group(process.pid, signal.SIGKILL)",
            "managed command process-group ownership",
        ),
        (
            "workspace_verifier",
            "deadline = time.monotonic() + cleanup_grace_seconds",
            "deadline = time.monotonic()",
            "managed command process-group ownership",
        ),
        (
            "workspace_verifier",
            '''    selector = None
    signal_scope = None
    try:
        signal_scope = enter_managed_signal_scope()
        activate_managed_signal_scope(signal_scope)
        begin_managed_process_acquisition()
        try:
            process = subprocess.Popen(
                command,
                cwd=cwd,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
        finally:
            finish_managed_process_acquisition()
        if process.stdout is None or process.stderr is None:''',
            '''    selector = None
    signal_scope = None
    signal_scope = enter_managed_signal_scope()
    activate_managed_signal_scope(signal_scope)
    begin_managed_process_acquisition()
    try:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    finally:
        finish_managed_process_acquisition()
    try:
        if process.stdout is None or process.stderr is None:''',
            "managed command process-group ownership",
        ),
        (
            "workspace_verifier",
            "if process is not None and not process_reaped:\n                    terminate_and_reap_process_group(process, cleanup_grace_seconds, kill_grace_seconds)",
            "if False:\n                    terminate_and_reap_process_group(process, cleanup_grace_seconds, kill_grace_seconds)",
            "managed command process-group ownership",
        ),
        (
            "workspace_verifier",
            "if after != before:",
            "if False:",
            "stateful release-state proof",
        ),
        (
            "workspace_verifier",
            "result = run_stateful_command([str(path), mode], repo, poison)",
            "result = run_command([str(path), mode], repo, poison)",
            "transaction fixtures use the stateful runner",
        ),
        (
            "workspace_verifier",
            "            run_stateful_timeout_fixtures(repo)\n            run_transaction_fixtures(repo)",
            "            run_transaction_fixtures(repo) # stateful timeout fixtures removed",
            "stateful timeout fixture dispatch",
        ),
        (
            "build",
            'os.getxattr(path, "system.posix_acl_access", follow_symlinks=False)',
            'b"" # ACL inspection removed',
            "publication parent ACL rejection",
        ),
        (
            "build",
            "source_parent_fd, source_name, destination_parent_fd, destination_name, 2",
            "-100, source_name, -100, destination_name, 2",
            "dirfd-bound final exchange",
        ),
        (
            "build",
            '"$FINAL_DESTINATION" "$commit" "$version" "$epoch" "$manifest_hash"',
            'true # installed manifest proof removed',
            "record-bound published-set proof",
        ),
        (
            "build",
            'remove_registered_final_transaction "$FINAL_TRANSACTION_ID"',
            'rm -rf -- "$FINAL_TRANSACTION"',
            "post-commit transaction removal",
        ),
        (
            "build",
            'prepare_existing_dist_removal "$destination"',
            'prepare_existing_dist_removal "$destination"\n        chmod -R u+rwX "$destination"',
            "existing dist is weakened before the publication commit point",
        ),
        (
            "build",
            'run_snapshot_consumer "final APK certificate proof"',
            'compare_snapshots\n    run_snapshot_consumer "final APK certificate proof"',
            "release transaction",
        ),
        (
            "build",
            'run_publication_reconciliation_self_test "$SET_A"',
            'true # publication reconciliation fixture removed',
            "publication reconciliation fixture dispatch",
        ),
        (
            "build",
            'assert_single_writer_publication_parent "$REPO_ROOT" >/dev/null',
            'true # canonical parent proof removed',
            "canonical publication-parent fixture",
        ),
        (
            "scan",
            'if [ "$status" -eq 1 ]; then',
            'if [ "$status" -eq 2 ]; then',
            "scanner no-match status",
        ),
        (
            "scan",
            'else\n    status=$?\n  fi',
            'else\n    status=0\n  fi',
            "scanner status capture",
        ),
        (
            "release",
            "verify_scan_preflight || exit 1",
            "true # scanner preflight removed",
            "release scanner preflight",
        ),
        (
            "verify",
            "source scripts/verify-scan.sh",
            "source scripts/verify-scan.sh\nrg -n forbidden src",
            "undeclared ripgrep dependency",
        ),
        (
            "verify",
            "^[[:space:]]*virtual_display[[:space:]]*=",
            "virtual_display =",
            "anchored IDD dependency scan",
        ),
        (
            "smoke",
            'cd "$HOME"',
            "cd /work",
            "non-root smoke runner retains forbidden source/process authority",
        ),
        (
            "smoke",
            'install -o root -g "$gid" -m 0550 target/debug/examples/probe_client "$fixture/bin/probe_client"',
            "true # probe client fixture removed",
            "probe client fixture",
        ),
        (
            "smoke",
            'kill -TERM "$SRV" 2>/dev/null || true',
            'pkill -TERM -f "rustdesk --server" || true',
            "non-root smoke runner retains forbidden source/process authority",
        ),
        ("build", "renameat2 = libc.renameat2", "renameat2 = libc.rename", "atomic final-dist exchange"),
        ("build", "git --no-replace-objects", "git", "Git replacement-object suppression"),
        (
            "build",
            '--verify-apk "$SET_A/rustdesk-arm64.apk"',
            '--verify-apk "$FINAL_OUT_DIR/rustdesk-arm64.apk"',
            "staged final APK certificate proof",
        ),
        (
            "debian",
            'require_pinned_builder_image deb-builder "$IMAGE_ID"',
            "true # builder proof removed",
            "Debian builder provenance verification",
        ),
        (
            "android",
            'create_private_online_snapshot "$ONLINE_SNAPSHOT_PARENT"',
            "true # direct snapshot removed",
            "Android direct snapshot",
        ),
        (
            "publish",
            "EXPECTED_REPO_ID=1268555599",
            "EXPECTED_REPO_ID=1",
            "numeric GitHub repository identity pin",
        ),
        (
            "publish",
            'gh_api "repos/$REPO_SLUG/releases/$RELEASE_ID" --method PATCH',
            'gh_api "repos/$REPO_SLUG/releases/$TAG" --method PATCH',
            "numeric-ID publication",
        ),
        (
            "publish",
            'strict_release_inventory "$RELEASE_ID" 1',
            "true # barrier inventory removed",
            "barrier release inventory",
        ),
        (
            "publish",
            'assert_immutable_release_policy "final pre-publication barrier"',
            "true # immutable-release policy removed",
            "barrier immutable-release policy",
        ),
        (
            "publish",
            "parse_constant=reject_nonfinite",
            "parse_constant=None",
            "non-finite JSON rejection",
        ),
        (
            "publish",
            "GitHub release asset server digest differs",
            "GitHub release asset digest omitted",
            "server digest proof",
        ),
        (
            "publish",
            "--no-replace-objects -c core.hooksPath=/dev/null",
            "-c core.hooksPath=/dev/null",
            "publisher Git replacement suppression",
        ),
        ("version", "fork_version_real_date() {", "fork_version_date() {", "real calendar validation"),
    )
    for key, old, new, expected in mutations:
        if sources[key].count(old) < 1:
            raise VerificationError(f"mutation fixture target is absent: {old}")
        mutated = dict(sources)
        mutated[key] = mutated[key].replace(old, new, 1)
        try:
            validate_sources(mutated)
        except VerificationError as exc:
            if expected not in str(exc):
                raise VerificationError(f"mutation rejected for {exc}, expected {expected}") from exc
        else:
            raise VerificationError(f"source mutation was accepted: {expected}")


def main():
    parser = argparse.ArgumentParser(description="Verify private workspace and release transactions.")
    parser.add_argument("--repo", default=".", help="repository root")
    parser.add_argument("--self-test", action="store_true", help="run executable and mutation fixtures")
    args = parser.parse_args()
    try:
        repo = Path(args.repo).resolve()
        lines, positions = validate_verify_workspace((repo / "scripts/verify.sh").read_text(encoding="utf-8"))
        sources = {
            "build": (repo / "scripts/build-release.sh").read_text(encoding="utf-8"),
            "scan": (repo / "scripts/verify-scan.sh").read_text(encoding="utf-8"),
            "verify": (repo / "scripts/verify.sh").read_text(encoding="utf-8"),
            "apple": (repo / "scripts/apple-conform-check.sh").read_text(encoding="utf-8"),
            "release": (repo / "scripts/verify-release.sh").read_text(encoding="utf-8"),
            "smoke": (repo / "scripts/smoke-server.sh").read_text(encoding="utf-8"),
            "faillo": (repo / "scripts/test-build-faillo.sh").read_text(encoding="utf-8"),
            "closure": (repo / "scripts/verify-private-tree-closure.py").read_text(encoding="utf-8"),
            "publish": (repo / "scripts/publish-github-release.sh").read_text(encoding="utf-8"),
            "version": (repo / "scripts/fork-version.sh").read_text(encoding="utf-8"),
            "debian": (repo / "scripts/build-debian.sh").read_text(encoding="utf-8"),
            "android": (repo / "scripts/build-android.sh").read_text(encoding="utf-8"),
            "pins": (repo / "scripts/pins.env").read_text(encoding="utf-8"),
            "docs": (repo / "docs/VERSIONING.md").read_text(encoding="utf-8"),
            "workspace_verifier": (repo / "scripts/verify-verifier-workspace.py").read_text(encoding="utf-8"),
        }
        validate_sources(sources)
        if args.self_test:
            run_workspace_mutations(lines, positions)
            run_source_mutations(sources)
            run_version_fixtures(sources["version"])
            run_target_contract_fixtures(sources)
            run_stateful_timeout_fixtures(repo)
            run_transaction_fixtures(repo)
            closure = run_command(
                [sys.executable, str(repo / "scripts/verify-private-tree-closure.py"), "--self-test"],
                repo,
            )
            require_success(closure, "private-tree closure fixture", "")
    except ManagedSignal as exc:
        print(f"verify-verifier-workspace: interrupted by signal {exc.signum}", file=sys.stderr)
        return 128 + exc.signum
    except (OSError, UnicodeError, subprocess.TimeoutExpired, VerificationError) as exc:
        print(f"verify-verifier-workspace: FAIL: {exc}", file=sys.stderr)
        return 1
    print("verify-verifier-workspace: ok")
    return 0


def validate_workspace_verifier_self_contract(source):
    try:
        module = ast.parse(source)
    except SyntaxError as exc:
        raise VerificationError(f"managed command signal ownership: Python source does not parse: {exc}") from exc
    signal_assignments = [
        node
        for node in module.body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "MANAGED_SIGNALS" for target in node.targets)
    ]
    expected_signals = ast.parse(
        "MANAGED_SIGNALS = (signal.SIGHUP, signal.SIGINT, signal.SIGTERM)"
    ).body[0].value
    if len(signal_assignments) != 1 or ast.dump(signal_assignments[0].value) != ast.dump(expected_signals):
        raise VerificationError("managed command signal ownership: exact managed signal set is absent")
    signal_boundary = extract_between(
        source,
        "def handle_managed_signal(",
        "\n\ndef process_group_exists(",
        "managed verifier signal boundary",
    )
    terminator = extract_between(
        source,
        "def terminate_and_reap_process_group(",
        "\n\ndef run_managed_command(",
        "managed verifier process-group teardown",
    )
    managed = extract_between(
        source,
        "def run_managed_command(",
        "\n\ndef reserved_release_state(",
        "managed verifier command runner",
    )
    state_proof = extract_between(
        source,
        "def assert_reserved_release_state_unchanged(",
        "\n\ndef run_stateful_command(",
        "stateful reserved release-state proof",
    )
    stateful = extract_between(
        source,
        "def run_stateful_command(",
        "\n\ndef assert_process_absent(",
        "stateful verifier command runner",
    )
    transactions = extract_between(
        source,
        "def run_transaction_fixtures(repo):",
        "\n\ndef run_version_fixtures(",
        "stateful transaction fixture dispatch",
    )
    timeout_fixtures = extract_between(
        source,
        "def run_stateful_timeout_fixtures(repo):",
        "\n\ndef require_success(",
        "stateful timeout behavioral fixtures",
    )
    main = extract_between(
        source,
        "def main():",
        "\n\ndef validate_workspace_verifier_self_contract(",
        "verifier main dispatch",
    )
    require_order(
        signal_boundary,
        (
            'state["caught"] = True',
            'if state["acquiring_process"]:',
            'state["pending_signum"] = signum',
            "return",
            "signal.pthread_sigmask(signal.SIG_BLOCK, MANAGED_SIGNALS)",
            "raise ManagedSignal(signum)",
            "def enter_managed_signal_scope():",
            "if threading.current_thread() is not threading.main_thread():",
            "entry_mask = signal.pthread_sigmask(signal.SIG_BLOCK, MANAGED_SIGNALS)",
            'return {"entry_mask": entry_mask, "outer": False}',
            "signal.signal(signum, handle_managed_signal)",
            "_MANAGED_SIGNAL_STATE = state",
            "def activate_managed_signal_scope(scope):",
            'signal.pthread_sigmask(signal.SIG_SETMASK, scope["entry_mask"])',
            "def begin_managed_process_acquisition():",
            'state["acquiring_process"] = True',
            "def finish_managed_process_acquisition():",
            "previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, MANAGED_SIGNALS)",
            'state["acquiring_process"] = False',
            'pending_signum = state["pending_signum"]',
            "raise ManagedSignal(pending_signum)",
            "def leave_managed_signal_scope(scope, finalization_mask):",
            'if state["caught"]:',
            "signal.signal(signum, signal.SIG_IGN)",
            "signal.pthread_sigmask(signal.SIG_BLOCK, MANAGED_SIGNALS)",
            "signal.signal(signum, handler)",
            "_MANAGED_SIGNAL_STATE = None",
            "signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)",
        ),
        "managed command signal ownership",
    )
    validate_popen_finally_ownership(
        source,
        "run_managed_command",
        "terminate_and_reap_process_group",
        "process_reaped",
        "managed command process-group ownership",
    )
    require_order(
        terminator,
        (
            "process_group = process.pid",
            "signal_process_group(process_group, signal.SIGTERM)",
            "process.wait(timeout=cleanup_grace_seconds)",
            "signal_process_group(process_group, signal.SIGKILL)",
            "process.wait(timeout=kill_grace_seconds)",
            "if process_group_exists(process_group):",
            "signal_process_group(process_group, signal.SIGKILL)",
            "wait_process_group_absent(process_group, kill_grace_seconds)",
            "close_process_pipes(process)",
        ),
        "managed command process-group ownership",
    )
    require_order(
        managed,
        (
            "process = None",
            "process_reaped = False",
            "try:",
            "signal_scope = enter_managed_signal_scope()",
            "activate_managed_signal_scope(signal_scope)",
            "begin_managed_process_acquisition()",
            "try:",
            "process = subprocess.Popen(",
            "start_new_session=True",
            "finally:",
            "finish_managed_process_acquisition()",
            "signal_process_group(process.pid, signal.SIGTERM)",
            "deadline = time.monotonic() + cleanup_grace_seconds",
            "signal_process_group(process.pid, signal.SIGKILL)",
            "deadline = time.monotonic() + kill_grace_seconds",
            "if output_bytes > max_output_bytes:",
            "process_reaped = True",
            "finally:",
            "terminate_and_reap_process_group(process, cleanup_grace_seconds, kill_grace_seconds)",
            "leave_managed_signal_scope(signal_scope, finalization_mask)",
        ),
        "managed command process-group ownership",
    )
    require_order(
        stateful,
        (
            "signal_scope = None",
            "try:",
            "signal_scope = enter_managed_signal_scope()",
            "activate_managed_signal_scope(signal_scope)",
            "before = reserved_release_state(cwd)",
            "try:",
            "result = run_managed_command(",
            "except BaseException as exc:",
            "assert_reserved_release_state_unchanged(before, cwd, execution_error)",
            "except ManagedSignal:",
            "assert_reserved_release_state_unchanged(before, cwd)",
            "finally:",
            "leave_managed_signal_scope(signal_scope, finalization_mask)",
        ),
        "stateful release-state proof",
    )
    require_order(
        state_proof,
        (
            "after = reserved_release_state(cwd)",
            "if after != before:",
            '"new_worktrees"',
            '"new_directories"',
            '"changed_directories"',
            "raise state_error",
        ),
        "stateful release-state proof",
    )
    for text, label in (
        ("stateful fixture changed reserved release state", "stateful reserved-state mismatch rejection"),
        ("managed command output exceeds its bound", "managed command output bound"),
        ("cannot reap a hard-killed managed command process group", "managed command hard-kill reap"),
    ):
        require_text(source, text, label)
    require_text(
        transactions,
        "result = run_stateful_command([str(path), mode], repo, poison)",
        "transaction fixtures use the stateful runner",
    )
    for text, label in (
        ("STATEFUL-POST-SPAWN-CLEANUP", "post-spawn exception cleanup fixture"),
        ("def signal_before_popen_return", "pre-assignment managed signal fixture"),
        ("subprocess.Popen = signal_before_popen_return", "pre-assignment managed signal fixture"),
        (
            "handle_managed_signal(signal.SIGTERM, None)",
            "pre-assignment managed signal injection",
        ),
        ("pre-assignment managed signal retained", "pre-assignment process-group absence proof"),
        (
            'print(f"STATEFUL-PARENT-SIGNAL-STATE-CHECKED:{exc.signum}", flush=True)',
            "external parent-signal cleanup fixture",
        ),
        ("STATEFUL-GRACEFUL-CLEANUP", "graceful process-group cleanup fixture"),
        ("STATEFUL-RESISTANT-CHILD", "hard-kill process-group cleanup fixture"),
        ("assert_process_absent", "timeout descendant absence proof"),
    ):
        require_text(timeout_fixtures, text, label)
    require_text(main, "run_stateful_timeout_fixtures(repo)", "stateful timeout fixture dispatch")
    require_text(main, "except ManagedSignal as exc:", "managed signal main classification")
    require_text(main, "return 128 + exc.signum", "managed signal exit status")


if __name__ == "__main__":
    raise SystemExit(main())
