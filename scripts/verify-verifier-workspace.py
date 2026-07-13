#!/usr/bin/env python3
import argparse
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path


WORKSPACE_BLOCKS = (
    (
        "workspace creation",
        (
            "VERIFY_TMP=$(umask 077 && mktemp -d /tmp/rustdesk-verify.XXXXXXXXXX)",
            "readonly VERIFY_TMP",
        ),
    ),
    (
        "workspace cleanup",
        (
            "cleanup_verify_tmp() {",
            "  local status=$?",
            "  trap - EXIT HUP INT TERM",
            '  if ! rm -rf -- "$VERIFY_TMP"; then',
            '    echo "verify: failed to remove private workspace: $VERIFY_TMP" >&2',
            "    status=1",
            "  fi",
            '  exit "$status"',
            "}",
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


def require_text(source, text, label):
    if text not in source:
        raise VerificationError(f"{label}: required contract is absent")


def require_count(source, text, minimum, label):
    count = source.count(text)
    if count < minimum:
        raise VerificationError(f"{label}: expected at least {minimum} occurrences, found {count}")


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
    for line_number, line in enumerate(lines, 1):
        if OLD_SCRATCH_PREFIX.search(line):
            raise VerificationError(f"line {line_number}: predictable public scratch prefix is present")
        if PUBLIC_TMP_REDIRECTION.search(line):
            raise VerificationError(f"line {line_number}: direct public-/tmp redirection is present")
        if has_fixed_string_self_check(line):
            raise VerificationError(f"line {line_number}: fixed-string self-inspection is present")
    return lines, positions


def validate_build_release(source):
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
        "require_cmd cmp git docker python3 sha256sum stat readlink install find date /usr/bin/grep",
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
            'require_cmd cmp git docker python3 sha256sum stat readlink install find date /usr/bin/grep',
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
    require_count(source, "run_snapshot_consumer ", 6, "before/after online snapshot consumption")
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
    require_text(source, 'chmod 0700 "$source"', "private release snapshot mode")
    require_text(
        source,
        '[ "$(stat -c \'%u:%a\' "$source")" = "$(id -u):700" ]',
        "private release snapshot metadata proof",
    )
    require_text(source, 'git_closed -C "$source" clean -ffdx', "generated-state reset")
    require_count(source, "DOUBLE_BUILD=0", 3, "single target invocation per outer snapshot")
    require_text(source, 'build_snapshot A "$SOURCE_A"', "snapshot A target execution")
    require_text(source, 'build_snapshot B "$SOURCE_B"', "snapshot B target execution")
    require_text(source, "independent snapshot mismatch for $name", "all-artifact A/B comparison")
    require_text(source, "# reproducibility: independent-snapshots-a-equals-b", "manifest reproducibility identity")
    require_text(source, "renameat2 = libc.renameat2", "atomic final-dist exchange")
    require_text(source, "git --no-replace-objects", "Git replacement-object suppression")
    require_text(source, "Git grafts are forbidden for release builds", "Git graft rejection")
    require_text(source, "Git object alternates are forbidden for release builds", "Git alternate rejection")
    require_text(source, "Git replacement refs are forbidden for release builds", "Git replacement-ref rejection")
    require_text(source, "GIT_NO_REPLACE_OBJECTS=1", "child replacement-object suppression")
    require_text(source, '--verify-apk "$SET_A/rustdesk-arm64.apk"', "staged final APK certificate proof")
    require_text(source, "WINDOWS_UNSAFE=1", "Windows-owned state guard")
    require_text(source, "workspace retained because VM ownership is unresolved", "Windows failure retention")
    require_text(source, "--network=none --user 0:0", "offline cleanup")
    require_text(source, '"$DEBIAN_IMAGE_ID" chown', "content-ID cleanup image")
    require_text(source, "run_self_test()", "release behavioral fixture")
    require_text(source, "release self-test did not execute exactly six target commands", "target execution fixture")
    require_text(source, "release self-test did not use two independent snapshots", "snapshot independence fixture")
    require_text(source, "release self-test target outputs are not distinct", "output isolation fixture")
    require_order(
        source,
        (
            'prepare_release_snapshots\n',
            'build_snapshot A "$SOURCE_A"',
            'build_snapshot B "$SOURCE_B"',
            "compare_snapshots\n",
            'write_manifest "$SET_A"',
            'run_snapshot_consumer "final APK certificate proof"',
            'assert_snapshot_exact "$SOURCE_A" "after final APK certificate proof"',
            'assert_release_source_state "before final dist installation"',
            'assert_live_origin_master "before final dist installation"',
            'atomic_install_dist "$SET_A"',
            'log "RELEASE OK:',
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
    require_count(source, "--paginate", 4, "exhaustive REST inventory calls and stub enforcement")
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
    require_count(source, "parse_constant=reject_nonfinite", 7, "non-finite JSON rejection")
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
    require_count(source, "--no-replace-objects -c core.hooksPath=/dev/null", 2, "publisher Git replacement suppression")
    require_text(source, "Git grafts are forbidden for publication", "publisher Git graft rejection")
    require_text(source, "GitHub release field {key} has a hostile or missing type", "hostile schema rejection")
    require_text(source, "GitHub release asset size differs", "remote size proof")
    require_count(source, "GitHub release asset server digest differs", 2, "server digest proof")
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
    require_text(source, "release source-gate preflight accepts the fixed scanner", "scanner preflight proof")
    require_text(source, "verifier scanner rejects an operational error", "scanner error proof")
    if "every misconfiguration" in source:
        raise VerificationError("fail-loud suite overclaims every possible misconfiguration")


def validate_sources(sources):
    validate_build_release(sources["build"])
    validate_target_scripts(sources["debian"], sources["android"], sources["pins"])
    validate_publisher(sources["publish"])
    validate_fork_version(sources["version"])
    validate_docs(sources["docs"])
    validate_scan_contract(sources["scan"], sources["verify"], sources["apple"], sources["release"])
    validate_smoke_contract(sources["smoke"])
    validate_faillo_contract(sources["faillo"])


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
            "scripts/publish-github-release.sh",
            "publish-github-release self-test: OK",
            "publisher transaction fixture",
        ),
    ):
        path = repo / relative
        result = run_command([str(path), "--self-test"], repo, poison)
        require_success(result, label, marker)
        bypass = run_command(
            ["/usr/bin/bash", "--noprofile", "--norc", str(path), "--self-test"],
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
            "private release snapshot mode",
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
            "require_cmd cmp git docker python3 sha256sum stat readlink install find date /usr/bin/grep",
            "require_cmd cmp git docker python3 sha256sum stat readlink install find date",
            "release host-tool preflight",
        ),
        (
            "build",
            'run_child /usr/bin/bash --noprofile --norc "$REPO_ROOT/scripts/verify-release.sh" --preflight',
            "true # release source-gate preflight removed",
            "release source-gate preflight",
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
            "publish": (repo / "scripts/publish-github-release.sh").read_text(encoding="utf-8"),
            "version": (repo / "scripts/fork-version.sh").read_text(encoding="utf-8"),
            "debian": (repo / "scripts/build-debian.sh").read_text(encoding="utf-8"),
            "android": (repo / "scripts/build-android.sh").read_text(encoding="utf-8"),
            "pins": (repo / "scripts/pins.env").read_text(encoding="utf-8"),
            "docs": (repo / "docs/VERSIONING.md").read_text(encoding="utf-8"),
        }
        validate_sources(sources)
        if args.self_test:
            run_workspace_mutations(lines, positions)
            run_source_mutations(sources)
            run_version_fixtures(sources["version"])
            run_target_contract_fixtures(sources)
            run_transaction_fixtures(repo)
    except (OSError, UnicodeError, subprocess.TimeoutExpired, VerificationError) as exc:
        print(f"verify-verifier-workspace: FAIL: {exc}", file=sys.stderr)
        return 1
    print("verify-verifier-workspace: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
