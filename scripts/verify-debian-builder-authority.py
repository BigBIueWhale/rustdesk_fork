#!/usr/bin/env python3
"""Validate the Debian builder's private-source and confined-container authority."""

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


def require_order(source: str, tokens: Tuple[str, ...], label: str) -> None:
    try:
        positions = tuple(source.index(token) for token in tokens)
    except ValueError as exc:
        raise AuthorityError("{} is incomplete or misordered".format(label)) from exc
    if positions != tuple(sorted(positions)) or len(set(positions)) != len(positions):
        raise AuthorityError("{} is incomplete or misordered".format(label))


def extract(source: str, start: str, end: str, label: str) -> str:
    try:
        begin = source.index(start)
        finish = source.index(end, begin)
    except ValueError as exc:
        raise AuthorityError("missing {}".format(label)) from exc
    return source[begin:finish]


def validate(sources: Dict[str, str]) -> None:
    build = sources["build"]
    lib = sources["lib"]
    publisher = sources["publisher"]

    for token, label in (
        ("set -euo pipefail\numask 077", "private host-created state umask"),
        ("export PATH=/usr/bin:/bin", "closed host command path"),
        ('readonly BUILD_UID="$(/usr/bin/id -u)"', "absolute host UID source"),
        ('readonly BUILD_GID="$(/usr/bin/id -g)"', "absolute host GID source"),
        ('[ "$BUILD_UID" -ne 0 ]', "host UID-root refusal"),
        ('[ "$BUILD_GID" -ne 0 ]', "host GID-root refusal"),
        ("refuses host or container-root execution", "root execution refusal"),
        ("refuses a root primary group", "root primary-group refusal"),
        ('source "$SCRIPT_DIR/lib.sh"', "shared Docker authority source"),
        ("GIT_CONFIG_NOSYSTEM=1 \\\n    GIT_CONFIG_GLOBAL=/dev/null \\\n"
         "    GIT_CONFIG_SYSTEM=/dev/null \\\n    GIT_TERMINAL_PROMPT=0 \\\n"
         "    GIT_NO_REPLACE_OBJECTS=1", "closed Git configuration and replacement authority"),
        ('SOURCE_COMMIT="$current"', "exact source commit capture"),
        (
            "mktemp -d /tmp/rustdesk-debian-build.XXXXXXXXXX",
            "private direct-or-release workspace",
        ),
        ('OWNED_WORKSPACE_ID="$(/usr/bin/stat -c \'%d:%i\'',
         "private workspace identity capture"),
        ("prepare_output_contract", "absent canonical output preflight"),
        ("record_output_parent_identity", "output-parent identity capture"),
        ('OUT_PARENT_ID="$device:$inode"', "retained output-parent identity"),
        ("Debian output directory must be absent for no-clobber publication",
         "absent output requirement"),
        (
            'initialize_local_docker_authority "$OWNED_WORKSPACE/docker-config" "debian-builder"',
            "fixed local Docker authority initialization",
        ),
        (
            'if [ "$LOCAL_DOCKER_AUTHORITY_INITIALIZED" -eq 1 ]',
            "fixed local Docker authority cleanup admission",
        ),
        ("&& ! remove_local_docker_authority; then", "exact local Docker authority cleanup"),
        (
            "preserving changed private Debian builder Docker authority",
            "changed local Docker authority preservation",
        ),
        ("prepare_direct_build_source() {", "private direct-source constructor"),
        ('clone --quiet --no-hardlinks --no-checkout --reject-shallow "$REPO_ROOT" "$source"',
         "non-hardlinked private Git clone"),
        ('checkout --quiet --detach "$SOURCE_COMMIT"', "detached exact-commit checkout"),
        ('remote remove origin', "private clone remote removal"),
        ('fsck --full --strict --no-reflogs', "private object-database verification"),
        ('BUILD_SOURCE_ROOT="$REPO_ROOT"', "release-snapshot source selection"),
        ('prepare_direct_build_source "$label"', "direct-build private-source selection"),
        ('[ "$common" = "$path/.git" ]', "private Git-directory ownership"),
        ('$common/objects/info/alternates" ] && [ ! -L "$common/objects/info/alternates"',
         "Git-alternate refusal"),
        ('for-each-ref --format=\'%(refname)\' refs/replace', "replacement-ref refusal"),
        ('status --porcelain=v1 --untracked-files=no', "tracked-state comparison"),
        ('diff --quiet --no-ext-diff HEAD --', "worktree exact-commit comparison"),
        ('diff --cached --quiet --no-ext-diff HEAD --', "index exact-commit comparison"),
        ('BUILD_SOURCE_ID="$(stat -c \'%d:%i\'', "source root identity capture"),
        ('[ "$observed" = "$BUILD_SOURCE_ID" ]', "source root identity postcondition"),
        ('verify_build_source_postcondition "failed Debian $profile build"',
         "failed-build source postcondition"),
        ('verify_build_source_postcondition "completed Debian $profile build"',
         "successful-build source postcondition"),
        ('release child requires outer independent snapshots and DOUBLE_BUILD=0',
         "release outer-snapshot reproducibility ownership"),
        ("activate_build_source pass-a", "first private direct build source"),
        ("activate_build_source pass-b", "second independent direct build source"),
        ('local -a packages=("$BUILD_SOURCE_ROOT"/rustdesk-*.deb)',
         "closed private package selection"),
        ("Debian build must emit exactly one rustdesk-*.deb package",
         "single private package requirement"),
        ("Debian build output metadata is unsafe", "private package metadata gate"),
        ('PASS_A_DEB_ID="$package_identity"', "pass-A package identity retention"),
        ('PASS_A_SHA256="$before_sha256"', "pass-A private digest retention"),
        ('PASS_B_SHA256="$before_sha256"', "pass-B private digest retention"),
        ('[ "$PASS_A_SHA256" = "$PASS_B_SHA256" ]',
         "private A/B reproducibility comparison"),
        ('local_docker run --rm --pull=never', "fixed local immutable no-pull launch"),
        (
            'assert_local_docker_authority \\\n'
            '        || die "Debian builder local Docker authority changed"',
            "active Docker authority recheck",
        ),
        ("--network=none", "networkless compile container"),
        ("--read-only", "read-only container root"),
        ('--user "$BUILD_UID:$BUILD_GID"', "numeric nonroot identity"),
        ("--cap-drop=ALL", "complete capability drop"),
        ("--security-opt=no-new-privileges", "no-new-privileges boundary"),
        ("--pids-limit=1024", "PID ceiling"),
        ("--memory=16g", "memory ceiling"),
        ("--memory-swap=16g", "no-swap expansion"),
        ("--cpus=4", "CPU ceiling"),
        ("--tmpfs /tmp:rw,exec,nosuid,nodev,mode=1777,size=12g",
         "bounded executable scratch"),
        (
            '-e "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH"',
            "explicit reproducibility-epoch transfer through empty environment",
        ),
        ('--mount "type=bind,source=$BUILD_SOURCE_ROOT,target=/src"',
         "private writable build-source mount"),
        ("--tmpfs /src/.git:ro,noexec,nosuid,nodev,mode=0555,size=1m",
         "empty read-only nested Git-authority shield"),
        ('--mount "type=bind,source=$ONLINE_DIR,target=/online,readonly"',
         "read-only private online-input mount"),
        ('/usr/bin/stat -c \'%u:%g:%a:%h:%s:%d:%i\' -- "$deb"',
         "private package identity and metadata proof"),
        ('--repo "$BUILD_SOURCE_ROOT" --deb', "artifact validation against exact source"),
        ('[ "$after_metadata" = "$metadata" ] && [ "$after_sha256" = "$before_sha256" ]',
         "package stability across validation"),
        ("prepare_pending_result", "private pending-result preparation"),
        ('remove_local_docker_authority \\\n'
         '        || die "Debian builder Docker authority could not retire before publication"',
         "Docker authority retirement before publication"),
        ('remove_owned_workspace_exact \\\n'
         '        || die "private Debian build workspace could not retire before final publication"',
         "exact workspace retirement before final publication"),
        ('/usr/bin/python3 -I -S "$SCRIPT_DIR/publish-artifact-result.py"',
         "isolated closed-profile result publisher"),
        ("--artifact-kind debian-x86_64", "closed Debian publication profile"),
        ("--source-identity \"$PASS_A_DEB_ID\"", "publisher package identity transfer"),
        ("--source-sha256 \"$PASS_A_SHA256\"", "publisher package digest transfer"),
        ("--output-parent-identity \"$OUT_PARENT_ID\"",
         "publisher output-parent identity transfer"),
        ("--pending-identity \"$PENDING_RESULT_ID\"", "publisher pending identity transfer"),
    ):
        require(build, token, label)

    require_count(build, 'BUILD_SOURCE_ROOT="$REPO_ROOT"', 1, "release-source assignment")
    require_count(build, 'prepare_direct_build_source "$label"', 1, "direct-source selection")
    require_count(build, "local_docker run", 1, "sole fixed-local Debian compiler launch")
    require_count(build, "--cap-drop=ALL", 1, "sole compile capability policy")
    require_count(build, "--security-opt=no-new-privileges", 1, "sole privilege policy")
    require_count(
        build,
        '-e "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH"',
        1,
        "sole explicit reproducibility-epoch transfer",
    )
    require_count(build, "/src/.git:ro,noexec,nosuid,nodev,mode=0555,size=1m", 1,
                  "sole nested Git shield")
    require_count(build, "target=/online,readonly", 1, "sole online-input mount")
    require_count(
        build,
        '/usr/bin/python3 -I -S "$SCRIPT_DIR/publish-artifact-result.py"',
        2,
        "two-phase Debian publisher invocation",
    )

    release_assignment = build.index('BUILD_SOURCE_ROOT="$REPO_ROOT"')
    release_branch = build.rfind('if [ "$RELEASE_CHILD" -eq 1 ]', 0, release_assignment)
    direct_selection = build.index('prepare_direct_build_source "$label"', release_assignment)
    if release_branch < 0 or not release_branch < release_assignment < direct_selection:
        raise AuthorityError("release and direct source selection are not one closed branch")
    require_order(
        build,
        (
            'readonly BUILD_UID="$(/usr/bin/id -u)"',
            'readonly BUILD_GID="$(/usr/bin/id -g)"',
            '[ "$BUILD_UID" -ne 0 ]',
            '[ "$BUILD_GID" -ne 0 ]',
            'source "$SCRIPT_DIR/lib.sh"',
            "load_pins",
            "mktemp -d /tmp/rustdesk-debian-build.XXXXXXXXXX",
            'initialize_local_docker_authority "$OWNED_WORKSPACE/docker-config" "debian-builder"',
            'if [ -n "${RELEASE_SRC_COMMIT:-}" ]',
            'require_pinned_builder_image deb-builder "$IMAGE_ID"',
            "local_docker run --rm --pull=never",
        ),
        "root refusal, shared authority, release classification, provenance, and launch",
    )
    cleanup = extract(
        build,
        "cleanup_owned_workspace() {",
        "\n}\n\ntrap cleanup_owned_workspace EXIT",
        "Debian builder workspace cleanup",
    )
    preflight = extract(
        build,
        "preflight() {",
        "\n}\n\nverify_deb_control_scripts() {",
        "Debian builder preflight",
    )
    require_order(
        preflight,
        (
            "assert_clean_worktree",
            "assert_source_date_epoch",
            "prepare_output_contract",
            "prepare_execution_contract",
            "resolve_image",
            "activate_online_snapshot",
        ),
        "output contract before private build authority",
    )
    require_order(
        cleanup,
        (
            "remove_local_docker_authority",
            'elif [ -n "$OWNED_WORKSPACE" ]',
            "remove_owned_workspace_exact",
        ),
        "Docker-before-workspace cleanup order",
    )
    exact_cleanup = extract(
        build,
        "remove_owned_workspace_exact() {",
        "\n}\n\nrecord_output_parent_identity() {",
        "exact Debian workspace cleanup",
    )
    for token, label in (
        ('--remove-private-root "$OWNED_WORKSPACE"', "descriptor-relative workspace closer"),
        ('--expected-identity "$OWNED_WORKSPACE_ID"', "workspace identity transfer"),
        ('[ ! -e "$OWNED_WORKSPACE" ] && [ ! -L "$OWNED_WORKSPACE" ]',
         "workspace edge absence proof"),
        ('OWNED_WORKSPACE=""', "retired workspace pathname authority"),
        ('OWNED_WORKSPACE_ID=""', "retired workspace object authority"),
    ):
        require(exact_cleanup, token, label)
    for token, label in (
        ("chmod -R", "recursive workspace permission fallback"),
        ("rm -rf", "recursive workspace deletion fallback"),
    ):
        forbid(cleanup + exact_cleanup, token, label)
    package_check = extract(
        build,
        "verify_deb_control_scripts() {",
        "\n}\n\n# build_one PROFILE FEATURES PASS:",
        "private Debian package-check workspace",
    )
    require(
        package_check,
        'mktemp -d "$OWNED_WORKSPACE/debian-package-check.XXXXXXXXXX"',
        "package checks contained by the exact private workspace",
    )
    forbid(
        package_check,
        'rm -rf "$tmp_package"',
        "recursive package-check workspace deletion",
    )

    publication = extract(
        build,
        "publish_result() {",
        "\n}\n\nmain() {",
        "Debian result publication",
    )
    require_order(
        publication,
        (
            "verify_active_online_snapshot",
            'verify_build_source_postcondition "final Debian build-source state"',
            "assert_local_docker_authority",
            "remove_local_docker_authority",
            "prepare_pending_result",
            "remove_owned_workspace_exact",
            "--commit",
        ),
        "Docker retirement, pending preparation, workspace retirement, and final publication",
    )
    main = extract(build, "main() {", "\n}\n\nmain \"$@\"", "Debian builder main")
    require_order(
        main,
        (
            "preflight",
            "activate_build_source pass-a",
            'build_one x86_64 "$FEATURES" pass-a',
            "activate_build_source pass-b",
            'build_one x86_64 "$FEATURES" pass-b',
            '[ "$PASS_A_SHA256" = "$PASS_B_SHA256" ]',
            "publish_result",
        ),
        "private build, reproducibility, and publication order",
    )

    launch_tokens = (
        "local_docker run --rm --pull=never",
        "--network=none",
        "--read-only",
        '--user "$BUILD_UID:$BUILD_GID"',
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--pids-limit=1024",
        "--memory=16g",
        "--memory-swap=16g",
        "--cpus=4",
        "--tmpfs /tmp:rw,exec,nosuid,nodev,mode=1777,size=12g",
        '-e "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH"',
        'target=/src"',
        "/src/.git:ro,noexec,nosuid,nodev,mode=0555,size=1m",
        "target=/online,readonly",
        "-w /src",
        '"$IMAGE_ID"',
    )
    positions = tuple(build.index(token, build.index("local_docker run")) for token in launch_tokens)
    if positions != tuple(sorted(positions)) or len(set(positions)) != len(positions):
        raise AuthorityError("Debian compile-container authority is incomplete or misordered")

    for token, label in (
        ('$REPO_ROOT:/src', "real repository short bind"),
        ('source=$REPO_ROOT,target=/src', "real repository direct mount"),
        ("--name ", "daemon-global container name"),
        ("--privileged", "privileged container"),
        ("--cap-add", "added capability"),
        ("--network=host", "host network namespace"),
        ("--pid=host", "host PID namespace"),
        ("--ipc=host", "host IPC namespace"),
        ("--uts=host", "host UTS namespace"),
        ("/var/run/docker.sock:/var/run/docker.sock", "Docker socket volume"),
        ("source=/var/run/docker.sock", "Docker socket mount"),
        ("docker build", "image build fallback"),
        ("docker pull", "image pull fallback"),
        ("readonly DOCKER_BIN", "bespoke Docker-client selector"),
        ('"$DOCKER_BIN" run', "bespoke Docker launch"),
        ("/usr/bin/docker run", "direct absolute Docker launch"),
        ("assert_private_docker_config", "bespoke Docker-config assertion"),
        ("export DOCKER_CONFIG", "process-global Docker-config selection"),
        ("require_cmd cmp docker", "PATH-selected Docker prerequisite"),
        ('mkdir -p "$OUT_DIR"', "caller-visible output creation before verification"),
        ('cp "$deb" "$OUT_DIR', "caller-visible package copy before verification"),
        ('tee "$OUT_DIR', "overwrite-capable public checksum creation"),
        ('OUT_DIR="$OUT_DIR/_rebuild"', "caller-visible pass-B output"),
        ('"$OUT_DIR/rustdesk-x86_64.deb.sha256"', "public digest as reproducibility authority"),
    ):
        forbid(build, token, label)

    for token, label in (
        ("RENAME_NOREPLACE = 1", "no-clobber rename flag"),
        ('kind="debian-x86_64"', "closed Debian artifact profile"),
        ('artifact="rustdesk-x86_64.deb"', "canonical Debian artifact name"),
        ('checksum="rustdesk-x86_64.deb.sha256"', "canonical Debian checksum name"),
        ("def expected_inventory(self) -> tuple[str, str]:",
         "closed profile-derived result inventory"),
        ("return tuple(sorted((self.artifact, self.checksum)))",
         "exact two-file profile inventory"),
        ("os.O_NOFOLLOW", "no-follow object acquisition"),
        ("stable_file(before) != stable_file(opened)", "stable object acquisition"),
        ("os.listxattr(descriptor)", "POSIX ACL inspection"),
        ("before.st_nlink != 1", "single-link source and result proof"),
        ("or before.st_nlink != 1\n"
         "        or before.st_size <= 0\n"
         "        or before.st_size > MAX_ARTIFACT_BYTES",
         "single-link bounded package-source proof"),
        ("source does not match its validated SHA-256", "validated source digest binding"),
        ('pending = f"{contract.pending_prefix}{os.urandom(32).hex()}"',
         "kernel-random pending name"),
        ("os.mkdir(pending, 0o700, dir_fd=output_parent)",
         "exclusive private pending directory"),
        ("os.fchmod(output, 0o400)", "read-only result file mode"),
        ("os.fsync(output)", "result-file synchronization"),
        ("os.fsync(pending_descriptor)", "pending-directory synchronization"),
        ("os.fsync(output_parent)", "output namespace synchronization"),
        ("renameat2", "descriptor-relative no-clobber primitive"),
        ("rename_noreplace(output_parent, pending, destination)",
         "same-parent final no-clobber rename"),
        ("published build output is not the authenticated pending object",
         "exact final-object identity proof"),
        ('verify_result(pending_descriptor, "published build output", contract)',
         "post-publication content proof"),
        ("published build output changed during final verification",
         "post-content final-edge identity proof"),
        ("publish-artifact-result self-test: ok", "bounded publication behavior fixture"),
    ):
        require(publisher, token, label)
    require_count(publisher, "os.fchmod(output, 0o400)", 2,
                  "both exact read-only result modes")
    require_count(publisher, "os.fsync(output)", 2,
                  "both exact result-file synchronizations")
    require_count(
        publisher,
        'require_absent(output_parent, pending, "retired pending build output")',
        2,
        "pre-content and post-content pending-edge retirement proofs",
    )
    prepare = extract(publisher, "def prepare(", "\n\ndef commit(", "publisher prepare phase")
    require_order(
        prepare,
        (
            "open_source(",
            "open_bound_output_parent(",
            'require_absent(output_parent, destination, "build output destination")',
            "os.urandom(32).hex()",
            "os.mkdir(pending, 0o700, dir_fd=output_parent)",
            "copy_source(",
            "create_checksum(",
            'verify_result(pending_descriptor, "pending build output", contract)',
            "os.fsync(pending_descriptor)",
            "os.fsync(output_parent)",
            "reprove_output_parent(",
        ),
        "publisher source-to-pending authority order",
    )
    commit = extract(publisher, "def commit(", "\n\ndef make_source(", "publisher commit phase")
    require_order(
        commit,
        (
            'require_absent(output_parent, destination, "build output destination")',
            "open_pending(",
            'verify_result(pending_descriptor, "pending build output", contract)',
            "os.fsync(pending_descriptor)",
            "reprove_output_parent(",
            "rename_noreplace(output_parent, pending, destination)\n"
            "        os.fsync(output_parent)",
            'require_absent(output_parent, pending, "retired pending build output")',
            'verify_result(pending_descriptor, "published build output", contract)',
            "published build output changed during final verification",
        ),
        "publisher final no-clobber commit order",
    )

    for token, label in (
        ("initialize_local_docker_authority() {", "shared Docker authority initializer"),
        (
            "DOCKER_HOST DOCKER_CONTEXT DOCKER_CONFIG DOCKER_CERT_PATH DOCKER_TLS_VERIFY DOCKER_TLS",
            "shared Docker ambient-input refusal",
        ),
        (
            "DOCKER_API_VERSION DOCKER_DEFAULT_PLATFORM DOCKER_CONTENT_TRUST",
            "shared Docker API/platform/trust-input refusal",
        ),
        (
            "DOCKER_CONTENT_TRUST_SERVER DOCKER_CUSTOM_HEADERS",
            "shared Docker trust-server/header-input refusal",
        ),
        (
            "[ -f /usr/bin/docker ] && [ ! -L /usr/bin/docker ] && [ -x /usr/bin/docker ]",
            "shared absolute Docker-client shape proof",
        ),
        (
            "case \"$(/usr/bin/stat -c '%u:%g:%a:%h' -- /usr/bin/docker 2>/dev/null)\" in\n"
            "        0:0:755:1) ;;",
            "shared root-owned Docker-client metadata proof",
        ),
        (
            "[ -S /var/run/docker.sock ] && [ ! -L /var/run/docker.sock ]",
            "shared local Docker-socket shape proof",
        ),
        (
            "case \"$(/usr/bin/stat -c '%u:%h' -- /var/run/docker.sock 2>/dev/null)\" in\n"
            "        0:1) ;;",
            "shared root-owned Docker-socket metadata proof",
        ),
        (
            "(umask 077 && set -o noclobber && printf '{}\\n' >\"$config/config.json\")",
            "shared canonical no-clobber Docker configuration",
        ),
        ('LOCAL_DOCKER_AUTHORITY_PARENT_ID="$(/usr/bin/stat',
         "shared Docker-authority parent identity binding"),
        ('LOCAL_DOCKER_AUTHORITY_CONFIG_ID="$(/usr/bin/stat',
         "shared Docker-config directory identity binding"),
        ('LOCAL_DOCKER_AUTHORITY_CONFIG_FILE_ID="$(/usr/bin/stat',
         "shared Docker-config file identity binding"),
        ('LOCAL_DOCKER_AUTHORITY_CLIENT_ID="$(/usr/bin/stat',
         "shared Docker-client identity binding"),
        ('LOCAL_DOCKER_AUTHORITY_SOCKET_ID="$(/usr/bin/stat',
         "shared Docker-socket identity binding"),
        ("local_docker() {", "shared fixed Docker launcher"),
        ("local_docker_image_provenance() {", "shared fixed Docker provenance wrapper"),
        ("remove_local_docker_authority() {", "shared exact Docker cleanup"),
        ('local_docker_image_provenance "${args[@]}"',
         "builder provenance shared-authority routing"),
    ):
        require(lib, token, label)
    asserted_authority = extract(
        lib,
        "assert_local_docker_authority() {",
        "\n}\n\nlocal_docker() {",
        "shared Docker authority assertion",
    )
    for token, label in (
        ("LOCAL_DOCKER_AUTHORITY_PARENT_ID", "shared Docker parent identity recheck"),
        ("LOCAL_DOCKER_AUTHORITY_CONFIG_ID", "shared Docker-config identity recheck"),
        ("LOCAL_DOCKER_AUTHORITY_CONFIG_FILE_ID", "shared Docker-config file identity recheck"),
        ("LOCAL_DOCKER_AUTHORITY_CLIENT_ID", "shared Docker-client identity recheck"),
        ("LOCAL_DOCKER_AUTHORITY_SOCKET_ID", "shared Docker-socket identity recheck"),
        (
            '/usr/bin/cmp -s -- "$LOCAL_DOCKER_AUTHORITY_CONFIG/config.json" <(printf \'{}\\n\')',
            "shared Docker-config byte recheck",
        ),
    ):
        require(asserted_authority, token, label)
    local_docker = extract(
        lib,
        "local_docker() {",
        "\n}\n\nlocal_docker_image_provenance() {",
        "shared fixed Docker launcher",
    )
    require_count(local_docker, "assert_local_docker_authority", 2,
                  "shared Docker pre/post authority proof")
    for token, label in (
        ("/usr/bin/env -i", "shared Docker launcher empty environment"),
        ("/usr/bin/docker", "shared Docker launcher absolute client"),
        ("--host unix:///var/run/docker.sock", "shared Docker launcher endpoint"),
        ('--config "$LOCAL_DOCKER_AUTHORITY_CONFIG"',
         "shared Docker launcher configuration"),
    ):
        require(local_docker, token, label)
    docker_provenance = extract(
        lib,
        "local_docker_image_provenance() {",
        "\n}\n\nremove_local_docker_authority() {",
        "shared fixed Docker provenance wrapper",
    )
    require_count(docker_provenance, "assert_local_docker_authority", 2,
                  "shared Docker provenance pre/post authority proof")
    for token, label in (
        ("/usr/bin/env -i", "shared Docker provenance empty environment"),
        ("/usr/bin/python3 -I -S", "shared absolute isolated provenance interpreter"),
        ('"$LIB_DIR/offline-image-provenance.py"', "shared fixed provenance program"),
    ):
        require(docker_provenance, token, label)
    docker_cleanup = extract(
        lib,
        "remove_local_docker_authority() {",
        "\n}\n\nrequire_pinned_builder_image() {",
        "shared exact Docker cleanup",
    )
    require_order(
        docker_cleanup,
        (
            "assert_local_docker_authority",
            '/usr/bin/rm -- "$LOCAL_DOCKER_AUTHORITY_CONFIG/config.json"',
            '/usr/bin/rmdir -- "$LOCAL_DOCKER_AUTHORITY_CONFIG"',
            "LOCAL_DOCKER_AUTHORITY_INITIALIZED=0",
        ),
        "shared exact Docker cleanup order",
    )

    require(
        sources["verify"],
        "python3 scripts/verify-debian-builder-authority.py --repo . --self-test",
        "shared focused-verifier wiring",
    )
    require(
        sources["verify"],
        "/usr/bin/python3 -I -S scripts/publish-artifact-result.py --self-test",
        "bounded Debian publisher fixture wiring",
    )
    require(
        sources["verify"],
        "R-S11cf/R-S11dk/R-S11dv direct builds use independent private exact-commit sources, provenance and the sole compiler use one fixed local Docker authority",
        "shared Debian-builder Docker-authority disposition",
    )
    require(sources["requirements"], '<span class="id">R-S11cf</span>', "R-S11cf requirement")
    require(sources["requirements"], "<tr><td>225</td>", "Appendix C #225 disposition")
    require(
        sources["hardening"],
        "R-S11cf/R-S11e-98 — Debian builder private-source and container authority",
        "hardening-ledger disposition",
    )
    require(
        sources["requirements"],
        '<span class="id">R-S11dj</span>',
        "R-S11dj release-child Docker isolation requirement",
    )
    require(
        sources["hardening"],
        "R-S11dj/R-S11e-128 — Android artifact-builder Docker client, daemon, and configuration authority",
        "release-child Docker isolation hardening ledger",
    )
    require(sources["requirements"], '<span class="id">R-S11dk</span>',
            "R-S11dk Debian builder Docker authority requirement")
    require(sources["requirements"], "<tr><td>264</td>",
            "Appendix C #264 disposition")
    require(
        sources["hardening"],
        "R-S11dk/R-S11e-129 — Debian artifact-builder Docker client, daemon, and configuration authority",
        "Debian builder Docker authority hardening ledger",
    )
    require(sources["requirements"], '<span class="id">R-S11dv</span>',
            "R-S11dv Debian result-publication requirement")
    require(sources["requirements"], "<tr><td>275</td>",
            "Appendix C #275 disposition")
    require(
        sources["hardening"],
        "R-S11dv/R-S11e-140 — Debian result publication is private-until-verified",
        "Debian result-publication hardening ledger",
    )
    require(
        sources["workspace"],
        '"debian_builder_authority_verifier"',
        "workspace-verifier source ownership",
    )
    require(
        sources["workspace"],
        "Debian builder focused authority verifier",
        "workspace-verifier semantic binding",
    )


MUTATIONS: Tuple[Mutation, ...] = (
    Mutation("build", "set -euo pipefail\numask 077", "set -euo pipefail\numask 022",
             "private host-created state umask"),
    Mutation("build", "export PATH=/usr/bin:/bin", "export PATH=/hostile:/usr/bin:/bin",
             "closed host command path"),
    Mutation("build", 'readonly BUILD_UID="$(/usr/bin/id -u)"',
             'readonly BUILD_UID="$(id -u)"', "absolute host UID source"),
    Mutation("build", 'readonly BUILD_GID="$(/usr/bin/id -g)"',
             'readonly BUILD_GID="$(id -g)"', "absolute host GID source"),
    Mutation("build", '[ "$BUILD_UID" -ne 0 ]', '[ "$BUILD_UID" -eq 0 ]',
             "root execution refusal"),
    Mutation("build", '[ "$BUILD_GID" -ne 0 ]', '[ "$BUILD_GID" -eq 0 ]',
             "root primary-group refusal"),
    Mutation(
        "build",
        'initialize_local_docker_authority "$OWNED_WORKSPACE/docker-config" "debian-builder"',
        "true # fixed local Docker authority disabled",
        "fixed local Docker authority initialization",
    ),
    Mutation(
        "build",
        'if [ "$LOCAL_DOCKER_AUTHORITY_INITIALIZED" -eq 1 ] \\\n'
        '        && ! remove_local_docker_authority; then',
        "if false; then",
        "fixed local Docker authority cleanup",
    ),
    Mutation(
        "build",
        "local_docker run --rm --pull=never",
        "/usr/bin/docker run --rm --pull=never",
        "fixed local Docker launch funnel",
    ),
    Mutation("build", "GIT_CONFIG_NOSYSTEM=1 \\\n    GIT_CONFIG_GLOBAL=/dev/null",
             "GIT_CONFIG_NOSYSTEM=0 \\\n    GIT_CONFIG_GLOBAL=/hostile/gitconfig",
             "closed Git configuration authority"),
    Mutation("build", "--no-hardlinks", "--local", "non-hardlinked private clone"),
    Mutation("build", 'checkout --quiet --detach "$SOURCE_COMMIT"', 'checkout --quiet master',
             "detached exact-commit checkout"),
    Mutation("build", "remote remove origin", "remote -v", "private clone remote removal"),
    Mutation("build", "fsck --full --strict --no-reflogs", "status --short",
             "private object-database verification"),
    Mutation("build", 'prepare_direct_build_source "$label"', 'BUILD_SOURCE_ROOT="$REPO_ROOT"',
             "direct private-source selection"),
    Mutation("build",
             '$common/objects/info/alternates" ] && [ ! -L "$common/objects/info/alternates"',
             '$common/objects/info/alternates" ] && [ ! -L "$common/objects/info/alternate-disabled"',
             "Git-alternate refusal"),
    Mutation("build", 'status --porcelain=v1 --untracked-files=no', 'status --porcelain=v1',
             "tracked-state comparison"),
    Mutation("build", 'diff --quiet --no-ext-diff HEAD --', 'diff --quiet --no-ext-diff --',
             "worktree exact-commit comparison"),
    Mutation("build", '[ "$observed" = "$BUILD_SOURCE_ID" ]', "true",
             "source root identity postcondition"),
    Mutation("build", 'verify_build_source_postcondition "completed Debian $profile build"',
             'true # completed-build source proof removed', "successful-build source postcondition"),
    Mutation("build", "release child requires outer independent snapshots and DOUBLE_BUILD=0",
             "release child accepted an inner warm rebuild", "release outer-snapshot ownership"),
    Mutation("build", "activate_build_source pass-b", "true # reused pass-a source",
             "independent direct second source"),
    Mutation("build", "local_docker run --rm --pull=never", "local_docker run --rm",
             "no-pull launch"),
    Mutation("build", "        --network=none \\\n        --read-only",
             "        --network=bridge \\\n        --read-only", "networkless compile"),
    Mutation("build", "--read-only", "--read-write", "read-only root"),
    Mutation("build", '--user "$BUILD_UID:$BUILD_GID"', "--user 0:0", "numeric nonroot identity"),
    Mutation("build", "--cap-drop=ALL", "--cap-drop=NET_RAW", "complete capability drop"),
    Mutation("build", "--security-opt=no-new-privileges", "--security-opt=seccomp=unconfined",
             "no-new-privileges boundary"),
    Mutation("build", "--pids-limit=1024", "--pids-limit=-1", "PID ceiling"),
    Mutation("build", "--memory=16g", "--memory=0", "memory ceiling"),
    Mutation("build", "--memory-swap=16g", "--memory-swap=-1", "no-swap expansion"),
    Mutation("build", "--cpus=4", "--cpus=0", "CPU ceiling"),
    Mutation("build", "size=12g", "size=120g", "bounded scratch"),
    Mutation(
        "build",
        '-e "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH"',
        "-e SOURCE_DATE_EPOCH",
        "explicit reproducibility-epoch transfer",
    ),
    Mutation("build", "/src/.git:ro,noexec,nosuid,nodev,mode=0555,size=1m",
             "/src/.git:rw,exec,suid,dev,mode=0777,size=1g",
             "empty read-only Git-authority shield"),
    Mutation("build", "target=/online,readonly", "target=/online", "read-only online input"),
    Mutation(
        "lib",
        "DOCKER_HOST DOCKER_CONTEXT DOCKER_CONFIG DOCKER_CERT_PATH DOCKER_TLS_VERIFY DOCKER_TLS",
        "DOCKER_HOST DOCKER_CONFIG DOCKER_CERT_PATH DOCKER_TLS_VERIFY DOCKER_TLS",
        "ambient Docker context refusal",
    ),
    Mutation(
        "lib",
        "DOCKER_API_VERSION DOCKER_DEFAULT_PLATFORM DOCKER_CONTENT_TRUST",
        "DOCKER_DEFAULT_PLATFORM DOCKER_CONTENT_TRUST",
        "ambient Docker API-version refusal",
    ),
    Mutation(
        "lib",
        "DOCKER_CONTENT_TRUST_SERVER DOCKER_CUSTOM_HEADERS",
        "DOCKER_CONTENT_TRUST_SERVER",
        "ambient Docker custom-header refusal",
    ),
    Mutation(
        "lib",
        "case \"$(/usr/bin/stat -c '%u:%g:%a:%h' -- /usr/bin/docker 2>/dev/null)\" in\n"
        "        0:0:755:1) ;;",
        "case \"$(/usr/bin/stat -c '%u:%g:%a:%h' -- /usr/bin/docker 2>/dev/null)\" in\n"
        "        *:0:755:1) ;;",
        "root-owned Docker-client identity",
    ),
    Mutation(
        "lib",
        "case \"$(/usr/bin/stat -c '%u:%h' -- /var/run/docker.sock 2>/dev/null)\" in\n"
        "        0:1) ;;",
        "case \"$(/usr/bin/stat -c '%u:%h' -- /var/run/docker.sock 2>/dev/null)\" in\n"
        "        *:1) ;;",
        "root-owned Docker-socket identity",
    ),
    Mutation(
        "lib",
        "(umask 077 && set -o noclobber && printf '{}\\n' >\"$config/config.json\")",
        "(umask 077 && printf '{}\\n' >\"$config/config.json\")",
        "private Docker config no-clobber creation",
    ),
    Mutation(
        "lib",
        'LOCAL_DOCKER_AUTHORITY_PARENT_ID="$(/usr/bin/stat -c \'%d:%i:%u:%g:%a\' -- "$parent")"',
        "LOCAL_DOCKER_AUTHORITY_PARENT_ID=unchecked",
        "Docker-authority parent identity binding",
    ),
    Mutation(
        "lib",
        'LOCAL_DOCKER_AUTHORITY_CONFIG_ID="$(/usr/bin/stat -c \'%d:%i:%u:%g:%a:%h\' -- "$config")"',
        "LOCAL_DOCKER_AUTHORITY_CONFIG_ID=unchecked",
        "Docker-config directory identity binding",
    ),
    Mutation(
        "lib",
        'LOCAL_DOCKER_AUTHORITY_CONFIG_FILE_ID="$(/usr/bin/stat -c \'%d:%i:%u:%g:%a:%h\' -- "$config/config.json")"',
        "LOCAL_DOCKER_AUTHORITY_CONFIG_FILE_ID=unchecked",
        "Docker-config file identity binding",
    ),
    Mutation(
        "lib",
        'LOCAL_DOCKER_AUTHORITY_CLIENT_ID="$(/usr/bin/stat -c \'%d:%i:%u:%g:%a:%h\' -- /usr/bin/docker)"',
        "LOCAL_DOCKER_AUTHORITY_CLIENT_ID=unchecked",
        "Docker-client identity binding",
    ),
    Mutation(
        "lib",
        'LOCAL_DOCKER_AUTHORITY_SOCKET_ID="$(/usr/bin/stat -c \'%d:%i:%u:%g:%a:%h\' -- /var/run/docker.sock)"',
        "LOCAL_DOCKER_AUTHORITY_SOCKET_ID=unchecked",
        "Docker-socket identity binding",
    ),
    Mutation(
        "lib",
        '/usr/bin/cmp -s -- "$LOCAL_DOCKER_AUTHORITY_CONFIG/config.json" <(printf \'{}\\n\')',
        "true # Docker config bytes unchecked",
        "Docker-config byte recheck",
    ),
    Mutation(
        "lib",
        "local_docker() {\n    local status=0\n    assert_local_docker_authority || return 1\n    /usr/bin/env -i",
        "local_docker() {\n    local status=0\n    assert_local_docker_authority || return 1\n    /usr/bin/env",
        "empty Docker client environment",
    ),
    Mutation(
        "lib",
        "--host unix:///var/run/docker.sock",
        "--host tcp://127.0.0.1:2375",
        "fixed local Docker endpoint",
    ),
    Mutation(
        "lib",
        'local_docker_image_provenance "${args[@]}"',
        'python3 "$LIB_DIR/offline-image-provenance.py" "${args[@]}"',
        "builder provenance shared-authority routing",
    ),
    Mutation(
        "lib",
        '/usr/bin/rm -- "$LOCAL_DOCKER_AUTHORITY_CONFIG/config.json" || return 125',
        "true # Docker configuration retained",
        "exact Docker-authority cleanup",
    ),
    Mutation("verify", "python3 scripts/verify-debian-builder-authority.py --repo . --self-test",
             "true # Debian builder verifier removed", "shared focused-verifier wiring"),
    Mutation(
        "verify",
        "R-S11cf/R-S11dk/R-S11dv direct builds use independent private exact-commit sources, provenance and the sole compiler use one fixed local Docker authority",
        "R-S11cf direct builds use independent private exact-commit sources",
        "shared Debian-builder Docker-authority disposition",
    ),
    Mutation("requirements", '<span class="id">R-S11cf</span>',
             '<span class="id">R-S11cf-disabled</span>', "R-S11cf requirement"),
    Mutation("requirements", "<tr><td>225</td>", "<tr><td>225-disabled</td>",
             "Appendix C #225 disposition"),
    Mutation("hardening", "R-S11cf/R-S11e-98 — Debian builder private-source and container authority",
             "R-S11cf/R-S11e-98 — Debian builder ambient authority",
             "hardening-ledger disposition"),
    Mutation("requirements", '<span class="id">R-S11dj</span>',
             '<span class="id">R-S11dj-disabled</span>',
             "R-S11dj release-child Docker isolation requirement"),
    Mutation(
        "hardening",
        "R-S11dj/R-S11e-128 — Android artifact-builder Docker client, daemon, and configuration authority",
        "R-S11dj/R-S11e-XXX — release-child Docker isolation deferred",
        "release-child Docker isolation hardening ledger",
    ),
    Mutation("requirements", '<span class="id">R-S11dk</span>',
             '<span class="id">R-S11dk-disabled</span>',
             "R-S11dk Debian builder Docker authority requirement"),
    Mutation("requirements", "<tr><td>264</td>", "<tr><td>264-disabled</td>",
             "Appendix C #264 disposition"),
    Mutation(
        "hardening",
        "R-S11dk/R-S11e-129 — Debian artifact-builder Docker client, daemon, and configuration authority",
        "R-S11dk/R-S11e-XXX — Debian artifact-builder Docker authority deferred",
        "Debian builder Docker authority hardening ledger",
    ),
    Mutation(
        "build",
        'OWNED_WORKSPACE_ID="$(/usr/bin/stat -c \'%d:%i\' -- "$OWNED_WORKSPACE" 2>/dev/null)"',
        "OWNED_WORKSPACE_ID=unchecked",
        "private workspace identity capture",
    ),
    Mutation(
        "build",
        "prepare_output_contract\n    prepare_execution_contract",
        "prepare_execution_contract",
        "output contract before build authority",
    ),
    Mutation(
        "build",
        'mktemp -d "$OWNED_WORKSPACE/debian-package-check.XXXXXXXXXX"',
        "mktemp -d /tmp/debian-package-check.XXXXXXXXXX",
        "package checks contained by the exact private workspace",
    ),
    Mutation(
        "build",
        'OUT_PARENT_ID="$device:$inode"',
        "OUT_PARENT_ID=unchecked",
        "output-parent identity retention",
    ),
    Mutation(
        "build",
        'local -a packages=("$BUILD_SOURCE_ROOT"/rustdesk-*.deb)',
        'local -a packages=("$BUILD_SOURCE_ROOT"/rustdesk-*.deb "$BUILD_SOURCE_ROOT"/other.deb)',
        "closed private package selection",
    ),
    Mutation(
        "build",
        "Debian build must emit exactly one rustdesk-*.deb package",
        "Debian build may select the first package",
        "single private package requirement",
    ),
    Mutation(
        "build",
        '[ "$after_metadata" = "$metadata" ] && [ "$after_sha256" = "$before_sha256" ]',
        "true # package stability unchecked",
        "package stability across validation",
    ),
    Mutation(
        "build",
        'PASS_A_DEB_ID="$package_identity"',
        "PASS_A_DEB_ID=unchecked",
        "pass-A package identity retention",
    ),
    Mutation(
        "build",
        '[ "$PASS_A_SHA256" = "$PASS_B_SHA256" ]',
        "true # private A/B equality disabled",
        "private A/B reproducibility comparison",
    ),
    Mutation(
        "build",
        "remove_local_docker_authority \\\n"
        '        || die "Debian builder Docker authority could not retire before publication"',
        "true # Docker authority retained through publication",
        "pre-publication Docker retirement",
    ),
    Mutation(
        "build",
        "remove_owned_workspace_exact \\\n"
        '        || die "private Debian build workspace could not retire before final publication"',
        "true # workspace retained through final publication",
        "pre-publication exact workspace retirement",
    ),
    Mutation(
        "build",
        '--source-identity "$PASS_A_DEB_ID"',
        "--source-identity unchecked",
        "publisher source identity transfer",
    ),
    Mutation(
        "build",
        '--pending-identity "$PENDING_RESULT_ID"',
        "--pending-identity unchecked",
        "publisher pending identity transfer",
    ),
    Mutation(
        "publisher",
        "RENAME_NOREPLACE = 1",
        "RENAME_NOREPLACE = 0",
        "publisher no-clobber flag",
    ),
    Mutation(
        "publisher",
        "return tuple(sorted((self.artifact, self.checksum)))",
        'return tuple(sorted((self.artifact, self.checksum, "optional")))',
        "publisher closed inventory",
    ),
    Mutation(
        "publisher",
        "or before.st_nlink != 1\n"
        "        or before.st_size <= 0\n"
        "        or before.st_size > MAX_ARTIFACT_BYTES",
        "or before.st_nlink < 1\n"
        "        or before.st_size <= 0\n"
        "        or before.st_size > MAX_ARTIFACT_BYTES",
        "publisher source hardlink refusal",
    ),
    Mutation(
        "publisher",
        'pending = f"{contract.pending_prefix}{os.urandom(32).hex()}"',
        'pending = f"{contract.pending_prefix}fixed"',
        "kernel-random pending name",
    ),
    Mutation(
        "publisher",
        "os.mkdir(pending, 0o700, dir_fd=output_parent)",
        "os.mkdir(pending, 0o777, dir_fd=output_parent)",
        "private pending mode",
    ),
    Mutation(
        "publisher",
        "if digest.hexdigest() != expected_sha256:\n"
        '            fail("build artifact source does not match its validated SHA-256")\n'
        "        os.fchmod(output, 0o400)",
        "if digest.hexdigest() != expected_sha256:\n"
        '            fail("build artifact source does not match its validated SHA-256")\n'
        "        os.fchmod(output, 0o666)",
        "read-only result files",
    ),
    Mutation(
        "publisher",
        "rename_noreplace(output_parent, pending, destination)",
        "os.rename(pending, destination, src_dir_fd=output_parent, dst_dir_fd=output_parent)",
        "final no-clobber rename",
    ),
    Mutation(
        "publisher",
        "rename_noreplace(output_parent, pending, destination)\n"
        "        os.fsync(output_parent)\n"
        '        require_absent(output_parent, pending, "retired pending build output")',
        "rename_noreplace(output_parent, pending, destination)\n"
        "        os.fsync(output_parent)\n"
        "        pass # pre-content pending-edge retirement unchecked",
        "pre-content pending-edge retirement proof",
    ),
    Mutation(
        "publisher",
        'verify_result(pending_descriptor, "published build output", contract)\n'
        '        require_absent(output_parent, pending, "retired pending build output")',
        'verify_result(pending_descriptor, "published build output", contract)\n'
        "        pass # post-content pending-edge retirement unchecked",
        "post-content pending-edge retirement proof",
    ),
    Mutation(
        "publisher",
        'verify_result(pending_descriptor, "published build output", contract)',
        "pass # published content unchecked",
        "post-publication content proof",
    ),
    Mutation(
        "publisher",
        "published build output changed during final verification",
        "published build output final edge unchecked",
        "post-content final-edge identity proof",
    ),
    Mutation(
        "verify",
        "/usr/bin/python3 -I -S scripts/publish-artifact-result.py --self-test",
        "true # Debian publisher behavior fixture removed",
        "publisher behavior fixture wiring",
    ),
    Mutation("requirements", '<span class="id">R-S11dv</span>',
             '<span class="id">R-S11dv-disabled</span>',
             "R-S11dv Debian result-publication requirement"),
    Mutation("requirements", "<tr><td>275</td>", "<tr><td>275-disabled</td>",
             "Appendix C #275 disposition"),
    Mutation(
        "hardening",
        "R-S11dv/R-S11e-140 — Debian result publication is private-until-verified",
        "R-S11dv/R-S11e-XXX — Debian result publication remains pathname-owned",
        "Debian result-publication hardening ledger",
    ),
)


def load_sources(repo: pathlib.Path) -> Dict[str, str]:
    return {
        "build": (repo / "scripts/build-debian.sh").read_text(encoding="utf-8"),
        "lib": (repo / "scripts/lib.sh").read_text(encoding="utf-8"),
        "verify": (repo / "scripts/verify.sh").read_text(encoding="utf-8"),
        "requirements": (repo / "requirements.html").read_text(encoding="utf-8"),
        "hardening": (repo / "HARDENING_STATUS.md").read_text(encoding="utf-8"),
        "workspace": (repo / "scripts/verify-verifier-workspace.py").read_text(encoding="utf-8"),
        "publisher": (repo / "scripts/publish-artifact-result.py").read_text(encoding="utf-8"),
    }


def run_mutations(sources: Dict[str, str]) -> None:
    for mutation in MUTATIONS:
        original = sources[mutation.source]
        if original.count(mutation.old) != 1:
            raise AuthorityError(
                "mutation target for {} occurs {} times".format(
                    mutation.label, original.count(mutation.old)
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
    args = parser.parse_args()
    sources = load_sources(args.repo.resolve())
    validate(sources)
    if args.self_test:
        run_mutations(sources)
    print(
        "verify-debian-builder-authority: OK"
        + (" ({} mutations)".format(len(MUTATIONS)) if args.self_test else "")
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AuthorityError, OSError) as error:
        print("verify-debian-builder-authority: {}".format(error))
        raise SystemExit(1)
