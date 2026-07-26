#!/usr/bin/env python3
"""Validate Android artifact-builder and mandatory release-gate authority."""

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
    ordered_positions = tuple(sorted(positions))
    if positions != ordered_positions or len(set(positions)) != len(positions):
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
    rust_gate = sources["rust_gate"]
    gradle_gate = sources["gradle_gate"]
    checker = sources["checker"]
    inner = sources["inner"]
    lib = sources["lib"]
    release = sources["release"]
    debian = sources["debian"]
    systemd_smoke = sources["systemd_smoke"]
    systemd_authority = sources["systemd_authority"]

    for token, label in (
        ("set -euo pipefail\numask 077", "private host-created state umask"),
        ('export PATH=/usr/bin:/bin', "closed host command path"),
        ('readonly BUILD_UID="$(/usr/bin/id -u)"', "absolute host UID source"),
        ('readonly BUILD_GID="$(/usr/bin/id -g)"', "absolute host GID source"),
        ('[ "$BUILD_UID" -ne 0 ]', "host UID-root refusal"),
        ('[ "$BUILD_GID" -ne 0 ]', "host GID-root refusal"),
        ("refuses host or container-root execution", "root execution refusal"),
        ("refuses a root primary group", "root primary-group refusal"),
        ('source "$SCRIPT_DIR/lib.sh"', "shared Docker authority source"),
        ('readonly PYTHON_BIN=/usr/bin/python3', "fixed Python interpreter"),
        ('mktemp -d /tmp/rustdesk-android-build.XXXXXXXXXX', "private random workspace"),
        (
            'initialize_local_docker_authority "$OWNED_WORKSPACE/docker-config" "android-builder"',
            "fixed local Docker authority initialization",
        ),
        (
            'if [ "$LOCAL_DOCKER_AUTHORITY_INITIALIZED" -eq 1 ]',
            "fixed local Docker authority cleanup admission",
        ),
        ("&& ! remove_local_docker_authority; then", "exact local Docker authority cleanup"),
        (
            "preserving changed private Android builder Docker authority",
            "changed local Docker authority preservation",
        ),
        ('SOURCE_COMMIT="$current"', "exact source commit capture"),
        ('mode not in (b"100644", b"100755")', "regular-file-only commit inventory"),
        ('archive --format=tar "$SOURCE_COMMIT"', "commit-object source archive"),
        ('SOURCE_AUTHORITY_ROOT="$OWNED_WORKSPACE/source-authority"', "immutable source authority"),
        ('BUILD_SOURCE_ROOT="$OWNED_WORKSPACE/source-build"', "private writable source"),
        ('chmod -R a=rX "$SOURCE_AUTHORITY_ROOT"', "canonical read-only source authority modes"),
        ('prepare_build_source() {', "fresh writable-source constructor"),
        ('Android writable source path was not freshly absent', "fresh writable-source precondition"),
        ('chmod -R u=rwX,go=rX "$BUILD_SOURCE_ROOT"', "canonical writable source modes"),
        ('--reference "$SOURCE_AUTHORITY_ROOT" --candidate "$BUILD_SOURCE_ROOT" --allow-extras', "post-build source comparator wiring"),
        ('remove_build_source() {', "writable-source cleanup"),
        ('private Android writable source survived cleanup', "writable-source cleanup postcondition"),
        ('the Android artifact builder accepts only an exact clean commit', "dirty-build refusal"),
        ('android_docker_run() {', "single container-confinement wrapper"),
        ('local_docker run --rm --pull=never --network=none --read-only', "no-pull/networkless/read-only root"),
        (
            'assert_local_docker_authority \\\n        || die "Android builder local Docker authority changed"',
            "active Docker authority recheck",
        ),
        ('--user "$BUILD_UID:$BUILD_GID"', "numeric nonroot identity"),
        ('--cap-drop=ALL --security-opt=no-new-privileges', "capability and privilege confinement"),
        ('--pids-limit=32 --memory=512m --memory-swap=512m --cpus=1', "keytool resource bounds"),
        ('--pids-limit=512 --memory=12g --memory-swap=12g --cpus=4', "build resource bounds"),
        ('--pids-limit=128 --memory=4g --memory-swap=4g --cpus=2', "signing/verifier resource bounds"),
        ('--tmpfs /tmp:rw,exec,nosuid,nodev,mode=1777,size=10g', "bounded executable build scratch"),
        ('--tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777,size=2g', "bounded non-executable verification scratch"),
        ('source=$BUILD_SOURCE_ROOT,target=/src"', "private writable build mount"),
        ('source=$SOURCE_AUTHORITY_ROOT/scripts/android-apk-build.sh,target=/authority/android-apk-build.sh,readonly', "immutable inner build script"),
        ('source=$pass_output,target=/out"', "private signing output mount"),
        ('source=$KEYSTORE,target=/ks/keystore.jks,readonly', "read-only keystore mount"),
        ('source=$KEYSTORE_PASS_FILE,target=/ks/pass,readonly', "read-only keystore-password mount"),
        ('target=/checks/verify-android-apk-manifest.py,readonly', "immutable manifest verifier"),
        ('target=/checks/verify-android-mobile-key-artifact.py,readonly', "immutable mobile-key verifier"),
        ('install -m 0400 "$pass_output/rustdesk-arm64.apk" "$OUT_DIR/rustdesk-arm64.apk"', "host-side final APK publication"),
        ('cmp -s "$pass_output/rustdesk-arm64.apk" "$OUT_DIR/rustdesk-arm64.apk"', "final publication byte comparison"),
        ('published Android APK differs from the verified private artifact', "final publication byte proof"),
        ('sha256sum -c rustdesk-arm64.apk.sha256', "published checksum proof"),
        ('prepare_pass_output "$pass_a"', "private first pass"),
        ('prepare_pass_output "$pass_b"', "private second pass"),
        ('publish_apk "$pass_a"', "verified pass-A publication"),
    ):
        require(build, token, label)

    require_count(
        build,
        "local_docker run --rm --pull=never --network=none --read-only",
        1,
        "single fixed local Docker launch funnel",
    )
    require_count(build, "if ! android_docker_run", 3, "fallible build/sign/verify container launches")
    require_count(build, 'info="$(android_docker_run', 1, "fallible keytool container launch")
    require_count(build, "    prepare_build_source\n", 1, "fresh source per build-pass call")
    require_count(build, "    remove_build_source\n", 1, "build-source cleanup call")
    require_count(build, 'verify-android-build-source.py"', 2, "initial and post-build source comparisons")
    require_count(build, "source=$KEYSTORE,target=/ks/keystore.jks,readonly", 2, "read-only keystore mounts")
    require_count(build, "source=$KEYSTORE_PASS_FILE,target=/ks/pass,readonly", 2, "read-only password mounts")
    require_count(build, "target=/checks/verify-android-apk-manifest.py,readonly", 2, "immutable manifest-checker mounts")
    require_count(build, "target=/checks/verify-android-mobile-key-artifact.py,readonly", 2, "immutable mobile-key-checker mounts")
    if build.count("verify_build_source_unchanged") != 3:
        raise AuthorityError("source identity is not checked before and after build consumption")
    if build.count("--pids-limit=128 --memory=4g --memory-swap=4g --cpus=2") != 2:
        raise AuthorityError("signing and verification do not each carry explicit resource bounds")

    require_order(
        build,
        (
            'readonly BUILD_UID="$(/usr/bin/id -u)"',
            'readonly BUILD_GID="$(/usr/bin/id -g)"',
            '[ "$BUILD_UID" -ne 0 ]',
            '[ "$BUILD_GID" -ne 0 ]',
            'source "$SCRIPT_DIR/lib.sh"',
            "load_pins",
            'mktemp -d /tmp/rustdesk-android-build.XXXXXXXXXX',
            'initialize_local_docker_authority "$OWNED_WORKSPACE/docker-config" "android-builder"',
            "local_docker run --rm --pull=never --network=none --read-only",
            'require_pinned_builder_image android-builder "$IMAGE_ID"',
        ),
        "root refusal, shared authority, launch funnel, and provenance definitions",
    )
    cleanup = extract(
        build,
        "cleanup_owned_workspace() {",
        "\n}\n\ntrap cleanup_owned_workspace EXIT",
        "Android builder workspace cleanup",
    )
    require_order(
        cleanup,
        (
            "remove_local_docker_authority",
            'elif [ -n "$OWNED_WORKSPACE" ] && [ -d "$OWNED_WORKSPACE" ]',
            'chmod -R u+rwX "$OWNED_WORKSPACE"',
            'rm -rf -- "$OWNED_WORKSPACE"',
        ),
        "Docker-before-workspace cleanup order",
    )
    run_child = extract(
        release,
        "run_child() {",
        "\n}\n\nrun_verification() {",
        "release child environment",
    )
    require_count(
        release,
        'printf \'[ -z "${DOCKER_HOST+x}" ] && [ -z "${DOCKER_CONFIG+x}" ]\\n\'',
        2,
        "ordinary-target and Debian-lifecycle Docker-environment absence fixtures",
    )
    require(
        release,
        'printf \'[ "${DOUBLE_BUILD:-}" = 0 ]\\n\'\n'
        '        printf \'[ -z "${DOCKER_HOST+x}" ] && [ -z "${DOCKER_CONFIG+x}" ]\\n\'',
        "ordinary release-target Docker-environment absence fixture",
    )
    require(
        release,
        'printf \'[ "$#" = 6 ]\\n\'\n'
        '        printf \'[ -z "${DOCKER_HOST+x}" ] && [ -z "${DOCKER_CONFIG+x}" ]\\n\'',
        "final Debian-lifecycle Docker-environment absence fixture",
    )
    forbid(run_child, 'DOCKER_HOST="$DOCKER_HOST_URI"', "release Docker endpoint inheritance")
    forbid(run_child, 'DOCKER_CONFIG="$DOCKER_CONFIG_DIR"', "release Docker configuration inheritance")
    for token, label in (
        ('readonly BUILD_UID="$(/usr/bin/id -u)"', "Debian child absolute UID capture"),
        ('readonly BUILD_GID="$(/usr/bin/id -g)"', "Debian child absolute GID capture"),
        ('[ "$BUILD_UID" -ne 0 ]', "Debian child UID-root refusal"),
        ('[ "$BUILD_GID" -ne 0 ]', "Debian child GID-root refusal"),
        ("mktemp -d /tmp/rustdesk-debian-build.XXXXXXXXXX", "Debian child private workspace"),
        (
            'initialize_local_docker_authority "$OWNED_WORKSPACE/docker-config" "debian-builder"',
            "Debian child fixed local Docker authority",
        ),
        (
            "local_docker run --rm --pull=never",
            "Debian child fixed local Docker launch",
        ),
    ):
        require(debian, token, label)
    require_order(
        debian,
        (
            'readonly BUILD_UID="$(/usr/bin/id -u)"',
            'readonly BUILD_GID="$(/usr/bin/id -g)"',
            '[ "$BUILD_UID" -ne 0 ]',
            '[ "$BUILD_GID" -ne 0 ]',
            'source "$SCRIPT_DIR/lib.sh"',
            "mktemp -d /tmp/rustdesk-debian-build.XXXXXXXXXX",
            'initialize_local_docker_authority "$OWNED_WORKSPACE/docker-config" "debian-builder"',
            'if [ -n "${RELEASE_SRC_COMMIT:-}" ]',
            "local_docker run --rm --pull=never",
        ),
        "Debian child root refusal and independent authority before classification and launch",
    )
    for token, label in (
        (
            'readonly HOST_UID="$(/usr/bin/id -u)"',
            "Debian lifecycle child absolute UID capture",
        ),
        (
            'readonly HOST_GID="$(/usr/bin/id -g)"',
            "Debian lifecycle child absolute GID capture",
        ),
        (
            'initialize_local_docker_authority "$WORK/docker-config" "debian-systemd-lifecycle"',
            "Debian lifecycle child fixed local Docker authority",
        ),
        (
            "local_docker_image_provenance verify-local",
            "Debian lifecycle child isolated image provenance",
        ),
        (
            "local_docker run --rm --pull=never --network=none --read-only",
            "Debian lifecycle child fixed local Docker launch",
        ),
    ):
        require(systemd_smoke, token, label)
    require_order(
        systemd_smoke,
        (
            'readonly HOST_UID="$(/usr/bin/id -u)"',
            'readonly HOST_GID="$(/usr/bin/id -g)"',
            '[ "$HOST_UID" -ne 0 ]',
            '[ "$HOST_GID" -ne 0 ]',
            'source "$SCRIPT_DIR/lib.sh"',
            'WORK=$(mktemp -d "$STATE_DIR/run.XXXXXXXXXX")',
            'initialize_local_docker_authority "$WORK/docker-config" "debian-systemd-lifecycle"',
            "local_docker_image_provenance verify-local",
            "local_docker run --rm --pull=never --network=none --read-only",
        ),
        "Debian lifecycle root refusal and independent authority before Docker operations",
    )
    for token, label in (
        (
            "def validate(sources: Dict[str, str]) -> None:",
            "Debian lifecycle focused authority validator",
        ),
        (
            "MUTATIONS = (",
            "Debian lifecycle focused mutation catalog",
        ),
        (
            "R-S11dl/R-S11e-130 — Debian systemd-lifecycle Docker client, daemon",
            "Debian lifecycle focused normative binding",
        ),
    ):
        require(systemd_authority, token, label)

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
            "shared Docker canonical no-clobber configuration",
        ),
        (
            'LOCAL_DOCKER_AUTHORITY_PARENT_ID="$(/usr/bin/stat',
            "shared Docker-authority parent identity binding",
        ),
        (
            'LOCAL_DOCKER_AUTHORITY_CONFIG_ID="$(/usr/bin/stat',
            "shared Docker-config directory identity binding",
        ),
        (
            'LOCAL_DOCKER_AUTHORITY_CONFIG_FILE_ID="$(/usr/bin/stat',
            "shared Docker-config file identity binding",
        ),
        (
            'LOCAL_DOCKER_AUTHORITY_CLIENT_ID="$(/usr/bin/stat',
            "shared Docker-client identity binding",
        ),
        (
            'LOCAL_DOCKER_AUTHORITY_SOCKET_ID="$(/usr/bin/stat',
            "shared Docker-socket identity binding",
        ),
        ("local_docker() {", "shared fixed Docker launcher"),
        ("local_docker_image_provenance() {", "shared fixed Docker provenance wrapper"),
        ("remove_local_docker_authority() {", "shared exact Docker cleanup"),
        (
            'local_docker_image_provenance "${args[@]}"',
            "builder provenance shared-authority routing",
        ),
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
    require_count(
        local_docker,
        "assert_local_docker_authority",
        2,
        "shared Docker pre/post authority proof",
    )
    for token, label in (
        ("/usr/bin/env -i", "shared Docker launcher empty environment"),
        ("/usr/bin/docker", "shared Docker launcher absolute client"),
        ("--host unix:///var/run/docker.sock", "shared Docker launcher endpoint"),
        ('--config "$LOCAL_DOCKER_AUTHORITY_CONFIG"', "shared Docker launcher configuration"),
    ):
        require(local_docker, token, label)
    docker_provenance = extract(
        lib,
        "local_docker_image_provenance() {",
        "\n}\n\nremove_local_docker_authority() {",
        "shared fixed Docker provenance wrapper",
    )
    require_count(
        docker_provenance,
        "assert_local_docker_authority",
        2,
        "shared Docker provenance pre/post authority proof",
    )
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

    for gate, uid_name, gid_name, label in (
        (rust_gate, "BUILD_UID", "BUILD_GID", "Android Rust release gate"),
        (gradle_gate, "HOST_UID", "HOST_GID", "Android Gradle release gate"),
    ):
        for token, token_label in (
            ("set -euo pipefail\numask 077", "private-state umask"),
            ("export PATH=/usr/bin:/bin", "closed command path"),
            (
                'readonly {}="$(/usr/bin/id -u)"'.format(uid_name),
                "absolute UID capture",
            ),
            (
                'readonly {}="$(/usr/bin/id -g)"'.format(gid_name),
                "absolute GID capture",
            ),
            ('[ "${}" -ne 0 ]'.format(uid_name), "UID-root refusal"),
            ('[ "${}" -ne 0 ]'.format(gid_name), "GID-root refusal"),
            ('source "$SCRIPT_DIR/lib.sh"', "shared Docker-authority source"),
            ("load_pins", "pin loading"),
            ("require_pinned_builder_image android-builder", "isolated image provenance"),
            ("remove_local_docker_authority", "exact Docker-authority retirement"),
            (
                'verify-private-tree-closure.py" \\\n'
                '            --remove-private-root "$WORKSPACE" '
                '--expected-identity "$WORKSPACE_ID"',
                "descriptor-safe private-workspace retirement",
            ),
            ("preserving changed private Docker authority", "changed-authority preservation"),
            ("preserving changed private workspace", "changed-workspace preservation"),
        ):
            require(gate, token, "{} {}".format(label, token_label))
        forbid(gate, "require_cmd docker", "{} PATH Docker requirement".format(label))
        forbid(gate, "\ndocker run ", "{} direct PATH Docker launch".format(label))
        forbid(gate, "\n/usr/bin/docker run ", "{} direct absolute Docker launch".format(label))
        forbid(gate, "\n    /usr/bin/docker run ", "{} direct absolute Docker launch".format(label))
        forbid(gate, " -v ", "{} short volume authority".format(label))
        forbid(gate, "--volume", "{} volume authority".format(label))

    for token, label in (
        (
            'WORKSPACE="$(umask 077 && /usr/bin/mktemp -d '
            '/tmp/rustdesk-android-rust-check.XXXXXXXXXX)"',
            "Android Rust private random workspace",
        ),
        (
            '[ "$(/usr/bin/stat -c \'%u:%g:%a\' -- "$WORKSPACE")" = '
            '"$BUILD_UID:$BUILD_GID:700" ]',
            "Android Rust workspace identity/mode proof",
        ),
        (
            'initialize_local_docker_authority "$WORKSPACE/docker-config" '
            '"android-rust-check"',
            "Android Rust fixed local Docker authority",
        ),
        (
            "ls-files -z --cached --others --exclude-standard",
            "Android Rust current-source inventory",
        ),
        (
            "if not stat.S_ISREG(metadata.st_mode):",
            "Android Rust regular-file-only source inventory",
        ),
        (
            "--null --verbatim-files-from --no-recursion --files-from=-",
            "Android Rust exact source archive",
        ),
        (
            'SOURCE_AUTHORITY="$WORKSPACE/source-authority"',
            "Android Rust immutable source authority",
        ),
        (
            'BUILD_SOURCE="$WORKSPACE/source-build"',
            "Android Rust private writable source",
        ),
        (
            '/usr/bin/chmod -R a=rX "$SOURCE_AUTHORITY"',
            "Android Rust canonical immutable source modes",
        ),
        (
            '/usr/bin/chmod -R u=rwX,go=rX "$BUILD_SOURCE"',
            "Android Rust canonical writable source modes",
        ),
        (
            '--reference "$SOURCE_AUTHORITY" --candidate "$BUILD_SOURCE"',
            "Android Rust initial source comparison",
        ),
        (
            '--reference "$SOURCE_AUTHORITY" --candidate "$BUILD_SOURCE" --allow-extras',
            "Android Rust post-check source comparison",
        ),
        (
            'SOURCE_DIGEST_AFTER="$(archive_current_source | /usr/bin/sha256sum',
            "Android Rust live-source post-check",
        ),
        (
            'die "live source changed while the disposable Android Rust check was running"',
            "Android Rust live-source change rejection",
        ),
    ):
        require(rust_gate, token, label)
    require_order(
        rust_gate,
        (
            'readonly BUILD_UID="$(/usr/bin/id -u)"',
            'readonly BUILD_GID="$(/usr/bin/id -g)"',
            '[ "$BUILD_UID" -ne 0 ]',
            '[ "$BUILD_GID" -ne 0 ]',
            'source "$SCRIPT_DIR/lib.sh"',
            "load_pins",
            'WORKSPACE="$(umask 077 && /usr/bin/mktemp -d '
            '/tmp/rustdesk-android-rust-check.XXXXXXXXXX)"',
            'initialize_local_docker_authority "$WORKSPACE/docker-config" '
            '"android-rust-check"',
            'require_pinned_builder_image android-builder "$ANDROID_BUILDER_IMAGE_ID"',
            "if ! local_docker run --rm --pull=never --network=none --read-only",
        ),
        "Android Rust root refusal, fixed Docker authority, provenance, and launch",
    )
    rust_cleanup = extract(
        rust_gate,
        "cleanup_workspace() {",
        "\n}\ntrap cleanup_workspace EXIT",
        "Android Rust private-workspace cleanup",
    )
    require_order(
        rust_cleanup,
        (
            "remove_local_docker_authority",
            'elif [ -z "$WORKSPACE_ID" ]',
            'verify-private-tree-closure.py" \\\n'
            '            --remove-private-root "$WORKSPACE"',
        ),
        "Android Rust Docker-before-workspace cleanup",
    )
    rust_run = extract(
        rust_gate,
        "if ! local_docker run ",
        "; then",
        "Android Rust release-check Docker launch",
    )
    for token, label in (
        ("--rm --pull=never --network=none --read-only", "launch isolation"),
        ('--user "$BUILD_UID:$BUILD_GID"', "numeric non-root identity"),
        ("--cap-drop=ALL --security-opt=no-new-privileges", "privilege confinement"),
        ("--pids-limit=512 --memory=12g --memory-swap=12g --cpus=4", "resource bounds"),
        ("--ulimit core=0:0 --ulimit nofile=4096:4096", "core/descriptor bounds"),
        ("--ulimit fsize=2147483648:2147483648", "file-size bound"),
        ("--tmpfs /tmp:rw,exec,nosuid,nodev,mode=1777,size=10g", "bounded scratch"),
        ("--env RUSTDESK_CANARY_OFFLINE=1", "offline canary"),
        ("--env APK_MODE=rust-check", "exact operation mode"),
        (
            "type=bind,source=$BUILD_SOURCE,target=/src,bind-recursive=disabled",
            "private writable source mount",
        ),
        (
            "type=bind,source=$SOURCE_AUTHORITY/scripts/android-apk-build.sh,"
            "target=/authority/android-apk-build.sh,readonly,bind-recursive=disabled",
            "immutable operation-script mount",
        ),
        (
            "type=bind,source=$online,target=/online,readonly,bind-recursive=disabled",
            "read-only online mount",
        ),
        ('"$ANDROID_BUILDER_IMAGE_ID"', "immutable image ID"),
    ):
        require(rust_run, token, "Android Rust {}".format(label))
    require_count(rust_run, "--mount ", 3, "Android Rust exact mount inventory")
    require_count(
        rust_gate,
        "local_docker run ",
        1,
        "Android Rust fixed-authority launch inventory",
    )
    require_count(
        rust_run,
        "bind-recursive=disabled",
        3,
        "Android Rust descendant-mount exclusion",
    )
    for token, label in (
        ("source=$REPO_ROOT", "live repository mount"),
        ("source=$SCRIPT_DIR/..", "script-parent mount"),
        ("docker.sock", "Docker socket mount"),
        ("--privileged", "privileged launch"),
        ("--cap-add", "added capability"),
        ("--pid=host", "host PID namespace"),
        ("--ipc=host", "host IPC namespace"),
        ("--uts=host", "host UTS namespace"),
        ("--network=host", "host network namespace"),
        ("--publish", "published port"),
        ("--expose", "exposed port"),
    ):
        forbid(rust_run, token, "Android Rust {}".format(label))
    require_count(
        rust_gate,
        "require_online_complete",
        2,
        "Android Rust online-closure pre/post proof",
    )

    for token, label in (
        (
            'WORKSPACE="$(umask 077 && /usr/bin/mktemp -d '
            '/tmp/rustdesk-android-gradle-gate.XXXXXXXXXX)"',
            "Android Gradle private random workspace",
        ),
        (
            '[ "$(/usr/bin/stat -c \'%u:%g:%a\' -- "$WORKSPACE")" = '
            '"$HOST_UID:$HOST_GID:700" ]',
            "Android Gradle workspace identity/mode proof",
        ),
        (
            'initialize_local_docker_authority "$WORKSPACE/docker-config" '
            '"android-gradle-gate"',
            "Android Gradle fixed local Docker authority",
        ),
        ('HOST_FIXTURE="$WORKSPACE/fixture"', "Android Gradle private fixture root"),
        (
            'assert_local_docker_authority \\\n'
            '            || die "Android Gradle release-gate Docker authority changed"',
            "Android Gradle final Docker-authority proof",
        ),
    ):
        require(gradle_gate, token, label)
    require_order(
        gradle_gate,
        (
            'readonly HOST_UID="$(/usr/bin/id -u)"',
            'readonly HOST_GID="$(/usr/bin/id -g)"',
            '[ "$HOST_UID" -ne 0 ]',
            '[ "$HOST_GID" -ne 0 ]',
            'source "$SCRIPT_DIR/lib.sh"',
            "load_pins",
            'WORKSPACE="$(umask 077 && /usr/bin/mktemp -d '
            '/tmp/rustdesk-android-gradle-gate.XXXXXXXXXX)"',
            'initialize_local_docker_authority "$WORKSPACE/docker-config" '
            '"android-gradle-gate"',
            'require_pinned_builder_image android-builder "$ANDROID_BUILDER_IMAGE_ID"',
            "if local_docker run --rm --pull=never --network=none --read-only",
        ),
        "Android Gradle root refusal, fixed Docker authority, provenance, and launch",
    )
    gradle_cleanup = extract(
        gradle_gate,
        "cleanup_host_workspace() {",
        "\n}\n\ntrap cleanup_host_workspace EXIT",
        "Android Gradle private-workspace cleanup",
    )
    require_order(
        gradle_cleanup,
        (
            "remove_local_docker_authority",
            'elif [ -z "$WORKSPACE_ID" ]',
            'verify-private-tree-closure.py" \\\n'
            '            --remove-private-root "$WORKSPACE"',
        ),
        "Android Gradle Docker-before-workspace cleanup",
    )
    gradle_mount_run = extract(
        gradle_gate,
        "# ANDROID_GRADLE_MOUNT_REJECTION_DOCKER_BEGIN",
        "# ANDROID_GRADLE_MOUNT_REJECTION_DOCKER_END",
        "Android Gradle descendant-mount rejection launch",
    )
    gradle_semantics_run = extract(
        gradle_gate,
        "# ANDROID_GRADLE_SEMANTICS_DOCKER_BEGIN",
        "# ANDROID_GRADLE_SEMANTICS_DOCKER_END",
        "Android Gradle semantics launch",
    )
    for block, label, identity, resource, limits, tmpfs, mount_count in (
        (
            gradle_mount_run,
            "Android Gradle mount-rejection",
            '--user "$HOST_UID:$HOST_GID"',
            "--pids-limit=64 --memory=512m --memory-swap=512m --cpus=1",
            "--ulimit core=0:0 --ulimit nofile=1024:1024",
            "--tmpfs /tmp:rw,nosuid,nodev,mode=1777,size=256m",
            4,
        ),
        (
            gradle_semantics_run,
            "Android Gradle semantics",
            '--user "$HOST_UID:$HOST_GID"',
            "--pids-limit=256 --memory=4g --memory-swap=4g --cpus=2",
            "--ulimit core=0:0 --ulimit nofile=4096:4096",
            "--tmpfs /tmp:rw,nosuid,nodev,mode=1777,size=2g",
            5,
        ),
    ):
        for token, token_label in (
            ("local_docker run --rm --pull=never --network=none --read-only", "fixed launch"),
            (identity, "numeric non-root identity"),
            ("--cap-drop=ALL --security-opt=no-new-privileges", "privilege confinement"),
            (resource, "resource bounds"),
            (limits, "core/descriptor/file-size bounds"),
            (tmpfs, "bounded scratch"),
            ('"$ANDROID_BUILDER_IMAGE_ID"', "immutable image ID"),
        ):
            require(block, token, "{} {}".format(label, token_label))
        require_count(block, "--mount ", mount_count, "{} exact mount inventory".format(label))
        require_count(
            block,
            "bind-recursive=disabled",
            mount_count,
            "{} descendant-mount exclusion".format(label),
        )
        for token, token_label in (
            ("docker.sock", "Docker socket mount"),
            ("--privileged", "privileged launch"),
            ("--cap-add", "added capability"),
            ("--pid=host", "host PID namespace"),
            ("--ipc=host", "host IPC namespace"),
            ("--uts=host", "host UTS namespace"),
            ("--network=host", "host network namespace"),
            ("--publish", "published port"),
            ("--expose", "exposed port"),
        ):
            forbid(block, token, "{} {}".format(label, token_label))
    require(
        gradle_mount_run,
        "--ulimit fsize=1048576:1048576",
        "Android Gradle mount-rejection file-size bound",
    )
    require(
        gradle_semantics_run,
        "--ulimit fsize=1073741824:1073741824",
        "Android Gradle semantics file-size bound",
    )
    for token, label in (
        (
            "type=bind,source=$SCRIPT_DIR/android-gradle-cache.py,"
            "target=$CONTAINER_TEST_ROOT/android-gradle-cache.py,readonly,"
            "bind-recursive=disabled",
            "cache-projector mount",
        ),
        (
            "type=bind,source=$SCRIPT_DIR/android-gradle-offline.init.gradle,"
            "target=$CONTAINER_TEST_ROOT/android-gradle-offline.init.gradle,readonly,"
            "bind-recursive=disabled",
            "offline-init mount",
        ),
        (
            "type=bind,source=$HOST_FIXTURE/seed,target=/seed,readonly,"
            "bind-recursive=disabled",
            "seed mount",
        ),
        (
            "type=bind,source=$HOST_FIXTURE/overlay,target=/seed/nested,readonly,"
            "bind-recursive=disabled",
            "nested-overlay mount",
        ),
    ):
        require(gradle_mount_run, token, "Android Gradle mount-rejection {}".format(label))
    for token, label in (
        (
            "type=bind,source=$SCRIPT_DIR/android-gradle-cache.py,"
            "target=$CONTAINER_TEST_ROOT/android-gradle-cache.py,readonly,"
            "bind-recursive=disabled",
            "cache-projector mount",
        ),
        (
            "type=bind,source=$SCRIPT_DIR/android-gradle-offline.init.gradle,"
            "target=$CONTAINER_TEST_ROOT/android-gradle-offline.init.gradle,readonly,"
            "bind-recursive=disabled",
            "offline-init mount",
        ),
        (
            "type=bind,source=$SCRIPT_DIR/android-apk-build.sh,"
            "target=$CONTAINER_TEST_ROOT/android-apk-build.sh,readonly,"
            "bind-recursive=disabled",
            "Android mode-contract mount",
        ),
        (
            "type=bind,source=$SCRIPT_DIR/test-android-gradle-cache.sh,"
            "target=$CONTAINER_TEST_ROOT/test-android-gradle-cache.sh,readonly,"
            "bind-recursive=disabled",
            "inner-test mount",
        ),
        (
            "type=bind,source=$gradle_root,target=/gradle-distribution,readonly,"
            "bind-recursive=disabled",
            "pinned Gradle distribution mount",
        ),
    ):
        require(gradle_semantics_run, token, "Android Gradle semantics {}".format(label))
    require_count(
        gradle_gate,
        "require_online_complete",
        2,
        "Android Gradle online-closure pre/post proof",
    )
    require_count(
        gradle_gate,
        "local_docker run ",
        2,
        "Android Gradle fixed-authority launch inventory",
    )
    require(
        sources["hardening"],
        "R-S11dn/R-S11e-132",
        "missing Android release-gate Docker-authority ledger",
    )
    require(
        sources["requirements"],
        '<span class="id">R-S11dn</span>',
        "missing Android release-gate Docker-authority requirement",
    )
    require(
        sources["requirements"],
        "<tr><td>267</td>",
        "missing Android release-gate Docker-authority Appendix disposition",
    )

    for token, label in (
        ('unset ANDROID_USER_HOME ANDROID_SDK_HOME', "single Android preference-location injection"),
        ('export ANDROID_PREFS_ROOT=/tmp/android-preferences-root', "AGP 7.3.1 shared preferences root"),
        ('Android preferences root was not freshly absent', "fresh Android preferences precondition"),
        ('install -d -m 0700 "$ANDROID_PREFS_ROOT"', "private legacy analytics preferences constructor"),
        ('install -d -m 0700 "$ANDROID_PREFS_ROOT/.android"', "private current-tools preferences constructor"),
        ('Android preferences root is not private to the build identity', "legacy analytics preferences mode/owner postcondition"),
        ('current Android preferences directory is not private to the build identity', "current-tools preferences mode/owner postcondition"),
        ('prepare_offline_gradle_cache() {', "deferred Gradle-cache constructor"),
        ('tar -C "$TC" -xf /online/rust-1.75.tar.xz', "pinned Rust installer extraction"),
        ('tar -C "$TC" -xf /online/rust-std-1.75-aarch64-linux-android.tar.xz', "pinned Android std extraction"),
        ('rm -rf -- "$RUST_INSTALLER_ROOT" "$ANDROID_STD_INSTALLER_ROOT"', "consumed Rust-installer retirement"),
        ('consumed Rust installer payload survived scratch retirement', "Rust-installer retirement postcondition"),
        ('tar -C "$TC" -xf /online/flutter-3.24.5.tar.xz', "pinned Flutter extraction"),
        ('tar -C "$TC" -xf /online/llvm-15.0.6.tar.xz', "pinned LLVM extraction"),
        ('rm -rf -- "$LLVM_ROOT"', "consumed LLVM retirement"),
        ('consumed LLVM payload survived scratch retirement', "LLVM retirement postcondition"),
        ('unset LIBCLANG_PATH BINDGEN_EXTRA_CLANG_ARGS', "retired LLVM environment"),
        ('prepare_offline_gradle_cache\ncd flutter && flutter build apk', "late Gradle projection before packaging"),
        ('commandLine("cargo", "metadata", "--format-version", "1")', "Gradle Cargo-metadata consumer"),
    ):
        require(inner, token, label)

    require_count(inner, 'android-gradle-cache.py materialize', 1, "single Gradle-cache projection")
    require_count(inner, 'export ANDROID_PREFS_ROOT=/tmp/android-preferences-root', 1, "single Android preference-location binding")
    require_count(inner, 'rm -rf -- "$RUST_INSTALLER_ROOT" "$ANDROID_STD_INSTALLER_ROOT"', 1, "single Rust-installer retirement")
    require_count(inner, 'rm -rf -- "$LLVM_ROOT"', 1, "single LLVM retirement")
    require_count(inner, 'prepare_offline_gradle_cache\n', 1, "single deferred Gradle-cache call")

    ordered_tokens = (
        'unset ANDROID_USER_HOME ANDROID_SDK_HOME',
        'export ANDROID_PREFS_ROOT=/tmp/android-preferences-root',
        'install -d -m 0700 "$ANDROID_PREFS_ROOT"',
        'install -d -m 0700 "$ANDROID_PREFS_ROOT/.android"',
        '"$ANDROID_STD_INSTALLER_ROOT/install.sh"',
        'rm -rf -- "$RUST_INSTALLER_ROOT" "$ANDROID_STD_INSTALLER_ROOT"',
        'tar -C "$TC" -xf /online/flutter-3.24.5.tar.xz',
        'tar -C "$TC" -xf /online/llvm-15.0.6.tar.xz',
        'flutter_rust_bridge_codegen --rust-input',
        'bash ./flutter/ndk_arm64.sh',
        'rm -rf -- "$LLVM_ROOT"',
        'prepare_offline_gradle_cache\n',
        'cd flutter && flutter build apk',
    )
    positions = tuple(inner.index(token) for token in ordered_tokens)
    if positions != tuple(sorted(positions)) or len(set(positions)) != len(positions):
        raise AuthorityError("Android scratch consumers and retirement phases are misordered")

    for token, label in (
        ('ANDROID_USER_HOME=', "conflicting current Android home override"),
        ('ANDROID_SDK_HOME=', "broader legacy Android home override"),
        ('JAVA_TOOL_OPTIONS=', "JVM-wide Java tool options override"),
        ('JDK_JAVA_OPTIONS=', "JDK-wide Java options override"),
        ('_JAVA_OPTIONS=', "legacy JVM-wide Java options override"),
    ):
        forbid(inner, token, label)

    for token, label in (
        ('"$DOCKER_BIN" run', "obsolete direct Docker launch"),
        ("readonly DOCKER_BIN=", "obsolete direct Docker client"),
        ("assert_private_docker_config", "obsolete bespoke Docker-config helper"),
        ('case "${DOCKER_HOST:', "caller-selected Docker endpoint"),
        ("export DOCKER_CONFIG=", "caller-visible Docker configuration"),
        ('$REPO_ROOT:/src', "real repository bind"),
        ('source=$REPO_ROOT,target=/src', "real repository mount"),
        ('$OUT_DIR:/out', "final output directory bind"),
        ('source=$OUT_DIR,target=/out', "final output directory mount"),
        ('--name rustdesk-fork-harness-apk', "daemon-global fixed container name"),
        ('--privileged', "privileged container"),
        ('--cap-add', "added container capability"),
        ('--pid=host', "host PID namespace"),
        ('--network=host', "host network namespace"),
        ('source=/var/run/docker.sock', "Docker socket mount"),
        ('/var/run/docker.sock:/var/run/docker.sock', "Docker socket volume"),
        ('docker build', "image build fallback"),
        ('docker pull', "image pull fallback"),
    ):
        forbid(build, token, label)

    for token, label in (
        ('getattr(os, "O_NOFOLLOW", 0)', "descriptor no-follow open"),
        ('before.st_nlink != 1', "hardlink refusal"),
        ('identity_before != identity_after', "stable-read identity proof"),
        ('reference_digest != candidate_digest', "exact byte comparison"),
        ('reference_root_mode != REFERENCE_DIRECTORY_MODE', "canonical authority-root mode"),
        ('candidate_root_mode != CANDIDATE_DIRECTORY_MODE', "canonical writable-root mode"),
        ('reference_mode != REFERENCE_DIRECTORY_MODE', "canonical authority-directory mode"),
        ('candidate_mode != CANDIDATE_DIRECTORY_MODE', "canonical writable-directory mode"),
        ('reference file has noncanonical mode', "canonical authority-file mode"),
        ('candidate_mode != expected_candidate_mode', "canonical writable-file mode"),
        ('if not allow_extras:', "initial extra-input control"),
        ('candidate source contains an extra input', "initial extra-input refusal"),
        ('allow_extras=args.allow_extras', "post-build generated-output allowance"),
        ('candidate source is missing', "missing-input refusal"),
        ('expect_failure(reference, candidate, "changed directory type")', "directory-type negative test"),
        ('expect_failure(reference, candidate, "hardlink substitution")', "hardlink negative test"),
        ('expect_failure(reference, candidate, "group-writable reference root")', "authority-root-mode negative test"),
        ('expect_failure(reference, candidate, "group-writable candidate root")', "writable-root-mode negative test"),
        ('expect_failure(reference, candidate, "group-writable reference directory")', "authority-directory-mode negative test"),
        ('expect_failure(reference, candidate, "group-writable candidate directory")', "writable-directory-mode negative test"),
        ('expect_failure(reference, candidate, "group-writable reference source")', "authority-file-mode negative test"),
        ('expect_failure(reference, candidate, "group-writable candidate source")', "writable-file-mode negative test"),
        ('expect_failure(reference, candidate, "changed executable mode")', "executable-mode negative test"),
        ('self_test()', "source comparator self-test"),
    ):
        require(checker, token, label)

    require(
        sources["verify"],
        'python3 scripts/verify-android-build-source.py --self-test',
        "source-comparator self-test wiring",
    )
    require(
        sources["verify"],
        'python3 scripts/verify-android-builder-authority.py --repo . --self-test',
        "shared verifier wiring",
    )
    require(
        sources["verify"],
        "R-S11e-76/R-S11e-77/R-S11e-78/R-S11e-79/R-S11e-128/R-S11e-132 Android APK builds and mandatory Android release gates use canonical-mode private source, independent fixed local Docker authority",
        "shared Android builder Docker-authority disposition",
    )
    require(sources["requirements"], '<span class="id">R-S11bj</span>', "R-S11bj requirement")
    require(sources["requirements"], '<span class="id">R-S11bk</span>', "R-S11bk requirement")
    require(sources["requirements"], '<span class="id">R-S11bl</span>', "R-S11bl requirement")
    require(sources["requirements"], '<span class="id">R-S11bm</span>', "R-S11bm requirement")
    require(sources["requirements"], '<tr><td>199</td>', "Appendix C #199 disposition")
    require(sources["requirements"], '<tr><td>200</td>', "Appendix C #200 disposition")
    require(sources["requirements"], '<tr><td>201</td>', "Appendix C #201 disposition")
    require(sources["requirements"], '<tr><td>202</td>', "Appendix C #202 disposition")
    require(
        sources["hardening"],
        'R-S11bj/R-S11e-76 — Android APK builder container and source authority',
        "hardening ledger row",
    )
    require(
        sources["hardening"],
        'R-S11bk/R-S11e-77 — Android exact-commit snapshot mode authority',
        "snapshot-mode hardening ledger row",
    )
    require(
        sources["hardening"],
        'R-S11bl/R-S11e-78 — Android bounded scratch lifecycle',
        "scratch-lifecycle hardening ledger row",
    )
    require(
        sources["hardening"],
        'R-S11bm/R-S11e-79 — Android tool preferences scratch ownership',
        "Android-preferences hardening ledger row",
    )
    require(sources["requirements"], '<span class="id">R-S11dj</span>',
            "R-S11dj requirement")
    require(sources["requirements"], '<tr><td>263</td>',
            "Appendix C #263 disposition")
    require(
        sources["hardening"],
        "R-S11dj/R-S11e-128 — Android artifact-builder Docker client, daemon, and configuration authority",
        "Android artifact-builder Docker authority hardening ledger",
    )
    require(
        sources["requirements"],
        'Clean pushed commit <code>36ed7a621496ed470cad5347f7598c18858de827</code> supplied the exact corrected-commit target-local A/B proof',
        "R-S11bm exact corrected-commit evidence",
    )
    require(
        sources["requirements"],
        'Clean pushed commit <code>36ed7a621496ed470cad5347f7598c18858de827</code> supplied exact target-local A/B evidence',
        "Appendix C #202 exact corrected-commit evidence",
    )
    require(
        sources["hardening"],
        "Exact target-local artifact evidence: clean pushed commit\n  `36ed7a621496ed470cad5347f7598c18858de827`",
        "R-S11e-79 exact corrected-commit evidence",
    )
    require(
        sources["requirements"],
        "The complete independent-snapshot R-B2/R-B10 transaction and device behavior remain separate open obligations.",
        "R-S11bm remaining release/device obligations",
    )
    require(
        sources["requirements"],
        "The full independent-snapshot R-B2/R-B10 release and device evidence remain open.",
        "Appendix C #202 remaining release/device obligations",
    )
    require(
        sources["hardening"],
        "It is not the independent-snapshot full R-B2/R-B10 release transaction\n  and does not prove Android device behavior; those obligations remain open.",
        "R-S11e-79 remaining release/device obligations",
    )


MUTATIONS: Tuple[Mutation, ...] = (
    Mutation("build", "set -euo pipefail\numask 077",
             "set -euo pipefail\numask 022", "private state umask"),
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
        'initialize_local_docker_authority "$OWNED_WORKSPACE/docker-config" "android-builder"',
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
        "local_docker run --rm --pull=never --network=none --read-only",
        "/usr/bin/docker run --rm --pull=never --network=none --read-only",
        "fixed local Docker launch funnel",
    ),
    Mutation(
        "rust_gate",
        'readonly BUILD_UID="$(/usr/bin/id -u)"',
        'readonly BUILD_UID="$(id -u)"',
        "Android Rust absolute UID capture",
    ),
    Mutation(
        "rust_gate",
        '[ "$BUILD_UID" -ne 0 ]',
        '[ "$BUILD_UID" -eq 0 ]',
        "Android Rust UID-root refusal",
    ),
    Mutation(
        "rust_gate",
        '[ "$BUILD_GID" -ne 0 ]',
        '[ "$BUILD_GID" -eq 0 ]',
        "Android Rust GID-root refusal",
    ),
    Mutation(
        "rust_gate",
        'initialize_local_docker_authority "$WORKSPACE/docker-config" "android-rust-check"',
        "true # Android Rust fixed Docker authority omitted",
        "Android Rust fixed Docker authority",
    ),
    Mutation(
        "rust_gate",
        'if [ "$LOCAL_DOCKER_AUTHORITY_INITIALIZED" -eq 1 ] \\\n'
        '            && ! remove_local_docker_authority; then',
        "if false; then",
        "Android Rust exact Docker-authority retirement",
    ),
    Mutation(
        "rust_gate",
        "if ! local_docker run --rm --pull=never --network=none --read-only",
        "if ! /usr/bin/docker run --rm --pull=never --network=none --read-only",
        "Android Rust fixed Docker launch",
    ),
    Mutation(
        "rust_gate",
        "--pids-limit=512 --memory=12g --memory-swap=12g --cpus=4",
        "--memory=12g --memory-swap=12g --cpus=4",
        "Android Rust PID bound",
    ),
    Mutation(
        "rust_gate",
        "--pids-limit=512 --memory=12g --memory-swap=12g --cpus=4",
        "--pids-limit=512 --memory=12g --memory-swap=12g",
        "Android Rust CPU bound",
    ),
    Mutation(
        "rust_gate",
        "--ulimit core=0:0 --ulimit nofile=4096:4096",
        "--ulimit core=0:0",
        "Android Rust descriptor bound",
    ),
    Mutation(
        "rust_gate",
        "type=bind,source=$BUILD_SOURCE,target=/src,bind-recursive=disabled",
        "type=bind,source=$REPO_ROOT,target=/src,bind-recursive=disabled",
        "Android Rust private writable source",
    ),
    Mutation(
        "rust_gate",
        "type=bind,source=$online,target=/online,readonly,bind-recursive=disabled",
        "type=bind,source=$online,target=/online,bind-recursive=disabled",
        "Android Rust read-only online closure",
    ),
    Mutation(
        "rust_gate",
        "type=bind,source=$BUILD_SOURCE,target=/src,bind-recursive=disabled",
        "type=bind,source=$BUILD_SOURCE,target=/src",
        "Android Rust descendant-mount exclusion",
    ),
    Mutation(
        "rust_gate",
        '--reference "$SOURCE_AUTHORITY" --candidate "$BUILD_SOURCE" --allow-extras',
        "true # Android Rust post-check source comparison removed",
        "Android Rust post-check source comparison",
    ),
    Mutation(
        "rust_gate",
        'SOURCE_DIGEST_AFTER="$(archive_current_source | /usr/bin/sha256sum',
        'SOURCE_DIGEST_AFTER="$(printf %s "$SOURCE_DIGEST" | /usr/bin/sha256sum',
        "Android Rust live-source post-check",
    ),
    Mutation(
        "gradle_gate",
        'readonly HOST_UID="$(/usr/bin/id -u)"',
        'readonly HOST_UID="$(id -u)"',
        "Android Gradle absolute UID capture",
    ),
    Mutation(
        "gradle_gate",
        '[ "$HOST_UID" -ne 0 ]',
        '[ "$HOST_UID" -eq 0 ]',
        "Android Gradle UID-root refusal",
    ),
    Mutation(
        "gradle_gate",
        '[ "$HOST_GID" -ne 0 ]',
        '[ "$HOST_GID" -eq 0 ]',
        "Android Gradle GID-root refusal",
    ),
    Mutation(
        "gradle_gate",
        'initialize_local_docker_authority "$WORKSPACE/docker-config" "android-gradle-gate"',
        "true # Android Gradle fixed Docker authority omitted",
        "Android Gradle fixed Docker authority",
    ),
    Mutation(
        "gradle_gate",
        'if [ "${LOCAL_DOCKER_AUTHORITY_INITIALIZED:-0}" -eq 1 ] \\\n'
        '            && ! remove_local_docker_authority; then',
        "if false; then",
        "Android Gradle exact Docker-authority retirement",
    ),
    Mutation(
        "gradle_gate",
        "if local_docker run --rm --pull=never --network=none --read-only",
        "if /usr/bin/docker run --rm --pull=never --network=none --read-only",
        "Android Gradle mount-rejection fixed Docker launch",
    ),
    Mutation(
        "gradle_gate",
        "# ANDROID_GRADLE_SEMANTICS_DOCKER_BEGIN\n"
        "        local_docker run --rm --pull=never --network=none --read-only",
        "# ANDROID_GRADLE_SEMANTICS_DOCKER_BEGIN\n"
        "        /usr/bin/docker run --rm --pull=never --network=none --read-only",
        "Android Gradle semantics fixed Docker launch",
    ),
    Mutation(
        "gradle_gate",
        "--pids-limit=64 --memory=512m --memory-swap=512m --cpus=1",
        "--memory=512m --memory-swap=512m --cpus=1",
        "Android Gradle mount-rejection PID bound",
    ),
    Mutation(
        "gradle_gate",
        "--pids-limit=256 --memory=4g --memory-swap=4g --cpus=2",
        "--pids-limit=256 --memory=4g --memory-swap=4g",
        "Android Gradle semantics CPU bound",
    ),
    Mutation(
        "gradle_gate",
        "--ulimit core=0:0 --ulimit nofile=1024:1024",
        "--ulimit core=0:0",
        "Android Gradle mount-rejection descriptor bound",
    ),
    Mutation(
        "gradle_gate",
        "--ulimit fsize=1073741824:1073741824",
        "--ulimit fsize=unlimited",
        "Android Gradle semantics file-size bound",
    ),
    Mutation(
        "gradle_gate",
        "type=bind,source=$HOST_FIXTURE/seed,target=/seed,readonly,"
        "bind-recursive=disabled",
        "type=bind,source=$HOST_FIXTURE/seed,target=/seed,readonly",
        "Android Gradle descendant-mount exclusion",
    ),
    Mutation(
        "gradle_gate",
        "type=bind,source=$gradle_root,target=/gradle-distribution,readonly,"
        "bind-recursive=disabled",
        "type=bind,source=$gradle_root,target=/gradle-distribution,"
        "bind-recursive=disabled",
        "Android Gradle read-only distribution",
    ),
    Mutation(
        "gradle_gate",
        'HOST_FIXTURE="$WORKSPACE/fixture"',
        'HOST_FIXTURE="$(mktemp -d /tmp/android-gradle-fixture.XXXXXXXXXX)"',
        "Android Gradle private fixture root",
    ),
    Mutation(
        "release",
        '        GIT_NO_REPLACE_OBJECTS=1 \\\n        "$@"',
        '        GIT_NO_REPLACE_OBJECTS=1 \\\n'
        '        DOCKER_HOST="$DOCKER_HOST_URI" DOCKER_CONFIG="$DOCKER_CONFIG_DIR" \\\n'
        '        "$@"',
        "release-child Docker authority inheritance",
    ),
    Mutation(
        "release",
        'printf \'[ "${DOUBLE_BUILD:-}" = 0 ]\\n\'\n'
        '        printf \'[ -z "${DOCKER_HOST+x}" ] && [ -z "${DOCKER_CONFIG+x}" ]\\n\'',
        'printf \'[ "${DOUBLE_BUILD:-}" = 0 ]\\n\'\n'
        '        printf \'[ -n "${DOCKER_HOST+x}" ] && [ -n "${DOCKER_CONFIG+x}" ]\\n\'',
        "ordinary release-target Docker environment absence fixture",
    ),
    Mutation(
        "release",
        'printf \'[ "$#" = 6 ]\\n\'\n'
        '        printf \'[ -z "${DOCKER_HOST+x}" ] && [ -z "${DOCKER_CONFIG+x}" ]\\n\'',
        'printf \'[ "$#" = 6 ]\\n\'\n'
        '        printf \'[ -n "${DOCKER_HOST+x}" ] && [ -n "${DOCKER_CONFIG+x}" ]\\n\'',
        "final Debian-lifecycle Docker environment absence fixture",
    ),
    Mutation(
        "debian",
        'initialize_local_docker_authority "$OWNED_WORKSPACE/docker-config" "debian-builder"',
        "true # Debian child fixed Docker authority omitted",
        "Debian child fixed Docker authority",
    ),
    Mutation(
        "debian",
        "if ! local_docker run --rm --pull=never",
        "if ! /usr/bin/docker run --rm --pull=never",
        "Debian child fixed Docker launcher",
    ),
    Mutation(
        "systemd_smoke",
        'initialize_local_docker_authority "$WORK/docker-config" "debian-systemd-lifecycle"',
        "true # lifecycle child fixed Docker authority omitted",
        "Debian lifecycle child fixed Docker authority",
    ),
    Mutation(
        "systemd_smoke",
        "local_docker_image_provenance verify-local",
        "/usr/bin/python3 scripts/offline-image-provenance.py verify-local",
        "Debian lifecycle child isolated provenance",
    ),
    Mutation(
        "systemd_authority",
        "MUTATIONS = (",
        "MUTATIONS_DISABLED = (",
        "Debian lifecycle focused mutation catalog",
    ),
    Mutation(
        "lib",
        "DOCKER_HOST DOCKER_CONTEXT DOCKER_CONFIG DOCKER_CERT_PATH DOCKER_TLS_VERIFY DOCKER_TLS",
        "DOCKER_HOST DOCKER_CONFIG DOCKER_CERT_PATH DOCKER_TLS_VERIFY DOCKER_TLS",
        "ambient Docker-authority refusal",
    ),
    Mutation(
        "lib",
        "DOCKER_API_VERSION DOCKER_DEFAULT_PLATFORM DOCKER_CONTENT_TRUST",
        "DOCKER_DEFAULT_PLATFORM DOCKER_CONTENT_TRUST",
        "ambient Docker API-version refusal",
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
    Mutation("build", "--rm --pull=never --network=none --read-only", "--rm --network=none --read-only", "pull fallback"),
    Mutation("build", "--rm --pull=never --network=none --read-only", "--rm --pull=never --read-only", "network isolation"),
    Mutation("build", "--rm --pull=never --network=none --read-only", "--rm --pull=never --network=none", "read-only root"),
    Mutation("build", '--user "$BUILD_UID:$BUILD_GID"', '--user 0:0', "nonroot identity"),
    Mutation("build", "--cap-drop=ALL --security-opt=no-new-privileges", "--security-opt=no-new-privileges", "capability drop"),
    Mutation("build", "--cap-drop=ALL --security-opt=no-new-privileges", "--cap-drop=ALL", "no-new-privileges"),
    Mutation("build", "--pids-limit=512 --memory=12g --memory-swap=12g --cpus=4", "--memory=12g --memory-swap=12g --cpus=4", "build PID bound"),
    Mutation("build", "--pids-limit=512 --memory=12g --memory-swap=12g --cpus=4", "--pids-limit=512 --memory=12g --memory-swap=12g", "build CPU bound"),
    Mutation("inner", 'unset ANDROID_USER_HOME ANDROID_SDK_HOME', 'true # conflicting Android preference locations retained', "single Android preference-location injection"),
    Mutation("inner", 'export ANDROID_PREFS_ROOT=/tmp/android-preferences-root', 'export ANDROID_PREFS_ROOT=/home/ubuntu/.android', "Android preferences scratch selection"),
    Mutation("inner", 'export ANDROID_PREFS_ROOT=/tmp/android-preferences-root', 'export ANDROID_PREFS_ROOT=/tmp/android-preferences-root\nexport ANDROID_USER_HOME=/tmp/android-user-home', "conflicting current Android home override refusal"),
    Mutation("inner", 'export ANDROID_PREFS_ROOT=/tmp/android-preferences-root', 'export ANDROID_PREFS_ROOT=/tmp/android-preferences-root\nexport ANDROID_SDK_HOME=/tmp/buildhome', "broader legacy Android home override refusal"),
    Mutation("inner", 'export ANDROID_PREFS_ROOT=/tmp/android-preferences-root', 'export ANDROID_PREFS_ROOT=/tmp/android-preferences-root\nexport JAVA_TOOL_OPTIONS=-Duser.home=/tmp/buildhome', "JVM-wide Java tool options refusal"),
    Mutation("inner", 'export ANDROID_PREFS_ROOT=/tmp/android-preferences-root', 'export ANDROID_PREFS_ROOT=/tmp/android-preferences-root\nexport JDK_JAVA_OPTIONS=-Duser.home=/tmp/buildhome', "JDK-wide Java options refusal"),
    Mutation("inner", 'export ANDROID_PREFS_ROOT=/tmp/android-preferences-root', 'export ANDROID_PREFS_ROOT=/tmp/android-preferences-root\nexport _JAVA_OPTIONS=-Duser.home=/tmp/buildhome', "legacy JVM-wide Java options refusal"),
    Mutation("inner", 'install -d -m 0700 "$ANDROID_PREFS_ROOT"', 'mkdir -p "$ANDROID_PREFS_ROOT"', "private legacy analytics preferences constructor"),
    Mutation("inner", 'install -d -m 0700 "$ANDROID_PREFS_ROOT/.android"', 'mkdir -p "$ANDROID_PREFS_ROOT/.android"', "private current-tools preferences constructor"),
    Mutation("inner", 'Android preferences root was not freshly absent', 'pre-existing Android preferences root accepted', "fresh Android preferences precondition"),
    Mutation("inner", 'Android preferences root is not private to the build identity', 'non-private Android preferences root accepted', "legacy analytics preferences owner/mode postcondition"),
    Mutation("inner", 'current Android preferences directory is not private to the build identity', 'non-private current Android preferences directory accepted', "current-tools preferences owner/mode postcondition"),
    Mutation("inner", 'rm -rf -- "$RUST_INSTALLER_ROOT" "$ANDROID_STD_INSTALLER_ROOT"', 'true # consumed Rust installers retained', "Rust-installer retirement"),
    Mutation("inner", 'consumed Rust installer payload survived scratch retirement', 'consumed Rust installer payload accepted', "Rust-installer retirement postcondition"),
    Mutation("inner", 'rm -rf -- "$LLVM_ROOT"', 'true # consumed LLVM retained', "LLVM retirement"),
    Mutation("inner", 'consumed LLVM payload survived scratch retirement', 'consumed LLVM payload accepted', "LLVM retirement postcondition"),
    Mutation("inner", 'prepare_offline_gradle_cache\ncd flutter && flutter build apk', 'cd flutter && flutter build apk', "late Gradle projection"),
    Mutation("inner", 'unset LIBCLANG_PATH BINDGEN_EXTRA_CLANG_ARGS', 'true # stale LLVM environment retained', "LLVM environment retirement"),
    Mutation("inner", 'commandLine("cargo", "metadata", "--format-version", "1")', 'commandLine("true")', "Gradle Cargo-metadata consumer"),
    Mutation("build", "source=$BUILD_SOURCE_ROOT,target=/src", "source=$REPO_ROOT,target=/src", "real source bind"),
    Mutation("build", "source=$pass_output,target=/out", "source=$OUT_DIR,target=/out", "final output bind"),
    Mutation("build", 'archive --format=tar "$SOURCE_COMMIT"', 'archive --format=tar HEAD~1', "source commit binding"),
    Mutation("build", 'mode not in (b"100644", b"100755")', 'mode not in (b"100644", b"100755", b"120000")', "regular-only source tree"),
    Mutation("build", 'chmod -R a=rX "$SOURCE_AUTHORITY_ROOT"', 'chmod -R a=rwX "$SOURCE_AUTHORITY_ROOT"', "canonical immutable source modes"),
    Mutation("build", 'chmod -R u=rwX,go=rX "$BUILD_SOURCE_ROOT"', 'chmod -R u=rwX,g=rwX,o=rX "$BUILD_SOURCE_ROOT"', "canonical writable source modes"),
    Mutation("build", "    prepare_build_source\n", "    true # fresh source construction removed\n", "fresh build source"),
    Mutation("build", "    verify_build_source_unchanged\n    # The docker run built", "    true # post-build source comparison removed\n    # The docker run built", "post-build source comparison"),
    Mutation("build", "    remove_build_source\n", "    true # build-source cleanup removed\n", "build-source cleanup"),
    Mutation("build", 'source=$pass_output,target=/out" \\\n        --mount "type=bind,source=$KEYSTORE,target=/ks/keystore.jks,readonly', 'source=$pass_output,target=/out" \\\n        --mount "type=bind,source=$KEYSTORE,target=/ks/keystore.jks', "keystore read-only mount"),
    Mutation("build", 'source=$resolved,target=/verify/app.apk,readonly" \\\n        --mount "type=bind,source=$SOURCE_AUTHORITY_ROOT/scripts/verify-android-apk-manifest.py,target=/checks/verify-android-apk-manifest.py,readonly', 'source=$resolved,target=/verify/app.apk,readonly" \\\n        --mount "type=bind,source=$SOURCE_AUTHORITY_ROOT/scripts/verify-android-apk-manifest.py,target=/checks/verify-android-apk-manifest.py', "manifest checker read-only mount"),
    Mutation("build", 'publish_apk "$pass_a"', 'publish_apk "$pass_b"', "pass-A publication"),
    Mutation("build", 'cmp -s "$pass_output/rustdesk-arm64.apk" "$OUT_DIR/rustdesk-arm64.apk"', 'true # publication comparison removed', "publication byte comparison"),
    Mutation("build", "sha256sum -c rustdesk-arm64.apk.sha256", "true # published checksum not checked", "published checksum proof"),
    Mutation("checker", 'flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)', 'flags = os.O_RDONLY', "source no-follow open"),
    Mutation("checker", "if reference_digest != candidate_digest:", "if False:", "source digest comparison"),
    Mutation("checker", "if before.st_nlink != 1:", "if False:", "source hardlink refusal"),
    Mutation("checker", "if reference_root_mode != REFERENCE_DIRECTORY_MODE:", "if False:", "canonical authority-root comparison"),
    Mutation("checker", "if candidate_root_mode != CANDIDATE_DIRECTORY_MODE:", "if False:", "canonical writable-root comparison"),
    Mutation("checker", "if reference_mode != REFERENCE_DIRECTORY_MODE:", "if False:", "canonical authority-directory comparison"),
    Mutation("checker", "if candidate_mode != CANDIDATE_DIRECTORY_MODE:", "if False:", "canonical writable-directory comparison"),
    Mutation("checker", 'raise SourceError("reference file has noncanonical mode: {}".format(relative))', "expected_candidate_mode = CANDIDATE_FILE_MODE", "canonical authority-file comparison"),
    Mutation("checker", "if candidate_mode != expected_candidate_mode:", "if False:", "canonical file-mode comparison"),
    Mutation("checker", "if not allow_extras:", "if False:", "initial extra-input refusal"),
    Mutation("checker", 'expect_failure(reference, candidate, "hardlink substitution")', 'validate(reference, candidate) # hardlink negative test removed', "hardlink negative test"),
    Mutation("checker", 'expect_failure(reference, candidate, "group-writable reference root")', 'validate(reference, candidate) # authority-root-mode negative test removed', "authority-root-mode negative test"),
    Mutation("checker", 'expect_failure(reference, candidate, "group-writable candidate root")', 'validate(reference, candidate) # writable-root-mode negative test removed', "writable-root-mode negative test"),
    Mutation("checker", 'expect_failure(reference, candidate, "group-writable reference directory")', 'validate(reference, candidate) # authority-directory-mode negative test removed', "authority-directory-mode negative test"),
    Mutation("checker", 'expect_failure(reference, candidate, "group-writable candidate directory")', 'validate(reference, candidate) # writable-directory-mode negative test removed', "writable-directory-mode negative test"),
    Mutation("checker", 'expect_failure(reference, candidate, "group-writable reference source")', 'validate(reference, candidate) # authority-file-mode negative test removed', "authority-file-mode negative test"),
    Mutation("checker", 'expect_failure(reference, candidate, "group-writable candidate source")', 'validate(reference, candidate) # writable-file-mode negative test removed', "writable-file-mode negative test"),
    Mutation("checker", 'expect_failure(reference, candidate, "changed executable mode")', 'validate(reference, candidate) # executable-mode negative test removed', "executable-mode negative test"),
    Mutation("verify", "python3 scripts/verify-android-build-source.py --self-test", "true # Android source comparator self-test removed", "source-comparator self-test wiring"),
    Mutation("verify", "python3 scripts/verify-android-builder-authority.py --repo . --self-test", "true # Android builder authority verifier removed", "shared gate wiring"),
    Mutation(
        "verify",
        "R-S11e-76/R-S11e-77/R-S11e-78/R-S11e-79/R-S11e-128/R-S11e-132 Android APK builds and mandatory Android release gates use canonical-mode private source, independent fixed local Docker authority",
        "R-S11e-76/R-S11e-77/R-S11e-78/R-S11e-79 Android APK builds use ambient Docker authority",
        "shared Android builder Docker-authority disposition",
    ),
    Mutation("requirements", '<span class="id">R-S11bj</span>', '<span class="id">R-S11bj-disabled</span>', "requirement"),
    Mutation("requirements", '<span class="id">R-S11bk</span>', '<span class="id">R-S11bk-disabled</span>', "snapshot-mode requirement"),
    Mutation("requirements", '<span class="id">R-S11bl</span>', '<span class="id">R-S11bl-disabled</span>', "scratch-lifecycle requirement"),
    Mutation("requirements", '<span class="id">R-S11bm</span>', '<span class="id">R-S11bm-disabled</span>', "Android-preferences requirement"),
    Mutation("requirements", '<tr><td>199</td>', '<tr><td>199-disabled</td>', "Appendix disposition"),
    Mutation("requirements", '<tr><td>200</td>', '<tr><td>200-disabled</td>', "snapshot-mode Appendix disposition"),
    Mutation("requirements", '<tr><td>201</td>', '<tr><td>201-disabled</td>', "scratch-lifecycle Appendix disposition"),
    Mutation("requirements", '<tr><td>202</td>', '<tr><td>202-disabled</td>', "Android-preferences Appendix disposition"),
    Mutation("hardening", 'R-S11bj/R-S11e-76 — Android APK builder container and source authority', 'R-S11bj/R-S11e-76 — Android APK builder ambient authority', "ledger"),
    Mutation("hardening", 'R-S11bk/R-S11e-77 — Android exact-commit snapshot mode authority', 'R-S11bk/R-S11e-77 — Android archive umask authority', "snapshot-mode ledger"),
    Mutation("hardening", 'R-S11bl/R-S11e-78 — Android bounded scratch lifecycle', 'R-S11bl/R-S11e-78 — Android unbounded scratch lifecycle', "scratch-lifecycle ledger"),
    Mutation("hardening", 'R-S11bm/R-S11e-79 — Android tool preferences scratch ownership', 'R-S11bm/R-S11e-79 — Android tool preferences ambient ownership', "Android-preferences ledger"),
    Mutation("requirements", '<span class="id">R-S11dj</span>',
             '<span class="id">R-S11dj-disabled</span>',
             "Android artifact-builder Docker authority requirement"),
    Mutation("requirements", "<tr><td>263</td>", "<tr><td>263-disabled</td>",
             "Android artifact-builder Docker authority Appendix disposition"),
    Mutation(
        "hardening",
        "R-S11dj/R-S11e-128 — Android artifact-builder Docker client, daemon, and configuration authority",
        "R-S11dj/R-S11e-XXX — Android artifact-builder Docker authority deferred",
        "Android artifact-builder Docker authority hardening ledger",
    ),
    Mutation(
        "requirements",
        '<span class="id">R-S11dn</span>',
        '<span class="id">R-S11dn-disabled</span>',
        "Android release-gate Docker authority requirement",
    ),
    Mutation(
        "requirements",
        "<tr><td>267</td>",
        "<tr><td>267-disabled</td>",
        "Android release-gate Docker authority Appendix disposition",
    ),
    Mutation(
        "hardening",
        "R-S11dn/R-S11e-132 — mandatory Android release-gate Docker, source,",
        "R-S11dn/R-S11e-XXX — mandatory Android release-gate authority deferred,",
        "Android release-gate Docker authority hardening ledger",
    ),
    Mutation("requirements", 'Clean pushed commit <code>36ed7a621496ed470cad5347f7598c18858de827</code> supplied the exact corrected-commit target-local A/B proof', 'Clean pushed commit <code>0000000000000000000000000000000000000000</code> supplied the exact corrected-commit target-local A/B proof', "R-S11bm exact corrected-commit evidence"),
    Mutation("requirements", 'Clean pushed commit <code>36ed7a621496ed470cad5347f7598c18858de827</code> supplied exact target-local A/B evidence', 'Clean pushed commit <code>0000000000000000000000000000000000000000</code> supplied exact target-local A/B evidence', "Appendix C #202 exact corrected-commit evidence"),
    Mutation("hardening", "Exact target-local artifact evidence: clean pushed commit\n  `36ed7a621496ed470cad5347f7598c18858de827`", "Exact target-local artifact evidence: clean pushed commit\n  `0000000000000000000000000000000000000000`", "R-S11e-79 exact corrected-commit evidence"),
    Mutation("requirements", "The complete independent-snapshot R-B2/R-B10 transaction and device behavior remain separate open obligations.", "The complete independent-snapshot R-B2/R-B10 transaction and device behavior are closed.", "R-S11bm remaining release/device obligations"),
    Mutation("requirements", "The full independent-snapshot R-B2/R-B10 release and device evidence remain open.", "The full independent-snapshot R-B2/R-B10 release and device evidence are closed.", "Appendix C #202 remaining release/device obligations"),
    Mutation("hardening", "It is not the independent-snapshot full R-B2/R-B10 release transaction\n  and does not prove Android device behavior; those obligations remain open.", "It is the independent-snapshot full R-B2/R-B10 release transaction\n  and proves Android device behavior; those obligations are closed.", "R-S11e-79 remaining release/device obligations"),
)


def run_mutations(sources: Dict[str, str]) -> None:
    for mutation in MUTATIONS:
        original = sources[mutation.source]
        if original.count(mutation.old) != 1:
            raise AuthorityError(
                "mutation '{}' expected one source token, found {}".format(
                    mutation.label, original.count(mutation.old)
                )
            )
        changed = dict(sources)
        changed[mutation.source] = original.replace(mutation.old, mutation.new, 1)
        try:
            validate(changed)
        except AuthorityError:
            continue
        raise AuthorityError("mutation survived: {}".format(mutation.label))


def read_regular(repo: pathlib.Path, relative: str) -> str:
    path = repo / relative
    if path.is_symlink() or not path.is_file():
        raise AuthorityError("required source is not a regular file: {}".format(relative))
    return path.read_text(encoding="utf-8")


def load_sources(repo: pathlib.Path) -> Dict[str, str]:
    return {
        "build": read_regular(repo, "scripts/build-android.sh"),
        "rust_gate": read_regular(repo, "scripts/android-rust-check.sh"),
        "gradle_gate": read_regular(repo, "scripts/test-android-gradle-cache.sh"),
        "release": read_regular(repo, "scripts/build-release.sh"),
        "debian": read_regular(repo, "scripts/build-debian.sh"),
        "systemd_smoke": read_regular(repo, "scripts/smoke-debian-systemd-lifecycle.sh"),
        "systemd_authority": read_regular(
            repo, "scripts/verify-debian-systemd-lifecycle-authority.py"
        ),
        "lib": read_regular(repo, "scripts/lib.sh"),
        "inner": read_regular(repo, "scripts/android-apk-build.sh")
        + read_regular(repo, "flutter/android/app/build.gradle"),
        "checker": read_regular(repo, "scripts/verify-android-build-source.py"),
        "verify": read_regular(repo, "scripts/verify.sh"),
        "requirements": read_regular(repo, "requirements.html"),
        "hardening": read_regular(repo, "HARDENING_STATUS.md"),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=".")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    repo = pathlib.Path(args.repo).resolve()
    sources = load_sources(repo)
    validate(sources)
    if args.self_test:
        run_mutations(sources)
    print(
        "ANDROID-BUILDER-AUTHORITY: private artifact/release-gate source, independent fixed local Docker authority, phased bounded scratch and Android preferences, private signing output, and confined artifact plus mandatory Android gate operations are GREEN ({} mutations)".format(
            len(MUTATIONS) if args.self_test else 0
        )
    )


if __name__ == "__main__":
    try:
        main()
    except (AuthorityError, OSError, UnicodeError) as error:
        raise SystemExit("verify-android-builder-authority: {}".format(error))
