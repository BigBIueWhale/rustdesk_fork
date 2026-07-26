#!/usr/bin/env python3
"""Validate the Android APK builder's private-source and container authority."""

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
    checker = sources["checker"]
    inner = sources["inner"]
    lib = sources["lib"]
    release = sources["release"]
    debian = sources["debian"]
    systemd_smoke = sources["systemd_smoke"]

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
        (
            '[ -z "${DOCKER_CONFIG+x}" ] \\\n'
            '        || die "DOCKER_CONFIG must not influence a direct or release-child Debian build"',
            "Debian child inherited Docker-configuration refusal",
        ),
        (
            "mktemp -d /tmp/rustdesk-debian-build.XXXXXXXXXX",
            "Debian child private workspace",
        ),
        (
            'install -d -m 0700 "$OWNED_WORKSPACE/docker-config"',
            "Debian child private Docker configuration",
        ),
        (
            'export DOCKER_CONFIG="$OWNED_WORKSPACE/docker-config"',
            "Debian child-owned Docker configuration selection",
        ),
    ):
        require(debian, token, label)
    require_order(
        debian,
        (
            'SOURCE_COMMIT="$current"',
            '[ -z "${DOCKER_CONFIG+x}" ]',
            "mktemp -d /tmp/rustdesk-debian-build.XXXXXXXXXX",
            'install -d -m 0700 "$OWNED_WORKSPACE/docker-config"',
            'export DOCKER_CONFIG="$OWNED_WORKSPACE/docker-config"',
            'if [ -n "${RELEASE_SRC_COMMIT:-}" ]',
        ),
        "Debian child-owned Docker configuration before release classification",
    )
    for token, label in (
        (
            'if [ -n "${DOCKER_CONFIG+x}" ]; then',
            "Debian lifecycle child inherited Docker-configuration refusal",
        ),
        (
            'readonly DOCKER_CONFIG="$WORK/docker-config"',
            "Debian lifecycle child private Docker-configuration path",
        ),
        (
            "(umask 077 && set -o noclobber && printf '{}\\n' >\"$DOCKER_CONFIG/config.json\")",
            "Debian lifecycle child canonical no-clobber Docker configuration",
        ),
        (
            "export DOCKER_CONFIG",
            "Debian lifecycle child Docker-configuration selection",
        ),
    ):
        require(systemd_smoke, token, label)
    require_order(
        systemd_smoke,
        (
            'if [ -n "${DOCKER_CONFIG+x}" ]; then',
            'WORK=$(mktemp -d "$STATE_DIR/run.XXXXXXXXXX")',
            'readonly DOCKER_CONFIG="$WORK/docker-config"',
            "(umask 077 && set -o noclobber && printf '{}\\n' >\"$DOCKER_CONFIG/config.json\")",
            "export DOCKER_CONFIG",
            'docker image inspect "$DEV_IMAGE"',
            "docker run --rm --network none --read-only --pids-limit 64",
        ),
        "Debian lifecycle child-owned Docker configuration before Docker operations",
    )
    image_inspect = extract(
        systemd_smoke,
        'assert_private_docker_config\ndocker_status=0\ndocker image inspect "$DEV_IMAGE"',
        '\n\nif [ "$MODE" = release-deb ]; then',
        "Debian lifecycle Docker image inspection",
    )
    require_count(
        image_inspect,
        "assert_private_docker_config",
        2,
        "Debian lifecycle Docker-image pre/post configuration proof",
    )
    runtime_stage = extract(
        systemd_smoke,
        "assert_private_docker_config\ndocker_status=0\ndocker run --rm --network none",
        "\nlibrary_count=",
        "Debian lifecycle runtime-dependency Docker stage",
    )
    require_count(
        runtime_stage,
        "assert_private_docker_config",
        2,
        "Debian lifecycle Docker-run pre/post configuration proof",
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
        "R-S11e-76/R-S11e-77/R-S11e-78/R-S11e-79/R-S11e-128 Android APK builds use canonical-mode private exact-commit source, independent fixed local Docker authority",
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
        '[ -z "${DOCKER_CONFIG+x}" ] \\\n'
        '        || die "DOCKER_CONFIG must not influence a direct or release-child Debian build"',
        "true # inherited Docker configuration accepted",
        "Debian child inherited Docker-configuration refusal",
    ),
    Mutation(
        "debian",
        'install -d -m 0700 "$OWNED_WORKSPACE/docker-config"',
        'mkdir -p "$OWNED_WORKSPACE/docker-config"',
        "Debian child private Docker configuration",
    ),
    Mutation(
        "debian",
        'export DOCKER_CONFIG="$OWNED_WORKSPACE/docker-config"',
        "true # ambient Docker configuration retained",
        "Debian child-owned Docker configuration selection",
    ),
    Mutation(
        "systemd_smoke",
        'if [ -n "${DOCKER_CONFIG+x}" ]; then',
        "if false; then",
        "Debian lifecycle child inherited Docker-configuration refusal",
    ),
    Mutation(
        "systemd_smoke",
        "(umask 077 && set -o noclobber && printf '{}\\n' >\"$DOCKER_CONFIG/config.json\")",
        "(umask 077 && printf '{}\\n' >\"$DOCKER_CONFIG/config.json\")",
        "Debian lifecycle child canonical no-clobber Docker configuration",
    ),
    Mutation(
        "systemd_smoke",
        "export DOCKER_CONFIG",
        "true # Debian lifecycle Docker configuration retained ambient",
        "Debian lifecycle child Docker-configuration selection",
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
        "R-S11e-76/R-S11e-77/R-S11e-78/R-S11e-79/R-S11e-128 Android APK builds use canonical-mode private exact-commit source, independent fixed local Docker authority",
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
        "release": read_regular(repo, "scripts/build-release.sh"),
        "debian": read_regular(repo, "scripts/build-debian.sh"),
        "systemd_smoke": read_regular(repo, "scripts/smoke-debian-systemd-lifecycle.sh"),
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
        "ANDROID-BUILDER-AUTHORITY: private exact-commit source, independent fixed local Docker authority, phased bounded scratch and Android preferences, private signing output, and four confined launches are GREEN ({} mutations)".format(
            len(MUTATIONS) if args.self_test else 0
        )
    )


if __name__ == "__main__":
    try:
        main()
    except (AuthorityError, OSError, UnicodeError) as error:
        raise SystemExit("verify-android-builder-authority: {}".format(error))
