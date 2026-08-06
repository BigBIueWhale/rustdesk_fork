#!/usr/bin/env python3
"""Bind the Dart/FRB verifier to its non-root disposable-snapshot contract."""

import argparse
import re
from pathlib import Path
from typing import Dict, Iterable, NamedTuple


class ContractError(RuntimeError):
    pass


class Mutation(NamedTuple):
    source: str
    old: str
    new: str
    label: str


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def require_once(source: str, token: str, label: str) -> None:
    count = source.count(token)
    require(count == 1, f"{label}: expected one exact occurrence, found {count}")


def require_all(source: str, tokens: Iterable[str], label: str) -> None:
    for token in tokens:
        require(token in source, f"{label}: missing {token!r}")


def docker_run_block(source: str, label: str) -> str:
    require(source.count("local_docker run ") == 1, f"{label}: expected exactly one fixed-authority Docker launch")
    require("\ndocker run " not in source, f"{label}: retained a PATH-selected Docker launch")
    start = source.index("local_docker run ")
    match = re.search(r"\n\s+bash -euo pipefail -c '\n", source[start:])
    require(match is not None, f"{label}: Docker launch has no exact fail-closed shell boundary")
    return source[start : start + match.end()]


def validate_docker_block(block: str, label: str, source_mount: str, online_mount: str) -> None:
    require_all(
        block,
        (
            "--rm",
            "--pull=never",
            "--network=none",
            "--read-only",
            '--user "$BUILD_UID:$BUILD_GID"',
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--pids-limit=512",
            "--memory=12g",
            "--memory-swap=12g",
            "--cpus=4",
            "--tmpfs /tmp:rw,exec,nosuid,nodev,mode=1777,size=10g",
            source_mount,
            online_mount,
        ),
        label,
    )
    require(block.index(source_mount) < block.index(online_mount), f"{label}: mount order drifted")
    require(block.count("--mount ") == 2, f"{label}: expected exactly two bind mounts")
    forbidden = (
        "docker.sock",
        "--privileged",
        "--cap-add",
        "--pid=host",
        "--pid host",
        "--ipc=host",
        "--ipc host",
        "--uts=host",
        "--uts host",
        "--network=host",
        "--network host",
        "--net=host",
        "--net host",
        "--publish",
        "--expose",
        "--volume",
        "source=$REPO_ROOT",
        "source=$SOURCE_SNAPSHOT",
        "-v ",
    )
    for token in forbidden:
        require(token not in block, f"{label}: forbidden Docker authority {token!r}")
    require(
        re.search(r"(?:^|\s)-p(?:\s|=)", block) is None,
        f"{label}: a Docker port publication flag is present",
    )


def validate_contract(sources: Dict[str, str]) -> None:
    dart = sources["dart"]
    frb = sources["frb"]
    lib = sources["lib"]
    verify = sources["verify"]
    requirements = sources["requirements"]
    hardening = sources["hardening"]
    legacy_flutter_verifier = sources["legacy_flutter_verifier"]

    require_all(
        lib,
        (
            "LOCAL_DOCKER_AUTHORITY_INITIALIZED=0\nLOCAL_DOCKER_AUTHORITY_LABEL=",
            "initialize_local_docker_authority() {",
            '[ "$LOCAL_DOCKER_AUTHORITY_INITIALIZED" -eq 0 ]',
            '[ "$(/usr/bin/id -u)" -ne 0 ] || die "$2 refuses host or container-root Docker authority"',
            '[ "$(/usr/bin/id -g)" -ne 0 ] || die "$2 refuses a root primary group for Docker authority"',
            "/*/docker-config) ;;",
            '[ "$(/usr/bin/stat -c \'%u:%g:%a\' -- "$parent" 2>/dev/null)" =',
            "[ -f /usr/bin/docker ] && [ ! -L /usr/bin/docker ] && [ -x /usr/bin/docker ]",
            "0:0:755:1) ;;",
            "[ -S /var/run/docker.sock ] && [ ! -L /var/run/docker.sock ]",
            "0:1) ;;",
            "DOCKER_HOST DOCKER_CONTEXT DOCKER_CONFIG DOCKER_CERT_PATH DOCKER_TLS_VERIFY DOCKER_TLS",
            "DOCKER_API_VERSION DOCKER_DEFAULT_PLATFORM DOCKER_CONTENT_TRUST",
            "DOCKER_CONTENT_TRUST_SERVER DOCKER_CUSTOM_HEADERS",
            '[ "$(/usr/bin/stat -c \'%a\' "$1" 2>/dev/null)" = "700" ]',
            '/usr/bin/install -d -m 0700 -- "$config"',
            "(umask 077 && set -o noclobber && printf '{}\\n' >\"$config/config.json\")",
            '[ "$(/usr/bin/stat -c \'%u:%g:%a:%h\' -- "$config/config.json" 2>/dev/null)" =',
            '"$(/usr/bin/id -u):$(/usr/bin/id -g):600:1" ]',
            "LOCAL_DOCKER_AUTHORITY_PARENT_ID=\"$(/usr/bin/stat -c '%d:%i:%u:%g:%a' -- \"$parent\")\"",
            "LOCAL_DOCKER_AUTHORITY_CONFIG_ID=\"$(/usr/bin/stat -c '%d:%i:%u:%g:%a:%h' -- \"$config\")\"",
            "LOCAL_DOCKER_AUTHORITY_CONFIG_FILE_ID=\"$(/usr/bin/stat -c '%d:%i:%u:%g:%a:%h' -- \"$config/config.json\")\"",
            "LOCAL_DOCKER_AUTHORITY_CLIENT_ID=\"$(/usr/bin/stat -c '%d:%i:%u:%g:%a:%h' -- /usr/bin/docker)\"",
            "LOCAL_DOCKER_AUTHORITY_SOCKET_ID=\"$(/usr/bin/stat -c '%d:%i:%u:%g:%a:%h' -- /var/run/docker.sock)\"",
            "assert_local_docker_authority() {",
            '/usr/bin/cmp -s -- "$LOCAL_DOCKER_AUTHORITY_CONFIG/config.json" <(printf \'{}\\n\')',
            "local_docker() {",
            "local_docker_image_provenance() {",
            "remove_local_docker_authority() {",
            '/usr/bin/python3 -I -S "$LIB_DIR/offline-image-provenance.py" "$@"',
            'local_docker_image_provenance "${args[@]}"',
            'echo "$LOCAL_DOCKER_AUTHORITY_LABEL preserving changed private Docker authority"',
        ),
        "shared local Docker authority",
    )
    initialize_start = lib.index("initialize_local_docker_authority() {")
    assert_start = lib.index("assert_local_docker_authority() {")
    initializer = lib[initialize_start:assert_start]
    require(
        "[ -S /var/run/docker.sock ] && [ ! -L /var/run/docker.sock ]" in initializer,
        "Docker authority initializer does not bind the local socket type",
    )
    local_docker_start = lib.index("local_docker() {")
    provenance_start = lib.index("local_docker_image_provenance() {")
    remove_start = lib.index("remove_local_docker_authority() {")
    pinned_start = lib.index("require_pinned_builder_image() {")
    local_docker = lib[local_docker_start:provenance_start]
    provenance = lib[provenance_start:remove_start]
    removal = lib[remove_start:pinned_start]
    for block, label in (
        (local_docker, "Docker client wrapper"),
        (provenance, "Docker provenance wrapper"),
    ):
        require(block.count("assert_local_docker_authority") == 2, f"{label}: authority must be checked before and after")
        require("/usr/bin/env -i" in block, f"{label}: client environment is not empty")
        require("PATH=/usr/bin:/bin" in block, f"{label}: fixed PATH is absent")
        require("HOME=\"$LOCAL_DOCKER_AUTHORITY_PARENT\"" in block, f"{label}: private HOME is absent")
        require("DOCKER_HOST=unix:///var/run/docker.sock" in block, f"{label}: fixed local endpoint is absent")
        require("DOCKER_CONFIG=\"$LOCAL_DOCKER_AUTHORITY_CONFIG\"" in block, f"{label}: private configuration is absent")
    require("/usr/bin/docker" in local_docker, "Docker client wrapper is not absolute")
    require("--host unix:///var/run/docker.sock" in local_docker, "Docker client wrapper lacks an explicit local host")
    require('--config "$LOCAL_DOCKER_AUTHORITY_CONFIG"' in local_docker, "Docker client wrapper lacks explicit private config")
    require("/usr/bin/docker" not in provenance, "provenance wrapper must let the fixed helper select its absolute Docker client")
    require("assert_local_docker_authority" in removal, "Docker authority removal lacks an identity precondition")
    require('/usr/bin/rm -- "$LOCAL_DOCKER_AUTHORITY_CONFIG/config.json"' in removal, "Docker config removal is not exact")
    require('/usr/bin/rmdir -- "$LOCAL_DOCKER_AUTHORITY_CONFIG"' in removal, "Docker config directory removal is not exact")
    require("rm -rf" not in removal, "Docker authority removal is broad")

    require_all(
        dart,
        (
            'readonly BUILD_UID="$(/usr/bin/id -u)"',
            'readonly BUILD_GID="$(/usr/bin/id -g)"',
            '[ "$BUILD_UID" -ne 0 ] || die "dart-verify refuses host or container-root execution"',
            '[ "$BUILD_GID" -ne 0 ] || die "dart-verify refuses a root primary group"',
            'IMAGE_ID="$DEB_BUILDER_IMAGE_ID"',
            'WORKSPACE_ID="$(/usr/bin/stat -c \'%d:%i:%u:%g:%a\' -- "$WORKSPACE")"',
            'initialize_local_docker_authority "$WORKSPACE/docker-config" "dart-verify"',
            'require_pinned_builder_image deb-builder "$IMAGE_ID"',
            "local_docker run --rm",
            'WORKSPACE="$(umask 077 && mktemp -d /tmp/rustdesk-dart-verify.XXXXXXXXXX)"',
            '[ "$(/usr/bin/stat -c \'%u:%g:%a\' "$WORKSPACE")" = "$BUILD_UID:$BUILD_GID:700" ]',
            'create_private_online_snapshot "$ONLINE_SNAPSHOT_PARENT"',
            'ONLINE_SNAPSHOT="$ONLINE_SNAPSHOT_PARENT/online"',
            'archive_current_source >"$SOURCE_ARCHIVE"',
            'if relative and os.path.lexists(os.path.join(root, relative)):',
            'SOURCE_DIGEST="$(sha256sum "$SOURCE_ARCHIVE" | awk \'{print $1}\')"',
            'chmod -R a-w "$SOURCE_SNAPSHOT"',
            'FRB_IMAGE_ID="$IMAGE_ID"',
            '--source-root "$SOURCE_SNAPSHOT"',
            '--online-root "$ONLINE_SNAPSHOT"',
            '--output-root "$FRB_OUTPUT"',
            'cp -a --reflink=auto "$SOURCE_SNAPSHOT/." "$ANALYSIS_ROOT/"',
            'cp -a "$FRB_OUTPUT/." "$ANALYSIS_ROOT/"',
            '    dart pub get --offline --enforce-lockfile >/dev/null',
            'if [ "$lock_before" != "$lock_after" ]; then',
            'grep -qE "GpuTexture|gpu_texture|AdapterLuid|adapter_luid|mainHasHwcodec|mainHasVram|main_has_hwcodec|main_has_vram"',
            'DART-VERIFY: FAILED — freshly generated bridge retained the retired GPU/VRAM presentation surface',
            'flutter analyze --no-pub --no-fatal-infos --no-fatal-warnings lib/',
            'flutter analyze --no-pub \\\n'
            '      third_party/texture_rgba_renderer/lib/',
            'analyze_status=$?',
            'if [ "$analyze_status" -ne 0 ] || [ "$errs" != "0" ]; then',
            'flutter test --no-pub test/address_validator_test.dart',
            'flutter test --no-pub test/mobile_file_session_lifecycle_test.dart',
            'flutter test --no-pub test/desktop_texture_lifecycle_test.dart',
            'flutter test --no-pub test/desktop_tab_retirement_test.dart',
            'flutter test --no-pub test/password_field_semantics_test.dart',
            "if grep -RInF --include='*.dart' 'workaroundFreezeLinuxMint' flutter/lib",
            "grep -qF 'focusable: true,' flutter/lib/common/widgets/dialog.dart",
            "for flag in isTextField isObscured hasEnabledState isEnabled isFocusable isFocused; do",
            "grep -qF 'semanticsEnabled: true' flutter/test/password_field_semantics_test.dart",
            'for page in flutter/lib/desktop/pages/remote_page.dart \\\n  flutter/lib/desktop/pages/view_camera_page.dart; do',
            "grep -qF 'await controller.closeAll();' flutter/lib/desktop/widgets/tabbar_widget.dart",
            "grep -qF 'while (state.value.tabs.isNotEmpty) {'",
            "if grep -qF 'tabController.clear();' \"$tab_page\"; then",
            '--env "RUSTDESK_RUST_VERSION=$RUST_VERSION"',
            'tar -C "$toolchain" -xf "/online/rust-${RUSTDESK_RUST_VERSION}.tar.xz"',
            '--components=rustc,cargo,rust-std-x86_64-unknown-linux-gnu,rustfmt-preview',
            'printf "[net]\\noffline = true\\n"',
            'sed "s#directory = .*#directory = \\"/online/cargo-vendor\\"#" /online/cargo-vendor-config.toml',
            'export VCPKG_ROOT=/online/vcpkg',
            '[ -d "$VCPKG_ROOT/installed/x64-linux/lib" ]',
            'export CARGO_TARGET_DIR=/src/.dart-verify-cargo-target CARGO_INCREMENTAL=0',
            '(cd "$toolchain/flutter/packages/flutter_tools" && dart pub get --offline --enforce-lockfile >/dev/null)',
            'cargo check --offline --locked --features flutter,unix-file-copy-paste --lib --color never',
            'cargo test --offline --locked --lib --features flutter,unix-file-copy-paste \\\n'
            '      flutter::mobile_session_lifecycle_tests:: -- --test-threads=1',
            'if [ "$cargo_lock_before" != "$cargo_lock_after" ]; then',
            'SOURCE_DIGEST_AFTER="$(archive_current_source | sha256sum | awk \'{print $1}\')"',
            '[ "$SOURCE_DIGEST_AFTER" = "$SOURCE_DIGEST" ]',
        ),
        "dart verifier authority",
    )
    require(
        dart.index('initialize_local_docker_authority "$WORKSPACE/docker-config" "dart-verify"')
        < dart.index('require_pinned_builder_image deb-builder "$IMAGE_ID"')
        < dart.index("local_docker run "),
        "dart verifier does not initialize fixed Docker authority before provenance and launch",
    )
    require(
        '&& ! remove_local_docker_authority; then' in dart,
        "dart verifier cleanup does not retire exact Docker authority first",
    )
    require("require_cmd docker" not in dart, "dart verifier still accepts a PATH-selected Docker client")
    require(
        dart.count('verify_private_online_snapshot "$ONLINE_SNAPSHOT_PARENT"') == 2,
        "dart verifier must verify its private online snapshot before and after use",
    )
    require(
        dart.index('create_private_online_snapshot "$ONLINE_SNAPSHOT_PARENT"')
        < dart.index('FRB_IMAGE_ID="$IMAGE_ID"'),
        "dart verifier consumes the online tree before snapshot creation",
    )
    require(
        dart.index('SOURCE_DIGEST="$(sha256sum "$SOURCE_ARCHIVE"')
        < dart.index("local_docker run "),
        "dart verifier records source identity after container execution",
    )
    require(
        dart.rindex('verify_private_online_snapshot "$ONLINE_SNAPSHOT_PARENT"')
        < dart.index('SOURCE_DIGEST_AFTER="$(archive_current_source'),
        "dart verifier final online/source checks are not ordered",
    )
    require(
        dart.index('(cd "$toolchain/flutter/packages/flutter_tools" && dart pub get --offline --enforce-lockfile >/dev/null)')
        < dart.index('flutter analyze --no-pub --no-fatal-infos --no-fatal-warnings lib/'),
        "Flutter tool dependencies are not explicitly resolved offline before analyzer launch",
    )
    require(
        dart.index('flutter test --no-pub test/address_validator_test.dart')
        < dart.index('cargo check --offline --locked --features flutter,unix-file-copy-paste'),
        "shipped-feature Rust check does not follow generated-binding Dart verification",
    )
    require(
        dart.index('cargo_lock_before="$(sha256sum /src/Cargo.lock')
        < dart.index('cargo check --offline --locked --features flutter,unix-file-copy-paste'),
        "Rust lock identity is not recorded before the shipped-feature check",
    )
    require(
        dart.index('cargo check --offline --locked --features flutter,unix-file-copy-paste')
        < dart.index(
            'cargo test --offline --locked --lib --features flutter,unix-file-copy-paste'
        ),
        "generated-bridge mobile lifecycle tests do not follow the shipped-feature check",
    )
    require(
        dart.index(
            'cargo test --offline --locked --lib --features flutter,unix-file-copy-paste'
        )
        < dart.index('cargo_lock_after="$(sha256sum Cargo.lock'),
        "Rust lock identity is not checked after the generated-bridge lifecycle tests",
    )
    for forbidden in (
        "docker build",
        "docker volume",
        "rd-fluttercheck",
        "rd-devcheck",
        "rd-pub-cache",
        "rd-cargo-cache",
        "rd-git-cache",
        "rd-verify-target",
        "/root/.pub-cache",
        "frb_log=/tmp/",
        "build_runner build --delete-conflicting-outputs",
        "|| true\n    if ! flutter_rust_bridge_codegen",
        '-v "$PWD:/work:rw"',
    ):
        require(forbidden not in dart, f"dart verifier retained forbidden legacy authority {forbidden!r}")

    dart_block = docker_run_block(dart, "dart analyzer container")
    validate_docker_block(
        dart_block,
        "dart analyzer container",
        '--mount "type=bind,source=$ANALYSIS_ROOT,target=/src"',
        '--mount "type=bind,source=$ONLINE_SNAPSHOT,target=/online,readonly"',
    )
    require(
        '--workdir /src "$IMAGE_ID"' in dart_block,
        "dart analyzer does not execute the immutable pinned image in its private source",
    )

    require_all(
        frb,
        (
            'readonly BUILD_UID="$(/usr/bin/id -u)"',
            'readonly BUILD_GID="$(/usr/bin/id -g)"',
            '[ "$BUILD_UID" -ne 0 ] || die "FRB code generation refuses host or container-root execution"',
            '[ "$BUILD_GID" -ne 0 ] || die "FRB code generation refuses a root primary group"',
            '[[ "$IMAGE_ID" =~ ^sha256:[0-9a-f]{64}$ ]]',
            '[ "$IMAGE_ID" = "${DEB_BUILDER_IMAGE_ID:-}" ]',
            'WORK_ROOT="$(umask 077 && mktemp -d "$OUTPUT_PARENT/.frb-work.XXXXXXXX")"',
            'WORK_ROOT_ID="$(/usr/bin/stat -c \'%d:%i:%u:%g:%a\' -- "$WORK_ROOT")"',
            'initialize_local_docker_authority "$WORK_ROOT/docker-config" "frb-codegen"',
            'require_pinned_builder_image deb-builder "$IMAGE_ID"',
            "local_docker run --rm",
            'remove_local_docker_authority \\\n    || die "FRB private Docker authority could not be removed safely"',
        ),
        "FRB generator authority",
    )
    require(
        frb.index('initialize_local_docker_authority "$WORK_ROOT/docker-config" "frb-codegen"')
        < frb.index('require_pinned_builder_image deb-builder "$IMAGE_ID"')
        < frb.index("local_docker run "),
        "FRB generator does not initialize fixed Docker authority before provenance and launch",
    )
    require(
        '&& ! remove_local_docker_authority; then' in frb,
        "FRB cleanup does not retire exact Docker authority first",
    )
    require("require_cmd docker" not in frb, "FRB generator still accepts a PATH-selected Docker client")
    frb_block = docker_run_block(frb, "FRB generator container")
    validate_docker_block(
        frb_block,
        "FRB generator container",
        '--mount "type=bind,source=$WORK_SOURCE,target=/src"',
        '--mount "type=bind,source=$ONLINE_DIR,target=/online,readonly"',
    )
    require(
        '--workdir /src "$IMAGE_ID"' in frb_block,
        "FRB generator does not execute the immutable pinned image in its private source",
    )

    require_once(
        verify,
        "python3 scripts/verify-dart-verifier-authority.py",
        "shared verifier wiring",
    )
    require(
        '<span class="id">R-S11bc</span>' in requirements,
        "requirements are missing R-S11bc",
    )
    require(
        "<tr><td>180</td>" in requirements,
        "requirements are missing Appendix C #180",
    )
    require(
        "R-S11bc/R-S11e-69" in hardening,
        "hardening ledger is missing the Dart verifier authority closure",
    )
    require(
        legacy_flutter_verifier == "absent",
        "the unsafe parallel Flutter verifier or its live-fetching image recipe is present",
    )
    require(
        '<span class="id">R-S11bd</span>' in requirements,
        "requirements are missing R-S11bd",
    )
    require(
        "<tr><td>181</td>" in requirements,
        "requirements are missing Appendix C #181",
    )
    require(
        "R-S11bd/R-S11e-70" in hardening,
        "hardening ledger is missing the consolidated Flutter/Rust verifier closure",
    )
    require(
        '<span class="id">R-S11de</span>' in requirements,
        "requirements are missing R-S11de",
    )
    require(
        "<tr><td>258</td>" in requirements,
        "requirements are missing Appendix C #258",
    )
    require(
        "R-S11de/R-S11e-123" in hardening,
        "hardening ledger is missing the Dart/FRB Docker authority correction",
    )


def mutate_once(sources: Dict[str, str], mutation: Mutation) -> Dict[str, str]:
    source = sources[mutation.source]
    count = source.count(mutation.old)
    require(count == 1, f"self-test fixture {mutation.label!r} matched {count} times")
    changed = dict(sources)
    changed[mutation.source] = source.replace(mutation.old, mutation.new, 1)
    return changed


MUTATIONS = (
    Mutation(
        "lib",
        "LOCAL_DOCKER_AUTHORITY_INITIALIZED=0\nLOCAL_DOCKER_AUTHORITY_LABEL=",
        "LOCAL_DOCKER_AUTHORITY_INITIALIZED=1\nLOCAL_DOCKER_AUTHORITY_LABEL=",
        "ambient local Docker authority state",
    ),
    Mutation(
        "lib",
        "[ -f /usr/bin/docker ] && [ ! -L /usr/bin/docker ] && [ -x /usr/bin/docker ]",
        "command -v docker >/dev/null",
        "absolute trusted Docker client",
    ),
    Mutation(
        "lib",
        "LOCAL_DOCKER_AUTHORITY_CLIENT_ID=\"$(/usr/bin/stat -c",
        "LOCAL_DOCKER_AUTHORITY_CLIENT_ID=\"$(stat -c",
        "absolute Docker metadata inspector",
    ),
    Mutation(
        "lib",
        '[ "$(/usr/bin/stat -c \'%a\' "$1" 2>/dev/null)" = "700" ]',
        '[ "$(stat -c \'%a\' "$1" 2>/dev/null)" = "700" ]',
        "absolute private-snapshot metadata inspector",
    ),
    Mutation(
        "lib",
        "0:0:755:1) ;;",
        "*:*) ;;",
        "Docker client ownership and mode",
    ),
    Mutation(
        "lib",
        "[ -S /var/run/docker.sock ] && [ ! -L /var/run/docker.sock ] \\\n        || die \"$label fixed local Docker Unix socket is unavailable\"",
        "[ -e /var/run/docker.sock ] \\\n        || die \"$label fixed local Docker Unix socket is unavailable\"",
        "local Docker socket type",
    ),
    Mutation(
        "lib",
        "DOCKER_HOST DOCKER_CONTEXT DOCKER_CONFIG DOCKER_CERT_PATH DOCKER_TLS_VERIFY DOCKER_TLS",
        "DOCKER_HOST DOCKER_CONFIG DOCKER_CERT_PATH DOCKER_TLS_VERIFY DOCKER_TLS",
        "ambient Docker context refusal",
    ),
    Mutation(
        "lib",
        '/usr/bin/install -d -m 0700 -- "$config"',
        '/usr/bin/install -d -m 0777 -- "$config"',
        "private Docker configuration mode",
    ),
    Mutation(
        "lib",
        "(umask 077 && set -o noclobber && printf '{}\\n' >\"$config/config.json\")",
        "(umask 077 && printf '{}\\n' >\"$config/config.json\")",
        "private Docker config no-clobber creation",
    ),
    Mutation(
        "lib",
        '"$(/usr/bin/id -u):$(/usr/bin/id -g):600:1" ]',
        '"$(/usr/bin/id -u):$(/usr/bin/id -g):666:2" ]',
        "private Docker config file mode and link count",
    ),
    Mutation(
        "lib",
        "(umask 077 && set -o noclobber && printf '{}\\n' >\"$config/config.json\")",
        "(umask 077 && set -o noclobber && printf '{\"proxies\":{\"default\":{\"httpProxy\":\"http://127.0.0.1:9\"}}}\\n' >\"$config/config.json\")",
        "canonical empty Docker configuration",
    ),
    Mutation(
        "lib",
        "local_docker() {\n    local status=0\n    assert_local_docker_authority || return 1",
        "local_docker() {\n    local status=0\n    true # Docker authority precondition disabled",
        "Docker launch authority precondition",
    ),
    Mutation(
        "lib",
        "local_docker() {\n    local status=0\n    assert_local_docker_authority || return 1\n    /usr/bin/env -i",
        "local_docker() {\n    local status=0\n    assert_local_docker_authority || return 1\n    env",
        "Docker launch empty environment",
    ),
    Mutation(
        "lib",
        "--host unix:///var/run/docker.sock",
        "--host tcp://127.0.0.1:2375",
        "explicit local Docker endpoint",
    ),
    Mutation(
        "lib",
        'local_docker_image_provenance() {\n    local status=0\n    assert_local_docker_authority || return 1\n    /usr/bin/env -i',
        'local_docker_image_provenance() {\n    local status=0\n    assert_local_docker_authority || return 1\n    env',
        "image provenance empty environment",
    ),
    Mutation(
        "lib",
        '/usr/bin/python3 -I -S "$LIB_DIR/offline-image-provenance.py" "$@"',
        'python3 "$LIB_DIR/offline-image-provenance.py" "$@"',
        "fixed image provenance interpreter",
    ),
    Mutation(
        "lib",
        'local_docker_image_provenance "${args[@]}" \\\n            || die "pinned $role image provenance verification failed"',
        'python3 "$LIB_DIR/offline-image-provenance.py" "${args[@]}" \\\n            || die "pinned $role image provenance verification failed"',
        "builder provenance fixed Docker authority",
    ),
    Mutation(
        "lib",
        "remove_local_docker_authority() {\n    assert_local_docker_authority || {",
        "remove_local_docker_authority() {\n    true || {",
        "Docker authority removal identity",
    ),
    Mutation("dart", 'readonly BUILD_UID="$(/usr/bin/id -u)"', 'readonly BUILD_UID="$(id -u)"', "dart absolute UID source"),
    Mutation("dart", '[ "$BUILD_UID" -ne 0 ]', '[ "$BUILD_UID" -ge 0 ]', "dart uid-root refusal"),
    Mutation("dart", '[ "$BUILD_GID" -ne 0 ]', '[ "$BUILD_GID" -ge 0 ]', "dart gid-root refusal"),
    Mutation("dart", 'IMAGE_ID="$DEB_BUILDER_IMAGE_ID"', 'IMAGE_ID=rd-fluttercheck', "mutable Dart image"),
    Mutation(
        "dart",
        '[ "$(/usr/bin/stat -c \'%u:%g:%a\' "$WORKSPACE")" = "$BUILD_UID:$BUILD_GID:700" ]',
        '[ -d "$WORKSPACE" ]',
        "private workspace identity",
    ),
    Mutation(
        "dart",
        'initialize_local_docker_authority "$WORKSPACE/docker-config" "dart-verify"',
        'true # local Docker authority initialization disabled',
        "Dart fixed Docker authority",
    ),
    Mutation(
        "dart",
        "local_docker run --rm",
        "docker run --rm",
        "Dart fixed Docker launcher",
    ),
    Mutation(
        "dart",
        'if [ "$LOCAL_DOCKER_AUTHORITY_INITIALIZED" -eq 1 ] \\\n      && ! remove_local_docker_authority; then',
        'if false; then',
        "Dart exact Docker authority cleanup",
    ),
    Mutation("dart", 'create_private_online_snapshot "$ONLINE_SNAPSHOT_PARENT"\n', "", "online snapshot creation"),
    Mutation(
        "dart",
        'cd "$REPO_ROOT"\nverify_private_online_snapshot "$ONLINE_SNAPSHOT_PARENT"',
        'cd "$REPO_ROOT"\ntrue # private snapshot final proof disabled',
        "final online proof",
    ),
    Mutation("dart", 'archive_current_source >"$SOURCE_ARCHIVE"\n', "", "source snapshot identity"),
    Mutation(
        "dart",
        'if relative and os.path.lexists(os.path.join(root, relative)):',
        'if relative:',
        "deleted-path source inventory",
    ),
    Mutation("dart", 'chmod -R a-w "$SOURCE_SNAPSHOT"', 'chmod -R u+w "$SOURCE_SNAPSHOT"', "read-only source snapshot"),
    Mutation("dart", '--pull=never', '--pull=always', "Dart pull refusal"),
    Mutation("dart", '--network=none', '--network=bridge', "Dart network isolation"),
    Mutation("dart", '--read-only', '--hostname=dart-verify', "Dart read-only root"),
    Mutation("dart", '--user "$BUILD_UID:$BUILD_GID"', '--user 0:0', "Dart numeric non-root user"),
    Mutation("dart", '--cap-drop=ALL', '--cap-add=SYS_ADMIN', "Dart capability drop"),
    Mutation("dart", '--security-opt=no-new-privileges', '--security-opt=label=disable', "Dart no-new-privileges"),
    Mutation("dart", '--pids-limit=512', '--pids-limit=-1', "Dart pid bound"),
    Mutation("dart", '--memory=12g', '--memory=0', "Dart memory bound"),
    Mutation("dart", '--memory-swap=12g', '--memory-swap=-1', "Dart no-swap bound"),
    Mutation("dart", '--cpus=4', '--cpuset-cpus=0-255', "Dart cpu bound"),
    Mutation(
        "dart",
        '--tmpfs /tmp:rw,exec,nosuid,nodev,mode=1777,size=10g',
        '--tmpfs /tmp:rw,exec,mode=1777',
        "Dart temporary-storage bound",
    ),
    Mutation("dart", 'source=$ANALYSIS_ROOT,target=/src', 'source=$REPO_ROOT,target=/src', "Dart private source mount"),
    Mutation(
        "dart",
        '--mount "type=bind,source=$ANALYSIS_ROOT,target=/src"',
        '--mount "type=bind,source=$ANALYSIS_ROOT,target=/src" --mount "type=bind,source=/var/run/docker.sock,target=/var/run/docker.sock"',
        "Dart complete mount inventory",
    ),
    Mutation("dart", 'source=$ONLINE_SNAPSHOT,target=/online,readonly', 'source=$ONLINE_DIR,target=/online', "Dart immutable online mount"),
    Mutation(
        "dart",
        '    dart pub get --offline --enforce-lockfile >/dev/null',
        '    dart pub get --offline >/dev/null',
        "offline enforced-lockfile Pub resolution",
    ),
    Mutation(
        "dart",
        'if [ "$lock_before" != "$lock_after" ]; then',
        'if false; then',
        "Pub lock preservation",
    ),
    Mutation(
        "dart",
        'grep -qE "GpuTexture|gpu_texture|AdapterLuid|adapter_luid|mainHasHwcodec|mainHasVram|main_has_hwcodec|main_has_vram"',
        'grep -qE "this_pattern_cannot_match"',
        "fresh generated bridge GPU/VRAM absence",
    ),
    Mutation(
        "dart",
        'if [ "$analyze_status" -ne 0 ] || [ "$errs" != "0" ]; then',
        'if [ "$errs" != "0" ]; then',
        "analyzer exit finality",
    ),
    Mutation(
        "dart",
        'flutter test --no-pub test/address_validator_test.dart',
        'true # focused direct-address test disabled',
        "focused Dart regression",
    ),
    Mutation(
        "dart",
        '--env "RUSTDESK_RUST_VERSION=$RUST_VERSION"',
        '--env "RUSTDESK_RUST_VERSION=nightly"',
        "pinned Rust toolchain input",
    ),
    Mutation(
        "dart",
        'printf "[net]\\noffline = true\\n"',
        'printf "[net]\\noffline = false\\n"',
        "offline Cargo resolver",
    ),
    Mutation(
        "dart",
        'export VCPKG_ROOT=/online/vcpkg',
        'export VCPKG_ROOT=/usr/local/vcpkg',
        "staged native dependency root",
    ),
    Mutation(
        "dart",
        'export CARGO_TARGET_DIR=/src/.dart-verify-cargo-target CARGO_INCREMENTAL=0',
        'export CARGO_TARGET_DIR=/build CARGO_INCREMENTAL=1',
        "private disposable Cargo target",
    ),
    Mutation(
        "dart",
        '(cd "$toolchain/flutter/packages/flutter_tools" && dart pub get --offline --enforce-lockfile >/dev/null)',
        '(cd "$toolchain/flutter/packages/flutter_tools" && dart pub get --offline >/dev/null)',
        "offline enforced-lockfile Flutter-tool bootstrap",
    ),
    Mutation(
        "dart",
        'cargo check --offline --locked --features flutter,unix-file-copy-paste --lib --color never',
        'cargo check --features flutter --lib --color never',
        "exact locked shipped-feature Rust check",
    ),
    Mutation(
        "dart",
        'cargo test --offline --locked --lib --features flutter,unix-file-copy-paste \\\n'
        '      flutter::mobile_session_lifecycle_tests:: -- --test-threads=1',
        'true # generated-bridge mobile lifecycle tests disabled',
        "generated-bridge mobile lifecycle regressions",
    ),
    Mutation(
        "dart",
        "flutter test --no-pub test/mobile_file_session_lifecycle_test.dart",
        "true # mobile file-session lifecycle test disabled",
        "mobile file-session lifecycle regression",
    ),
    Mutation(
        "dart",
        "flutter test --no-pub test/desktop_texture_lifecycle_test.dart",
        "true # desktop texture lifecycle test disabled",
        "desktop texture lifecycle regression",
    ),
    Mutation(
        "dart",
        "flutter test --no-pub test/password_field_semantics_test.dart",
        "true # password-field semantics test disabled",
        "password-field semantics regression",
    ),
    Mutation(
        "dart",
        "if grep -RInF --include='*.dart' 'workaroundFreezeLinuxMint' flutter/lib",
        "if false; then # Linux semantics exclusion accepted",
        "global Linux semantics-exclusion absence",
    ),
    Mutation(
        "dart",
        "grep -qF 'focusable: true,' flutter/lib/common/widgets/dialog.dart",
        "true # dialog focusability export accepted absent",
        "dialog focusability export",
    ),
    Mutation(
        "dart",
        "for flag in isTextField isObscured hasEnabledState isEnabled isFocusable isFocused; do",
        "for flag in isTextField isObscured; do",
        "complete password semantics flag contract",
    ),
    Mutation(
        "dart",
        "grep -qF 'semanticsEnabled: true' flutter/test/password_field_semantics_test.dart",
        "true # semantics-enabled regression accepted absent",
        "password regression semantics enablement",
    ),
    Mutation(
        "dart",
        "flutter test --no-pub test/desktop_tab_retirement_test.dart",
        "true # desktop tab retirement regression disabled",
        "desktop tab retirement behavior gate",
    ),
    Mutation(
        "dart",
        "grep -qF 'await controller.closeAll();' flutter/lib/desktop/widgets/tabbar_widget.dart",
        "true # native window cleanup boundary accepted absent",
        "native window cleanup source gate",
    ),
    Mutation(
        "dart",
        "grep -qF 'while (state.value.tabs.isNotEmpty) {'",
        "true # close-time arrivals are not drained",
        "close-time tab drain source gate",
    ),
    Mutation(
        "dart",
        'flutter analyze --no-pub \\\n'
        '      third_party/texture_rgba_renderer/lib/',
        "true # in-tree native RGBA Dart wrapper analysis disabled",
        "in-tree native RGBA Dart wrapper analysis",
    ),
    Mutation(
        "dart",
        'if [ "$cargo_lock_before" != "$cargo_lock_after" ]; then',
        'if false; then # Rust lock postcondition disabled',
        "Cargo lock preservation",
    ),
    Mutation("dart", 'SOURCE_DIGEST_AFTER="$(archive_current_source', 'SOURCE_DIGEST_AFTER="$(printf stale |', "final source proof"),
    Mutation("frb", 'readonly BUILD_UID="$(/usr/bin/id -u)"', 'readonly BUILD_UID="$(id -u)"', "FRB absolute UID source"),
    Mutation("frb", '[ "$BUILD_UID" -ne 0 ]', '[ "$BUILD_UID" -ge 0 ]', "FRB uid-root refusal"),
    Mutation("frb", '[ "$BUILD_GID" -ne 0 ]', '[ "$BUILD_GID" -ge 0 ]', "FRB gid-root refusal"),
    Mutation(
        "frb",
        'initialize_local_docker_authority "$WORK_ROOT/docker-config" "frb-codegen"',
        'true # local Docker authority initialization disabled',
        "FRB fixed Docker authority",
    ),
    Mutation(
        "frb",
        "local_docker run --rm",
        "docker run --rm",
        "FRB fixed Docker launcher",
    ),
    Mutation(
        "frb",
        'if [ "$LOCAL_DOCKER_AUTHORITY_INITIALIZED" -eq 1 ] \\\n            && ! remove_local_docker_authority; then',
        'if false; then',
        "FRB exact Docker authority cleanup",
    ),
    Mutation(
        "frb",
        'require_pinned_builder_image deb-builder "$IMAGE_ID"',
        'true # image provenance disabled',
        "FRB image provenance",
    ),
    Mutation("frb", '--pull=never', '--pull=missing', "FRB pull refusal"),
    Mutation("frb", '--network=none', '--network=host', "FRB network isolation"),
    Mutation("frb", '--read-only', '--hostname=frb-codegen', "FRB read-only root"),
    Mutation("frb", '--user "$BUILD_UID:$BUILD_GID"', '--user 0:0', "FRB numeric non-root user"),
    Mutation("frb", '--cap-drop=ALL', '--cap-add=SYS_ADMIN', "FRB capability drop"),
    Mutation("frb", '--security-opt=no-new-privileges', '--security-opt=label=disable', "FRB no-new-privileges"),
    Mutation("frb", '--pids-limit=512', '--pids-limit=-1', "FRB pid bound"),
    Mutation("frb", '--memory=12g', '--memory=0', "FRB memory bound"),
    Mutation("frb", '--memory-swap=12g', '--memory-swap=-1', "FRB no-swap bound"),
    Mutation("frb", '--cpus=4', '--cpuset-cpus=0-255', "FRB cpu bound"),
    Mutation(
        "frb",
        '--tmpfs /tmp:rw,exec,nosuid,nodev,mode=1777,size=10g',
        '--tmpfs /tmp:rw,exec,mode=1777',
        "FRB temporary-storage bound",
    ),
    Mutation("frb", 'source=$WORK_SOURCE,target=/src', 'source=$SOURCE_ROOT,target=/src', "FRB private source mount"),
    Mutation(
        "frb",
        '--mount "type=bind,source=$WORK_SOURCE,target=/src"',
        '--mount "type=bind,source=$WORK_SOURCE,target=/src" --mount "type=bind,source=/var/run/docker.sock,target=/var/run/docker.sock"',
        "FRB complete mount inventory",
    ),
    Mutation(
        "frb",
        'source=$ONLINE_DIR,target=/online,readonly',
        'source=$ONLINE_DIR,target=/online',
        "FRB immutable online mount",
    ),
    Mutation(
        "verify",
        "python3 scripts/verify-dart-verifier-authority.py --repo . --self-test \\\n",
        "",
        "shared gate wiring",
    ),
    Mutation("requirements", '<span class="id">R-S11bc</span>', '<span class="id">R-S11bc-broken</span>', "normative requirement"),
    Mutation("requirements", "<tr><td>180</td>", "<tr><td>180-broken</td>", "Appendix disposition"),
    Mutation("hardening", "R-S11bc/R-S11e-69", "R-S11bc/R-S11e-XX", "hardening ledger"),
    Mutation("legacy_flutter_verifier", "absent", "present", "unsafe parallel Flutter verifier absence"),
    Mutation("requirements", '<span class="id">R-S11bd</span>', '<span class="id">R-S11bd-broken</span>', "consolidation requirement"),
    Mutation("requirements", "<tr><td>181</td>", "<tr><td>181-broken</td>", "consolidation disposition"),
    Mutation("hardening", "R-S11bd/R-S11e-70", "R-S11bd/R-S11e-XX", "consolidation ledger"),
    Mutation("requirements", '<span class="id">R-S11de</span>', '<span class="id">R-S11de-broken</span>', "Docker authority requirement"),
    Mutation("requirements", "<tr><td>258</td>", "<tr><td>258-broken</td>", "Docker authority disposition"),
    Mutation("hardening", "R-S11de/R-S11e-123", "R-S11de/R-S11e-XXX", "Docker authority ledger"),
)


def load_sources(repo: Path) -> Dict[str, str]:
    paths = {
        "dart": repo / "scripts/dart-verify.sh",
        "frb": repo / "scripts/frb-codegen.sh",
        "lib": repo / "scripts/lib.sh",
        "verify": repo / "scripts/verify.sh",
        "requirements": repo / "requirements.html",
        "hardening": repo / "HARDENING_STATUS.md",
    }
    sources = {name: path.read_text(encoding="utf-8") for name, path in paths.items()}
    retired_paths = (
        repo / "scripts/flutter-verify.sh",
        repo / "scripts/Dockerfile.fluttercheck",
    )
    sources["legacy_flutter_verifier"] = (
        "absent" if all(not path.exists() for path in retired_paths) else "present"
    )
    return sources


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    sources = load_sources(args.repo.resolve())
    validate_contract(sources)
    if args.self_test:
        for mutation in MUTATIONS:
            mutated = mutate_once(sources, mutation)
            try:
                validate_contract(mutated)
            except ContractError:
                continue
            raise ContractError(f"self-test mutation was accepted: {mutation.label}")
        print(f"verify-dart-verifier-authority: ok ({len(MUTATIONS)} mutations rejected)")
    else:
        print("verify-dart-verifier-authority: ok")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ContractError as error:
        raise SystemExit(f"verify-dart-verifier-authority: {error}")
