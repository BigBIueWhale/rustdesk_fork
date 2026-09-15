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


def docker_run_block(source: str, label: str, launcher: str = "verifier_vm_docker") -> str:
    launch = f"{launcher} run "
    require(source.count(launch) == 1, f"{label}: expected exactly one fixed-authority Docker launch")
    require("\ndocker run " not in source, f"{label}: retained a PATH-selected Docker launch")
    start = source.index(launch)
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


def validate_vm_wrappers(
    source: str, state_token: str, label: str
) -> tuple[str, str]:
    docker_start = source.index("verifier_vm_docker() {")
    provenance_start = source.index("verifier_vm_image_provenance() {")
    state_start = source.index(state_token, provenance_start)
    docker_wrapper = source[docker_start:provenance_start]
    provenance_wrapper = source[provenance_start:state_start]
    for wrapper, wrapper_label in (
        (docker_wrapper, f"{label} verifier-VM Docker wrapper"),
        (provenance_wrapper, f"{label} verifier-VM provenance wrapper"),
    ):
        require(
            wrapper.count(
                '/usr/bin/bash "$VERIFIER_VM_ENTRY_PREFLIGHT" >/dev/null || return 1'
            )
            == 2,
            f"{wrapper_label} does not reprove authority exactly before and after its operation",
        )
        require_all(
            wrapper,
            (
                "/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C HOME=/nonexistent",
                'DOCKER_HOST="unix://$VERIFIER_VM_DOCKER_SOCKET"',
                'DOCKER_CONFIG="$VERIFIER_VM_DOCKER_CONFIG"',
                'return "$status"',
            ),
            wrapper_label,
        )
    require_all(
        docker_wrapper,
        (
            '"$VERIFIER_VM_DOCKER_CLIENT"',
            '--host "unix://$VERIFIER_VM_DOCKER_SOCKET"',
            '--config "$VERIFIER_VM_DOCKER_CONFIG" "$@" || status=$?',
        ),
        f"{label} verifier-VM Docker wrapper",
    )
    require_all(
        provenance_wrapper,
        (
            '/usr/bin/python3 -I -S "$SCRIPT_DIR/offline-image-provenance.py" "$@"',
            '|| status=$?',
        ),
        f"{label} verifier-VM provenance wrapper",
    )
    return docker_wrapper, provenance_wrapper


def validate_contract(sources: Dict[str, str]) -> None:
    dart = sources["dart"]
    frb = sources["frb"]
    verify = sources["verify"]
    requirements = sources["requirements"]
    hardening = sources["hardening"]
    legacy_flutter_verifier = sources["legacy_flutter_verifier"]

    require_all(
        dart,
        (
            'readonly SCRIPT_DIR="$(cd "$(/usr/bin/dirname -- "',
            'readonly BUILD_UID="$(/usr/bin/id -u)"',
            'readonly BUILD_GID="$(/usr/bin/id -g)"',
            '[ "$BUILD_UID" -ne 0 ]',
            '[ "$BUILD_GID" -ne 0 ]',
            "echo 'dart-verify refuses host or container-root execution'",
            "echo 'dart-verify refuses a root primary group'",
            'readonly VERIFIER_VM_ENTRY_PREFLIGHT=$SCRIPT_DIR/verify-vm-entry-preflight.sh',
            '"$(/usr/bin/stat -c \'%a:%h\' -- "$VERIFIER_VM_ENTRY_PREFLIGHT")" = 755:1',
            '/usr/bin/bash "$VERIFIER_VM_ENTRY_PREFLIGHT"',
            'readonly VERIFIER_VM_AUTHORITY_ROOT=/run/rustdesk-verifier-vm',
            'readonly VERIFIER_VM_DOCKER_CLIENT=/usr/bin/docker',
            'readonly VERIFIER_VM_DOCKER_SOCKET=$VERIFIER_VM_AUTHORITY_ROOT/docker.sock',
            'readonly VERIFIER_VM_DOCKER_CONFIG=$VERIFIER_VM_AUTHORITY_ROOT/docker-config',
            '[ "$VERIFIER_VM_MARKER_DOCKER" = "docker=$VERIFIER_VM_DOCKER_VERSION" ]',
            'verifier_vm_docker() {',
            'verifier_vm_image_provenance() {',
            '/usr/bin/bash "$SCRIPT_DIR/frb-codegen.sh" --self-test-vm-authority',
            'DART_VM_AUTHORITY=pass uid=%s gid=%s docker=%s channel=guest-unix prepost=replayed frb=chained',
            'IMAGE_ID="$DEB_BUILDER_IMAGE_ID"',
            'WORKSPACE_ID="$(/usr/bin/stat -c \'%d:%i:%u:%g:%a\' -- "$WORKSPACE")"',
            'verifier_vm_image_provenance verify-local',
            '--role deb-builder',
            '--image-ref "$IMAGE_ID"',
            "verifier_vm_docker run --rm",
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
            'flutter analyze --no-pub --no-fatal-infos --no-fatal-warnings \\\n'
            '      third_party/texture_rgba_renderer/lib/',
            'flutter analyze --no-pub --no-fatal-infos --no-fatal-warnings \\\n'
            '      third_party/desktop_multi_window/lib/',
            'flutter analyze --no-pub --no-fatal-infos --no-fatal-warnings \\\n'
            '      third_party/window_manager/lib/',
            'analyze_status=$?',
            'if [ "$analyze_status" -ne 0 ] || [ "$errs" != "0" ]; then',
            'flutter test --no-pub test/address_validator_test.dart',
            'flutter test --no-pub test/mobile_file_session_lifecycle_test.dart',
            'flutter test --no-pub test/file_command_session_ownership_test.dart',
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
            "grep -qF 'path: third_party/desktop_multi_window' flutter/pubspec.yaml",
            "grep -qF 'third_party/desktop_multi_window/** -text' flutter/.gitattributes",
            "grep -qF 'waits for the method' \"$multi_window/UPSTREAM.md\"",
            "grep -qF 'response before scheduling the idle erase' \"$multi_window/UPSTREAM.md\"",
            "grep -qF 'bool destroy_pending_ = false;' \"$multi_window/linux/flutter_window.h\"",
            "grep -qF 'gulong releasedEmissionHook = 0;' \"$multi_window/linux/flutter_window.h\"",
            "grep -qF 'using CompletionHandler = std::function<void()>;'",
            "'struct SelfMethodInvokeAsyncUserData'",
            "'fl_method_channel_invoke_method_finish(data->channel, res, &error);'",
            "'auto completion = std::move(data->completion);'",
            "'completion();'",
            "'gboolean destroyWindowWhenIdle(gpointer data)'",
            "'pending->callback->OnWindowDestroy(pending->id);'",
            "'if (self->destroy_pending_)'",
            "'self->destroy_pending_ = true;'",
            "'channel->InvokeMethodSelf(\"onDestroy\", args, [callback, id]() {'",
            "if grep -qF 'InvokeMethodSelfVoid(\"onDestroy\"'",
            "if grep -qF 'callback->OnWindowDestroy(self->id_);'",
            "if grep -qF 'callback->OnWindowDestroy(id);'",
            "if grep -qF 'return self->isPreventClose;'",
            '"$url_launcher/test/url_launcher_shutdown_test.cc"',
            '\n    /tmp/url_launcher_shutdown_test\n',
            "grep -qF 'third_party/url_launcher_linux/** -text' flutter/.gitattributes",
            "grep -qF 'path: third_party/url_launcher_linux' flutter/pubspec.yaml",
            "if grep -qF 'ful_url_launcher_api_clear_method_handlers('",
            "'messenger->handler_sets_during_shutdown == 2'",
            "'upstream_url_launcher=/online/pub-cache/hosted/pub.dev/url_launcher_linux-3.2.1/linux'",
            "'52cd2d6ef9bc4e1b28eca16d4593c06c52fbc4de3be8083230060c35c4b0db2d'",
            '"$upstream_url_launcher/url_launcher_plugin.cc" | sha256sum -c -',
            "'/tmp/url_launcher_upstream_test >/tmp/url_launcher_upstream.out 2>&1'",
            "'[ \"$upstream_status\" -eq 1 ]'",
            "'FAIL: shutdown did not perform exactly one terminal reset per URL channel'",
            '"$window_manager/test/window_manager_shutdown_test.cc"',
            '\n    /tmp/window_manager_shutdown_test\n',
            '"$window_manager/test/window_manager_shutdown_test.cc" \\\n'
            '      /tmp/window_manager_guard_disabled.cc',
            "'[ \"$guard_disabled_status\" -eq 1 ]'",
            "'FAIL: destroyed-window call was not rejected'",
            "grep -qF 'third_party/window_manager/** -text' flutter/.gitattributes",
            "grep -qF 'path: third_party/window_manager' flutter/pubspec.yaml",
            "grep -qxF \"!flutter/third_party/window_manager/$asset\" .gitignore",
            "'images/ic_chrome_close.png'",
            "'images/ic_chrome_maximize.png'",
            "'images/ic_chrome_minimize.png'",
            "'images/ic_chrome_unmaximize.png'",
            "sha256sum -c - <<'EOF'",
            "70fe0130bbbd928d04cd33a49ecde422ec54fd748b7a4e983f4e31be6e73f5f5  images/ic_chrome_close.png",
            "93f2ed012ec01288b78ad4816ef254261e9ff25e8a9858359b45431c9a5de5f4  images/ic_chrome_maximize.png",
            "0976edbb9977136544af17de125f345a41065694de92036d9365817ea6d8f05a  images/ic_chrome_minimize.png",
            "3d375930c514ec2ebc0603ad1e1398b4daf458951042a97232d16f17e1c9603b  images/ic_chrome_unmaximize.png",
            "'messenger->handler_sets_during_shutdown == 0'",
            "'g_object_add_weak_pointer(G_OBJECT(weak_plugin), &weak_plugin);'",
            "'g_strcmp0(code, \"window_unavailable\") == 0'",
            "'Timer? _initialMaximizedTimer;'",
            "'_initialMaximizedTimer?.cancel();'",
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
        dart.count('[ "$upstream_status" -eq 1 ]') == 2,
        "exact stock URL-launcher rejection must appear once in execution and once in its source gate",
    )
    require(
        dart.count('[ "$guard_disabled_status" -eq 1 ]') == 2,
        "window-manager guard-disabled rejection must appear once in execution and once in its source gate",
    )
    require(
        dart.index('/usr/bin/bash "$VERIFIER_VM_ENTRY_PREFLIGHT"')
        < dart.index('source "$SCRIPT_DIR/lib.sh"')
        < dart.index("verifier_vm_image_provenance verify-local")
        < dart.index('/usr/bin/bash "$SCRIPT_DIR/frb-codegen.sh" \\\n')
        < dart.index("verifier_vm_docker run "),
        "dart verifier does not establish VM authority before provenance, FRB, and launch",
    )
    require("require_cmd docker" not in dart, "dart verifier still accepts a PATH-selected Docker client")
    validate_vm_wrappers(
        dart, "\nVERIFY_VM_AUTHORITY_SELF_TEST=", "Dart"
    )
    for forbidden in (
        "initialize_local_docker_authority",
        "local_docker",
        "remove_local_docker_authority",
        "require_pinned_builder_image",
        "/var/run/docker.sock",
    ):
        require(forbidden not in dart, f"dart verifier retained forbidden host authority {forbidden!r}")
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
        < dart.index("verifier_vm_docker run "),
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
        dart.index('flutter analyze --no-pub --no-fatal-infos --no-fatal-warnings \\\n'
                   '      third_party/texture_rgba_renderer/lib/')
        < dart.index('flutter analyze --no-pub --no-fatal-infos --no-fatal-warnings \\\n'
                     '      third_party/desktop_multi_window/lib/')
        < dart.index('flutter analyze --no-pub --no-fatal-infos --no-fatal-warnings \\\n'
                     '      third_party/window_manager/lib/')
        < dart.index('flutter test --no-pub test/address_validator_test.dart'),
        "vendored plugin analysis is not complete before focused Flutter tests",
    )
    require(
        dart.index("grep -qF 'path: third_party/desktop_multi_window' flutter/pubspec.yaml")
        < dart.index("'struct SelfMethodInvokeAsyncUserData'")
        < dart.index("'gboolean destroyWindowWhenIdle(gpointer data)'")
        < dart.index("if grep -qF 'callback->OnWindowDestroy(self->id_);'"),
        "desktop multi-window source gate is incomplete or misordered",
    )
    require(
        dart.index('"$window_manager/test/window_manager_shutdown_test.cc"')
        < dart.index('\n    /tmp/window_manager_shutdown_test\n')
        < dart.index('/tmp/window_manager_guard_disabled.cc')
        < dart.index('[ "$guard_disabled_status" -eq 1 ]')
        < dart.index("FAIL: destroyed-window call was not rejected"),
        "window-manager behavior and negative-control gate is incomplete or misordered",
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
            'readonly SCRIPT_DIR="$(cd "$(/usr/bin/dirname -- "',
            'readonly BUILD_UID="$(/usr/bin/id -u)"',
            'readonly BUILD_GID="$(/usr/bin/id -g)"',
            '[ "$BUILD_UID" -ne 0 ]',
            '[ "$BUILD_GID" -ne 0 ]',
            "echo 'FRB code generation refuses host or container-root execution'",
            "echo 'FRB code generation refuses a root primary group'",
            'readonly VERIFIER_VM_ENTRY_PREFLIGHT=$SCRIPT_DIR/verify-vm-entry-preflight.sh',
            '/usr/bin/bash "$VERIFIER_VM_ENTRY_PREFLIGHT"',
            'readonly VERIFIER_VM_DOCKER_CLIENT=/usr/bin/docker',
            'readonly VERIFIER_VM_DOCKER_SOCKET=$VERIFIER_VM_AUTHORITY_ROOT/docker.sock',
            'verifier_vm_docker() {',
            'verifier_vm_image_provenance() {',
            '[[ "$IMAGE_ID" =~ ^sha256:[0-9a-f]{64}$ ]]',
            '[ "$IMAGE_ID" = "${DEB_BUILDER_IMAGE_ID:-}" ]',
            'WORK_ROOT="$(umask 077 && mktemp -d "$OUTPUT_PARENT/.frb-work.XXXXXXXX")"',
            'WORK_ROOT_ID="$(/usr/bin/stat -c \'%d:%i:%u:%g:%a\' -- "$WORK_ROOT")"',
            'verifier_vm_image_provenance verify-local',
            '--role deb-builder',
            '--image-ref "$IMAGE_ID"',
            "verifier_vm_docker run --rm",
        ),
        "FRB generator authority",
    )
    require(
        frb.index('/usr/bin/bash "$VERIFIER_VM_ENTRY_PREFLIGHT"')
        < frb.index('source "$SCRIPT_DIR/lib.sh"')
        < frb.index("verifier_vm_image_provenance verify-local")
        < frb.index("verifier_vm_docker run "),
        "FRB generator does not establish VM authority before provenance and launch",
    )
    validate_vm_wrappers(frb, "\nSOURCE_ROOT=", "FRB")
    require("require_cmd docker" not in frb, "FRB generator still accepts a PATH-selected Docker client")
    for forbidden in (
        "initialize_local_docker_authority",
        "local_docker",
        "remove_local_docker_authority",
        "/var/run/docker.sock",
    ):
        require(forbidden not in frb, f"FRB generator retained forbidden host authority {forbidden!r}")
    frb_block = docker_run_block(frb, "FRB generator container", "verifier_vm_docker")
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
        '<span class="id">R-S11dh</span>' in requirements,
        "requirements are missing the verifier-VM execution-authority rule",
    )


def mutate_once(sources: Dict[str, str], mutation: Mutation) -> Dict[str, str]:
    source = sources[mutation.source]
    count = source.count(mutation.old)
    require(count == 1, f"self-test fixture {mutation.label!r} matched {count} times")
    changed = dict(sources)
    changed[mutation.source] = source.replace(mutation.old, mutation.new, 1)
    return changed


MUTATIONS = (
    Mutation("dart", 'readonly BUILD_UID="$(/usr/bin/id -u)"', 'readonly BUILD_UID="$(id -u)"', "dart absolute UID source"),
    Mutation("dart", '[ "$BUILD_UID" -ne 0 ]', '[ "$BUILD_UID" -ge 0 ]', "dart uid-root refusal"),
    Mutation("dart", '[ "$BUILD_GID" -ne 0 ]', '[ "$BUILD_GID" -ge 0 ]', "dart gid-root refusal"),
    Mutation(
        "dart",
        '/usr/bin/bash "$VERIFIER_VM_ENTRY_PREFLIGHT"\n# shellcheck source=scripts/lib.sh',
        'true # verifier-VM entry authority disabled\n# shellcheck source=scripts/lib.sh',
        "Dart verifier-VM entry authority",
    ),
    Mutation(
        "dart",
        '"$(/usr/bin/stat -c \'%a:%h\' -- "$VERIFIER_VM_ENTRY_PREFLIGHT")" = 755:1',
        '"$(/usr/bin/stat -c \'%a:%h\' -- "$VERIFIER_VM_ENTRY_PREFLIGHT")" = 755:*',
        "Dart verifier-VM preflight identity",
    ),
    Mutation(
        "dart",
        'readonly VERIFIER_VM_DOCKER_CLIENT=/usr/bin/docker',
        'readonly VERIFIER_VM_DOCKER_CLIENT=docker',
        "Dart fixed guest Docker client",
    ),
    Mutation(
        "dart",
        'readonly VERIFIER_VM_DOCKER_SOCKET=$VERIFIER_VM_AUTHORITY_ROOT/docker.sock',
        'readonly VERIFIER_VM_DOCKER_SOCKET=/var/run/docker.sock',
        "Dart fixed guest Docker socket",
    ),
    Mutation(
        "dart",
        '[ "$VERIFIER_VM_MARKER_DOCKER" = "docker=$VERIFIER_VM_DOCKER_VERSION" ]',
        '[ -n "$VERIFIER_VM_MARKER_DOCKER" ]',
        "Dart guest Docker version pin",
    ),
    Mutation("dart", 'IMAGE_ID="$DEB_BUILDER_IMAGE_ID"', 'IMAGE_ID=rd-fluttercheck', "mutable Dart image"),
    Mutation(
        "dart",
        '[ "$(/usr/bin/stat -c \'%u:%g:%a\' "$WORKSPACE")" = "$BUILD_UID:$BUILD_GID:700" ]',
        '[ -d "$WORKSPACE" ]',
        "private workspace identity",
    ),
    Mutation(
        "dart",
        'verifier_vm_docker() {\n  local status=0\n  /usr/bin/bash "$VERIFIER_VM_ENTRY_PREFLIGHT" >/dev/null || return 1',
        'verifier_vm_docker() {\n  local status=0\n  true # Docker pre-operation authority replay disabled',
        "Dart Docker pre-operation authority replay",
    ),
    Mutation(
        "dart",
        '--config "$VERIFIER_VM_DOCKER_CONFIG" "$@" || status=$?\n  /usr/bin/bash "$VERIFIER_VM_ENTRY_PREFLIGHT" >/dev/null || return 1',
        '--config "$VERIFIER_VM_DOCKER_CONFIG" "$@" || status=$?\n  true # Docker post-operation authority replay disabled',
        "Dart Docker post-operation authority replay",
    ),
    Mutation(
        "dart",
        'verifier_vm_docker() {\n  local status=0\n  /usr/bin/bash "$VERIFIER_VM_ENTRY_PREFLIGHT" >/dev/null || return 1\n  /usr/bin/env -i',
        'verifier_vm_docker() {\n  local status=0\n  /usr/bin/bash "$VERIFIER_VM_ENTRY_PREFLIGHT" >/dev/null || return 1\n  /usr/bin/env',
        "Dart Docker empty environment",
    ),
    Mutation(
        "dart",
        'verifier_vm_image_provenance() {\n  local status=0\n  /usr/bin/bash "$VERIFIER_VM_ENTRY_PREFLIGHT" >/dev/null || return 1',
        'verifier_vm_image_provenance() {\n  local status=0\n  true # provenance pre-operation authority replay disabled',
        "Dart provenance pre-operation authority replay",
    ),
    Mutation(
        "dart",
        'verifier_vm_image_provenance() {\n  local status=0\n  /usr/bin/bash "$VERIFIER_VM_ENTRY_PREFLIGHT" >/dev/null || return 1\n  /usr/bin/env -i',
        'verifier_vm_image_provenance() {\n  local status=0\n  /usr/bin/bash "$VERIFIER_VM_ENTRY_PREFLIGHT" >/dev/null || return 1\n  /usr/bin/env',
        "Dart provenance empty environment",
    ),
    Mutation(
        "dart",
        '    || status=$?\n  /usr/bin/bash "$VERIFIER_VM_ENTRY_PREFLIGHT" >/dev/null || return 1\n  return "$status"\n}\n\nVERIFY_VM_AUTHORITY_SELF_TEST=',
        '    || status=$?\n  true # provenance post-operation authority replay disabled\n  return "$status"\n}\n\nVERIFY_VM_AUTHORITY_SELF_TEST=',
        "Dart provenance post-operation authority replay",
    ),
    Mutation(
        "dart",
        '/usr/bin/python3 -I -S "$SCRIPT_DIR/offline-image-provenance.py" "$@"',
        'python3 "$SCRIPT_DIR/offline-image-provenance.py" "$@"',
        "Dart provenance fixed interpreter",
    ),
    Mutation(
        "dart",
        'verifier_vm_image_provenance verify-local',
        'true # image provenance disabled',
        "Dart image provenance",
    ),
    Mutation(
        "dart",
        '/usr/bin/bash "$SCRIPT_DIR/frb-codegen.sh" --self-test-vm-authority',
        'true # nested FRB authority chain disabled',
        "Dart nested FRB verifier-VM authority",
    ),
    Mutation(
        "dart",
        "verifier_vm_docker run --rm",
        "docker run --rm",
        "Dart verifier-VM Docker launcher",
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
        "flutter test --no-pub test/file_command_session_ownership_test.dart",
        "true # file-command session ownership test disabled",
        "file-command session ownership regression",
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
        'flutter analyze --no-pub --no-fatal-infos --no-fatal-warnings \\\n'
        '      third_party/texture_rgba_renderer/lib/',
        "true # in-tree native RGBA Dart wrapper analysis disabled",
        "in-tree native RGBA Dart wrapper analysis",
    ),
    Mutation(
        "dart",
        'flutter analyze --no-pub --no-fatal-infos --no-fatal-warnings \\\n'
        '      third_party/desktop_multi_window/lib/',
        "true # vendored desktop multi-window Dart analysis disabled",
        "vendored desktop multi-window Dart analysis",
    ),
    Mutation(
        "dart",
        'flutter analyze --no-pub --no-fatal-infos --no-fatal-warnings \\\n'
        '      third_party/window_manager/lib/',
        "true # vendored window-manager Dart analysis disabled",
        "vendored window-manager Dart analysis",
    ),
    Mutation(
        "dart",
        "grep -qF 'path: third_party/desktop_multi_window' flutter/pubspec.yaml",
        "true # vendored dependency source gate disabled",
        "vendored desktop multi-window dependency source gate",
    ),
    Mutation(
        "dart",
        "grep -qF 'third_party/desktop_multi_window/** -text' flutter/.gitattributes",
        "true # vendored byte-preservation gate disabled",
        "vendored desktop multi-window byte-preservation gate",
    ),
    Mutation(
        "dart",
        "grep -qF 'response before scheduling the idle erase' \"$multi_window/UPSTREAM.md\"",
        "true # native/Dart teardown deviation record accepted absent",
        "vendored native/Dart teardown deviation record",
    ),
    Mutation(
        "dart",
        "grep -qF 'using CompletionHandler = std::function<void()>;'",
        "true # native response completion contract accepted absent",
        "native Dart-response completion contract",
    ),
    Mutation(
        "dart",
        "grep -qF 'gulong releasedEmissionHook = 0;' \"$multi_window/linux/flutter_window.h\"",
        "true # release-hook ownership accepted absent",
        "native release-hook ownership",
    ),
    Mutation(
        "dart",
        "'fl_method_channel_invoke_method_finish(data->channel, res, &error);'",
        "'response completion omitted'",
        "native Dart-response finality",
    ),
    Mutation(
        "dart",
        "if grep -qF 'InvokeMethodSelfVoid(\"onDestroy\"'",
        "if false; then # fire-and-forget engine teardown accepted",
        "fire-and-forget native teardown refusal",
    ),
    Mutation(
        "dart",
        "'gboolean destroyWindowWhenIdle(gpointer data)'",
        "'gboolean destroyWindowSynchronously(gpointer data)'",
        "deferred native destruction source gate",
    ),
    Mutation(
        "dart",
        "if grep -qF 'return self->isPreventClose;'",
        "if false; then # post-destruction owner read accepted",
        "post-destruction owner-read refusal",
    ),
    Mutation(
        "dart",
        '\n    /tmp/url_launcher_shutdown_test\n',
        '\n    true # URL-launcher shutdown test disabled\n',
        "URL-launcher native shutdown behavior gate",
    ),
    Mutation(
        "dart",
        "grep -qF 'third_party/url_launcher_linux/** -text' flutter/.gitattributes",
        "true # URL-launcher byte-preservation gate disabled",
        "vendored URL-launcher byte preservation",
    ),
    Mutation(
        "dart",
        "grep -qF 'path: third_party/url_launcher_linux' flutter/pubspec.yaml",
        "true # URL-launcher path override accepted absent",
        "vendored URL-launcher dependency source gate",
    ),
    Mutation(
        "dart",
        "if grep -qF 'ful_url_launcher_api_clear_method_handlers('",
        "if false; then # recursive URL handler clear accepted",
        "recursive URL handler clear refusal",
    ),
    Mutation(
        "dart",
        "'messenger->handler_sets_during_shutdown == 2'",
        "'messenger->handler_sets_during_shutdown == 6'",
        "URL-launcher shutdown registration regression",
    ),
    Mutation(
        "dart",
        '"$upstream_url_launcher/url_launcher_plugin.cc" | sha256sum -c -',
        '"$upstream_url_launcher/url_launcher_plugin.cc" | true',
        "exact stock URL-launcher source authentication",
    ),
    Mutation(
        "dart",
        '    [ "$upstream_status" -eq 1 ] \\\n'
        '      || { echo "  FAIL URL launcher: exact stock disposal unexpectedly passed or crashed"; exit 1; }',
        '    [ "$upstream_status" -eq 0 ] \\\n'
        '      || { echo "  FAIL URL launcher: exact stock disposal unexpectedly passed or crashed"; exit 1; }',
        "exact stock URL-launcher rejection",
    ),
    Mutation(
        "dart",
        '\n    /tmp/window_manager_shutdown_test\n',
        '\n    true # window-manager shutdown test disabled\n',
        "window-manager native shutdown behavior gate",
    ),
    Mutation(
        "dart",
        '    [ "$guard_disabled_status" -eq 1 ] \\\n'
        '      || { echo "  FAIL window manager: guard-disabled source unexpectedly passed or crashed"; exit 1; }',
        '    [ "$guard_disabled_status" -eq 0 ] \\\n'
        '      || { echo "  FAIL window manager: guard-disabled source unexpectedly passed or crashed"; exit 1; }',
        "window-manager guard-removed negative control",
    ),
    Mutation(
        "dart",
        "grep -qF 'third_party/window_manager/** -text' flutter/.gitattributes",
        "true # window-manager byte-preservation gate disabled",
        "vendored window-manager byte preservation",
    ),
    Mutation(
        "dart",
        "grep -qF 'path: third_party/window_manager' flutter/pubspec.yaml",
        "true # window-manager path override accepted absent",
        "vendored window-manager dependency source gate",
    ),
    Mutation(
        "dart",
        'grep -qxF "!flutter/third_party/window_manager/$asset" .gitignore',
        "true # ignored window-manager assets accepted",
        "vendored window-manager asset inventory",
    ),
    Mutation(
        "dart",
        "70fe0130bbbd928d04cd33a49ecde422ec54fd748b7a4e983f4e31be6e73f5f5  images/ic_chrome_close.png",
        "00fe0130bbbd928d04cd33a49ecde422ec54fd748b7a4e983f4e31be6e73f5f5  images/ic_chrome_close.png",
        "vendored window-manager close asset identity",
    ),
    Mutation(
        "dart",
        "93f2ed012ec01288b78ad4816ef254261e9ff25e8a9858359b45431c9a5de5f4  images/ic_chrome_maximize.png",
        "00f2ed012ec01288b78ad4816ef254261e9ff25e8a9858359b45431c9a5de5f4  images/ic_chrome_maximize.png",
        "vendored window-manager maximize asset identity",
    ),
    Mutation(
        "dart",
        "0976edbb9977136544af17de125f345a41065694de92036d9365817ea6d8f05a  images/ic_chrome_minimize.png",
        "0076edbb9977136544af17de125f345a41065694de92036d9365817ea6d8f05a  images/ic_chrome_minimize.png",
        "vendored window-manager minimize asset identity",
    ),
    Mutation(
        "dart",
        "3d375930c514ec2ebc0603ad1e1398b4daf458951042a97232d16f17e1c9603b  images/ic_chrome_unmaximize.png",
        "00375930c514ec2ebc0603ad1e1398b4daf458951042a97232d16f17e1c9603b  images/ic_chrome_unmaximize.png",
        "vendored window-manager unmaximize asset identity",
    ),
    Mutation(
        "dart",
        "  'g_object_add_weak_pointer(G_OBJECT(weak_plugin), &weak_plugin);' \\\n",
        "  'g_object_add_weak_pointer(G_OBJECT(messenger), &weak_plugin);' \\\n",
        "direct window-manager plugin release witness source gate",
    ),
    Mutation(
        "dart",
        "  '_initialMaximizedTimer?.cancel();' \\\n",
        "  '_initialMaximizedTimer?.isActive;' \\\n",
        "delayed window-manager query cancellation source gate",
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
        '/usr/bin/bash "$VERIFIER_VM_ENTRY_PREFLIGHT"\n# shellcheck source=scripts/lib.sh',
        'true # verifier-VM entry authority disabled\n# shellcheck source=scripts/lib.sh',
        "FRB verifier-VM entry authority",
    ),
    Mutation(
        "frb",
        'verifier_vm_docker() {\n    local status=0\n    /usr/bin/bash "$VERIFIER_VM_ENTRY_PREFLIGHT" >/dev/null || return 1',
        'verifier_vm_docker() {\n    local status=0\n    true # Docker pre-operation authority replay disabled',
        "FRB Docker pre-operation authority replay",
    ),
    Mutation(
        "frb",
        '--config "$VERIFIER_VM_DOCKER_CONFIG" "$@" || status=$?\n    /usr/bin/bash "$VERIFIER_VM_ENTRY_PREFLIGHT" >/dev/null || return 1',
        '--config "$VERIFIER_VM_DOCKER_CONFIG" "$@" || status=$?\n    true # Docker post-operation authority replay disabled',
        "FRB Docker post-operation authority replay",
    ),
    Mutation(
        "frb",
        'verifier_vm_docker() {\n    local status=0\n    /usr/bin/bash "$VERIFIER_VM_ENTRY_PREFLIGHT" >/dev/null || return 1\n    /usr/bin/env -i',
        'verifier_vm_docker() {\n    local status=0\n    /usr/bin/bash "$VERIFIER_VM_ENTRY_PREFLIGHT" >/dev/null || return 1\n    /usr/bin/env',
        "FRB Docker empty environment",
    ),
    Mutation(
        "frb",
        'verifier_vm_image_provenance() {\n    local status=0\n    /usr/bin/bash "$VERIFIER_VM_ENTRY_PREFLIGHT" >/dev/null || return 1',
        'verifier_vm_image_provenance() {\n    local status=0\n    true # provenance pre-operation authority replay disabled',
        "FRB provenance pre-operation authority replay",
    ),
    Mutation(
        "frb",
        '/usr/bin/python3 -I -S "$SCRIPT_DIR/offline-image-provenance.py" "$@"',
        'python3 "$SCRIPT_DIR/offline-image-provenance.py" "$@"',
        "FRB provenance fixed interpreter",
    ),
    Mutation(
        "frb",
        "verifier_vm_docker run --rm",
        "docker run --rm",
        "FRB verifier-VM Docker launcher",
    ),
    Mutation(
        "frb",
        'verifier_vm_image_provenance verify-local',
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
    Mutation("requirements", '<span class="id">R-S11dh</span>', '<span class="id">R-S11dh-broken</span>', "verifier-VM authority requirement"),
)


def load_sources(repo: Path) -> Dict[str, str]:
    paths = {
        "dart": repo / "scripts/dart-verify.sh",
        "frb": repo / "scripts/frb-codegen.sh",
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
