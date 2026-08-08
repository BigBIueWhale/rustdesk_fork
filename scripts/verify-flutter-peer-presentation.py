#!/usr/bin/env python3
"""Verify the isolated full RustDesk Linux peer-presentation evidence contract."""

from __future__ import annotations

import argparse
from pathlib import Path


class VerificationError(RuntimeError):
    pass


def require(source: str, needle: str, label: str) -> None:
    if needle not in source:
        raise VerificationError(f"missing {label}: {needle!r}")


def forbid(source: str, needle: str, label: str) -> None:
    if needle in source:
        raise VerificationError(f"forbidden {label}: {needle!r}")


def require_order(source: str, needles: tuple[str, ...], label: str) -> None:
    position = -1
    for needle in needles:
        position = source.find(needle, position + 1)
        if position < 0:
            raise VerificationError(f"{label}: missing or misordered {needle!r}")


PATHS = {
    "host": "scripts/smoke-flutter-peer-presentation.sh",
    "stage": "scripts/smoke-flutter-peer-presentation-stage.sh",
    "pins": "scripts/pins.env",
    "ready": "scripts/smoke-ready.sh",
    "linux_runner": "flutter/linux/main.cc",
    "controller": "scripts/flutter-peer-presentation-x11.c",
    "source": "scripts/flutter-peer-source-x11.c",
    "bind_shim": "scripts/smoke-bind-loopback.c",
    "flutter_common": "flutter/lib/common.dart",
    "flutter_dialog": "flutter/lib/common/widgets/dialog.dart",
    "password_semantics_test": "flutter/test/password_field_semantics_test.dart",
    "desktop_remote_page": "flutter/lib/desktop/pages/remote_page.dart",
    "desktop_remote_tabs": "flutter/lib/desktop/pages/remote_tab_page.dart",
    "desktop_camera_page": "flutter/lib/desktop/pages/view_camera_page.dart",
    "desktop_camera_tabs": "flutter/lib/desktop/pages/view_camera_tab_page.dart",
    "desktop_tabbar": "flutter/lib/desktop/widgets/tabbar_widget.dart",
    "desktop_tab_retirement_test": "flutter/test/desktop_tab_retirement_test.dart",
    "flutter_attributes": "flutter/.gitattributes",
    "flutter_pubspec": "flutter/pubspec.yaml",
    "flutter_lock": "flutter/pubspec.lock",
    "multi_window_linux": "flutter/third_party/desktop_multi_window/linux/flutter_window.cc",
    "multi_window_header": "flutter/third_party/desktop_multi_window/linux/flutter_window.h",
    "multi_window_channel": "flutter/third_party/desktop_multi_window/linux/window_channel.cc",
    "multi_window_channel_header": "flutter/third_party/desktop_multi_window/linux/window_channel.h",
    "multi_window_upstream": "flutter/third_party/desktop_multi_window/UPSTREAM.md",
    "url_launcher_linux": "flutter/third_party/url_launcher_linux/linux/url_launcher_plugin.cc",
    "url_launcher_test": "flutter/third_party/url_launcher_linux/linux/test/url_launcher_shutdown_test.cc",
    "url_launcher_upstream": "flutter/third_party/url_launcher_linux/UPSTREAM.md",
    "window_manager_linux": "flutter/third_party/window_manager/linux/window_manager_plugin.cc",
    "window_manager_test": "flutter/third_party/window_manager/linux/test/window_manager_shutdown_test.cc",
    "window_manager_upstream": "flutter/third_party/window_manager/UPSTREAM.md",
    "dart_verify": "scripts/dart-verify.sh",
    "verify": "scripts/verify.sh",
    "workspace": "scripts/verify-verifier-workspace.py",
    "requirements": "requirements.html",
    "hardening": "HARDENING_STATUS.md",
    "readme": "scripts/README.md",
}


def load(repo: Path) -> dict[str, str]:
    return {
        key: (repo / relative).read_text(encoding="utf-8")
        for key, relative in PATHS.items()
    }


def validate(sources: dict[str, str]) -> None:
    host = sources["host"]
    stage = sources["stage"]
    pins = sources["pins"]
    ready = sources["ready"]
    linux_runner = sources["linux_runner"]
    controller = sources["controller"]
    source = sources["source"]
    bind_shim = sources["bind_shim"]
    flutter_common = sources["flutter_common"]
    flutter_dialog = sources["flutter_dialog"]
    password_semantics_test = sources["password_semantics_test"]
    desktop_remote_page = sources["desktop_remote_page"]
    desktop_remote_tabs = sources["desktop_remote_tabs"]
    desktop_camera_page = sources["desktop_camera_page"]
    desktop_camera_tabs = sources["desktop_camera_tabs"]
    desktop_tabbar = sources["desktop_tabbar"]
    desktop_tab_retirement_test = sources["desktop_tab_retirement_test"]
    flutter_attributes = sources["flutter_attributes"]
    flutter_pubspec = sources["flutter_pubspec"]
    flutter_lock = sources["flutter_lock"]
    multi_window_linux = sources["multi_window_linux"]
    multi_window_header = sources["multi_window_header"]
    multi_window_channel = sources["multi_window_channel"]
    multi_window_channel_header = sources["multi_window_channel_header"]
    multi_window_upstream = sources["multi_window_upstream"]
    url_launcher_linux = sources["url_launcher_linux"]
    url_launcher_test = sources["url_launcher_test"]
    url_launcher_upstream = sources["url_launcher_upstream"]
    window_manager_linux = sources["window_manager_linux"]
    window_manager_test = sources["window_manager_test"]
    window_manager_upstream = sources["window_manager_upstream"]
    dart_verify = sources["dart_verify"]

    require(
        flutter_attributes,
        "third_party/desktop_multi_window/** -text",
        "vendored desktop multi-window byte preservation",
    )
    require_order(
        host,
        (
            "assert_clean_worktree",
            'readonly SOURCE_COMMIT="$(git rev-parse HEAD)"',
            "git archive --format=tar",
            'run_input_check "$WORKSPACE/input-pre.cid"',
            "smoke-xvfb-prepare.sh",
            "smoke-flutter-peer-presentation-stage.sh pub-cache",
            "smoke-flutter-peer-presentation-stage.sh build",
            "smoke-flutter-peer-presentation-stage.sh pub-cache-check",
            'local_docker run --detach --cidfile "$SERVER_CID_FILE"',
            "--pull=never --network=none --read-only",
            'inspect_container_contract "$SERVER_CID" none server',
            '--network="container:$SERVER_CID" --read-only',
            'inspect_container_contract "$VIEWER_CID" "container:$SERVER_CID" viewer',
            'run_input_check "$WORKSPACE/input-post.cid"',
            "FLUTTER_PEER_PRESENTATION_SMOKE_OK",
        ),
        "exact-source build and separate-peer transaction",
    )
    if host.count("--network=bridge") != 1:
        raise VerificationError("the exact Xvfb producer must be the sole bridge-network container")
    if host.count("--network=none") != 5:
        raise VerificationError(
            "only the reusable input check, Pub-cache copy/check, build, and controlled-peer anchor use network-none"
        )
    if host.count('run_input_check "$WORKSPACE/input-') != 2:
        raise VerificationError("persistent build inputs must be checked before and after the transaction")
    require(host, "dbus-run-session --", "private viewer accessibility session")
    if host.count("dbus-run-session --") != 1:
        raise VerificationError("the private accessibility session must be viewer-only")
    require(host, 'readonly VIEWER_PASSWD="$WORKSPACE/viewer.passwd"', "private passwd witness")
    require(
        host,
        'readonly VIEWER_PASSWD_ENTRY="rustdesk-evidence:x:$HOST_UID:$HOST_GID:RustDesk peer evidence:/tmp/viewer-home:/usr/sbin/nologin"',
        "exact numeric-nonroot passwd identity",
    )
    require(host, 'chmod 0400 "$VIEWER_PASSWD.tmp"', "private passwd witness mode")
    require(
        host,
        'source=$VIEWER_PASSWD,target=/etc/passwd,readonly,bind-recursive=disabled',
        "read-only viewer passwd mount",
    )
    if host.count("target=/etc/passwd") != 1:
        raise VerificationError("only the viewer may receive the passwd witness")
    require_order(
        host,
        (
            'readonly VIEWER_CID_FILE="$WORKSPACE/viewer.cid"',
            'local_docker run --cidfile "$VIEWER_CID_FILE"',
            'source=$VIEWER_PASSWD,target=/etc/passwd,readonly,bind-recursive=disabled',
            "dbus-run-session --",
        ),
        "viewer-only passwd identity mount",
    )
    require(
        host,
        'if [ "$destination" = /etc/passwd ]; then',
        "inspected passwd mount destination",
    )
    require(host, '[ "$writable" = false ]', "inspected read-only passwd mount")
    require(host, "private viewer passwd witness changed during runtime", "passwd witness finality")
    require(
        host,
        'readonly EVIDENCE_PUB_CACHE="$ONLINE_DIR/pub-cache"',
        "canonical current-lock Pub-cache input",
    )
    require(
        host,
        'readonly EVIDENCE_PUB_CACHE_SHA256="$SHA256_FLUTTER_PEER_PUB_CACHE_CLOSURE_V1"',
        "canonical current-lock Pub-cache digest",
    )
    require(
        host,
        '"$HOST_UID:$HOST_GID:500"',
        "sealed canonical Pub-cache metadata",
    )
    require(
        host,
        'source=$EVIDENCE_PUB_CACHE,target=/evidence-pub-cache,readonly',
        "read-only canonical Pub-cache mount",
    )
    require(host, '[ "$network" = "$expected_network" ]', "inspected network mode")
    require_order(
        host,
        (
            "local cid=$1 expected_network=$2 label=$3",
            "local expected_passwd_source= mounts_path source destination writable extra",
            "local network ipc pid uts privileged read_only user ports devices caps security",
            "local passwd_mounts=0",
            "network=\"$(local_docker container inspect --format '{{.HostConfig.NetworkMode}}' \"$cid\")\"",
            'mounts_path="$WORKSPACE/$label.mounts.tsv"',
        ),
        "nounset-safe inspected-container receipt path",
    )
    require(host, '{ [ -z "$ipc" ] || [ "$ipc" = private ]; }', "private IPC namespace")
    require(host, '[ -z "$pid" ] && [ -z "$uts" ]', "private PID and UTS namespaces")
    require(host, "[ \"$ports\" = null ] || [ \"$ports\" = '{}' ]", "no port publication")
    require(host, "[ \"$caps\" = '[\"ALL\"]' ]", "all capabilities dropped")
    require(host, '[ "$user" = "$HOST_UID:$HOST_GID" ]', "numeric non-root user")
    require(host, '[ "$privileged" = false ] && [ "$read_only" = true ]', "read-only unprivileged rootfs")
    require(host, "'[\"no-new-privileges\"]'|'[\"no-new-privileges:true\"]'", "exact no-new-privileges")
    require(host, "[[ \"$source\" != */docker.sock ]] && [[ \"$source\" != /dev/* ]]", "unsafe mount rejection")
    require(host, 'require_exact_local_image deb-builder "$DEB_BUILDER_IMAGE_ID"', "exact builder image ID")
    require(host, 'require_exact_local_image devcheck "$DEV_CHECK_IMAGE_ID"', "exact verifier image ID")
    if host.count('source=$ONLINE_DIR,target=/online,readonly') != 1:
        raise VerificationError("only the persistent-input verifier may mount the complete online root")
    require(
        host,
        'source=$BUILD_INPUT_ROOT,target=/online,readonly,bind-recursive=disabled',
        "empty build-input namespace root",
    )
    for relative in (
        "rust-${RUST_VERSION}.tar.xz",
        "flutter-${FLUTTER_VERSION}.tar.xz",
        "llvm-${LLVM_VERSION}.tar.xz",
        "cargo-vendor",
        "cargo-vendor-config.toml",
        "frb-tool/bin/flutter_rust_bridge_codegen",
        "vcpkg/installed/x64-linux",
    ):
        require(
            host,
            f"source=$ONLINE_DIR/{relative},target=/online/{relative},readonly,bind-recursive=disabled",
            f"exact build-input mount {relative}",
        )
    forbid(host, "require_online_complete", "unrelated full-online closure gate")
    forbid(host, "local_docker_image_provenance", "host Python image verifier")
    forbid(host, "/usr/bin/python3", "host Python execution")
    require(host, "assert_clean_worktree", "clean postcondition")
    require(host, "source archive changed during the probe", "exact source postcondition")
    for unsafe in (
        "sudo ",
        "--privileged",
        "--publish",
        "--network=host",
        "/var/run/docker.sock",
        "systemctl",
        "ufw ",
        "iptables",
        "nft ",
        "/dev/kvm",
    ):
        forbid(host, unsafe, "host authority expansion")

    require_order(
        stage,
        (
            "input-check)",
            'verify_archive "/online/rust-',
            'verify_archive "/online/flutter-',
            'verify_archive "/online/llvm-',
            "/source/scripts/online-input-provenance.py verify-subtree",
            '--tree /online/cargo-vendor --expected "$RUSTDESK_CARGO_VENDOR_SHA256"',
            "/source/scripts/online-cargo-tool-output.py check-complete",
            '"$(sha256sum /online/frb-tool/bin/flutter_rust_bridge_codegen | awk \'{print $1}\')" = \\\n      "$RUSTDESK_FRB_SHA256"',
            '--tree /online/vcpkg/installed/x64-linux',
            "FLUTTER_PEER_INPUTS_OK",
        ),
        "exact consumed-input pre/post validation",
    )
    for pin_name, pin_value in (
        (
            "SHA256_FLUTTER_PEER_PUB_CACHE_CLOSURE_V1",
            "fe81f679a0a1acd8291472162e867a566f33a50c813d27775125cee4644736b4",
        ),
        (
            "SHA256_FLUTTER_PEER_VCPKG_X64_LINUX_CLOSURE_V1",
            "24a2295145b04938abed637daac104252c4374a119db19749451a8fc69858436",
        ),
        (
            "SHA256_FLUTTER_PEER_FRB_CODEGEN",
            "24508d54dcad4f6b5c5b70395d24437a563d64fc2c24a17ca7e25f24ddb418fa",
        ),
        ("SIZE_FLUTTER_PEER_FRB_CODEGEN", "17211448"),
    ):
        require(pins, f'{pin_name}="{pin_value}"', f"exact R-S11gc input pin {pin_name}")
    require(
        pins,
        "This does not repin SHA256_ONLINE_CLOSURE_V1.",
        "full-online closure non-inference",
    )

    require_order(
        stage,
        (
            "FLUTTER_PEER_CANONICAL_PUB_CACHE_OK",
            "cp -a /evidence-pub-cache /evidence-online/pub-cache",
            "check-complete --online /evidence-online",
            "FLUTTER_PEER_PUB_CACHE_PREPARED",
        ),
        "canonical Pub-cache immutable copy and verification",
    )
    require(stage, "published=True", "published canonical Pub-cache inspection")
    require(
        stage,
        "printf 'sha256=%s source=canonical-pinned-online-copy semantics=current-three-git-lock\\n'",
        "canonical Pub-cache copy provenance",
    )
    require_order(
        stage,
        (
            'verify_archive "/online/rust-',
            'verify_archive "/online/flutter-',
            'verify_archive "/online/llvm-',
            "dart pub get --offline --enforce-lockfile",
            '"$REAL_FLUTTER" pub get --offline --enforce-lockfile',
            "flutter_rust_bridge_codegen",
            "! grep -Fq '[SEVERE]'",
            "cargo build --locked --features flutter,unix-file-copy-paste",
            "--lib --example smoke_readiness --release",
            '"$REAL_FLUTTER" build linux --release --no-pub',
            "readelf --wide --dyn-syms",
            '"$BUILD_SOURCE/scripts/smoke-bind-loopback.c"',
            "-Wl,-z,relro,-z,now,-z,noexecstack",
            "FLUTTER_PEER_BUILD_OK",
        ),
        "exact offline full-product bundle build",
    )
    require(stage, "cp -a /source/. \"$BUILD_SOURCE/\"", "private writable build copy")
    require(
        stage,
        'cp "$BUILD_SOURCE/target/release/examples/smoke_readiness" /out/smoke-readiness',
        "typed main-IPC readiness probe artifact",
    )
    require(stage, "readonly PROBE=/out/smoke-readiness", "runtime readiness probe binding")
    require(stage, "export HOME CARGO_HOME CI=true PUB_CACHE=/evidence-online/pub-cache", "current-lock sealed Pub cache")
    require(stage, '[ -z "${LD_PRELOAD:-}" ]', "ambient preload refusal")
    require(stage, "assert_loopback_only_interface", "runtime loopback-only inspection")
    require(stage, '[ "$interfaces" = lo ]', "sole loopback interface")
    require(stage, '0100007F:527E', "exact 127.0.0.1:21118 listener")
    require(stage, "verify_regular /out/smoke-bind-loopback.so", "manifested bind shim")
    require(
        stage,
        "sha256sum build.identity smoke-bind-loopback.so smoke-readiness",
        "bind shim manifest entry",
    )
    require(stage, '[ "$(udp_socket_count)" -eq 0 ]', "zero UDP runtime surface")
    require(
        stage,
        "pkg-config --cflags --libs x11 xtst atspi-2 gobject-2.0",
        "direct AT-SPI and GObject controller link",
    )
    require(
        stage,
        '[ -n "${DBUS_SESSION_BUS_ADDRESS:-}" ]',
        "private accessibility-session address",
    )
    require(
        stage,
        '[ "$(getent passwd "$(id -u)")" = "$EXPECTED_PASSWD_ENTRY" ]',
        "resolved numeric viewer identity",
    )
    require(
        stage,
        "FLUTTER_PEER_PASSWORD_PROMPT_OK accessible=true retired=true typed_via_xtest=true",
        "accessible password-prompt verdict",
    )
    require_order(
        stage,
        (
            "export DISPLAY=:98 HOME=/tmp/server-home",
            "start_xvfb :98 640x480x24",
            '"$SOURCE_FIXTURE" >/tmp/source.log',
            'LD_PRELOAD="$BIND_SHIM" RUST_LOG=info exec "$APP" --server',
            'wait_process_maps_exact_file "$SERVER_PID" "$SERVER_START" "$BIND_SHIM"',
            '"$READY" --wait-typed-parked "$SERVER_PID" "$SERVER_START"',
            "--password-stdin",
            '"$READY" --wait-typed-user-server "$SERVER_PID" "$SERVER_START"',
            "listener_is_exact",
            'mv "$COORD/server.ready.tmp" "$COORD/server.ready"',
            'mv "$COORD/server.result.tmp" "$COORD/server.result"',
        ),
        "controlled-peer credential, listener, and finality",
    )
    require_order(
        stage,
        (
            "export DISPLAY=:99 HOME=/tmp/viewer-home",
            "start_xvfb :99 1280x800x24",
            '(cd /out/bundle && RUST_LOG=info exec "$APP" --connect 127.0.0.1)',
            '"$CONTROLLER" :98 :99 "$VIEWER_PID"',
            "stable_connection=true",
            "viewer did not retire after its real remote window closed",
            'mv "$COORD/stop.tmp" "$COORD/stop"',
            "FLUTTER_PEER_VIEWER_RUNTIME_OK",
        ),
        "viewer prompt/pixel/lifecycle transaction",
    )
    require_order(
        stage,
        (
            'if [ "$(<"$COORD/stop")" != viewer-complete ]; then',
            "FLUTTER_PEER_SERVER_DIAGNOSTIC_BEGIN",
            "cat /tmp/server.log >&2",
            'emit_runtime_logs SERVER "$HOME/.local/share/logs"',
            "FLUTTER_PEER_SERVER_DIAGNOSTIC_END",
        ),
        "failed-viewer server diagnostic",
    )
    require_order(
        stage,
        (
            "emit_runtime_logs() {",
            "runtime-log diagnostic selected a non-regular file",
            "runtime-log diagnostic file metadata differs",
            "runtime-log diagnostic exceeds its exact bounds",
            "cat -- \"$path\" >&2",
        ),
        "bounded owned runtime-file diagnostics",
    )
    require(
        stage,
        'emit_runtime_logs VIEWER "$HOME/.local/share/logs"',
        "failed-viewer file diagnostics",
    )
    forbid(stage, '"$APP" --connect 127.0.0.1 --password', "connect password argv")
    forbid(stage, "RUSTDESK_PASSWORD", "password environment variable")
    forbid(stage, "export LD_PRELOAD", "process-wide preload export")
    if stage.count('LD_PRELOAD="$BIND_SHIM"') != 1:
        raise VerificationError("the bind shim must be scoped to the controlled server launch")
    for unsafe in ("sudo ", "--privileged", "systemctl", "ufw ", "iptables", "nft "):
        forbid(stage, unsafe, "runtime authority expansion")

    for function, expected_state in (
        ("server_typed_parked() {", "parked"),
        ("server_typed_ready() {", '"$expected"'),
    ):
        require(ready, function, "typed release-runner readiness predicate")
        body = ready.split(function, 1)[1].split("\n}", 1)[0]
        require(body, 'ipc_surface_ready "$pid" "$uid"', "owned dual-IPC surface proof")
        require(body, f"typed_ipc_ready \"$probe\" {expected_state}", "typed IPC state proof")
        require(body, '"$(udp_socket_count)" = 0', "typed readiness zero-UDP proof")
        forbid(body, "grep ", "release-runner text-log dependency")
    require(ready, "--wait-typed-parked)", "typed parked CLI mode")
    require(ready, "--wait-typed-user-server)", "typed listening CLI mode")

    require_order(
        linux_runner,
        (
            "bool flutter_rustdesk_core_main(bool* should_start_ui)",
            "*should_start_ui = core_main();",
            "bool should_start_ui = false;",
            "if (!flutter_rustdesk_core_main(&should_start_ui))",
            "return EXIT_FAILURE;",
            "if (!should_start_ui)",
            "return EXIT_SUCCESS;",
            "g_application_run",
        ),
        "Linux runner load/handled-command/UI decision contract",
    )
    forbid(
        linux_runner,
        "if (!flutter_rustdesk_core_main())",
        "handled core command classified as loader failure",
    )

    require(source, "The two independently colored halves encode one of 256", "source-state contract")
    require(source, "frame = (frame + 1U) & 255U;", "256-state source cadence")
    require(source, "attributes.override_redirect = True;", "source fixture isolation")
    require(source, "sigaction(SIGTERM", "source fixture teardown")

    require_order(
        bind_shim,
        (
            "addr->sa_family == AF_INET",
            "rewritten.sin_addr.s_addr == htonl(INADDR_ANY)",
            "ntohs(rewritten.sin_port) == 21118",
            "rewritten.sin_addr.s_addr = htonl(INADDR_LOOPBACK)",
            "return fn(sockfd, (const struct sockaddr *)&rewritten, sizeof(rewritten));",
            "return fn(sockfd, addr, addrlen);",
        ),
        "narrow loopback bind rewrite and exact passthrough",
    )
    if bind_shim.count("21118") != 1:
        raise VerificationError("the bind shim port match is not singular")

    require(controller, 'strstr(title, "127.0.0.1 - Remote Desktop")', "exact real viewer title")
    require(controller, "pid != expected_pid", "viewer process identity")
    if controller.count("pid != expected_pid") != 2:
        raise VerificationError("X11 and AT-SPI process-identity checks must both be exact")
    require(
        controller,
        'strcmp(hint.res_name, "rustdesk") != 0',
        "exact RustDesk X11 instance identity",
    )
    require(
        controller,
        'strcmp(hint.res_class, "Rustdesk") != 0',
        "exact GTK-derived RustDesk X11 class identity",
    )
    require(controller, "XTestFakeKeyEvent", "real X11 password input")
    if controller.count("XTestFakeKeyEvent") != 2:
        raise VerificationError("XTest key press/release calls are not exact")
    require(controller, 'static const char password[] = "rustdesk-peer-9f2a7c4e";', "test credential")
    require(controller, "atspi_init() != 0", "private AT-SPI initialization")
    require(controller, "atspi_get_desktop_count() != 1", "single private accessibility desktop")
    require(controller, "pid != expected_pid", "accessible process identity")
    require(controller, "role == ATSPI_ROLE_PASSWORD_TEXT", "password-field accessible role")
    if controller.count("role == ATSPI_ROLE_PASSWORD_TEXT") != 2:
        raise VerificationError("password-role accounting and readiness checks must both be exact")
    for state in (
        "ATSPI_STATE_EDITABLE",
        "ATSPI_STATE_ENABLED",
        "ATSPI_STATE_SENSITIVE",
        "ATSPI_STATE_VISIBLE",
        "ATSPI_STATE_FOCUSED",
        "ATSPI_STATE_FOCUSABLE",
    ):
        require(controller, state, f"password accessible {state}")
    forbid(
        controller,
        "ATSPI_STATE_SHOWING",
        "impossible Flutter obscured-password showing state",
    )
    require(
        controller,
        "scan.password_nodes == 1U && scan.visible_passwords == 1U",
        "singular ready password accessible",
    )
    require(controller, "scan.password_nodes == 0U", "exact password-node retirement")
    require(controller, "ACCESSIBLE_NAME_LIMIT 96U", "bounded accessible-name diagnostic")
    require(
        controller,
        "strnlen(name, ACCESSIBLE_NAME_LIMIT + 1U)",
        "bounded accessible-name read",
    )
    require(controller, "if (emit_diagnostic != 0)", "failure-only accessibility diagnostic")
    require(
        controller,
        '"FLUTTER_PEER_ATSPI_NODE depth=%u role=%d "',
        "sanitized accessibility-tree diagnostic",
    )
    require(
        controller,
        "scan_password_prompt((unsigned int)viewer_pid, &diagnostic_scan, 1)",
        "exact same-PID failure rescan",
    )
    require(
        controller,
        "memset(last_scan, 0, sizeof(*last_scan));",
        "initialized prompt failure diagnostics",
    )
    require(controller, "g_free(name);", "accessible-name diagnostic release")
    forbid(controller, "atspi_accessible_get_text", "accessible text/value disclosure")
    if controller.count("scan_password_prompt(expected_pid, &scan, 0)") != 2:
        raise VerificationError("normal prompt scans must not emit accessibility diagnostics")
    forbid(
        flutter_common,
        "WorkaroundFreezeLinuxMint",
        "global Linux semantics-exclusion abstraction",
    )
    forbid(
        flutter_dialog,
        "workaroundFreezeLinuxMint",
        "connect-password descendant-semantics exclusion",
    )
    require(
        flutter_dialog,
        "obscureText: !_passwordVisible,",
        "connect-password default obscured state",
    )
    require(
        flutter_dialog,
        "obscureText: obscureText,",
        "dialog password-state forwarding",
    )
    require(
        flutter_dialog,
        "focusable: true,",
        "dialog text-field focusability export",
    )
    for flag in (
        "isTextField",
        "isObscured",
        "hasEnabledState",
        "isEnabled",
        "isFocusable",
        "isFocused",
    ):
        require(
            password_semantics_test,
            f"{flag}: true",
            f"password semantics regression {flag}",
        )
    require(
        password_semantics_test,
        "semanticsEnabled: true",
        "password regression semantics enablement",
    )
    require(
        dart_verify,
        "flutter test --no-pub test/password_field_semantics_test.dart",
        "offline password semantics behavior gate",
    )
    require(
        dart_verify,
        "if grep -RInF --include='*.dart' 'workaroundFreezeLinuxMint' flutter/lib",
        "authored-Dart global semantics-exclusion absence gate",
    )
    for page, label in (
        (desktop_remote_page, "remote desktop"),
        (desktop_camera_page, "view camera"),
    ):
        require(
            page,
            "Future<void> prepareForRemoval({bool closeSession = true})",
            f"{label} explicit cleanup boundary",
        )
        require_order(
            page,
            (
                "final textureDisposal = _ffi.textureModel.dispose();",
                "await _awaitCleanup('texture retirement', textureDisposal);",
                "'session retirement', _ffi.close(closeSession: closeSession)",
                "void dispose() {",
                "super.dispose();",
            ),
            f"{label} engine-backed cleanup before synchronous State disposal",
        )
        forbid(page, "Future<void> dispose() async", f"{label} asynchronous State.dispose")
    require_order(
        desktop_tabbar,
        (
            "await onBeforeRemove?.call(tab, closeSession);",
            "final currentIndex =",
            "state.value.tabs.indexWhere((item) => identical(item, tab));",
            "remove(currentIndex);",
        ),
        "exact individual tab retirement before removal",
    )
    require_order(
        desktop_tabbar,
        (
            "Future<void> closeAll({bool closeSession = true}) async {",
            "while (state.value.tabs.isNotEmpty) {",
            "await Future.wait<void>(",
            "state.value.tabs.removeWhere(closingTabs.contains);",
        ),
        "all-tab retirement before clearing",
    )
    require(
        desktop_tabbar,
        "await controller.closeAll();",
        "native window-close retirement boundary",
    )
    for tabs, page_type, label in (
        (desktop_remote_tabs, "RemotePage", "remote desktop tabs"),
        (desktop_camera_tabs, "ViewCameraPage", "view-camera tabs"),
    ):
        require(
            tabs,
            "tabController.onBeforeRemove = _prepareTabForRemoval;",
            f"{label} cleanup binding",
        )
        require(
            tabs,
            f"if (page is {page_type}) {{",
            f"{label} exact page type",
        )
        require(
            tabs,
            "await page.prepareForRemoval(closeSession: closeSession);",
            f"{label} awaited page cleanup",
        )
        require(
            tabs,
            "await tabController.closeBy(id, closeSession: false);",
            f"{label} transfer without native session close",
        )
        forbid(tabs, "tabController.clear();", f"{label} synchronous clear bypass")
    for name in (
        "tab removal waits for exact resource retirement",
        "window close retires every snapshotted tab before clearing",
        "delayed close cannot remove a replacement with the same key",
    ):
        require(
            desktop_tab_retirement_test,
            f"testWidgets('{name}'",
            f"desktop tab regression {name}",
        )
    require(
        desktop_tab_retirement_test,
        "await retirement.future;",
        "individual tab retirement barrier",
    )
    require(
        desktop_tab_retirement_test,
        "expect(started, unorderedEquals(['first', 'second', 'late']));",
        "late-arriving window tab retirement",
    )
    if desktop_tab_retirement_test.count("expect(controller.length, 2);") != 1:
        raise VerificationError(
            "window retirement regression must retain its initial pre-clear length check"
        )
    require(
        dart_verify,
        "flutter test --no-pub test/desktop_tab_retirement_test.dart",
        "offline desktop tab retirement behavior gate",
    )
    require_order(
        flutter_pubspec,
        (
            "desktop_multi_window:",
            "path: third_party/desktop_multi_window",
        ),
        "vendored desktop multi-window dependency",
    )
    forbid(
        flutter_pubspec,
        "https://github.com/rustdesk-org/rustdesk_desktop_multi_window",
        "ambient desktop multi-window Git dependency",
    )
    require_order(
        flutter_lock,
        (
            "desktop_multi_window:",
            'path: "third_party/desktop_multi_window"',
            "relative: true",
            "source: path",
            'version: "0.1.0"',
        ),
        "locked vendored desktop multi-window dependency",
    )
    require(
        multi_window_upstream,
        "b47e8385e5a75d38319ad706a64b0ead3108b093",
        "vendored desktop multi-window provenance",
    )
    require(
        multi_window_upstream,
        "waits for the method\nresponse before scheduling the idle erase",
        "vendored native/Dart teardown handshake record",
    )
    require(
        multi_window_header,
        "bool destroy_pending_ = false;",
        "idempotent native subwindow destruction state",
    )
    require(
        multi_window_header,
        "gulong releasedEmissionHook = 0;",
        "owned native button-release emission hook",
    )
    require(
        multi_window_channel_header,
        "using CompletionHandler = std::function<void()>;",
        "native Dart-response completion contract",
    )
    require_order(
        multi_window_channel,
        (
            "struct SelfMethodInvokeAsyncUserData",
            "fl_method_channel_invoke_method_finish(data->channel, res, &error);",
            "auto completion = std::move(data->completion);",
            "delete data;",
            "completion();",
        ),
        "native method-response ownership and completion",
    )
    if multi_window_channel.count(
        "fl_method_channel_invoke_method_finish(data->channel, res, &error);"
    ) != 2:
        raise VerificationError(
            "both forwarded and self method calls must finish their exact response"
        )
    require_order(
        multi_window_linux,
        (
            "gboolean destroyWindowWhenIdle(gpointer data)",
            "pending->callback->OnWindowDestroy(pending->id);",
            "if (!self->isPreventClose)",
            "if (self->destroy_pending_)",
            "self->destroy_pending_ = true;",
            "callback->OnWindowClose(id);",
            'channel->InvokeMethodSelf("onDestroy", args, [callback, id]() {',
            "g_idle_add_full(",
            "destroyWindowWhenIdle,",
            "new PendingWindowDestroy{callback, id}",
            "return TRUE;",
        ),
        "Dart cleanup response and native callback return before owning-map retirement",
    )
    require_order(
        multi_window_linux,
        (
            "this->pressedEmissionHook = g_signal_add_emission_hook(",
            "this->releasedEmissionHook = g_signal_add_emission_hook(",
            "FlutterWindow::~FlutterWindow()",
            "if (this->pressedEmissionHook != 0)",
            "this->pressedEmissionHook);",
            "if (this->releasedEmissionHook != 0)",
            "this->releasedEmissionHook);",
            "gtk_widget_destroy(this->window_);",
        ),
        "paired GTK global emission-hook ownership before subwindow destruction",
    )
    forbid(
        multi_window_linux,
        'InvokeMethodSelfVoid("onDestroy"',
        "fire-and-forget native destruction notification",
    )
    forbid(
        multi_window_linux,
        "callback->OnWindowDestroy(self->id_);",
        "synchronous native self-destruction",
    )
    forbid(
        multi_window_linux,
        "callback->OnWindowDestroy(id);",
        "synchronous native self-destruction",
    )
    forbid(
        multi_window_linux,
        "return self->isPreventClose;",
        "post-destruction native field read",
    )
    require(
        dart_verify,
        "desktop multi-window waits for Dart cleanup response before owner retirement",
        "offline native multi-window lifetime gate",
    )
    if dart_verify.count(
        "desktop multi-window waits for Dart cleanup response before owner retirement"
    ) != 2:
        raise VerificationError(
            "offline native multi-window lifetime gate must bind heading and verdict"
        )
    require(
        dart_verify,
        "third_party/desktop_multi_window/lib/",
        "vendored desktop multi-window analyzer gate",
    )
    require(
        flutter_attributes,
        "third_party/url_launcher_linux/** -text",
        "vendored URL-launcher byte preservation",
    )
    require_order(
        flutter_pubspec,
        (
            "url_launcher_linux:",
            "path: third_party/url_launcher_linux",
        ),
        "vendored URL-launcher dependency override",
    )
    require_order(
        flutter_lock,
        (
            "url_launcher_linux:",
            'path: "third_party/url_launcher_linux"',
            "relative: true",
            "source: path",
            'version: "3.2.1"',
        ),
        "locked vendored URL-launcher dependency",
    )
    require(
        url_launcher_upstream,
        "4e9ba368772369e3e08f231d2301b4ef72b9ff87c31192ef471b380ef29a4935",
        "vendored URL-launcher hosted provenance",
    )
    require(
        url_launcher_upstream,
        "52cd2d6ef9bc4e1b28eca16d4593c06c52fbc4de3be8083230060c35c4b0db2d",
        "vendored URL-launcher upstream Linux source identity",
    )
    forbid(
        url_launcher_linux,
        "ful_url_launcher_api_clear_method_handlers(",
        "recursive URL handler clearing during plugin disposal",
    )
    require_order(
        url_launcher_linux,
        (
            "static void fl_url_launcher_plugin_dispose(GObject* object)",
            "g_clear_object(&self->registrar);",
            "G_OBJECT_CLASS(fl_url_launcher_plugin_parent_class)->dispose(object);",
        ),
        "non-recursive URL plugin disposal",
    )
    require_order(
        url_launcher_test,
        (
            "g_hash_table_size(messenger->handlers) == 2",
            "weak_plugin != nullptr",
            "FL_BINARY_MESSENGER_GET_IFACE(messenger)->shutdown(",
            "g_hash_table_size(messenger->handlers) == 0",
            "messenger->handler_sets_during_shutdown == 2",
            "weak_plugin == nullptr",
        ),
        "URL plugin messenger-shutdown ownership regression",
    )
    require(
        dart_verify,
        "\n    /tmp/url_launcher_shutdown_test\n",
        "confined URL-launcher native shutdown test",
    )
    require_order(
        dart_verify,
        (
            "upstream_url_launcher=/online/pub-cache/hosted/pub.dev/url_launcher_linux-3.2.1/linux",
            "52cd2d6ef9bc4e1b28eca16d4593c06c52fbc4de3be8083230060c35c4b0db2d",
            '"$upstream_url_launcher/url_launcher_plugin.cc" | sha256sum -c -',
            "/tmp/url_launcher_upstream_test >/tmp/url_launcher_upstream.out 2>&1",
            '[ "$upstream_status" -eq 1 ]',
            "FAIL: shutdown did not perform exactly one terminal reset per URL channel",
        ),
        "exact stock URL-launcher negative control",
    )
    if dart_verify.count('[ "$upstream_status" -eq 1 ]') != 2:
        raise VerificationError(
            "exact stock URL-launcher rejection must appear once in execution and once in its source gate"
        )
    require(
        flutter_attributes,
        "third_party/window_manager/** -text",
        "vendored window-manager byte preservation",
    )
    require_order(
        flutter_pubspec,
        (
            "window_manager:",
            "path: third_party/window_manager",
        ),
        "vendored window-manager dependency override",
    )
    require_order(
        flutter_lock,
        (
            "window_manager:",
            'path: "third_party/window_manager"',
            "relative: true",
            "source: path",
            'version: "0.3.6"',
        ),
        "locked vendored window-manager dependency",
    )
    for token, label in (
        (
            "85789bfe6e4cfaf4ecc00c52857467fdb7f26879",
            "window-manager upstream commit",
        ),
        (
            "9627e63c85411da995da37cb7cd6d392766a509d",
            "window-manager upstream tree",
        ),
        (
            "5b2a562f2e853cde3661468aea2a38fc9d1abef5e2fbd3befbc86831a7f7cd87",
            "window-manager upstream Linux source digest",
        ),
        (
            "70fe0130bbbd928d04cd33a49ecde422ec54fd748b7a4e983f4e31be6e73f5f5",
            "window-manager close asset digest",
        ),
        (
            "93f2ed012ec01288b78ad4816ef254261e9ff25e8a9858359b45431c9a5de5f4",
            "window-manager maximize asset digest",
        ),
        (
            "0976edbb9977136544af17de125f345a41065694de92036d9365817ea6d8f05a",
            "window-manager minimize asset digest",
        ),
        (
            "3d375930c514ec2ebc0603ad1e1398b4daf458951042a97232d16f17e1c9603b",
            "window-manager unmaximize asset digest",
        ),
    ):
        require(window_manager_upstream, token, label)
    require_order(
        dart_verify,
        (
            'grep -qxF "!flutter/third_party/window_manager/$asset" .gitignore',
            "sha256sum -c - <<'EOF'",
            "70fe0130bbbd928d04cd33a49ecde422ec54fd748b7a4e983f4e31be6e73f5f5  images/ic_chrome_close.png",
            "93f2ed012ec01288b78ad4816ef254261e9ff25e8a9858359b45431c9a5de5f4  images/ic_chrome_maximize.png",
            "0976edbb9977136544af17de125f345a41065694de92036d9365817ea6d8f05a  images/ic_chrome_minimize.png",
            "3d375930c514ec2ebc0603ad1e1398b4daf458951042a97232d16f17e1c9603b  images/ic_chrome_unmaximize.png",
        ),
        "vendored window-manager shipped asset authority",
    )
    require_order(
        window_manager_linux,
        (
            "GtkWindow* window;",
            "GtkWindow* get_window(WindowManagerPlugin* self)",
            "return self->window;",
            "if (get_window(self) == nullptr)",
            '"window_unavailable"',
            "fl_method_call_respond(method_call, response, nullptr);",
            "return;",
        ),
        "queued window call rejection after GTK destruction",
    )
    require_order(
        window_manager_linux,
        (
            "static void window_manager_plugin_dispose(GObject* object)",
            "g_signal_handlers_disconnect_by_data(self->window, self);",
            "g_signal_remove_emission_hook(",
            "g_clear_object(&self->channel);",
            "g_clear_object(&self->registrar);",
            "main_window_initialized = false;",
        ),
        "window-manager callback/channel/registrar retirement",
    )
    require_order(
        window_manager_linux,
        (
            "void on_window_destroy(GtkWidget* widget, gpointer data)",
            "plugin->button_press_emission_hook = 0;",
            "plugin->window = nullptr;",
            "GObject* window_manager_plugin_register_with_registrar_for_window(",
            "plugin->window = window;",
            'g_signal_connect(window, "destroy", G_CALLBACK(on_window_destroy), plugin);',
            "plugin->button_press_emission_hook = g_signal_add_emission_hook(",
        ),
        "concrete native window registration and terminal destroy callback",
    )
    require_order(
        window_manager_test,
        (
            "gpointer weak_plugin =",
            "window_manager_plugin_register_with_registrar_for_window(",
            "g_object_add_weak_pointer(G_OBJECT(weak_plugin), &weak_plugin);",
            '"isMaximized"',
            "FL_IS_METHOD_ERROR_RESPONSE(response)",
            'g_strcmp0(code, "window_unavailable") == 0',
            "FL_BINARY_MESSENGER_GET_IFACE(messenger)->shutdown(",
            "messenger->handler_sets_during_shutdown == 0",
            "weak_plugin == nullptr",
        ),
        "window-manager destroyed-window and shutdown regression",
    )
    require_order(
        sources["desktop_tabbar"],
        (
            "Timer? _initialMaximizedTimer;",
            "_initialMaximizedTimer = Timer(Duration(milliseconds: 500)",
            "Future<void> _syncInitialMaximizedState() async",
            "if (!mounted || stateGlobal.isMaximized.value == maximized)",
            "if (mounted) {",
            "_initialMaximizedTimer?.cancel();",
            "_initialMaximizedTimer = null;",
        ),
        "cancellable mounted delayed maximize query",
    )
    require_order(
        dart_verify,
        (
            "\n    /tmp/window_manager_shutdown_test\n",
            "window_manager_guard_disabled.cc",
            "/tmp/window_manager_guard_disabled_test",
            '[ "$guard_disabled_status" -eq 1 ]',
            "FAIL: destroyed-window call was not rejected",
        ),
        "confined window-manager behavior and guard-removed negative control",
    )
    if dart_verify.count('[ "$guard_disabled_status" -eq 1 ]') != 2:
        raise VerificationError(
            "window-manager guard-disabled rejection must appear once in execution and once in its source gate"
        )
    require(
        stage,
        "grep -qF 'FlBinaryMessenger without an engine' /tmp/viewer.log",
        "runtime refusal of post-engine messenger use",
    )
    forbid(controller, "PASSWORD_SETTLE_MS", "blind password-prompt delay")
    require(controller, "AUTH_WAIT_MS 30000U", "authentication deadline")
    require(controller, "FRESH_LIMIT_MS 1000U", "live-frame freshness bound")
    require(controller, "RECOVERY_LIMIT_MS 2500U", "focus-recovery bound")
    require_order(
        controller,
        (
            "wait_for_password_prompt((unsigned int)viewer_pid, &prompt_scan)",
            "scan_password_prompt((unsigned int)viewer_pid, &diagnostic_scan, 1)",
            "exit_atspi_after_failure()",
        ),
        "failed prompt scan diagnostic before teardown",
    )
    require_order(
        controller,
        (
            "wait_for_password_prompt((unsigned int)viewer_pid, &prompt_scan)",
            "type_password(display)",
            "wait_for_password_prompt_retirement((unsigned int)viewer_pid, &prompt_scan)",
            "atspi_exit() != 0",
            "wait_for_current_frames(source, display, &viewer, &history, AUTH_WAIT_MS",
            "read_connection_identity(&connection_before)",
            "sink = create_focus_sink(display)",
            "return_focus_with_pointer(display, &viewer)",
            "wait_for_current_frames(source, display, &viewer, &history, RECOVERY_LIMIT_MS",
            "read_connection_identity(&connection_after)",
            "same_connection(&connection_before, &connection_after)",
            "close_viewer(display, viewer.window)",
        ),
        "authenticated pixels, blur, pointer return, stable transport, and close",
    )
    require(controller, 'strcmp(remote, "0100007F:527E") == 0', "authenticated TCP tuple")
    require(controller, "left->inode == right->inode", "stable socket identity")
    require(controller, "WM_DELETE_WINDOW", "real viewer close")
    forbid(controller, "system(", "controller shell escape")
    forbid(controller, "Socket", "controller product-side probe socket")

    require(
        sources["verify"],
        "/usr/bin/python3 -I -S scripts/verify-flutter-peer-presentation.py --repo . --self-test",
        "shared verifier wiring",
    )
    require(
        sources["workspace"],
        '"flutter_peer_presentation_verifier"',
        "independent verifier binding",
    )
    require(
        sources["requirements"],
        '<div class="req"><span class="id">R-S11gc</span>',
        "normative evidence requirement",
    )
    require(
        sources["requirements"],
        "existing external <code>smoke-bind-loopback.c</code> confinement shim",
        "normative loopback-confinement boundary",
    )
    require(
        sources["requirements"],
        "exact GTK-derived X11 <code>WM_CLASS</code> instance/class pair",
        "normative exact viewer-window identity",
    )
    require(
        sources["requirements"],
        "viewer-only private D-Bus/AT-SPI session",
        "normative exact password-prompt readiness boundary",
    )
    require(
        sources["requirements"],
        "fe81f679a0a1acd8291472162e867a566f33a50c813d27775125cee4644736b4",
        "normative canonical current-lock Pub-cache input",
    )
    require(
        sources["requirements"],
        "canonical-pinned-online-copy",
        "normative canonical Pub-cache copy provenance",
    )
    if sources["requirements"].count(
        "fe81f679a0a1acd8291472162e867a566f33a50c813d27775125cee4644736b4"
    ) != 2:
        raise VerificationError(
            "canonical Pub-cache digest must bind the requirement and Appendix disposition"
        )
    if sources["requirements"].count("canonical-pinned-online-copy") != 2:
        raise VerificationError(
            "canonical Pub-cache provenance must bind the requirement and Appendix disposition"
        )
    require(
        sources["requirements"],
        "only after that response callback returns may native code defer",
        "normative Dart-response-before-engine-destruction boundary",
    )
    require(
        sources["requirements"],
        '<div class="req"><span class="id">R-S11ge</span>',
        "normative Linux plugin and GTK callback lifetime requirement",
    )
    require(
        sources["requirements"],
        "observe exactly two terminal handler-set operations",
        "normative non-re-entrant URL handler retirement",
    )
    require(
        sources["requirements"],
        "button-press and button-release hooks are one paired ownership unit",
        "normative paired GTK hook retirement",
    )
    require(
        sources["requirements"],
        "The GTK <code>destroy</code> signal is a terminal admission boundary",
        "normative terminal native-window admission boundary",
    )
    require(
        sources["requirements"],
        "zero shutdown-time handler mutations",
        "normative window-manager messenger shutdown finality",
    )
    if sources["requirements"].count("zero shutdown-time handler mutations") != 2:
        raise VerificationError(
            "window-manager messenger shutdown finality must be bound in the requirement and Appendix disposition"
        )
    require(
        sources["requirements"],
        "recheck <code>mounted</code> after awaiting and again inside a post-frame callback",
        "normative delayed Dart callback lifetime",
    )
    require(
        sources["requirements"],
        "maps AT-SPI <code>SHOWING</code> to the inverse of that same <code>IsObscured</code> flag",
        "normative pinned Flutter password-state contract",
    )
    require(sources["requirements"], "<tr><td>338</td>", "Appendix C evidence row")
    require(sources["requirements"], "<tr><td>340</td>", "Appendix C teardown row")
    require(
        sources["hardening"],
        "R-S11gc/R-S11e-216 exact Linux full-peer Flutter presentation evidence",
        "hardening evidence ledger",
    )
    require(
        sources["hardening"],
        "R-S11gc exact-current full-peer input authority recovery",
        "exact-current input-authority ledger",
    )
    require(
        sources["hardening"],
        "The full canonical online closure remains red and was not repinned.",
        "full-online closure residual ledger",
    )
    require(
        sources["hardening"],
        "The corrected evidence boundary now compiles the existing audited `smoke-bind-loopback.c`",
        "hardening loopback-confinement disposition",
    )
    require(
        sources["hardening"],
        "The corrected observer now requires the launcher PID and both exact `WM_CLASS` fields",
        "hardening exact viewer-window identity disposition",
    )
    require(
        sources["hardening"],
        "An eighth exact committed run used commit `731d0eed3d60824c9f9316da55e977334d63cd30`",
        "hardening invalid prompt-readiness evidence disposition",
    )
    require(
        sources["hardening"],
        "A twentieth exact committed run used commit",
        "warning-clean but crashing twentieth real-peer evidence",
    )
    require(
        sources["hardening"],
        "The exact top native frames were `gtk_window_is_maximized`",
        "exact stale window-manager crash diagnosis",
    )
    require(
        sources["hardening"],
        "Already-queued calls receive\n  `window_unavailable` without entering GTK",
        "window-manager terminal-admission correction record",
    )
    require(
        sources["hardening"],
        "An eleventh exact committed run used commit `c85303247b3599999113af806e8527de964a1f03`",
        "hardening corrected AT-SPI role interpretation",
    )
    require(
        sources["hardening"],
        "A twelfth exact committed run used commit `85c7c8ee9731e3548169fae1d031e1b225045012`",
        "hardening exact zero-password-node evidence disposition",
    )
    require(
        sources["hardening"],
        "The next diagnostic reused that same bounded, exact-PID accessibility traversal",
        "hardening bounded accessibility diagnostic",
    )
    require(
        sources["hardening"],
        "A thirteenth exact committed run used commit `0a01023fdc6530a93663ebd34871f614ede69c21`",
        "hardening exact prompt-tree evidence disposition",
    )
    require(
        sources["hardening"],
        "The correction removes that global semantics-deletion helper and all of its authored",
        "hardening Linux semantics-deletion product correction",
    )
    require(
        sources["hardening"],
        "A fourteenth exact committed run used commit `715171b9a9a03f0516130981f278a22d546775ac`",
        "hardening viewer teardown-crash evidence",
    )
    require(
        sources["hardening"],
        "The first correction gives the tab controller one asynchronous pre-removal boundary",
        "hardening awaited viewer teardown correction",
    )
    require(
        sources["hardening"],
        "A fifteenth exact committed run used commit `4dac16a203c8c98e7e3764c76250a69934922c14`",
        "hardening awaited-teardown runtime result",
    )
    require(
        sources["hardening"],
        "Its Linux GTK",
        "hardening native multi-window lifetime diagnosis",
    )
    require(
        sources["hardening"],
        "An eighteenth exact committed diagnostic run used commit",
        "hardening response-race runtime diagnosis",
    )
    require(
        sources["hardening"],
        "The pending correction adds one response completion to the existing channel",
        "hardening response-bound native teardown correction",
    )
    require(
        sources["hardening"],
        "A nineteenth exact committed run used commit",
        "hardening response-bound runtime result",
    )
    require(
        sources["hardening"],
        "Exact stacks bound both warnings to the two Pigeon channels",
        "hardening exact URL-launcher teardown diagnosis",
    )
    require(
        sources["hardening"],
        "retained and removed only the press-hook ID",
        "hardening unmatched GTK release-hook diagnosis",
    )
    require(
        sources["readme"],
        "smoke-flutter-peer-presentation.sh",
        "harness README inventory",
    )


MUTATIONS = (
    ("host", "local passwd_mounts=0", "local passwd_mounts=1"),
    ("host", "--pull=never --network=none --read-only", "--pull=never --network=host --read-only"),
    ("host", '--network="container:$SERVER_CID" --read-only', "--network=bridge --read-only"),
    ("host", 'run_input_check "$WORKSPACE/input-post.cid"', "true # persistent input postcheck removed"),
    ("host", 'require_exact_local_image deb-builder "$DEB_BUILDER_IMAGE_ID"', "true # exact builder image omitted"),
    ("host", 'source=$ONLINE_DIR/cargo-vendor,target=/online/cargo-vendor,readonly,bind-recursive=disabled', 'source=$ONLINE_DIR,target=/online,readonly,bind-recursive=disabled'),
    ("host", 'source=$EVIDENCE_PUB_CACHE,target=/evidence-pub-cache,readonly', 'source=$EVIDENCE_PUB_CACHE,target=/evidence-pub-cache'),
    ("host", '"$HOST_UID:$HOST_GID:500"', '"$HOST_UID:$HOST_GID:700"'),
    ("host", "[ \"$ports\" = null ] || [ \"$ports\" = '{}' ]", "true"),
    ("host", "dbus-run-session --", "true # private accessibility session removed"),
    ("host", 'local_docker run --cidfile "$VIEWER_CID_FILE"', 'local_docker run --cidfile "$SERVER_CID_FILE"'),
    ("host", 'chmod 0400 "$VIEWER_PASSWD.tmp"', 'chmod 0444 "$VIEWER_PASSWD.tmp"'),
    ("host", 'source=$VIEWER_PASSWD,target=/etc/passwd,readonly,bind-recursive=disabled', 'source=$VIEWER_PASSWD,target=/tmp/passwd,readonly,bind-recursive=disabled'),
    ("host", '[ "$writable" = false ]', "true"),
    ("host", "private viewer passwd witness changed during runtime", "passwd witness finality removed"),
    ("stage", '--tree /online/cargo-vendor --expected "$RUSTDESK_CARGO_VENDOR_SHA256"', '--tree /online/cargo-vendor --expected "$RUSTDESK_VCPKG_X64_LINUX_SHA256"'),
    ("stage", "/source/scripts/online-cargo-tool-output.py check-complete", "true # FRB semantic validation omitted"),
    ("stage", '"$(sha256sum /online/frb-tool/bin/flutter_rust_bridge_codegen | awk \'{print $1}\')" = \\\n      "$RUSTDESK_FRB_SHA256"', '"$(sha256sum /online/frb-tool/bin/flutter_rust_bridge_codegen | awk \'{print $1}\')" = \\\n      "$RUSTDESK_CARGO_VENDOR_SHA256"'),
    ("stage", "--tree /online/vcpkg/installed/x64-linux", "--tree /online/vcpkg/installed/arm64-android"),
    ("pins", 'SHA256_FLUTTER_PEER_PUB_CACHE_CLOSURE_V1="fe81f679a0a1acd8291472162e867a566f33a50c813d27775125cee4644736b4"', 'SHA256_FLUTTER_PEER_PUB_CACHE_CLOSURE_V1="c3c59a30604f10c11950cdb4d0a7646ddb46eb6ae031c27869a1b82a8d33c4d7"'),
    ("pins", 'SHA256_FLUTTER_PEER_VCPKG_X64_LINUX_CLOSURE_V1="24a2295145b04938abed637daac104252c4374a119db19749451a8fc69858436"', 'SHA256_FLUTTER_PEER_VCPKG_X64_LINUX_CLOSURE_V1="34a2295145b04938abed637daac104252c4374a119db19749451a8fc69858436"'),
    ("pins", 'SHA256_FLUTTER_PEER_FRB_CODEGEN="24508d54dcad4f6b5c5b70395d24437a563d64fc2c24a17ca7e25f24ddb418fa"', 'SHA256_FLUTTER_PEER_FRB_CODEGEN="34508d54dcad4f6b5c5b70395d24437a563d64fc2c24a17ca7e25f24ddb418fa"'),
    ("pins", 'SIZE_FLUTTER_PEER_FRB_CODEGEN="17211448"', 'SIZE_FLUTTER_PEER_FRB_CODEGEN="17211447"'),
    ("stage", '[ "$interfaces" = lo ]', '[ -n "$interfaces" ]'),
    ("stage", "--lib --example smoke_readiness --release", "--lib --release"),
    ("stage", '"$READY" --wait-typed-parked "$SERVER_PID" "$SERVER_START"', '"$READY" --wait-tcp-listener "$SERVER_PID" "$SERVER_START"'),
    ("ready", "server_typed_parked() {", "server_typed_parked_removed() {"),
    ("linux_runner", "return EXIT_SUCCESS;", "return EXIT_FAILURE;"),
    ("stage", "! grep -Fq '[SEVERE]'", "true # severe output ignored"),
    ("stage", "export HOME CARGO_HOME CI=true PUB_CACHE=/evidence-online/pub-cache", "export HOME CARGO_HOME CI=true PUB_CACHE=/online/pub-cache"),
    ("stage", "published=True", "published=False"),
    ("stage", "printf 'sha256=%s source=canonical-pinned-online-copy semantics=current-three-git-lock\\n'", "printf 'sha256=%s source=unverified-copy semantics=current-three-git-lock\\n'"),
    ("stage", '[ -z "${LD_PRELOAD:-}" ]', "true # ambient preload accepted"),
    ("stage", '[ -n "${DBUS_SESSION_BUS_ADDRESS:-}" ]', "true # accessibility bus not required"),
    ("stage", '[ "$(getent passwd "$(id -u)")" = "$EXPECTED_PASSWD_ENTRY" ]', "true # numeric identity unresolved"),
    ("stage", "pkg-config --cflags --libs x11 xtst atspi-2 gobject-2.0", "pkg-config --cflags --libs x11 xtst atspi-2"),
    ("stage", "--password-stdin", "--password rustdesk-peer-9f2a7c4e"),
    ("stage", 'LD_PRELOAD="$BIND_SHIM" RUST_LOG=info exec "$APP" --server', 'RUST_LOG=info exec "$APP" --server'),
    ("stage", 'RUST_LOG=info exec "$APP" --connect 127.0.0.1', 'exec "$APP" --connect 127.0.0.1'),
    ("stage", "FLUTTER_PEER_SERVER_DIAGNOSTIC_BEGIN", "FLUTTER_PEER_SERVER_DIAGNOSTIC_OMITTED"),
    ("stage", "runtime-log diagnostic exceeds its exact bounds", "runtime-log diagnostic bounds omitted"),
    ("stage", 'emit_runtime_logs VIEWER "$HOME/.local/share/logs"', 'true # viewer file diagnostics omitted'),
    ("stage", 'wait_process_maps_exact_file "$SERVER_PID" "$SERVER_START" "$BIND_SHIM"', "true # mapped shim unproved"),
    ("bind_shim", "ntohs(rewritten.sin_port) == 21118", "ntohs(rewritten.sin_port) == 21119"),
    ("bind_shim", "return fn(sockfd, addr, addrlen);", "return fn(sockfd, (const struct sockaddr *)&rewritten, sizeof(rewritten));"),
    ("stage", '"$CONTROLLER" :98 :99 "$VIEWER_PID"', '"$CONTROLLER" :99 :99 "$VIEWER_PID"'),
    ("controller", "FRESH_LIMIT_MS 1000U", "FRESH_LIMIT_MS 10000U"),
    ("controller", "RECOVERY_LIMIT_MS 2500U", "RECOVERY_LIMIT_MS 10000U"),
    ("controller", "left->inode == right->inode", "1"),
    ("controller", "XTestFakeKeyEvent", "RemovedFakeKeyEvent"),
    ("controller", "role == ATSPI_ROLE_PASSWORD_TEXT", "role == ATSPI_ROLE_ENTRY"),
    ("controller", "scan.password_nodes == 1U && scan.visible_passwords == 1U", "scan.visible_passwords > 0U"),
    ("controller", "scan.password_nodes == 0U", "scan.visible_passwords == 0U"),
    ("controller", "ACCESSIBLE_NAME_LIMIT 96U", "ACCESSIBLE_NAME_LIMIT 4096U"),
    ("controller", "strnlen(name, ACCESSIBLE_NAME_LIMIT + 1U)", "strlen(name)"),
    ("controller", "if (emit_diagnostic != 0)", "if (1)"),
    ("controller", '"FLUTTER_PEER_ATSPI_NODE depth=%u role=%d "', '"UNBOUND_ATSPI_NODE depth=%u role=%d "'),
    ("controller", "scan_password_prompt((unsigned int)viewer_pid, &diagnostic_scan, 1)", "scan_password_prompt((unsigned int)viewer_pid, &diagnostic_scan, 0)"),
    ("controller", "scan_password_prompt(expected_pid, &scan, 0)", "scan_password_prompt(expected_pid, &scan, 1)"),
    ("controller", "memset(last_scan, 0, sizeof(*last_scan));", "memset(last_scan, 0, 0);"),
    ("controller", "atspi_accessible_get_name(accessible, &error)", "atspi_accessible_get_text(accessible, &error)"),
    ("controller", "g_free(name);", "name = NULL;"),
    ("flutter_common", "void earlyAssert() {", "extension WorkaroundFreezeLinuxMint on Widget {}\nvoid earlyAssert() {"),
    ("flutter_dialog", "obscureText: !_passwordVisible,", "obscureText: false,"),
    ("flutter_dialog", "obscureText: obscureText,", "obscureText: false,"),
    ("flutter_dialog", "focusable: true,", "focusable: false,"),
    ("password_semantics_test", "isObscured: true", "isObscured: false"),
    ("password_semantics_test", "semanticsEnabled: true", "semanticsEnabled: false"),
    ("dart_verify", "flutter test --no-pub test/password_field_semantics_test.dart", "true # password semantics test disabled"),
    ("dart_verify", "if grep -RInF --include='*.dart' 'workaroundFreezeLinuxMint' flutter/lib", "if false; then # global semantics exclusion accepted"),
    ("desktop_remote_page", "Future<void> prepareForRemoval({bool closeSession = true})", "Future<void> prepareForRemoval({bool closeSession = false})"),
    ("desktop_remote_page", "await _awaitCleanup('texture retirement', textureDisposal);", "unawaited(textureDisposal);"),
    ("desktop_remote_page", "void dispose() {", "Future<void> dispose() async {"),
    ("desktop_camera_page", "await _awaitCleanup('texture retirement', textureDisposal);", "unawaited(textureDisposal);"),
    ("desktop_tabbar", "await onBeforeRemove?.call(tab, closeSession);", "onBeforeRemove?.call(tab, closeSession);"),
    ("desktop_tabbar", "state.value.tabs.indexWhere((item) => identical(item, tab));", "initialIndex;"),
    ("desktop_tabbar", "await Future.wait<void>(", "Future.wait<void>("),
    ("desktop_tabbar", "while (state.value.tabs.isNotEmpty) {", "if (state.value.tabs.isNotEmpty) {"),
    ("desktop_tabbar", "await controller.closeAll();", "controller.clear();"),
    ("desktop_remote_tabs", "tabController.onBeforeRemove = _prepareTabForRemoval;", "tabController.onBeforeRemove = null;"),
    ("desktop_remote_tabs", "await tabController.closeBy(id, closeSession: false);", "await tabController.closeBy(id);"),
    ("desktop_camera_tabs", "await page.prepareForRemoval(closeSession: closeSession);", "page.prepareForRemoval(closeSession: closeSession);"),
    ("desktop_tab_retirement_test", "await retirement.future;", "return;"),
    ("desktop_tab_retirement_test", "expect(controller.length, 2);", "expect(controller.length, 0);"),
    ("dart_verify", "flutter test --no-pub test/desktop_tab_retirement_test.dart", "true # desktop tab retirement test disabled"),
    ("flutter_attributes", "third_party/desktop_multi_window/** -text", "third_party/desktop_multi_window/** text=auto"),
    ("flutter_pubspec", "path: third_party/desktop_multi_window", "path: /tmp/desktop_multi_window"),
    ("flutter_lock", 'path: "third_party/desktop_multi_window"', 'path: "/tmp/desktop_multi_window"'),
    ("multi_window_upstream", "b47e8385e5a75d38319ad706a64b0ead3108b093", "unreviewed-upstream"),
    ("multi_window_upstream", "waits for the method\nresponse before scheduling the idle erase", "schedules the idle erase without waiting for Dart"),
    ("multi_window_header", "bool destroy_pending_ = false;", "bool destroy_pending_ = true;"),
    ("multi_window_header", "gulong releasedEmissionHook = 0;", "gulong releasedEmissionHook = 1;"),
    ("multi_window_channel_header", "using CompletionHandler = std::function<void()>;", "using CompletionHandler = void (*)();"),
    ("multi_window_channel", "fl_method_channel_invoke_method_finish(data->channel, res, &error);", "response = nullptr;"),
    ("multi_window_channel", "completion();", "true; # completion omitted"),
    ("multi_window_linux", "pending->callback->OnWindowDestroy(pending->id);", "return G_SOURCE_REMOVE;"),
    ("multi_window_linux", "if (self->destroy_pending_)", "if (false)"),
    ("multi_window_linux", 'channel->InvokeMethodSelf("onDestroy", args, [callback, id]() {', 'channel->InvokeMethodSelfVoid("onDestroy", args); if (false) {'),
    ("multi_window_linux", "g_idle_add_full(", "callback->OnWindowDestroy(id);\n      g_idle_add_full("),
    ("multi_window_linux", "this->releasedEmissionHook = g_signal_add_emission_hook(", "g_signal_add_emission_hook("),
    ("multi_window_linux", "if (this->releasedEmissionHook != 0)", "if (false)"),
    ("multi_window_linux", "return TRUE;", "return self->isPreventClose;"),
    ("dart_verify", "desktop multi-window waits for Dart cleanup response before owner retirement", "desktop multi-window native destruction gate removed"),
    ("dart_verify", "third_party/desktop_multi_window/lib/", "third_party/desktop_multi_window-disabled/lib/"),
    ("flutter_attributes", "third_party/url_launcher_linux/** -text", "third_party/url_launcher_linux/** text=auto"),
    ("flutter_pubspec", "path: third_party/url_launcher_linux", "path: /tmp/url_launcher_linux"),
    ("flutter_lock", 'path: "third_party/url_launcher_linux"', 'path: "/tmp/url_launcher_linux"'),
    ("url_launcher_upstream", "4e9ba368772369e3e08f231d2301b4ef72b9ff87c31192ef471b380ef29a4935", "unreviewed-url-launcher"),
    ("url_launcher_upstream", "52cd2d6ef9bc4e1b28eca16d4593c06c52fbc4de3be8083230060c35c4b0db2d", "unidentified-url-launcher-linux-source"),
    ("url_launcher_linux", "g_clear_object(&self->registrar);", "ful_url_launcher_api_clear_method_handlers(fl_plugin_registrar_get_messenger(self->registrar), nullptr);\n  g_clear_object(&self->registrar);"),
    ("url_launcher_test", "messenger->handler_sets_during_shutdown == 2", "messenger->handler_sets_during_shutdown == 6"),
    ("dart_verify", "\n    /tmp/url_launcher_shutdown_test\n", "\n    true # URL-launcher shutdown test disabled\n"),
    ("dart_verify", '"$upstream_url_launcher/url_launcher_plugin.cc" | sha256sum -c -', '"$upstream_url_launcher/url_launcher_plugin.cc" | true'),
    ("dart_verify", '[ "$upstream_status" -eq 1 ]', '[ "$upstream_status" -eq 0 ]'),
    ("flutter_attributes", "third_party/window_manager/** -text", "third_party/window_manager/** text=auto"),
    ("flutter_pubspec", "path: third_party/window_manager", "path: /tmp/window_manager"),
    ("flutter_lock", 'path: "third_party/window_manager"', 'path: "/tmp/window_manager"'),
    ("window_manager_upstream", "85789bfe6e4cfaf4ecc00c52857467fdb7f26879", "unreviewed-window-manager"),
    ("window_manager_upstream", "9627e63c85411da995da37cb7cd6d392766a509d", "unidentified-window-manager-tree"),
    ("window_manager_upstream", "5b2a562f2e853cde3661468aea2a38fc9d1abef5e2fbd3befbc86831a7f7cd87", "unidentified-window-manager-linux-source"),
    ("window_manager_upstream", "70fe0130bbbd928d04cd33a49ecde422ec54fd748b7a4e983f4e31be6e73f5f5", "unidentified-window-manager-close-asset"),
    ("window_manager_upstream", "93f2ed012ec01288b78ad4816ef254261e9ff25e8a9858359b45431c9a5de5f4", "unidentified-window-manager-maximize-asset"),
    ("window_manager_upstream", "0976edbb9977136544af17de125f345a41065694de92036d9365817ea6d8f05a", "unidentified-window-manager-minimize-asset"),
    ("window_manager_upstream", "3d375930c514ec2ebc0603ad1e1398b4daf458951042a97232d16f17e1c9603b", "unidentified-window-manager-unmaximize-asset"),
    ("dart_verify", 'grep -qxF "!flutter/third_party/window_manager/$asset" .gitignore', "true # ignored window-manager assets accepted"),
    ("window_manager_linux", "if (get_window(self) == nullptr)", "if (false)"),
    ("window_manager_linux", '"window_unavailable"', '"window_still_available"'),
    ("window_manager_linux", "g_clear_object(&self->channel);", "self->channel = nullptr;"),
    ("window_manager_linux", 'g_signal_connect(window, "destroy", G_CALLBACK(on_window_destroy), plugin);', 'g_signal_connect(window, "show", G_CALLBACK(on_window_destroy), plugin);'),
    ("window_manager_linux", "plugin->window = nullptr;", "plugin->window = GTK_WINDOW(widget);"),
    ("window_manager_test", "messenger->handler_sets_during_shutdown == 0", "messenger->handler_sets_during_shutdown == 1"),
    ("window_manager_test", "g_object_add_weak_pointer(G_OBJECT(weak_plugin), &weak_plugin);", "g_object_add_weak_pointer(G_OBJECT(messenger), &weak_plugin);"),
    ("desktop_tabbar", "_initialMaximizedTimer?.cancel();", "_initialMaximizedTimer?.isActive;"),
    ("desktop_tabbar", "if (mounted) {", "if (true) {"),
    ("dart_verify", "\n    /tmp/window_manager_shutdown_test\n", "\n    true # window-manager native test disabled\n"),
    ("dart_verify", '[ "$guard_disabled_status" -eq 1 ]', '[ "$guard_disabled_status" -eq 0 ]'),
    ("stage", "grep -qF 'FlBinaryMessenger without an engine' /tmp/viewer.log", "grep -qF 'unrelated warning' /tmp/viewer.log"),
    ("controller", "editable != 0 && enabled != 0 && sensitive != 0 && visible != 0", "editable != 0 && enabled != 0 && sensitive != 0 && visible != 0 && atspi_state_set_contains(states, ATSPI_STATE_SHOWING) != 0"),
    ("controller", "wait_for_password_prompt((unsigned int)viewer_pid, &prompt_scan)", "false"),
    ("controller", "wait_for_password_prompt_retirement((unsigned int)viewer_pid, &prompt_scan)", "false"),
    ("controller", 'strcmp(hint.res_name, "rustdesk") != 0', "0"),
    ("controller", 'strcmp(hint.res_class, "Rustdesk") != 0', "0"),
    ("source", "frame = (frame + 1U) & 255U;", "frame = 0U;"),
    ("verify", "/usr/bin/python3 -I -S scripts/verify-flutter-peer-presentation.py --repo . --self-test", "true"),
    ("requirements", '<div class="req"><span class="id">R-S11gc</span>', '<div class="req"><span class="id">R-S11gc-disabled</span>'),
    ("requirements", "existing external <code>smoke-bind-loopback.c</code> confinement shim", "unmanifested compatibility shim"),
    ("requirements", "exact GTK-derived X11 <code>WM_CLASS</code> instance/class pair", "arbitrary X11 class substring"),
    ("requirements", "viewer-only private D-Bus/AT-SPI session", "ambient accessibility session"),
    ("requirements", "fe81f679a0a1acd8291472162e867a566f33a50c813d27775125cee4644736b4", "c3c59a30604f10c11950cdb4d0a7646ddb46eb6ae031c27869a1b82a8d33c4d7"),
    ("requirements", "canonical-pinned-online-copy", "unverified-cache-copy"),
    ("requirements", "only after that response callback returns may native code defer", "native code may immediately defer"),
    ("requirements", '<div class="req"><span class="id">R-S11ge</span>', '<div class="req"><span class="id">R-S11ge-disabled</span>'),
    ("requirements", "observe exactly two terminal handler-set operations", "ignore terminal handler-set cardinality"),
    ("requirements", "button-press and button-release hooks are one paired ownership unit", "button-release hook ownership is optional"),
    ("requirements", "The GTK <code>destroy</code> signal is a terminal admission boundary", "GTK destruction does not affect method admission"),
    ("requirements", "zero shutdown-time handler mutations", "any number of shutdown-time handler mutations"),
    ("requirements", "recheck <code>mounted</code> after awaiting and again inside a post-frame callback", "assume the widget remains mounted"),
    ("requirements", "<tr><td>340</td>", "<tr><td>340-disabled</td>"),
    ("requirements", "maps AT-SPI <code>SHOWING</code> to the inverse of that same <code>IsObscured</code> flag", "maps password visibility consistently"),
    ("hardening", "R-S11gc/R-S11e-216 exact Linux full-peer Flutter presentation evidence", "R-S11gc-disabled/R-S11e-216"),
    ("hardening", "R-S11gc exact-current full-peer input authority recovery", "R-S11gc unbounded input acceptance"),
    ("hardening", "The full canonical online closure remains red and was not repinned.", "The full canonical online closure is green."),
    ("hardening", "The corrected evidence boundary now compiles the existing audited `smoke-bind-loopback.c`", "The evidence boundary assumes an ambient bind rewrite"),
    ("hardening", "The corrected observer now requires the launcher PID and both exact `WM_CLASS` fields", "The observer accepts any title match"),
    ("hardening", "An eighth exact committed run used commit `731d0eed3d60824c9f9316da55e977334d63cd30`", "The eighth exact run proved product presentation failure"),
    ("hardening", "An eleventh exact committed run used commit `c85303247b3599999113af806e8527de964a1f03`", "The eleventh exact run proved product presentation failure"),
    ("hardening", "A twelfth exact committed run used commit `85c7c8ee9731e3548169fae1d031e1b225045012`", "The twelfth exact run proved product presentation failure"),
    ("hardening", "The next diagnostic reused that same bounded, exact-PID accessibility traversal", "The next diagnostic accepted any accessibility traversal"),
    ("hardening", "A thirteenth exact committed run used commit `0a01023fdc6530a93663ebd34871f614ede69c21`", "The thirteenth exact run proved product presentation success"),
    ("hardening", "The correction removes that global semantics-deletion helper and all of its authored", "The correction retains global semantics deletion"),
    ("hardening", "A fourteenth exact committed run used commit `715171b9a9a03f0516130981f278a22d546775ac`", "The fourteenth exact run was green"),
    ("hardening", "The first correction gives the tab controller one asynchronous pre-removal boundary", "The first correction keeps asynchronous State.dispose"),
    ("hardening", "A fifteenth exact committed run used commit `4dac16a203c8c98e7e3764c76250a69934922c14`", "The fifteenth exact run was green"),
    ("hardening", "Its Linux GTK", "Its unrelated Linux GTK"),
    ("hardening", "An eighteenth exact committed diagnostic run used commit", "An uncounted diagnostic run used commit"),
    ("hardening", "The pending correction adds one response completion to the existing channel", "The pending correction adds one arbitrary delay"),
    ("hardening", "A nineteenth exact committed run used commit", "An uncounted nineteenth run used commit"),
    ("hardening", "Exact stacks bound both warnings to the two Pigeon channels", "A guess associated the warnings with a plugin"),
    ("hardening", "retained and removed only the press-hook ID", "owned both global hook IDs"),
    ("hardening", "A twentieth exact committed run used commit", "An uncounted twentieth run used commit"),
    ("hardening", "The exact top native frames were `gtk_window_is_maximized`", "The crash location was guessed"),
    ("hardening", "Already-queued calls receive\n  `window_unavailable` without entering GTK", "Queued calls continue into GTK"),
)


def self_test(sources: dict[str, str]) -> None:
    for key, old, new in MUTATIONS:
        if old not in sources[key]:
            raise VerificationError(f"self-test fixture missing from {key}: {old!r}")
        mutated = dict(sources)
        mutated[key] = sources[key].replace(old, new, 1)
        try:
            validate(mutated)
        except VerificationError:
            continue
        raise VerificationError(f"self-test accepted mutation in {key}: {old!r}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--self-test", action="store_true")
    arguments = parser.parse_args()
    sources = load(arguments.repo.resolve())
    validate(sources)
    if arguments.self_test:
        self_test(sources)
    print("flutter peer presentation verifier: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
