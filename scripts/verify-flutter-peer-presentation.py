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
    "multi_window_upstream": "flutter/third_party/desktop_multi_window/UPSTREAM.md",
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
    multi_window_upstream = sources["multi_window_upstream"]
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
            "require_online_complete",
            "git archive --format=tar",
            "smoke-xvfb-prepare.sh",
            "smoke-flutter-peer-presentation-stage.sh pub-cache",
            "smoke-flutter-peer-presentation-stage.sh build",
            "smoke-flutter-peer-presentation-stage.sh pub-cache-check",
            'local_docker run --detach --cidfile "$SERVER_CID_FILE"',
            "--pull=never --network=none --read-only",
            'inspect_container_contract "$SERVER_CID" none server',
            '--network="container:$SERVER_CID" --read-only',
            'inspect_container_contract "$VIEWER_CID" "container:$SERVER_CID" viewer',
            "FLUTTER_PEER_PRESENTATION_SMOKE_OK",
        ),
        "exact-source build and separate-peer transaction",
    )
    if host.count("--network=bridge") != 1:
        raise VerificationError("the exact Xvfb producer must be the sole bridge-network container")
    if host.count("--network=none") != 4:
        raise VerificationError(
            "only Pub-cache copy/check, build, and controlled-peer anchor use network-none"
        )
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
        'mount.get("Destination") == "/etc/passwd"',
        "inspected passwd mount destination",
    )
    require(host, 'passwd_mount.get("RW") is not False', "inspected read-only passwd mount")
    require(host, "private viewer passwd witness changed during runtime", "passwd witness finality")
    require(
        host,
        ".harness-state/android-current-evidence-7c29f39/pub-cache",
        "retained current-lock Pub-cache input",
    )
    require(
        host,
        "c3c59a30604f10c11950cdb4d0a7646ddb46eb6ae031c27869a1b82a8d33c4d7",
        "retained current-lock Pub-cache digest",
    )
    require(
        host,
        'source=$EVIDENCE_PUB_CACHE,target=/evidence-pub-cache,readonly',
        "read-only retained Pub-cache mount",
    )
    require(host, 'host.get("NetworkMode") != expected_network', "inspected network mode")
    require_order(
        host,
        (
            "local cid=$1 expected_network=$2 label=$3\n  local json_path expected_passwd_source=",
            'json_path="$WORKSPACE/$label.inspect.json"',
            'local_docker container inspect "$cid" > "$json_path"',
        ),
        "nounset-safe inspected-container receipt path",
    )
    require(host, 'host.get("IpcMode") not in ("private", "")', "private IPC namespace")
    require(host, 'host.get("PidMode") not in ("", None)', "private PID namespace")
    require(host, 'host.get("PortBindings") not in (None, {})', "no port publication")
    require(host, 'sorted(host.get("CapDrop") or []) != ["ALL"]', "all capabilities dropped")
    require(host, 'config.get("User") != expected_user', "numeric non-root user")
    require(host, 'host.get("ReadonlyRootfs") is not True', "read-only root")
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
            "FLUTTER_PEER_RETAINED_PUB_CACHE_OK",
            "cp -a /evidence-pub-cache /evidence-online/pub-cache",
            "check-complete --online /evidence-online",
            "FLUTTER_PEER_PUB_CACHE_PREPARED",
        ),
        "retained Pub-cache immutable copy and verification",
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
            '(cd /out/bundle && exec "$APP" --connect 127.0.0.1)',
            '"$CONTROLLER" :98 :99 "$VIEWER_PID"',
            "stable_connection=true",
            "viewer did not retire after its real remote window closed",
            'mv "$COORD/stop.tmp" "$COORD/stop"',
            "FLUTTER_PEER_VIEWER_RUNTIME_OK",
        ),
        "viewer prompt/pixel/lifecycle transaction",
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
        multi_window_header,
        "bool destroy_pending_ = false;",
        "idempotent native subwindow destruction state",
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
            "g_idle_add_full(",
            "destroyWindowWhenIdle,",
            "new PendingWindowDestroy{callback, id}",
            "return TRUE;",
        ),
        "native subwindow callback return before owning-map retirement",
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
        "desktop multi-window native destruction returns before owner retirement",
        "offline native multi-window lifetime gate",
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
        "maps AT-SPI <code>SHOWING</code> to the inverse of that same <code>IsObscured</code> flag",
        "normative pinned Flutter password-state contract",
    )
    require(sources["requirements"], "<tr><td>338</td>", "Appendix C evidence row")
    require(
        sources["hardening"],
        "R-S11gc/R-S11e-216 exact Linux full-peer Flutter presentation evidence",
        "hardening evidence ledger",
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
        sources["readme"],
        "smoke-flutter-peer-presentation.sh",
        "harness README inventory",
    )


MUTATIONS = (
    ("host", 'local cid=$1 expected_network=$2 label=$3\n  local json_path expected_passwd_source=\n  json_path="$WORKSPACE/$label.inspect.json"', 'local cid=$1 expected_network=$2 label=$3 json_path="$WORKSPACE/$label.inspect.json"\n  local expected_passwd_source='),
    ("host", "--pull=never --network=none --read-only", "--pull=never --network=host --read-only"),
    ("host", '--network="container:$SERVER_CID" --read-only', "--network=bridge --read-only"),
    ("host", 'source=$EVIDENCE_PUB_CACHE,target=/evidence-pub-cache,readonly', 'source=$EVIDENCE_PUB_CACHE,target=/evidence-pub-cache'),
    ("host", 'host.get("PortBindings") not in (None, {})', "False"),
    ("host", "dbus-run-session --", "true # private accessibility session removed"),
    ("host", 'local_docker run --cidfile "$VIEWER_CID_FILE"', 'local_docker run --cidfile "$SERVER_CID_FILE"'),
    ("host", 'chmod 0400 "$VIEWER_PASSWD.tmp"', 'chmod 0444 "$VIEWER_PASSWD.tmp"'),
    ("host", 'source=$VIEWER_PASSWD,target=/etc/passwd,readonly,bind-recursive=disabled', 'source=$VIEWER_PASSWD,target=/tmp/passwd,readonly,bind-recursive=disabled'),
    ("host", 'passwd_mount.get("RW") is not False', "False"),
    ("host", "private viewer passwd witness changed during runtime", "passwd witness finality removed"),
    ("stage", '[ "$interfaces" = lo ]', '[ -n "$interfaces" ]'),
    ("stage", "--lib --example smoke_readiness --release", "--lib --release"),
    ("stage", '"$READY" --wait-typed-parked "$SERVER_PID" "$SERVER_START"', '"$READY" --wait-tcp-listener "$SERVER_PID" "$SERVER_START"'),
    ("ready", "server_typed_parked() {", "server_typed_parked_removed() {"),
    ("linux_runner", "return EXIT_SUCCESS;", "return EXIT_FAILURE;"),
    ("stage", "! grep -Fq '[SEVERE]'", "true # severe output ignored"),
    ("stage", "export HOME CARGO_HOME CI=true PUB_CACHE=/evidence-online/pub-cache", "export HOME CARGO_HOME CI=true PUB_CACHE=/online/pub-cache"),
    ("stage", '[ -z "${LD_PRELOAD:-}" ]', "true # ambient preload accepted"),
    ("stage", '[ -n "${DBUS_SESSION_BUS_ADDRESS:-}" ]', "true # accessibility bus not required"),
    ("stage", '[ "$(getent passwd "$(id -u)")" = "$EXPECTED_PASSWD_ENTRY" ]', "true # numeric identity unresolved"),
    ("stage", "pkg-config --cflags --libs x11 xtst atspi-2 gobject-2.0", "pkg-config --cflags --libs x11 xtst atspi-2"),
    ("stage", "--password-stdin", "--password rustdesk-peer-9f2a7c4e"),
    ("stage", 'LD_PRELOAD="$BIND_SHIM" RUST_LOG=info exec "$APP" --server', 'RUST_LOG=info exec "$APP" --server'),
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
    ("multi_window_header", "bool destroy_pending_ = false;", "bool destroy_pending_ = true;"),
    ("multi_window_linux", "pending->callback->OnWindowDestroy(pending->id);", "return G_SOURCE_REMOVE;"),
    ("multi_window_linux", "if (self->destroy_pending_)", "if (false)"),
    ("multi_window_linux", "g_idle_add_full(", "callback->OnWindowDestroy(id);\n      g_idle_add_full("),
    ("multi_window_linux", "return TRUE;", "return self->isPreventClose;"),
    ("dart_verify", "desktop multi-window native destruction returns before owner retirement", "desktop multi-window native destruction gate removed"),
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
    ("requirements", "maps AT-SPI <code>SHOWING</code> to the inverse of that same <code>IsObscured</code> flag", "maps password visibility consistently"),
    ("hardening", "R-S11gc/R-S11e-216 exact Linux full-peer Flutter presentation evidence", "R-S11gc-disabled/R-S11e-216"),
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
