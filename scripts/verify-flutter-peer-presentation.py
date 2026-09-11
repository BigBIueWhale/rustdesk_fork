#!/usr/bin/env python3
"""Check the source contract for the isolated Linux full-peer presentation harness.

This fast check deliberately does not claim to execute or reproduce the full-peer
transaction. Runtime evidence comes only from smoke-flutter-peer-presentation.sh.
"""

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
    "verify": "scripts/verify.sh",
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
        raise VerificationError("the input checks/build/runtime network-none count changed")
    if host.count('run_input_check "$WORKSPACE/input-') != 2:
        raise VerificationError("persistent inputs need pre- and post-transaction checks")
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
    require(host, "/etc/passwd)", "inspected passwd mount destination")
    require(host, '[ "$writable" = false ]', "inspected read-only passwd mount")
    require(host, "private viewer passwd witness changed during runtime", "passwd witness finality")
    require(host, 'readonly EVIDENCE_PUB_CACHE="$ONLINE_DIR/pub-cache"', "canonical Pub-cache input")
    require(
        host,
        'readonly EVIDENCE_PUB_CACHE_SHA256="$SHA256_FLUTTER_PEER_PUB_CACHE_CLOSURE_V1"',
        "canonical Pub-cache digest",
    )
    require(host, '"$HOST_UID:$HOST_GID:500"', "sealed canonical Pub-cache metadata")
    require(
        host,
        'source=$EVIDENCE_PUB_CACHE,target=/evidence-pub-cache,readonly',
        "read-only canonical Pub-cache mount",
    )
    require_order(
        host,
        (
            "local cid=$1 expected_network=$2 label=$3",
            "local expected_passwd_source= mounts_path record_kind source destination writable extra",
            "local network ipc pid uts privileged read_only user ports devices caps security",
            "local source_mounts=0 output_mounts=0 xvfb_root_mounts=0 xkbcomp_mounts=0 coord_mounts=0",
            "local passwd_mounts=0",
            "local receipt_ends=0",
            "network=\"$(local_docker container inspect --format '{{.HostConfig.NetworkMode}}' \"$cid\")\"",
            'mounts_path="$WORKSPACE/$label.mounts.tsv"',
        ),
        "nounset-safe inspected-container receipt path",
    )
    require(host, '[ "$network" = "$expected_network" ]', "inspected network mode")
    require(host, '{ [ -z "$ipc" ] || [ "$ipc" = private ]; }', "private IPC namespace")
    require(host, '[ -z "$pid" ] && [ -z "$uts" ]', "private PID and UTS namespaces")
    require(host, "[ \"$ports\" = null ] || [ \"$ports\" = '{}' ]", "no port publication")
    require(host, "[ \"$caps\" = '[\"ALL\"]' ]", "all capabilities dropped")
    require(host, '[ "$user" = "$HOST_UID:$HOST_GID" ]', "numeric nonroot user")
    require(host, '[ "$privileged" = false ] && [ "$read_only" = true ]', "read-only unprivileged rootfs")
    require(host, "'[\"no-new-privileges\"]'|'[\"no-new-privileges:true\"]'", "no-new-privileges")
    require(host, '{{end}}{{printf "end"}}', "unambiguous inspected-mount terminator")
    require(
        host,
        '[ "$record_kind" = bind ] && [ "$receipt_ends" -eq 0 ]',
        "bind-only pre-terminator receipt",
    )
    require(host, "[[ \"$source\" != */docker.sock ]] && [[ \"$source\" != /dev/* ]]", "unsafe mount rejection")
    for expected_mount in (
        '[ "$source" = "$SOURCE_SNAPSHOT" ] && [ "$writable" = false ]',
        '[ "$source" = "$BUILD_OUTPUT" ] && [ "$writable" = false ]',
        '[ "$source" = "$XVFB_ROOT" ] && [ "$writable" = false ]',
        '[ "$source" = "$XVFB_ROOT/usr/bin/xkbcomp" ] && [ "$writable" = false ]',
        '[ "$source" = "$COORD" ] && [ "$writable" = true ]',
    ):
        require(host, expected_mount, "exact inspected runtime mount")
    require(
        host,
        '*) die "$label receives an unexpected mount destination: $destination" ;;',
        "unexpected mount rejection",
    )
    require(
        host,
        '[ "$receipt_ends" -eq 1 ] && [ "$source_mounts" -eq 1 ]',
        "exact runtime mount cardinality",
    )
    require(host, 'require_exact_local_image deb-builder "$DEB_BUILDER_IMAGE_ID"', "exact builder image")
    require(host, 'require_exact_local_image devcheck "$DEV_CHECK_IMAGE_ID"', "exact verifier image")
    if host.count('source=$ONLINE_DIR,target=/online,readonly') != 1:
        raise VerificationError("only the persistent-input verifier may mount the complete online root")
    require(
        host,
        'source=$BUILD_INPUT_ROOT,target=/online,readonly,bind-recursive=disabled',
        "empty build-input namespace root",
    )
    require_order(
        host,
        (
            'mkdir -p "$BUILD_INPUT_ROOT/cargo-vendor" "$BUILD_INPUT_ROOT/frb-tool/bin"',
            '"$BUILD_INPUT_ROOT/vcpkg/installed/x64-linux"',
            'touch "$BUILD_INPUT_ROOT/rust-${RUST_VERSION}.tar.xz"',
            '"$BUILD_INPUT_ROOT/frb-tool/bin/flutter_rust_bridge_codegen"',
            'chmod -R a-w "$BUILD_INPUT_ROOT"',
            'source=$BUILD_INPUT_ROOT,target=/online,readonly,bind-recursive=disabled',
        ),
        "sealed exact nested-mount namespace skeleton",
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
        "sudo ", "--privileged", "--publish", "--network=host", "/var/run/docker.sock",
        "systemctl", "ufw ", "iptables", "nft ", "/dev/kvm",
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
        "exact consumed-input validation",
    )
    for pin_name, pin_value in (
        ("SHA256_FLUTTER_PEER_PUB_CACHE_CLOSURE_V1", "fe81f679a0a1acd8291472162e867a566f33a50c813d27775125cee4644736b4"),
        ("SHA256_FLUTTER_PEER_VCPKG_X64_LINUX_CLOSURE_V1", "9564b164d4c6d4a9b3d7540a1655505009af34a9e610eadaf076e4807f63cf2c"),
        ("SHA256_FLUTTER_PEER_FRB_CODEGEN", "24508d54dcad4f6b5c5b70395d24437a563d64fc2c24a17ca7e25f24ddb418fa"),
        ("SIZE_FLUTTER_PEER_FRB_CODEGEN", "17211448"),
    ):
        require(pins, f'{pin_name}="{pin_value}"', f"exact input pin {pin_name}")
    require(pins, "This does not repin SHA256_ONLINE_CLOSURE_V1.", "full-online non-inference")
    require_order(
        stage,
        (
            "FLUTTER_PEER_CANONICAL_PUB_CACHE_OK",
            "cp -a /evidence-pub-cache /evidence-online/pub-cache",
            "check-complete --online /evidence-online",
            "FLUTTER_PEER_PUB_CACHE_PREPARED",
        ),
        "canonical Pub-cache copy and verification",
    )
    require(stage, "published=True", "published canonical Pub-cache inspection")
    require(stage, "source=canonical-pinned-online-copy semantics=current-three-git-lock", "Pub-cache provenance")
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
    require(stage, "readonly PROBE=/out/smoke-readiness", "runtime readiness probe")
    require(stage, "export HOME CARGO_HOME CI=true PUB_CACHE=/evidence-online/pub-cache", "sealed Pub cache")
    require(stage, '[ -z "${LD_PRELOAD:-}" ]', "ambient preload refusal")
    require(stage, "assert_loopback_only_interface", "loopback-only inspection")
    require(stage, '[ "$interfaces" = lo ]', "sole loopback interface")
    require(stage, "0100007F:527E", "exact 127.0.0.1:21118 listener")
    require(stage, "verify_regular /out/smoke-bind-loopback.so", "manifested bind shim")
    require(stage, '[ "$(udp_socket_count)" -eq 0 ]', "zero UDP runtime surface")
    require(stage, "pkg-config --cflags --libs x11 xtst atspi-2 gobject-2.0", "controller link")
    require(stage, '[ -n "${DBUS_SESSION_BUS_ADDRESS:-}" ]', "private accessibility session")
    require(stage, "FLUTTER_PEER_PASSWORD_PROMPT_OK accessible=true retired=true typed_via_xtest=true", "password prompt verdict")
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
            "emit_runtime_logs() {",
            "runtime-log diagnostic selected a non-regular file",
            "runtime-log diagnostic file metadata differs",
            "runtime-log diagnostic exceeds its exact bounds",
            'cat -- "$path" >&2',
        ),
        "bounded owned runtime diagnostics",
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
        require(ready, function, "typed readiness predicate")
        body = ready.split(function, 1)[1].split("\n}", 1)[0]
        require(body, 'ipc_surface_ready "$pid" "$uid"', "owned dual-IPC surface proof")
        require(body, f'typed_ipc_ready "$probe" {expected_state}', "typed IPC state proof")
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
        "Linux runner handled-command contract",
    )
    forbid(linux_runner, "if (!flutter_rustdesk_core_main())", "handled command classified as loader failure")
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
        "narrow loopback rewrite and passthrough",
    )
    if bind_shim.count("21118") != 1:
        raise VerificationError("the bind shim port match is not singular")

    require(controller, 'strstr(title, "127.0.0.1 - Remote Desktop")', "exact viewer title")
    if controller.count("pid != expected_pid") != 2:
        raise VerificationError("X11 and AT-SPI process identities must both be exact")
    require(controller, 'strcmp(hint.res_name, "rustdesk") != 0', "exact X11 instance")
    require(controller, 'strcmp(hint.res_class, "Rustdesk") != 0', "exact X11 class")
    if controller.count("XTestFakeKeyEvent") != 2:
        raise VerificationError("XTest key press/release calls are not exact")
    require(controller, 'static const char password[] = "rustdesk-peer-9f2a7c4e";', "test credential")
    require(controller, "atspi_init() != 0", "private AT-SPI initialization")
    require(controller, "atspi_get_desktop_count() != 1", "single accessibility desktop")
    if controller.count("role == ATSPI_ROLE_PASSWORD_TEXT") != 2:
        raise VerificationError("password-role accounting and readiness must both be exact")
    for state in (
        "ATSPI_STATE_EDITABLE", "ATSPI_STATE_ENABLED", "ATSPI_STATE_SENSITIVE",
        "ATSPI_STATE_VISIBLE", "ATSPI_STATE_FOCUSED", "ATSPI_STATE_FOCUSABLE",
    ):
        require(controller, state, f"password accessible {state}")
    forbid(controller, "ATSPI_STATE_SHOWING", "impossible obscured-password showing state")
    require(controller, "scan.password_nodes == 1U && scan.visible_passwords == 1U", "singular password field")
    require(controller, "scan.password_nodes == 0U", "password-field retirement")
    forbid(controller, "atspi_accessible_get_text", "accessible text/value disclosure")
    require(controller, "g_free(name);", "accessible-name release")
    forbid(controller, "PASSWORD_SETTLE_MS", "blind password-prompt delay")
    require(controller, "AUTH_WAIT_MS 30000U", "authentication deadline")
    require(controller, "FRESH_LIMIT_MS 1000U", "live-frame freshness bound")
    require(controller, "RECOVERY_LIMIT_MS 2500U", "focus-recovery bound")
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
        "/usr/bin/python3 -I -S scripts/verify-flutter-peer-presentation.py --repo .",
        "shared fast source-contract wiring",
    )
    require(sources["readme"], "smoke-flutter-peer-presentation.sh", "harness README inventory")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    arguments = parser.parse_args()
    validate(load(arguments.repo.resolve()))
    print("flutter peer presentation source contract: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
