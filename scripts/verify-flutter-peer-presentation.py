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
            "local cid=$1 expected_network=$2 label=$3\n  local json_path",
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
    require(controller, "AUTH_WAIT_MS 30000U", "authentication deadline")
    require(controller, "FRESH_LIMIT_MS 1000U", "live-frame freshness bound")
    require(controller, "RECOVERY_LIMIT_MS 2500U", "focus-recovery bound")
    require_order(
        controller,
        (
            "type_password(display)",
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
        sources["readme"],
        "smoke-flutter-peer-presentation.sh",
        "harness README inventory",
    )


MUTATIONS = (
    ("host", "local cid=$1 expected_network=$2 label=$3\n  local json_path\n  json_path=", "local cid=$1 expected_network=$2 label=$3 json_path="),
    ("host", "--pull=never --network=none --read-only", "--pull=never --network=host --read-only"),
    ("host", '--network="container:$SERVER_CID" --read-only', "--network=bridge --read-only"),
    ("host", 'source=$EVIDENCE_PUB_CACHE,target=/evidence-pub-cache,readonly', 'source=$EVIDENCE_PUB_CACHE,target=/evidence-pub-cache'),
    ("host", 'host.get("PortBindings") not in (None, {})', "False"),
    ("stage", '[ "$interfaces" = lo ]', '[ -n "$interfaces" ]'),
    ("stage", "--lib --example smoke_readiness --release", "--lib --release"),
    ("stage", '"$READY" --wait-typed-parked "$SERVER_PID" "$SERVER_START"', '"$READY" --wait-tcp-listener "$SERVER_PID" "$SERVER_START"'),
    ("ready", "server_typed_parked() {", "server_typed_parked_removed() {"),
    ("linux_runner", "return EXIT_SUCCESS;", "return EXIT_FAILURE;"),
    ("stage", "! grep -Fq '[SEVERE]'", "true # severe output ignored"),
    ("stage", "export HOME CARGO_HOME CI=true PUB_CACHE=/evidence-online/pub-cache", "export HOME CARGO_HOME CI=true PUB_CACHE=/online/pub-cache"),
    ("stage", '[ -z "${LD_PRELOAD:-}" ]', "true # ambient preload accepted"),
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
    ("controller", 'strcmp(hint.res_name, "rustdesk") != 0', "0"),
    ("controller", 'strcmp(hint.res_class, "Rustdesk") != 0', "0"),
    ("source", "frame = (frame + 1U) & 255U;", "frame = 0U;"),
    ("verify", "/usr/bin/python3 -I -S scripts/verify-flutter-peer-presentation.py --repo . --self-test", "true"),
    ("requirements", '<div class="req"><span class="id">R-S11gc</span>', '<div class="req"><span class="id">R-S11gc-disabled</span>'),
    ("requirements", "existing external <code>smoke-bind-loopback.c</code> confinement shim", "unmanifested compatibility shim"),
    ("requirements", "exact GTK-derived X11 <code>WM_CLASS</code> instance/class pair", "arbitrary X11 class substring"),
    ("hardening", "R-S11gc/R-S11e-216 exact Linux full-peer Flutter presentation evidence", "R-S11gc-disabled/R-S11e-216"),
    ("hardening", "The corrected evidence boundary now compiles the existing audited `smoke-bind-loopback.c`", "The evidence boundary assumes an ambient bind rewrite"),
    ("hardening", "The corrected observer now requires the launcher PID and both exact `WM_CLASS` fields", "The observer accepts any title match"),
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
