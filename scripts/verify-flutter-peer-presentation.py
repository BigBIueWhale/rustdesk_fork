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
    "controller": "scripts/flutter-peer-presentation-x11.c",
    "source": "scripts/flutter-peer-source-x11.c",
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
    controller = sources["controller"]
    source = sources["source"]

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
            "cargo build --locked --features flutter,unix-file-copy-paste --lib --release",
            '"$REAL_FLUTTER" build linux --release --no-pub',
            "readelf --wide --dyn-syms",
            "FLUTTER_PEER_BUILD_OK",
        ),
        "exact offline full-product bundle build",
    )
    require(stage, "cp -a /source/. \"$BUILD_SOURCE/\"", "private writable build copy")
    require(stage, "export HOME CARGO_HOME CI=true PUB_CACHE=/evidence-online/pub-cache", "current-lock sealed Pub cache")
    require(stage, "assert_loopback_only_interface", "runtime loopback-only inspection")
    require(stage, '[ "$interfaces" = lo ]', "sole loopback interface")
    require(stage, '0100007F:527E', "exact 127.0.0.1:21118 listener")
    require(stage, '[ "$(udp_socket_count)" -eq 0 ]', "zero UDP runtime surface")
    require_order(
        stage,
        (
            "export DISPLAY=:98 HOME=/tmp/server-home",
            "start_xvfb :98 640x480x24",
            '"$SOURCE_FIXTURE" >/tmp/source.log',
            "--password-stdin",
            '(cd /out/bundle && exec "$APP" --server)',
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
    for unsafe in ("sudo ", "--privileged", "systemctl", "ufw ", "iptables", "nft "):
        forbid(stage, unsafe, "runtime authority expansion")

    require(source, "The two independently colored halves encode one of 256", "source-state contract")
    require(source, "frame = (frame + 1U) & 255U;", "256-state source cadence")
    require(source, "attributes.override_redirect = True;", "source fixture isolation")
    require(source, "sigaction(SIGTERM", "source fixture teardown")

    require(controller, 'strstr(title, "127.0.0.1 - Remote Desktop")', "exact real viewer title")
    require(controller, "pid != expected_pid", "viewer process identity")
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
    require(sources["requirements"], "<tr><td>338</td>", "Appendix C evidence row")
    require(
        sources["hardening"],
        "R-S11gc/R-S11e-216 exact Linux full-peer Flutter presentation evidence",
        "hardening evidence ledger",
    )
    require(
        sources["readme"],
        "smoke-flutter-peer-presentation.sh",
        "harness README inventory",
    )


MUTATIONS = (
    ("host", "--pull=never --network=none --read-only", "--pull=never --network=host --read-only"),
    ("host", '--network="container:$SERVER_CID" --read-only', "--network=bridge --read-only"),
    ("host", 'source=$EVIDENCE_PUB_CACHE,target=/evidence-pub-cache,readonly', 'source=$EVIDENCE_PUB_CACHE,target=/evidence-pub-cache'),
    ("host", 'host.get("PortBindings") not in (None, {})', "False"),
    ("stage", '[ "$interfaces" = lo ]', '[ -n "$interfaces" ]'),
    ("stage", "cargo build --locked --features flutter,unix-file-copy-paste --lib --release", "cargo build --release"),
    ("stage", "! grep -Fq '[SEVERE]'", "true # severe output ignored"),
    ("stage", "export HOME CARGO_HOME CI=true PUB_CACHE=/evidence-online/pub-cache", "export HOME CARGO_HOME CI=true PUB_CACHE=/online/pub-cache"),
    ("stage", "--password-stdin", "--password rustdesk-peer-9f2a7c4e"),
    ("stage", '"$CONTROLLER" :98 :99 "$VIEWER_PID"', '"$CONTROLLER" :99 :99 "$VIEWER_PID"'),
    ("controller", "FRESH_LIMIT_MS 1000U", "FRESH_LIMIT_MS 10000U"),
    ("controller", "RECOVERY_LIMIT_MS 2500U", "RECOVERY_LIMIT_MS 10000U"),
    ("controller", "left->inode == right->inode", "1"),
    ("controller", "XTestFakeKeyEvent", "RemovedFakeKeyEvent"),
    ("source", "frame = (frame + 1U) & 255U;", "frame = 0U;"),
    ("verify", "/usr/bin/python3 -I -S scripts/verify-flutter-peer-presentation.py --repo . --self-test", "true"),
    ("requirements", '<div class="req"><span class="id">R-S11gc</span>', '<div class="req"><span class="id">R-S11gc-disabled</span>'),
    ("hardening", "R-S11gc/R-S11e-216 exact Linux full-peer Flutter presentation evidence", "R-S11gc-disabled/R-S11e-216"),
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
