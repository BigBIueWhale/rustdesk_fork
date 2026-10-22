#!/usr/bin/env python3
"""Focused source contract for the isolated Linux full-peer harness.

Only a completed no-NIC VM transaction establishes runtime evidence. This
supplementary check binds the maintained authority and native-observation paths;
it does not establish presented pixels, latency, recovery, or cleanup.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


class VerificationError(RuntimeError):
    pass


PATHS = {
    "peer": "scripts/smoke-flutter-peer-presentation.sh",
    "stage": "scripts/smoke-flutter-peer-presentation-stage.sh",
    "outer": "scripts/smoke-verifier-vm-authority.sh",
    "guest": "scripts/smoke-verifier-vm-authority-guest.sh",
    "controller": "scripts/flutter-peer-presentation-x11.c",
    "runner": "flutter/linux/my_application.cc",
    "multi_window": "flutter/third_party/desktop_multi_window/linux/flutter_window.cc",
    "verify": "scripts/verify.sh",
}


def require(source: str, needle: str, label: str) -> None:
    if needle not in source:
        raise VerificationError(f"missing {label}: {needle!r}")


def forbid(source: str, needle: str, label: str) -> None:
    if needle in source:
        raise VerificationError(f"forbidden {label}: {needle!r}")


def require_order(source: str, needles: tuple[str, ...], label: str) -> None:
    cursor = -1
    for needle in needles:
        cursor = source.find(needle, cursor + 1)
        if cursor < 0:
            raise VerificationError(f"{label}: missing or misordered {needle!r}")


def validate(sources: dict[str, str]) -> None:
    peer = sources["peer"]
    stage = sources["stage"]
    outer = sources["outer"]
    guest = sources["guest"]
    runner = sources["runner"]
    multi_window = sources["multi_window"]

    require_order(
        peer,
        (
            'readonly HOST_UID="$(/usr/bin/id -u)"',
            '[ "$HOST_UID" -ne 0 ]',
            '[ "$HOST_GID" -ne 0 ]',
            "for name in DOCKER_HOST DOCKER_CONFIG DOCKER_CONTEXT DOCKER_CERT_PATH",
            '/usr/bin/bash "$VERIFIER_VM_ENTRY_PREFLIGHT"',
            'source "$SCRIPT_DIR/lib.sh"',
            "readonly VERIFIER_VM_AUTHORITY_ROOT=/run/rustdesk-verifier-vm",
            "readonly VERIFIER_VM_DOCKER_CLIENT=/usr/bin/docker",
            "readonly VERIFIER_VM_DOCKER_SOCKET=$VERIFIER_VM_AUTHORITY_ROOT/docker.sock",
            "readonly VERIFIER_VM_DOCKER_CONFIG=$VERIFIER_VM_AUTHORITY_ROOT/docker-config",
            "peer_vm_docker() {",
        ),
        "VM admission before workload inputs",
    )
    docker = peer.split("peer_vm_docker() {\n", 1)[1].split("\n}\n", 1)[0]
    require_order(
        docker,
        (
            '/usr/bin/bash "$VERIFIER_VM_ENTRY_PREFLIGHT" >/dev/null || return 1',
            "/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C HOME=/nonexistent",
            'DOCKER_HOST="unix://$VERIFIER_VM_DOCKER_SOCKET"',
            'DOCKER_CONFIG="$VERIFIER_VM_DOCKER_CONFIG"',
            '"$VERIFIER_VM_DOCKER_CLIENT"',
            '--host "unix://$VERIFIER_VM_DOCKER_SOCKET"',
            '--config "$VERIFIER_VM_DOCKER_CONFIG" "$@"',
            '/usr/bin/bash "$VERIFIER_VM_ENTRY_PREFLIGHT" >/dev/null || return 1',
            'return "$status"',
        ),
        "fixed guest Docker channel with generation replay",
    )
    require_order(
        peer,
        (
            "SUPPLIED_SOURCE_ARCHIVE_SHA256=$8",
            'SOURCE_ARCHIVE=$SUPPLIED_SOURCE_ARCHIVE',
            '[ "$SOURCE_ARCHIVE_SHA256" = "$SUPPLIED_SOURCE_ARCHIVE_SHA256" ]',
            'tar -xf "$SOURCE_ARCHIVE" -C "$SOURCE_SNAPSHOT"',
            'chmod -R a-w "$SOURCE_SNAPSHOT"',
        ),
        "digest-bound read-only source snapshot",
    )
    for token in (
        "--replay-app", "--app-manifest-sha256", "--engine-context",
        "--network=none", '--network="container:$SERVER_CID"',
        '--user "$HOST_UID:$HOST_GID"', "--cap-drop=ALL",
        "--security-opt=no-new-privileges", "--read-only",
        'inspect_container_contract "$SERVER_CID" none server',
        'inspect_container_contract "$VIEWER_CID" "container:$SERVER_CID" viewer',
        "FLUTTER_PEER_PRESENTATION_SMOKE_OK",
    ):
        require(peer, token, "source-bound isolated peer execution")
    for token in (
        "/var/run/docker.sock", "--network=host", "--publish", "--privileged",
        "sudo ", "systemctl", "ufw ", "nft ",
    ):
        forbid(peer, token, "host authority expansion")

    require_order(
        outer,
        ("vm_storage_preflight", "reserve_vm_storage", "-nic none"),
        "admitted bounded-RAM no-NIC VM",
    )
    for source, manifest, receipt in (
        (outer, "FLUTTER_APP_EXPECTED_MANIFEST_SHA256", "LINUX_FLUTTER_APP_REPLAY_VM_OUTER=pass"),
        (guest, "FLUTTER_APP_MANIFEST_SHA256", "LINUX_FLUTTER_APP_REPLAY_VM=pass"),
    ):
        for token in (
            "--linux-flutter-app-replay", "FLUTTER_APP_REPLAY=1",
            manifest, receipt,
        ):
            require(source, token, "current app replay identity and receipt")
    for token in (
        "capture_listeners >\"$LISTENERS_BEFORE\"",
        "capture_listeners >\"$LISTENERS_DURING\"",
        "capture_listeners >\"$LISTENERS_AFTER\"",
    ):
        require(outer, token, "host listener observations")
    require(
        guest,
        "mount -t virtiofs -o ro,nodev,nosuid,noexec rustdesk-sealed-inputs",
        "read-only sealed guest inputs",
    )
    for token in (
        "--bridge none", "--iptables=false", "--ip6tables=false",
        "--ip-forward=false", "--ip-masq=false", "--userland-proxy=false",
        "networkless VM has an unexpected interface inventory",
        "guest Docker created an INET listener",
    ):
        require(guest, token, "guest network isolation")
    for source in (outer, guest):
        for token in ("--network=host", "--privileged", "sudo "):
            forbid(source, token, "VM authority fallback")
    for token in ("hostfwd", "-net user", "-nic user", "-vnc"):
        forbid(outer, token, "host network expansion")

    require_order(
        stage,
        (
            '--connect 127.0.0.1',
            'VIEWER_START=$("$READY" --identity "$VIEWER_PID")',
            'controller_args=(:98 :99 "$VIEWER_PID" "$VIEWER_START")',
            '"$CONTROLLER" "${controller_args[@]}"',
            'if [ "$controller_status" -ne 0 ]; then',
            'exit "$controller_status"',
            "FLUTTER_PEER_PASSWORD_PROMPT_OK",
            "FLUTTER_PEER_PRESENTATION_OK",
            "FLUTTER_PEER_VIEWER_RUNTIME_OK",
        ),
        "real viewer, exact identity, native controller and checked result",
    )
    for token in (
        "XTestFakeKeyEvent(", "atspi_text_get_character_count(",
        "wait_for_current_frames(", "same_connection(",
        "resources_are_bounded(",
    ):
        require(sources["controller"], token, "native presentation observer")
    forbid(sources["controller"], "system(", "controller shell escape")

    for token in (
        'dlsym(process, "fl_dart_project_set_enable_impeller")',
        'dlsym(process, "fl_dart_project_get_enable_impeller")',
        "has_setter != has_getter", "set_impeller(project, FALSE);",
        "get_impeller(project)",
    ):
        require(runner, token, "SDK-bound renderer selection")
    require_order(
        runner,
        (
            "desktop_multi_window_plugin_set_project_configure_callback(",
            "g_autoptr(FlDartProject) project = fl_dart_project_new();",
            "select_external_pixel_buffer_renderer(project);",
            "FlView* view = fl_view_new(project);",
        ),
        "pre-engine primary-window renderer policy",
    )
    forbid(runner, "FLUTTER_ENGINE_SWITCH", "ambient renderer selection")
    require_order(
        multi_window,
        (
            "project = fl_dart_project_new();",
            "if (_g_project_configure_callback == nullptr)",
            "_g_project_configure_callback(project);",
            "FlView* fl_view = fl_view_new(project);",
        ),
        "pre-engine secondary-window renderer policy",
    )
    require(
        sources["verify"],
        "/usr/bin/python3 -I -S scripts/verify-flutter-peer-presentation.py --repo .",
        "shared verification gate",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        repo = arguments.repo.resolve()
        sources = {
            name: (repo / relative).read_text(encoding="utf-8")
            for name, relative in PATHS.items()
        }
        validate(sources)
    except (OSError, VerificationError) as error:
        print(f"flutter peer presentation source guard: FAIL: {error}", file=sys.stderr)
        return 1
    print("flutter peer presentation source guard: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
