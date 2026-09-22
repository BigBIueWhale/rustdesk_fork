#!/usr/bin/env python3
"""Fast source guard for the isolated Linux full-peer runtime transaction.

This checker intentionally protects only the harness's execution authority,
candidate-input identity, and the presence of the native observation path.  It
does not claim that source text proves presented pixels, focus recovery,
reconnect behavior, latency, or cleanup.  Those claims require the no-NIC VM
transaction driven by smoke-verifier-vm-authority.sh.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


class VerificationError(RuntimeError):
    pass


PATHS = {
    "host": "scripts/smoke-flutter-peer-presentation.sh",
    "stage": "scripts/smoke-flutter-peer-presentation-stage.sh",
    "finalizer": "scripts/finalize-flutter-tools-offline.sh",
    "outer": "scripts/smoke-verifier-vm-authority.sh",
    "guest": "scripts/smoke-verifier-vm-authority-guest.sh",
    "pins": "scripts/pins.env",
    "controller": "scripts/flutter-peer-presentation-x11.c",
    "source": "scripts/flutter-peer-source-x11.c",
    "runner": "flutter/linux/my_application.cc",
    "multi_window": "flutter/third_party/desktop_multi_window/linux/flutter_window.cc",
    "verify": "scripts/verify.sh",
}


def load(repo: Path) -> dict[str, str]:
    return {
        name: (repo / relative).read_text(encoding="utf-8")
        for name, relative in PATHS.items()
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


def require_pin(source: str, name: str, pattern: str) -> None:
    if re.search(rf'(?m)^{re.escape(name)}="{pattern}"(?:\s|$)', source) is None:
        raise VerificationError(f"missing or malformed candidate pin: {name}")


def validate(sources: dict[str, str]) -> None:
    host = sources["host"]
    stage = sources["stage"]
    finalizer = sources["finalizer"]
    outer = sources["outer"]
    guest = sources["guest"]
    pins = sources["pins"]
    controller = sources["controller"]
    pixel_source = sources["source"]
    runner = sources["runner"]
    multi_window = sources["multi_window"]

    for token in (
        'dlsym(process, "fl_dart_project_set_enable_impeller")',
        'dlsym(process, "fl_dart_project_get_enable_impeller")',
        "has_setter != has_getter",
        "set_impeller(project, FALSE);",
        "get_impeller(project)",
    ):
        require(runner, token, "SDK-bound Linux renderer selection")
    require_order(
        runner,
        (
            "desktop_multi_window_plugin_set_project_configure_callback(",
            "g_autoptr(FlDartProject) project = fl_dart_project_new();",
            "select_external_pixel_buffer_renderer(project);",
            "FlView* view = fl_view_new(project);",
        ),
        "pre-engine Linux renderer selection",
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
        "pre-engine secondary-window project policy",
    )
    for token in (
        'g_getenv("RUSTDESK_PRESENTATION_TRACE")',
        'g_strcmp0(type, "FlViewRenderer")',
        'GTK_IS_DRAWING_AREA(widget)',
        '"RUSTDESK_PRESENTATION_TRACE stage=gtk-draw monotonic_us=%"',
    ):
        require(multi_window, token, "environment-gated GTK presentation trace")

    require_order(
        host,
        (
            "export PATH=/usr/bin:/bin",
            'readonly HOST_UID="$(/usr/bin/id -u)"',
            "for name in DOCKER_HOST DOCKER_CONFIG DOCKER_CONTEXT DOCKER_CERT_PATH",
            'readonly VERIFIER_VM_ENTRY_PREFLIGHT=$SCRIPT_DIR/verify-vm-entry-preflight.sh',
            '/usr/bin/bash "$VERIFIER_VM_ENTRY_PREFLIGHT"',
            "peer_vm_docker() {",
            'DOCKER_HOST="unix://$VERIFIER_VM_DOCKER_SOCKET"',
            'DOCKER_CONFIG="$VERIFIER_VM_DOCKER_CONFIG"',
            "PEER_VM_AUTHORITY_SELF_TEST=0",
            "assert_clean_worktree",
        ),
        "guest-only workload authority",
    )
    for token in (
        "10:--source-archive)",
        "--flutter-presentation-candidate",
        "Flutter presentation candidate metadata differs",
        "Flutter presentation candidate digest differs",
        "Flutter presentation candidate project lock differs",
        "BUILD_FLUTTER_TOOLS_MODE=offline-resolved",
        "EVIDENCE_PUB_CACHE_SHA256=$SHA256_FLUTTER_PRESENTATION_CANDIDATE_PUB_CACHE",
        "BUILD_PROJECT_LOCK_MODE=candidate-pinned",
        "source=$BUILD_FLUTTER_ARCHIVE,target=/flutter-sdk.tar.xz,readonly",
        "RUSTDESK_FLUTTER_ARCHIVE=/flutter-sdk.tar.xz",
        "FLUTTER_PEER_PRESENTATION_SMOKE_OK",
    ):
        require(host, token, "candidate full-peer workload wiring")
    for token in (
        "--network=none",
        '--network="container:$SERVER_CID"',
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--read-only",
        "inspect_container_contract",
        "run_input_check \"$WORKSPACE/input-pre.cid\"",
        "run_input_check \"$WORKSPACE/input-post.cid\"",
    ):
        require(host, token, "networkless unprivileged container contract")
    for token in (
        "/var/run/docker.sock",
        "--network=host",
        "--publish",
        "--privileged",
        "sudo ",
        "systemctl",
        "ufw ",
        "nft ",
    ):
        forbid(host, token, "host authority expansion")

    require_order(
        stage,
        (
            "input-check)",
            '[ "$RUSTDESK_FLUTTER_ARCHIVE" = /flutter-sdk.tar.xz ]',
            'verify_archive "$RUSTDESK_FLUTTER_ARCHIVE"',
            "build)",
            '[ "$RUSTDESK_FLUTTER_TOOLS_MODE" = offline-resolved ]',
            'tar -C "$TOOLCHAIN" -xf "$RUSTDESK_FLUTTER_ARCHIVE"',
            'if [ "$RUSTDESK_PROJECT_LOCK_MODE" = candidate-pinned ]',
            "RUSTDESK_FLUTTER_CANDIDATE_FRAMEWORK_REVISION",
            "candidate Flutter version manifest digest differs",
            "candidate Flutter engine revision differs",
            "candidate Dart SDK version differs",
            "FLUTTER_PEER_BUILD_PHASE=flutter-tools-offline-start",
            "dart pub get --offline --enforce-lockfile",
            '"$BUILD_SOURCE/scripts/finalize-flutter-tools-offline.sh"',
            "FLUTTER_PEER_BUILD_PHASE=flutter-tools-offline-complete",
            '"$REAL_FLUTTER" --suppress-analytics --version',
            "candidate Flutter invocation rebuilt or changed its pinned SDK state",
            "candidate-pinned)",
            "committed candidate project lock differs from its pin",
            "FLUTTER_PEER_BUILD_PHASE=project-dart-pub-start",
            "dart pub get --offline --enforce-lockfile",
            "FLUTTER_PEER_BUILD_PHASE=project-dart-pub-complete",
            "FLUTTER_PEER_BUILD_PHASE=plugin-injection-start",
            '"$REAL_FLUTTER" --suppress-analytics --no-version-check',
            "pub get --offline --enforce-lockfile",
            "FLUTTER_PEER_BUILD_PHASE=plugin-injection-complete",
            "FLUTTER_PEER_PLUGIN_INPUTS_OK",
            '"$FRB_CODEGEN" --rust-input ./src/flutter_ffi.rs',
            "cargo build --locked --offline --features flutter,unix-file-copy-paste",
            "FLUTTER_PEER_BUILD_PHASE=flutter-build-start",
            "/usr/bin/timeout --signal=TERM --kill-after=30s 1200s",
            '"$REAL_FLUTTER" --suppress-analytics --no-version-check --verbose',
            "build linux --release --no-pub",
            "FLUTTER_PEER_BUILD_PHASE=flutter-build-complete",
            "FLUTTER_PEER_BUILD_OK",
            "FLUTTER_PEER_VIEWER_RUNTIME_OK",
        ),
        "real candidate build and native peer path",
    )
    for token in ("curl ", "wget ", "apt-get", "--privileged", "sudo "):
        forbid(stage, token, "build/runtime acquisition or privilege fallback")
    forbid(stage, "bundled-sdk-candidate", "candidate Flutter-tools freshness bypass")
    require(
        stage,
        '"$REAL_FLUTTER" --suppress-analytics --no-version-check \\\n          pub get --offline --enforce-lockfile',
        "bounded real Flutter offline plugin injection",
    )
    for token in (
        'generated_plugins.cmake"',
        'generated_plugin_registrant.cc"',
        'generated_plugin_registrant.h"',
        "generated native/FFI Flutter plugin lists are absent or ambiguous",
        "generated native/FFI Flutter plugin lists are empty",
        "generated native Linux plugin symlink is missing",
        '"$PUB_CACHE"/*|"$BUILD_SOURCE/flutter"/*',
        "generated native Linux plugin escaped the admitted dependency roots",
        "generated native Linux plugin lacks Linux sources",
        "project pubspec.lock changed during Flutter plugin injection",
    ):
        require(stage, token, "generated Linux plugin input finality")
    for token in (
        "VERSION_MANIFEST=$FLUTTER_ROOT/bin/cache/flutter.version.json",
        'for key in ("frameworkVersion", "flutterVersion")',
        "Flutter version identity is absent or ambiguous",
        "offline Pub package roots do not satisfy Flutter's freshness predicate",
        'marker_tmp="$(mktemp "$DART_TOOL_ROOT/.version.XXXXXXXXXX")"',
        'printf \'%s\' "$EXPECTED_VERSION" > "$marker_tmp"',
        '&& [ "$(<"$MARKER")" = "$EXPECTED_VERSION" ]',
    ):
        require(finalizer, token, "cross-version Flutter-tools finalization")

    require_order(
        outer,
        (
            "1:--flutter-peer-presentation-candidate)",
            "FLUTTER_PEER_CANDIDATE=1",
            "SEALED_INPUT_ROOT=$REPO_ROOT/online",
            '--shared-dir "$SEALED_INPUT_ROOT"',
            "candidate Flutter-peer authority root inventory differs",
            "candidate Flutter-peer project lock differs",
            "sealed selected Flutter-peer Pub-cache root metadata differs",
            'guest_invocation+=" --flutter-peer-presentation-candidate',
            '-nic none',
            "FLUTTER_PEER_PRESENTATION_SMOKE_OK commit=",
            "FLUTTER_PEER_PRESENTATION_VM=pass commit=",
            "FLUTTER_PEER_PRESENTATION_VM_OUTER=pass",
        ),
        "no-NIC candidate VM transaction",
    )
    for token in (
        'capture_listeners >"$LISTENERS_BEFORE"',
        'capture_listeners >"$LISTENERS_DURING"',
        'capture_listeners >"$LISTENERS_AFTER"',
        '"$FLUTTER_PEER_FLUTTER_ARCHIVE"',
        "focused_inputs_before=\"$(flutter_peer_input_inventory)\"",
        "focused_inputs_after=\"$(flutter_peer_input_inventory)\"",
        "flutter=$FLUTTER_PEER_FLUTTER_VERSION tools=$FLUTTER_PEER_TOOLS_MODE",
        "candidate=$FLUTTER_PEER_CANDIDATE",
    ):
        require(outer, token, "candidate identity and finality")
    for token in ("hostfwd", "-net user", "-nic user", "-vnc", "--network=host", "sudo "):
        forbid(outer, token, "host network or privilege expansion")

    require_order(
        guest,
        (
            "12:--flutter-peer-presentation-candidate)",
            "FLUTTER_PEER_CANDIDATE=1",
            "run_flutter_peer_presentation() {",
            "mount -t virtiofs -o ro,nodev,nosuid,noexec rustdesk-sealed-inputs",
            "candidate Flutter-peer authority root inventory differs",
            "candidate Flutter SDK archive differs",
            "candidate Flutter project lock differs",
            "candidate Flutter Pub cache metadata differs",
            'mount --bind "$inputs" "$source_root/online/inputs"',
            'peer_args+=(--flutter-presentation-candidate "$candidate_archive")',
            "candidate Flutter SDK archive changed during execution",
            "FLUTTER_PEER_PRESENTATION_VM=pass commit=",
        ),
        "guest candidate admission and cleanup",
    )
    for token in (
        "--bridge none",
        "--iptables=false",
        "--ip6tables=false",
        "--ip-forward=false",
        "--ip-masq=false",
        "--userland-proxy=false",
        "networkless VM has an unexpected interface inventory",
        "guest Docker created an INET listener",
    ):
        require(guest, token, "guest network isolation")
    for token in ("--network=host", "--privileged", "sudo ", "/var/run/docker.sock"):
        forbid(guest, token, "guest authority fallback")

    require_pin(pins, "FLUTTER_PRESENTATION_CANDIDATE_VERSION", r"3\.47\.5")
    require_pin(pins, "SHA256_FLUTTER_PRESENTATION_CANDIDATE", r"[0-9a-f]{64}")
    require_pin(pins, "SIZE_FLUTTER_PRESENTATION_CANDIDATE", r"[1-9][0-9]*")
    require_pin(pins, "FLUTTER_PRESENTATION_CANDIDATE_FRAMEWORK_REVISION", r"[0-9a-f]{40}")
    require_pin(pins, "FLUTTER_PRESENTATION_CANDIDATE_ENGINE_REVISION", r"[0-9a-f]{40}")
    require_pin(pins, "FLUTTER_PRESENTATION_CANDIDATE_DART_VERSION", r"3\.13\.4")
    require_pin(pins, "SHA256_FLUTTER_PRESENTATION_CANDIDATE_VERSION_JSON", r"[0-9a-f]{64}")
    require_pin(pins, "SHA256_FLUTTER_PRESENTATION_CANDIDATE_TOOLS_LOCK", r"[0-9a-f]{64}")
    require_pin(pins, "SHA256_FLUTTER_PRESENTATION_CANDIDATE_PROJECT_LOCK", r"[0-9a-f]{64}")
    require_pin(pins, "SHA256_FLUTTER_PRESENTATION_CANDIDATE_PUB_CACHE", r"[0-9a-f]{64}")

    for token in (
        "XGetImage(",
        "XTestFakeKeyEvent(",
        "atspi_text_get_character_count(",
        "wait_for_current_frames(",
        "same_connection(",
        "resources_are_bounded(",
        "FOCUS_CYCLE_COUNT 3U",
        "RECONNECT_COUNT 3U",
        "FRESH_LIMIT_MS 1000U",
        "RECOVERY_LIMIT_MS 2500U",
    ):
        require(controller, token, "native presentation observer")
    require_order(
        pixel_source,
        (
            "back_buffer = XCreatePixmap(",
            "XFillRectangle(display, back_buffer, graphics",
            "XCopyArea(display, back_buffer, window, graphics",
            "XSync(display, False);",
            "frame = (frame + 1U) & 255U;",
        ),
        "atomically published changing source pixels",
    )
    forbid(controller, "system(", "controller shell escape")

    require(
        sources["verify"],
        "/usr/bin/python3 -I -S scripts/verify-flutter-peer-presentation.py --repo .",
        "fast source guard wiring",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        validate(load(arguments.repo.resolve()))
    except (OSError, VerificationError) as error:
        print(f"flutter peer presentation source guard: FAIL: {error}", file=sys.stderr)
        return 1
    print("flutter peer presentation source guard: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
