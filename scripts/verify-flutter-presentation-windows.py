#!/usr/bin/env python3
"""Verify the isolated native-Windows Flutter presentation evidence contract."""

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
    "host": "scripts/smoke-flutter-presentation-windows.sh",
    "runner": "scripts/run-flutter-presentation-windows.ps1",
    "controller": "scripts/flutter-presentation-probe-windows-controller.ps1",
    "focus_sink": "scripts/flutter-presentation-probe-windows-focus-sink.ps1",
    "dart": "scripts/flutter-presentation-probe-windows.dart",
    "pubspec": "scripts/flutter-presentation-probe-windows-pubspec.yaml",
    "window_pubspec": (
        "scripts/flutter-presentation-probe-desktop-multi-window-pubspec.yaml"
    ),
    "manifest": "scripts/windows-presentation-source-manifest.py",
    "guest_setup": "scripts/win-guest-setup.ps1",
    "golden_inspector": "scripts/windows-golden-inspect.sh",
    "recovery": "flutter/lib/models/presentation_recovery.dart",
    "verify": "scripts/verify.sh",
    "workspace": "scripts/verify-verifier-workspace.py",
    "requirements": "requirements.html",
    "hardening": "HARDENING_STATUS.md",
}


def load(repo: Path) -> dict[str, str]:
    return {
        key: (repo / relative).read_text(encoding="utf-8")
        for key, relative in PATHS.items()
    }


def validate(sources: dict[str, str]) -> None:
    host = sources["host"]
    runner = sources["runner"]
    controller = sources["controller"]
    dart = sources["dart"]
    manifest = sources["manifest"]
    guest_setup = sources["guest_setup"]
    golden_inspector = sources["golden_inspector"]

    require_order(
        host,
        (
            "assert_clean_worktree",
            'verify_sha256 "$GOLDEN" "$SHA256_WIN11_GOLDEN_QCOW2"',
            'capture_listeners >"$LISTENERS_BEFORE"',
            "materialize_source",
            "prepare_disks",
            "launch_domain",
            "wait_for_domain",
            "extract_and_validate",
            "verify_unchanged_inputs",
            "RUN_COMPLETE=1",
        ),
        "host evidence finality",
    )
    require_order(
        host,
        (
            "CURRENT_DOMAIN_CREATION_STARTED=1",
            "setsid --wait virt-install --connect qemu:///session",
            '--network none --graphics vnc,listen=127.0.0.1',
            "CURRENT_DOMAIN_OWNERSHIP_COMMITTED=1",
            "verify_domain_xml",
            'capture_listeners >"$LISTENERS_DURING"',
            "validate_new_listeners",
        ),
        "unprivileged loopback-only VM admission",
    )
    require(host, 'root.findall("./devices/interface")', "zero-interface XML check")
    require(host, "virsh --connect qemu:///session", "unprivileged virsh URI")
    forbid(host, "qemu:///system", "system libvirt URI")
    require(host, 'graphics[0].get("listen") != "127.0.0.1"', "VNC parent check")
    require(host, 'listens[0].get("address") != "127.0.0.1"', "VNC child check")
    require(host, "if not parsed.is_loopback:", "live listener loopback check")
    require(host, "windows_helper_guestfish_run", "device-free disk helper")
    forbid(host, "windows_helper_kvm_guestfish_run", "KVM device helper")
    require(host, "qemu-img create -f qcow2 -F qcow2 -b ../win11-golden.qcow2", "disposable overlay")
    require(host, 'sha256sum "$GOLDEN"', "golden before/after digest")
    require_order(
        host,
        (
            'windows_helper_runtime_resolve "$ONLINE_DIR/build-images/win-helper.docker.tar.gz"',
            "golden_has_contract",
            'die "Windows presentation golden lacks the exact non-expiring-builder contract"',
            "materialize_source",
        ),
        "golden contract before source materialization and VM creation",
    )
    require(
        host,
        "/authority/windows-golden-inspect.sh marker",
        "fixed golden receipt inspector",
    )
    require(host, "DESKTOP_MULTI_WINDOW_COMMIT=b47e8385e5a75d38319ad706a64b0ead3108b093", "window plugin commit")
    require(host, "DESKTOP_MULTI_WINDOW_TREE=ee184480a0e519b9f51f7496d3d90674782481d6", "window plugin tree")
    for unsafe in (
        "sudo ",
        "--privileged",
        "--publish",
        "/dev/kvm",
        "docker.sock",
        "systemctl",
        "ufw ",
        "iptables",
        "nft ",
    ):
        forbid(host, unsafe, "host authority expansion")

    require_order(
        runner,
        (
            "Get-OneSourceRoot",
            "Get-OneOutputRoot",
            "windows-presentation-source-manifest.py",
            "--verify",
            "flutter-presentation-probe-windows.dart",
            "presentation_recovery.dart",
            "flutter-presentation-probe-windows-pubspec.yaml",
            "$resolve = Start-Process -FilePath $flutter",
            "'get', '--offline'",
            "'build', 'windows', '--release', '--no-pub'",
            "flutter-presentation-probe-windows-controller.ps1",
        ),
        "guest exact-source offline build order",
    )
    require(runner, "$env:PUB_CACHE = Join-Path $env:LOCALAPPDATA 'Pub\\Cache'", "pinned golden pub cache")
    require(runner, "windows-presentation-pubspec.lock", "resolved graph receipt")
    require(runner, "Stop-Computer -Force", "disposable guest shutdown")
    for unsafe in ("Invoke-WebRequest", "curl ", "wget ", "Start-Service", "Stop-Service"):
        forbid(runner, unsafe, "guest network/service mutation")

    require_order(
        controller,
        (
            "[void][PresentationProbeNative]::DwmFlush()",
            "DesktopPixel",
            "Publish-Marker 'arm-1'",
            "ShowWindowAsync($window, 6)",
            "Publish-Marker 'hidden-1'",
            "ShowWindowAsync($window, 9)",
            "Wait-Marker 'rearm-requested-1'",
            "Publish-Marker 'allow-rearm-1'",
            "Require-Color $window 'green' 2500",
            "Publish-Marker 'arm-2'",
            "Wait-Foreground $focusWindow",
            "Publish-Marker 'hidden-2'",
            "SetCursorPos",
            "mouse_event(0x0002",
            "Wait-Marker 'pointer-down-2'",
            "Wait-Marker 'rearm-requested-2'",
            "Publish-Marker 'allow-rearm-2'",
            "Require-Color $window 'magenta' 2500",
        ),
        "native transition, pointer, and compositor transaction",
    )
    require(controller, "real_windows_flutter_engine = $true", "Windows engine result")
    require(controller, "real_desktop_compositor_pixels = $true", "pixel result")
    require(controller, "real_guest_pointer_input = $true", "pointer result")
    require(controller, "recovery_limit_ms = 2500", "latency result")
    require(controller, "queued_frames = 128", "coalesced frame result")

    require_order(
        dart,
        (
            "import 'presentation_recovery.dart';",
            "final PresentationRecovery _recovery = PresentationRecovery();",
            "void onWindowBlur()",
            "_suspend('window-blur');",
            "void onWindowFocus()",
            "_resume('window-focus');",
            "void onWindowMinimize()",
            "_suspend('window-minimize');",
            "void onWindowRestore()",
            "_resume('window-restore');",
            "void _pointerDown(PointerDownEvent event)",
            "if (_windowBlurred)",
            "_resume('pointer-down-fallback');",
        ),
        "exact recovery event ownership",
    )
    require(dart, "const _queuedFrameCount = 128;", "latest-wins load")
    require(dart, "FlutterRgbaRendererPluginTryOnRgba", "production C ABI")
    require(dart, "FlutterRgbaRendererPluginTryNotifyPending", "production notifier")
    require(dart, "DynamicLibrary.open('texture_rgba_renderer_plugin.dll')", "production DLL")
    require(dart, "await widget.texture.close();", "texture close finality")
    forbid(dart, "Socket", "probe socket")
    forbid(dart, "HttpClient", "probe HTTP client")

    require(sources["pubspec"], "path: third_party/desktop_multi_window", "local window plugin")
    require(sources["pubspec"], "path: third_party/texture_rgba_renderer", "local texture plugin")
    forbid(sources["pubspec"], "git:", "runtime dependency fetch")
    forbid(sources["pubspec"], "hosted:", "runtime hosted override")
    require(sources["window_pubspec"], "sdk: '>=2.17.0 <4.0.0'", "legacy listener language mode")
    require(sources["focus_sink"], "$form.TopMost = $true", "visible focus sink")
    require(sources["focus_sink"], "Application]::Run($form)", "focus sink message loop")

    require(manifest, 'FORMAT = "rustdesk-windows-presentation-source-v1"', "manifest format")
    require(manifest, "ENTRY_LIMIT = 32768", "manifest entry bound")
    require(manifest, "BYTE_LIMIT = 512 * 1024 * 1024", "manifest aggregate bound")
    require(manifest, "metadata.st_nlink != 1", "single-link source")
    if manifest.count("metadata.st_nlink != 1") != 3:
        raise VerificationError("manifest single-link checks are not exact")
    require(manifest, "not stat.S_ISREG(metadata.st_mode)", "regular source")
    require(manifest, "source paths collide on Windows", "case-collision refusal")
    require(manifest, "runner.read_bytes() != canonical_runner.read_bytes()", "runner equality")
    require(manifest, "actual != manifest[\"files\"]", "exact inventory")

    require_order(
        guest_setup,
        (
            "Get-LocalUser -Name 'builder'",
            "Set-LocalUser -PasswordNeverExpires $true",
            "if ($null -ne $builderAccount.PasswordExpires)",
            "rustdesk-windows-golden-v2",
            "builder-password-never-expires=true",
            "setup-complete=true",
            "Stop-Computer -Force",
        ),
        "non-expiring builder and exact completion receipt",
    )
    require(
        golden_inspector,
        "$'rustdesk-windows-golden-v2\\nbuilder-password-never-expires=true\\nsetup-complete=true'",
        "exact golden receipt validation",
    )
    if golden_inspector.count("EXPECTED_RECEIPT") != 3:
        raise VerificationError("golden receipt definition/use count is not exact")
    require(
        golden_inspector,
        "/usr/bin/tr -d '\\r'",
        "receipt newline normalization",
    )

    require(sources["recovery"], "class PresentationRecovery", "production recovery owner")
    require(
        sources["verify"],
        "/usr/bin/python3 -I -S scripts/verify-flutter-presentation-windows.py --repo . --self-test",
        "shared verifier wiring",
    )
    require(
        sources["workspace"],
        '"windows_presentation_verifier"',
        "independent verifier source binding",
    )
    require(
        sources["requirements"],
        '<span class="id">R-S11gb</span>',
        "native Windows presentation requirement",
    )
    require(
        sources["requirements"],
        "<tr><td>337</td>",
        "native Windows presentation disposition",
    )
    require(
        sources["hardening"],
        "R-S11gb/R-S11e-215 native Windows presentation transaction",
        "native Windows presentation ledger",
    )


def self_test(sources: dict[str, str]) -> None:
    mutations = (
        ("host", "--network none", "--network default"),
        ("host", "--graphics vnc,listen=127.0.0.1", "--graphics vnc"),
        ("host", "virsh --connect qemu:///session", "virsh --connect qemu:///system"),
        ("host", "if not parsed.is_loopback:", "if False:"),
        ("host", "windows_helper_guestfish_run", "windows_helper_kvm_guestfish_run"),
        (
            "host",
            "    golden_has_contract \\\n        || die \"Windows presentation golden lacks the exact non-expiring-builder contract\"",
            "    true # golden contract removed",
        ),
        ("host", "assert_clean_worktree", "true # worktree check removed"),
        ("runner", "'get', '--offline'", "'get'"),
        ("runner", "'build', 'windows', '--release', '--no-pub'", "'build', 'windows'"),
        ("runner", "Stop-Computer -Force", "# guest shutdown removed"),
        (
            "controller",
            "[void][PresentationProbeNative]::DwmFlush()",
            "# DWM synchronization removed",
        ),
        ("controller", "mouse_event(0x0002", "mouse_event(0x0000"),
        ("controller", "Require-Color $window 'green' 2500", "Start-Sleep -Seconds 10"),
        ("controller", "Require-Color $window 'magenta' 2500", "Start-Sleep -Seconds 10"),
        ("dart", "FlutterRgbaRendererPluginTryNotifyPending", "NotifierRemoved"),
        ("dart", "_resume('pointer-down-fallback');", "// pointer recovery removed"),
        ("dart", "await widget.texture.close();", "// texture close removed"),
        ("manifest", "metadata.st_nlink != 1", "False"),
        ("manifest", "actual != manifest[\"files\"]", "False"),
        (
            "guest_setup",
            "Set-LocalUser -PasswordNeverExpires $true",
            "Set-LocalUser -PasswordNeverExpires $false",
        ),
        (
            "guest_setup",
            "if ($null -ne $builderAccount.PasswordExpires)",
            "if ($false)",
        ),
        (
            "golden_inspector",
            "builder-password-never-expires=true",
            "builder-password-never-expires=unchecked",
        ),
        ("verify", "/usr/bin/python3 -I -S scripts/verify-flutter-presentation-windows.py --repo . --self-test", "true # verifier removed"),
        ("requirements", '<span class="id">R-S11gb</span>', '<span class="id">R-S11gb-disabled</span>'),
        ("requirements", "<tr><td>337</td>", "<tr><td>337-disabled</td>"),
        ("hardening", "R-S11gb/R-S11e-215 native Windows presentation transaction", "R-S11gb-disabled/R-S11e-215 native Windows presentation transaction"),
    )
    for index, (key, old, new) in enumerate(mutations, start=1):
        if old not in sources[key]:
            raise VerificationError(f"self-test mutation {index} source is absent")
        mutated = dict(sources)
        mutated[key] = sources[key].replace(old, new, 1)
        try:
            validate(mutated)
        except VerificationError:
            continue
        raise VerificationError(f"self-test mutation {index} was accepted")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=".", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        sources = load(args.repo.resolve())
        validate(sources)
        if args.self_test:
            self_test(sources)
    except (OSError, VerificationError) as error:
        print(f"verify-flutter-presentation-windows: FAIL: {error}")
        return 1
    print("verify-flutter-presentation-windows: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
