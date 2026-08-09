#!/usr/bin/env python3
"""Verify the isolated native-Windows Flutter presentation evidence contract."""

from __future__ import annotations

import argparse
import hashlib
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
    "d3d11": "scripts/flutter-presentation-d3d11-preflight-windows.cpp",
    "dart": "scripts/flutter-presentation-probe-windows.dart",
    "pubspec": "scripts/flutter-presentation-probe-windows-pubspec.yaml",
    "pubspec_lock": "scripts/flutter-presentation-probe-windows-pubspec.lock",
    "window_pubspec": (
        "scripts/flutter-presentation-probe-desktop-multi-window-pubspec.yaml"
    ),
    "size_pubspec": "scripts/flutter-presentation-probe-window-size-pubspec.yaml",
    "manifest": "scripts/windows-presentation-source-manifest.py",
    "pub_cache_output": "scripts/online-pub-cache-output.py",
    "pub_cache_projection": "scripts/windows-presentation-pub-cache.py",
    "pins": "scripts/pins.env",
    "provision": "scripts/provision-windows-vm.sh",
    "guest_setup": "scripts/win-guest-setup.ps1",
    "golden_inspector": "scripts/windows-golden-inspect.sh",
    "libyuv_port": "res/vcpkg/libyuv/portfile.cmake",
    "recovery": "flutter/lib/models/presentation_recovery.dart",
    "multi_window_upstream": "flutter/third_party/desktop_multi_window/UPSTREAM.md",
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
    d3d11 = sources["d3d11"]
    dart = sources["dart"]
    manifest = sources["manifest"]
    pubspec_lock = sources["pubspec_lock"]
    pub_cache_output = sources["pub_cache_output"]
    pub_cache_projection = sources["pub_cache_projection"]
    pins = sources["pins"]
    provision = sources["provision"]
    guest_setup = sources["guest_setup"]
    golden_inspector = sources["golden_inspector"]
    libyuv_port = sources["libyuv_port"]

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
            'die "Windows presentation golden lacks the exact interactive-builder contract"',
            "materialize_source",
        ),
        "golden contract before source materialization and VM creation",
    )
    require(
        host,
        "/authority/windows-golden-inspect.sh marker",
        "fixed golden receipt inspector",
    )
    require(
        pins,
        'SHA256_WINDOWS_PRESENTATION_PUB_CACHE_CLOSURE_V1="fe81f679a0a1acd8291472162e867a566f33a50c813d27775125cee4644736b4"',
        "dedicated Windows presentation Pub-cache authority pin",
    )
    require(
        pins,
        'SHA256_WINDOWS_PRESENTATION_PUBSPEC_LOCK="e1fbe433a385594ed67dfd0bfd9b65be5f9cd07865e6ee190c9193a737648038"',
        "exact Windows presentation lock pin",
    )
    require(
        pins,
        'SHA256_WINDOWS_PRESENTATION_PUB_CACHE_PROJECTION_V1="949ad80194975f2a64253a4b59cad9051105cada07137b5e7de39d034f4cc1ea"',
        "exact Windows presentation projected Pub-cache pin",
    )
    require(
        pub_cache_output,
        "def check_complete(online: Path, uid: int, gid: int) -> TreeSummary:",
        "read-only complete Pub-cache validator",
    )
    require_order(
        host,
        (
            'check-complete --online /online',
            '"sha256=$PRESENTATION_PUB_CACHE_SHA256"',
            'mkdir -m 0700 -p',
            'for specification in "${PRESENTATION_HOSTED_PACKAGES[@]}"; do',
            'observed_hash="$(tr -d \'\\r\\n\' <"$hash_source")"',
            'cp -a -- "$source" "$projection/hosted/pub.dev/$package"',
            "/source/scripts/windows-presentation-pub-cache.py",
            '--expected-digest "$PRESENTATION_PUB_CACHE_PROJECTION_SHA256"',
            "files=346 directories=82 symlinks=0 size=5666684 packages=8",
            "source_sha256=%s projection_sha256=%s packages=8 semantics=exact-probe-lock",
        ),
        "exact read-only app-cache projection",
    )
    require_order(
        host,
        (
            '"$WINDOWS_HELPER_BUILD_UID:$WINDOWS_HELPER_BUILD_GID:500"',
            'PRESENTATION_PUB_CACHE_ID="$(stat -c \'%d:%i:%u:%g:%a\' "$PRESENTATION_PUB_CACHE")"',
            'windows_helper_authority_open',
            'windows_helper_runtime_resolve "$ONLINE_DIR/build-images/win-helper.docker.tar.gz"',
            "golden_has_contract",
        ),
        "presentation input authority before materialization",
    )
    require_order(
        host,
        (
            "scripts/flutter-presentation-probe-windows-pubspec.lock",
            "scripts/online-pub-cache-output.py",
            "scripts/windows-presentation-pub-cache.py",
            "verify_sha256",
            '"$SOURCE_ROOT/scripts/flutter-presentation-probe-windows-pubspec.lock"',
            "project_presentation_pub_cache",
            "windows-presentation-source-manifest.py",
        ),
        "pinned lock and cache projection before source manifest",
    )
    require_order(
        host,
        (
            "verify_unchanged_inputs() {",
            'stat -c \'%d:%i:%u:%g:%a\' "$PRESENTATION_PUB_CACHE"',
            '"$PRESENTATION_PUB_CACHE_ID"',
            'die "Windows presentation source Pub-cache identity changed"',
            "assert_clean_worktree",
        ),
        "post-run app-cache identity check",
    )
    require(
        host,
        '"presentation_pub_cache_sha256": pub_cache',
        "host evidence app-cache identity",
    )
    require(
        host,
        '"presentation_pub_cache_projection_sha256": pub_cache_projection',
        "host evidence projected app-cache identity",
    )
    require(
        host,
        '"presentation_pubspec_lock_sha256": pubspec_lock',
        "host evidence exact-lock identity",
    )
    if host.count("SHA256_WINDOWS_PRESENTATION_PUBSPEC_LOCK") != 3:
        raise VerificationError("Windows presentation exact-lock pin use is not exact")
    presentation_package_identities = (
        "characters-1.3.0:04a925763edad70e8443c99234dc3328f442e811f1d8fd1a72f1c8ad0f69a605",
        "collection-1.18.0:ee67cb0715911d28db6bf4af1026078bd6f0128b07a5f66fb2ed94ec6783c09a",
        "material_color_utilities-0.11.1:f7142bb1154231d7ea5f96bc7bde4bda2a0945d2806bb11670e30b850d56bdec",
        "meta-1.15.0:bdb68674043280c3428e9ec998512fb681678676b3c54e773629ffe74419f8c7",
        "plugin_platform_interface-2.1.8:4820fbfdb9478b1ebae27888254d445073732dae3d6ea81f0b7e06d5dedc3f02",
        "url_launcher_platform_interface-2.3.2:552f8a1e663569be95a8190206a38187b531910283c3e982193e4f2733f01029",
        "url_launcher_windows-3.1.4:3284b6d2ac454cf34f114e1d3319866fdd1e19cdc329999057e44ffe936cfa77",
        "vector_math-2.1.4:80b3257d1492ce4d091729e3a67a60407d227c27241d6927be0130c98e741803",
    )
    if len(presentation_package_identities) != 8:
        raise VerificationError("Windows presentation package identity inventory is not exact")
    for identity in presentation_package_identities:
        require(host, identity, f"projected hosted package identity {identity.split(':', 1)[0]}")
        require(
            pub_cache_projection,
            identity.split(":", 1)[0],
            f"independent projected package identity {identity.split(':', 1)[0]}",
        )
    require(
        pub_cache_projection,
        "summary.digest != expected_digest",
        "projected cache digest validation",
    )
    require(
        pub_cache_projection,
        "summary.files != EXPECTED_FILES",
        "projected cache file cardinality validation",
    )
    require(
        pub_cache_projection,
        "summary.directories != EXPECTED_DIRECTORIES",
        "projected cache directory cardinality validation",
    )
    require(
        pub_cache_projection,
        "summary.symlinks != 0",
        "projected cache symlink validation",
    )
    require(
        pub_cache_projection,
        "summary.size != EXPECTED_SIZE",
        "projected cache byte cardinality validation",
    )
    require(
        pub_cache_projection,
        'exact_names(root, {"hosted", "hosted-hashes"}, "projection root", True)',
        "projected cache exact-root validation",
    )
    require(host, "WINDOW_SIZE_COMMIT=eb3964990cf19629c89ff8cb4a37640c7b3d5601", "window-size commit")
    require(host, "WINDOW_SIZE_TREE=c1b4ec4f759387d00f1024ce539487242cd7ae1a", "window-size subtree")
    if host.count("scripts/flutter-presentation-probe-window-size-pubspec.yaml") != 2:
        raise VerificationError("window-size replacement pubspec inclusion is not exact")
    if host.count("scripts/flutter-presentation-d3d11-preflight-windows.cpp") != 1:
        raise VerificationError("D3D11 preflight source inclusion is not exact")
    if host.count('"window_association_hresult",') != 2:
        raise VerificationError("host window-association outcome validators are not exact")
    require_order(
        host,
        (
            "flutter/third_party/desktop_multi_window",
            'vendored_window_source="$SOURCE_ROOT/flutter/third_party/desktop_multi_window"',
            '[ -d "$vendored_window_source" ] && [ ! -L "$vendored_window_source" ]',
            'mv -- "$vendored_window_source" "$SOURCE_ROOT/third_party/desktop_multi_window"',
            "flutter-presentation-probe-desktop-multi-window-pubspec.yaml",
        ),
        "exact-commit vendored desktop multi-window materialization",
    )
    forbid(host, "rustdesk_desktop_multi_window-*", "retired ambient window-plugin cache selector")
    require_order(
        host,
        (
            "-name 'flutter-desktop-embedding-*' -print0",
            'rev-parse "$WINDOW_SIZE_COMMIT^{commit}"',
            'rev-parse "$WINDOW_SIZE_COMMIT:plugins/window_size"',
            'archive --format=tar "$WINDOW_SIZE_COMMIT:plugins/window_size"',
            "flutter-presentation-probe-window-size-pubspec.yaml",
            "third_party/window_size/.rustdesk-source-identity.json",
            "windows_helper_small_run",
        ),
        "exact window-size source materialization",
    )
    require(
        host,
        '"url_launcher_windows": (',
        "resolved URL-launcher package receipt",
    )
    require(
        host,
        '"window_size": (',
        "resolved window-size package receipt",
    )
    for digest, label in (
        (
            "4820fbfdb9478b1ebae27888254d445073732dae3d6ea81f0b7e06d5dedc3f02",
            "plugin-platform-interface package content identity",
        ),
        (
            "552f8a1e663569be95a8190206a38187b531910283c3e982193e4f2733f01029",
            "URL-launcher-interface package content identity",
        ),
        (
            "3284b6d2ac454cf34f114e1d3319866fdd1e19cdc329999057e44ffe936cfa77",
            "URL-launcher package content identity",
        ),
    ):
        require(host, digest, label)
    require(
        host,
        "for package, (source, version, dependency, identity) in expected_packages.items():",
        "complete resolved-package identity validation",
    )
    require(
        host,
        '  dart: ">=3.4.0 <4.0.0"',
        "resolved Dart SDK envelope",
    )
    require_order(
        host,
        (
            '"windows-presentation-d3d11-preflight.json",',
            "diagnostic_progress = [",
            '"d3d11-preflight"',
            '"rustdesk-windows-d3d11-preflight-v1"',
            '"window_association_hresult",',
            'for field, expected_name in (("default_adapter", "default-adapter"), ("warp", "warp")):',
            're.fullmatch(r"0x[0-9A-F]{8}", value)',
            'print("windows presentation D3D11 preflight: validated")',
            'progress not in (diagnostic_progress, [*diagnostic_progress, "probe-passed"])',
            'unexpected presentation progress after validated D3D11 preflight',
            'raise SystemExit("guest presentation runner recorded failure after validated D3D11 preflight")',
            'if progress != [*diagnostic_progress, "probe-passed"]:',
            '"guest_d3d11_preflight_sha256": digest(',
        ),
        "host D3D11 diagnostic evidence binding",
    )
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
            "$sourcePubCache = Join-Path $sourceRoot 'pub-cache'",
            "$expectedPubCacheIdentity = 'source_sha256=fe81f679a0a1acd8291472162e867a566f33a50c813d27775125cee4644736b4 projection_sha256=949ad80194975f2a64253a4b59cad9051105cada07137b5e7de39d034f4cc1ea packages=8 semantics=exact-probe-lock'",
            "Get-ChildItem -LiteralPath $sourcePubCache -Force",
            "'hosted,hosted-hashes'",
            "$env:PUB_CACHE = Join-Path $workRoot 'pub-cache'",
            "foreach ($cacheRoot in @('hosted', 'hosted-hashes'))",
            "$expectedPackages = [ordered]@{",
            "foreach ($package in $expectedPackages.Keys)",
            "flutter-presentation-probe-windows.dart",
            "presentation_recovery.dart",
            "flutter-presentation-probe-windows-pubspec.yaml",
            "flutter-presentation-probe-windows-pubspec.lock",
            "$probeLockBefore = (Get-FileHash -LiteralPath $probeLock -Algorithm SHA256).Hash.ToLowerInvariant()",
            "flutter-presentation-d3d11-preflight-windows.cpp",
            r"third_party\window_size",
            "$resolve = Start-Process -FilePath $flutter",
            "'get', '--offline', '--enforce-lockfile'",
            "presentation Pub lock changed during enforced offline resolution",
            "'build', 'windows', '--release', '--no-pub'",
            "rustdesk_d3d11_preflight.exe",
            "windows-presentation-d3d11-preflight.json",
            "$d3d11PreflightRun.WaitForExit(30000)",
            "$d3d11PreflightRun.Kill()",
            "$d3d11PreflightRun.WaitForExit(5000)",
            "$d3d11PreflightRun.WaitForExit()",
            "$d3d11PreflightRun.Refresh()",
            "$d3d11PreflightRun.Dispose()",
            "native D3D11 preflight produced no typed exit status",
            "'format,default_adapter,warp'",
            "'rustdesk-windows-d3d11-preflight-v1'",
            "'^0x[0-9A-F]{8}$'",
            "flutter-presentation-probe-windows-controller.ps1",
        ),
        "guest exact-source offline build order",
    )
    forbid(runner, "Join-Path $env:LOCALAPPDATA 'Pub\\Cache'", "golden app-cache authority")
    forbid(runner, "pinned golden pub cache", "retired golden app-cache diagnostic")
    require(runner, "url_launcher_windows-3.1.4' = '3284b6d2ac454cf34f114e1d3319866fdd1e19cdc329999057e44ffe936cfa77'", "pinned URL-launcher cache")
    require(runner, "url_launcher_platform_interface-2.3.2' = '552f8a1e663569be95a8190206a38187b531910283c3e982193e4f2733f01029'", "pinned URL-launcher interface cache")
    require(runner, "plugin_platform_interface-2.1.8' = '4820fbfdb9478b1ebae27888254d445073732dae3d6ea81f0b7e06d5dedc3f02'", "pinned plugin interface cache")
    require(
        runner,
        "if ($probeLockBefore -cne 'e1fbe433a385594ed67dfd0bfd9b65be5f9cd07865e6ee190c9193a737648038')",
        "guest exact committed lock digest",
    )
    require(
        runner,
        "(Get-FileHash -LiteralPath $probeLock -Algorithm SHA256).Hash.ToLowerInvariant() -cne",
        "guest enforced-lock postcondition",
    )
    require(runner, "windows-presentation-pubspec.lock", "resolved graph receipt")
    require(runner, "Stop-Computer -Force", "disposable guest shutdown")
    require(runner, "'window_hresult'", "guest window outcome validation")
    require(runner, "$attempt.name -cne $expectedName", "guest attempt identity validation")
    require(runner, "$attempt.pixel_matches -isnot [bool]", "guest pixel-verdict type validation")
    require(
        runner,
        "if ($null -eq $d3d11PreflightExit -or $d3d11PreflightExit -isnot [int])",
        "guest typed diagnostic exit status",
    )
    if runner.count("'^0x[0-9A-F]{8}$'") != 3:
        raise VerificationError("D3D11 guest HRESULT validators are not exact")
    if runner.count("'window_hresult'") != 2:
        raise VerificationError("D3D11 guest window outcome validators are not exact")
    for unsafe in ("Invoke-WebRequest", "curl ", "wget ", "Start-Service", "Stop-Service"):
        forbid(runner, unsafe, "guest network/service mutation")

    require_order(
        d3d11,
        (
            "factory->EnumAdapters(0, &selected_adapter)",
            "warp ? D3D_DRIVER_TYPE_WARP : D3D_DRIVER_TYPE_UNKNOWN",
            "DXGI_FORMAT_B8G8R8A8_UNORM",
            "DXGI_USAGE_RENDER_TARGET_OUTPUT |",
            "DXGI_SWAP_EFFECT_SEQUENTIAL",
            "factory2->CreateSwapChainForHwnd(",
            "swap_chain->Present(1, 0)",
            "attempt.dwm_flush = DwmFlush()",
            "attempt.desktop_pixel = ReadDesktopPixel(window)",
            'rustdesk-windows-d3d11-preflight-v1',
        ),
        "default-adapter and explicit-WARP compositor preflight",
    )
    require(d3d11, "D3D_FEATURE_LEVEL_11_1", "ANGLE-matching feature-level head")
    require(d3d11, "D3D_FEATURE_LEVEL_9_3", "ANGLE-matching feature-level tail")
    require(d3d11, 'attempt.name = warp ? "warp" : "default-adapter"', "attempt identity")
    require(d3d11, "HRESULT window = E_UNEXPECTED", "window outcome sentinel")
    require(d3d11, "attempt.window = S_OK", "window admission outcome")
    require(d3d11, "attempt.window_association =", "window-association outcome")
    require(d3d11, "result.pop_back()", "bounded UTF-8 terminator removal")
    for unsafe in (
        "WinHttp",
        "WinINet",
        "URLDownloadToFile",
        "InternetOpen",
        "WSAStartup",
        "WSASocket",
        "socket(",
        "connect(",
        "bind(",
        "listen(",
        "CreateProcess",
        "ShellExecute",
        "WinExec",
        "CreateService",
        "OpenSCManager",
        "RegSetValue",
        "AdjustTokenPrivileges",
        "system(",
    ):
        forbid(d3d11, unsafe, "D3D11 preflight authority expansion")

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
    require(sources["pubspec"], "url_launcher_windows: 3.1.4", "exact URL-launcher dependency")
    require(sources["pubspec"], "path: third_party/window_size", "local window-size plugin")
    forbid(sources["pubspec"], "git:", "runtime dependency fetch")
    forbid(sources["pubspec"], "hosted:", "runtime hosted override")
    if hashlib.sha256(pubspec_lock.encode("utf-8")).hexdigest() != (
        "e1fbe433a385594ed67dfd0bfd9b65be5f9cd07865e6ee190c9193a737648038"
    ):
        raise VerificationError("committed Windows presentation lock digest differs")
    for package in (
        "characters",
        "collection",
        "desktop_multi_window",
        "flutter",
        "material_color_utilities",
        "meta",
        "plugin_platform_interface",
        "sky_engine",
        "texture_rgba_renderer",
        "url_launcher_platform_interface",
        "url_launcher_windows",
        "vector_math",
        "window_size",
    ):
        require(pubspec_lock, f"  {package}:\n", f"committed lock package {package}")
    require(sources["window_pubspec"], "sdk: '>=2.17.0 <4.0.0'", "legacy listener language mode")
    require(sources["size_pubspec"], "sdk: '>=2.12.0-0 <4.0.0'", "legacy window-size language mode")
    require(sources["size_pubspec"], "pluginClass: WindowSizePlugin", "window-size native plugin")
    if sources["size_pubspec"].count("pluginClass: WindowSizePlugin") != 3:
        raise VerificationError("window-size platform plugin declarations are not exact")
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
        provision,
        (
            'verify_sha512_file "$ONLINE_DIR/vcpkg-distfiles/libvpx-${LIBVPX_SOURCE_REF}.tar.gz" "$SHA512_LIBVPX_SOURCE"',
            'verify_sha512_file "$ONLINE_DIR/vcpkg-distfiles/libvpx-${LIBVPX_FIX_COMMIT}.patch" "$SHA512_LIBVPX_PATCH"',
            'verify_sha512_file "$ONLINE_DIR/libyuv-${LIBYUV_COMMIT}.tar.gz" "$SHA512_LIBYUV"',
            "verify_libvpx_windows_tools",
            '"/vcpkg-distfiles/libvpx-${LIBVPX_SOURCE_REF}.tar.gz=$ONLINE_DIR/vcpkg-distfiles/libvpx-${LIBVPX_SOURCE_REF}.tar.gz"',
            '"/vcpkg-distfiles/libvpx-${LIBVPX_FIX_COMMIT}.patch=$ONLINE_DIR/vcpkg-distfiles/libvpx-${LIBVPX_FIX_COMMIT}.patch"',
            '"/vcpkg-distfiles/libyuv-${LIBYUV_COMMIT}.tar.gz=$ONLINE_DIR/libyuv-${LIBYUV_COMMIT}.tar.gz"',
            '"/vcpkg-distfiles/windows-tools=$ONLINE_DIR/vcpkg-distfiles/windows-tools"',
        ),
        "golden host-side distfile verification and media construction",
    )
    require(
        provision,
        '"$(sha256sum "$REPO_ROOT/res/vcpkg/libvpx/windows-tools.sha512" | awk \'{print $1}\')" = "$SHA256_LIBVPX_WINDOWS_TOOLS_MANIFEST"',
        "pinned Windows helper manifest",
    )

    require_order(
        guest_setup,
        (
            "if ($LASTEXITCODE -ne 0) { Die \"vcpkg bootstrap failed (exit $LASTEXITCODE)\" }",
            "if (-not $src) { Die 'PROVISION media not found",
            "$distfilesMedia = Join-Path $tc 'vcpkg-distfiles'",
            "Get-FileHash -LiteralPath $source -Algorithm SHA512",
            "libvpx Windows tool manifest must contain exactly 32 entries",
            "$env:RUSTDESK_VCPKG_DISTFILES_DIR = $distfiles",
            "$env:VCPKG_KEEP_ENV_VARS = 'RUSTDESK_VCPKG_DISTFILES_DIR'",
            "$env:VCPKG_BINARY_SOURCES = 'clear'",
            "$env:VCPKG_DOWNLOADS = $downloads",
            "vcpkg install of the x64-windows natives failed",
            "Get-LocalUser -Name 'builder'",
            "Set-LocalUser -PasswordNeverExpires $true",
            "if ($null -ne $builderAccount.PasswordExpires)",
            "New-ScheduledTaskPrincipal -UserId 'builder' -LogonType Interactive -RunLevel Highest",
            "Register-ScheduledTask -TaskName 'RustdeskPerBuild' -Action $act -Trigger $trg",
            "-Principal $principal -Force",
            "Get-ScheduledTask -TaskName 'RustdeskPerBuild'",
            "$registeredTask.Principal.LogonType -cne 'Interactive'",
            "rustdesk-windows-golden-v3",
            "builder-password-never-expires=true",
            "builder-logon-task=interactive",
            "setup-complete=true",
            "Stop-Computer -Force",
        ),
        "non-expiring builder, interactive logon task, and exact completion receipt",
    )
    for value in (
        "824fe8719e4115ec359ae0642f5e1cea051d458f09eb8c24d60858cf082f66e411215e23228173ab154044bafbdfbb2d93b589bb726f55b233939b91f928aae0",
        "2980e0504e207047d55e6c98dcc55c2a3c06315b4ec04d59c42d786657e03ba0e1c73a0718ac6635990aac25fc642b204a1d56e13501ce2bd9625996ad0310d8",
        "be6b343ab6c62e8f2d1571fedf25f5facbf7cd7fe8e1cc4949dab7549ad15f962c91ea43bf567785e54382d7689514f6b66d61bd56b3f38ba54ef51c5fd0da9b",
    ):
        require(guest_setup, value, "guest-side distfile SHA512 pin")
    require(guest_setup, '$cacheName = "msys2-$toolName"', "MSYS2 cache-name normalization")
    require(guest_setup, '$cacheName = "$($toolHash.Substring(0, 8))-$toolName"', "7zr cache-name normalization")
    require(
        guest_setup,
        "$registeredTask.Principal.UserId -notmatch '(^|\\\\)builder$'",
        "interactive task exact builder identity validation",
    )
    require(
        guest_setup,
        "$registeredTask.Principal.RunLevel -cne 'Highest'",
        "interactive task declared run-level validation",
    )
    forbid(
        guest_setup,
        "-Password 'RustdeskBuild!1' -Force",
        "stored per-build task password",
    )
    forbid(guest_setup, "WARN: no SRC CD", "optional native warm")

    require_order(
        libyuv_port,
        (
            'set(_libyuv_distfiles_native "$ENV{RUSTDESK_VCPKG_DISTFILES_DIR}")',
            'file(TO_CMAKE_PATH "${_libyuv_distfiles_native}" _libyuv_distfiles)',
            'set(_libyuv_distfiles_archive "${_libyuv_distfiles}/${_libyuv_archive_name}")',
            'if(EXISTS "${_libyuv_distfiles_archive}")',
            'if(CMAKE_HOST_WIN32)',
            'set(_libyuv_file_url "file:///")',
            'vcpkg_download_distfile(_libyuv_tgz',
            'URLS "${_libyuv_file_url}${_libyuv_archive}"',
        ),
        "libyuv Windows distfile capture consumption",
    )
    require(
        golden_inspector,
        "$'rustdesk-windows-golden-v3\\nbuilder-password-never-expires=true\\nbuilder-logon-task=interactive\\nsetup-complete=true'",
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
        sources["multi_window_upstream"],
        "b47e8385e5a75d38319ad706a64b0ead3108b093",
        "vendored window plugin upstream identity",
    )
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


def self_test(sources: dict[str, str]) -> int:
    mutations = (
        ("host", "--network none", "--network default"),
        ("host", "--graphics vnc,listen=127.0.0.1", "--graphics vnc"),
        ("host", "virsh --connect qemu:///session", "virsh --connect qemu:///system"),
        ("host", "if not parsed.is_loopback:", "if False:"),
        ("host", "windows_helper_guestfish_run", "windows_helper_kvm_guestfish_run"),
        (
            "host",
            "    golden_has_contract \\\n        || die \"Windows presentation golden lacks the exact interactive-builder contract\"",
            "    true # golden contract removed",
        ),
        ("host", "assert_clean_worktree", "true # worktree check removed"),
        (
            "pins",
            'SHA256_WINDOWS_PRESENTATION_PUB_CACHE_CLOSURE_V1="fe81f679a0a1acd8291472162e867a566f33a50c813d27775125cee4644736b4"',
            'SHA256_WINDOWS_PRESENTATION_PUB_CACHE_CLOSURE_V1="0000000000000000000000000000000000000000000000000000000000000000"',
        ),
        (
            "pins",
            'SHA256_WINDOWS_PRESENTATION_PUBSPEC_LOCK="e1fbe433a385594ed67dfd0bfd9b65be5f9cd07865e6ee190c9193a737648038"',
            'SHA256_WINDOWS_PRESENTATION_PUBSPEC_LOCK="0000000000000000000000000000000000000000000000000000000000000000"',
        ),
        (
            "pins",
            'SHA256_WINDOWS_PRESENTATION_PUB_CACHE_PROJECTION_V1="949ad80194975f2a64253a4b59cad9051105cada07137b5e7de39d034f4cc1ea"',
            'SHA256_WINDOWS_PRESENTATION_PUB_CACHE_PROJECTION_V1="0000000000000000000000000000000000000000000000000000000000000000"',
        ),
        (
            "pubspec_lock",
            'version: "1.3.0"',
            'version: "1.3.1"',
        ),
        (
            "pub_cache_output",
            "def check_complete(online: Path, uid: int, gid: int) -> TreeSummary:",
            "def check_complete_removed(online: Path, uid: int, gid: int) -> TreeSummary:",
        ),
        (
            "pub_cache_projection",
            "summary.digest != expected_digest",
            "False",
        ),
        (
            "pub_cache_projection",
            "summary.files != EXPECTED_FILES",
            "False",
        ),
        (
            "pub_cache_projection",
            'exact_names(root, {"hosted", "hosted-hashes"}, "projection root", True)',
            "# exact root validation removed",
        ),
        (
            "host",
            "check-complete --online /online",
            "self-test # complete cache validation removed",
        ),
        (
            "host",
            "    project_presentation_pub_cache\n",
            "    project_unverified_presentation_pub_cache\n",
        ),
        (
            "host",
            "        scripts/flutter-presentation-probe-windows-pubspec.lock \\\n",
            "",
        ),
        (
            "host",
            "        scripts/online-pub-cache-output.py \\\n",
            "",
        ),
        (
            "host",
            "        scripts/windows-presentation-pub-cache.py \\\n",
            "",
        ),
        (
            "host",
            '--expected-digest "$PRESENTATION_PUB_CACHE_PROJECTION_SHA256"',
            '--expected-digest "$PRESENTATION_PUB_CACHE_SHA256"',
        ),
        (
            "host",
            '"presentation_pub_cache_projection_sha256": pub_cache_projection',
            '"presentation_pub_cache_projection_sha256_removed": pub_cache_projection',
        ),
        (
            "host",
            'die "Windows presentation source Pub-cache identity changed"',
            "true # source Pub-cache postcondition removed",
        ),
        (
            "host",
            "WINDOW_SIZE_COMMIT=eb3964990cf19629c89ff8cb4a37640c7b3d5601",
            "WINDOW_SIZE_COMMIT=0000000000000000000000000000000000000000",
        ),
        (
            "host",
            "WINDOW_SIZE_TREE=c1b4ec4f759387d00f1024ce539487242cd7ae1a",
            "WINDOW_SIZE_TREE=0000000000000000000000000000000000000000",
        ),
        (
            "host",
            "        scripts/flutter-presentation-probe-window-size-pubspec.yaml \\\n",
            "",
        ),
        (
            "host",
            "-name 'flutter-desktop-embedding-*' -print0",
            "-name 'unrelated-repository-*' -print0",
        ),
        (
            "host",
            'rev-parse "$WINDOW_SIZE_COMMIT^{commit}"',
            'rev-parse "HEAD^{commit}"',
        ),
        (
            "host",
            'rev-parse "$WINDOW_SIZE_COMMIT:plugins/window_size"',
            'rev-parse "$WINDOW_SIZE_COMMIT^{tree}"',
        ),
        (
            "host",
            'archive --format=tar "$WINDOW_SIZE_COMMIT:plugins/window_size"',
            'archive --format=tar "$WINDOW_SIZE_COMMIT"',
        ),
        (
            "host",
            "third_party/window_size/.rustdesk-source-identity.json",
            "third_party/window_size/source-identity-removed.json",
        ),
        (
            "host",
            '"url_launcher_windows": (',
            '"url_launcher_windows_removed": (',
        ),
        (
            "host",
            '"window_size": (',
            '"window_size_removed": (',
        ),
        (
            "host",
            "4820fbfdb9478b1ebae27888254d445073732dae3d6ea81f0b7e06d5dedc3f02",
            "0000000000000000000000000000000000000000000000000000000000000000",
        ),
        (
            "host",
            "552f8a1e663569be95a8190206a38187b531910283c3e982193e4f2733f01029",
            "0000000000000000000000000000000000000000000000000000000000000000",
        ),
        (
            "host",
            "3284b6d2ac454cf34f114e1d3319866fdd1e19cdc329999057e44ffe936cfa77",
            "0000000000000000000000000000000000000000000000000000000000000000",
        ),
        (
            "host",
            '  dart: ">=3.4.0 <4.0.0"',
            '  dart: ">=3.3.0 <4.0.0"',
        ),
        (
            "host",
            "        scripts/flutter-presentation-d3d11-preflight-windows.cpp \\\n",
            "",
        ),
        (
            "host",
            "        flutter/third_party/desktop_multi_window \\\n",
            "",
        ),
        (
            "host",
            'mv -- "$vendored_window_source" "$SOURCE_ROOT/third_party/desktop_multi_window"',
            'mv -- "$vendored_window_source" "$SOURCE_ROOT/third_party/removed_multi_window"',
        ),
        (
            "host",
            '"windows-presentation-d3d11-preflight.json",',
            '"windows-presentation-d3d11-preflight-removed.json",',
        ),
        (
            "host",
            'progress not in (diagnostic_progress, [*diagnostic_progress, "probe-passed"])',
            "progress != diagnostic_progress",
        ),
        (
            "host",
            '"guest_d3d11_preflight_sha256": digest(',
            '"guest_d3d11_preflight_sha256_removed": digest(',
        ),
        (
            "host",
            '"window_association_hresult",',
            '"window_association_removed",',
        ),
        (
            "host",
            'print("windows presentation D3D11 preflight: validated")',
            'print("windows presentation D3D11 preflight: unchecked")',
        ),
        (
            "runner",
            "$sourcePubCache = Join-Path $sourceRoot 'pub-cache'",
            "$sourcePubCache = Join-Path $env:LOCALAPPDATA 'Pub\\Cache'",
        ),
        (
            "runner",
            "source_sha256=fe81f679a0a1acd8291472162e867a566f33a50c813d27775125cee4644736b4 projection_sha256=949ad80194975f2a64253a4b59cad9051105cada07137b5e7de39d034f4cc1ea packages=8 semantics=exact-probe-lock",
            "source_sha256=fe81f679a0a1acd8291472162e867a566f33a50c813d27775125cee4644736b4 projection_sha256=0000000000000000000000000000000000000000000000000000000000000000 packages=8 semantics=exact-probe-lock",
        ),
        (
            "runner",
            "'hosted,hosted-hashes'",
            "'hosted,hosted-hashes,git'",
        ),
        (
            "runner",
            "foreach ($cacheRoot in @('hosted', 'hosted-hashes'))",
            "foreach ($cacheRoot in @('hosted'))",
        ),
        (
            "runner",
            "flutter-presentation-probe-windows-pubspec.lock",
            "removed-presentation-probe.lock",
        ),
        (
            "runner",
            "if ($probeLockBefore -cne 'e1fbe433a385594ed67dfd0bfd9b65be5f9cd07865e6ee190c9193a737648038')",
            "if ($false)",
        ),
        (
            "runner",
            "presentation Pub lock changed during enforced offline resolution",
            "presentation Pub lock postcondition removed",
        ),
        (
            "runner",
            "'get', '--offline', '--enforce-lockfile'",
            "'get', '--offline'",
        ),
        ("runner", "'build', 'windows', '--release', '--no-pub'", "'build', 'windows'"),
        (
            "runner",
            "flutter-presentation-d3d11-preflight-windows.cpp",
            "removed-d3d11-preflight.cpp",
        ),
        (
            "runner",
            "rustdesk_d3d11_preflight.exe",
            "removed_d3d11_preflight.exe",
        ),
        (
            "runner",
            "windows-presentation-d3d11-preflight.json",
            "removed-d3d11-preflight.json",
        ),
        (
            "runner",
            "$d3d11PreflightRun.WaitForExit(30000)",
            "$d3d11PreflightRun.WaitForExit()",
        ),
        (
            "runner",
            "$d3d11PreflightRun.Kill()",
            "# exact-process timeout cleanup removed",
        ),
        (
            "runner",
            "$d3d11PreflightRun.Refresh()",
            "# process-state refresh removed",
        ),
        (
            "runner",
            "if ($null -eq $d3d11PreflightExit -or $d3d11PreflightExit -isnot [int])",
            "if ($false)",
        ),
        (
            "runner",
            "'format,default_adapter,warp'",
            "'format,default_adapter'",
        ),
        (
            "runner",
            "'^0x[0-9A-F]{8}$'",
            "'.*'",
        ),
        (
            "runner",
            "$attempt.name -cne $expectedName",
            "$false",
        ),
        (
            "runner",
            "'window_hresult'",
            "'window_result_removed'",
        ),
        ("runner", "Stop-Computer -Force", "# guest shutdown removed"),
        (
            "runner",
            "url_launcher_windows-3.1.4",
            "url_launcher_windows-latest",
        ),
        (
            "runner",
            "url_launcher_platform_interface-2.3.2",
            "url_launcher_platform_interface-latest",
        ),
        (
            "runner",
            "plugin_platform_interface-2.1.8",
            "plugin_platform_interface-latest",
        ),
        (
            "runner",
            r"third_party\window_size",
            r"third_party\removed_window_size",
        ),
        (
            "pubspec",
            "url_launcher_windows: 3.1.4",
            "url_launcher_windows: any",
        ),
        (
            "pubspec",
            "path: third_party/window_size",
            "path: third_party/removed_window_size",
        ),
        (
            "size_pubspec",
            "sdk: '>=2.12.0-0 <4.0.0'",
            "sdk: '>=3.0.0 <4.0.0'",
        ),
        (
            "size_pubspec",
            "pluginClass: WindowSizePlugin",
            "pluginClass: RemovedWindowSizePlugin",
        ),
        (
            "controller",
            "[void][PresentationProbeNative]::DwmFlush()",
            "# DWM synchronization removed",
        ),
        ("controller", "mouse_event(0x0002", "mouse_event(0x0000"),
        (
            "d3d11",
            "warp ? D3D_DRIVER_TYPE_WARP : D3D_DRIVER_TYPE_UNKNOWN",
            "D3D_DRIVER_TYPE_UNKNOWN",
        ),
        (
            "d3d11",
            "DXGI_SWAP_EFFECT_SEQUENTIAL",
            "DXGI_SWAP_EFFECT_DISCARD",
        ),
        (
            "d3d11",
            "factory2->CreateSwapChainForHwnd(",
            "factory2->CreateSwapChainForComposition(",
        ),
        ("d3d11", "result.pop_back()", "result.clear()"),
        ("d3d11", "HRESULT window = E_UNEXPECTED", "HRESULT window = S_OK"),
        ("controller", "Require-Color $window 'green' 2500", "Start-Sleep -Seconds 10"),
        ("controller", "Require-Color $window 'magenta' 2500", "Start-Sleep -Seconds 10"),
        ("dart", "FlutterRgbaRendererPluginTryNotifyPending", "NotifierRemoved"),
        ("dart", "_resume('pointer-down-fallback');", "// pointer recovery removed"),
        ("dart", "await widget.texture.close();", "// texture close removed"),
        ("manifest", "metadata.st_nlink != 1", "False"),
        ("manifest", "actual != manifest[\"files\"]", "False"),
        (
            "multi_window_upstream",
            "b47e8385e5a75d38319ad706a64b0ead3108b093",
            "unreviewed-window-plugin-upstream",
        ),
        (
            "provision",
            'verify_sha512_file "$ONLINE_DIR/libyuv-${LIBYUV_COMMIT}.tar.gz" "$SHA512_LIBYUV"',
            "true # libyuv host verification removed",
        ),
        (
            "provision",
            '"/vcpkg-distfiles/windows-tools=$ONLINE_DIR/vcpkg-distfiles/windows-tools"',
            '"/vcpkg-distfiles/windows-tools=/tmp/unverified"',
        ),
        (
            "guest_setup",
            "$env:RUSTDESK_VCPKG_DISTFILES_DIR = $distfiles",
            "$env:RUSTDESK_VCPKG_DISTFILES_DIR = ''",
        ),
        (
            "guest_setup",
            "if (-not $src) { Die 'PROVISION media not found",
            "if (-not $src) { Log 'PROVISION media not found",
        ),
        (
            "guest_setup",
            "Get-FileHash -LiteralPath $source -Algorithm SHA512",
            "Get-FileHash -LiteralPath $source -Algorithm MD5",
        ),
        (
            "libyuv_port",
            'set(_libyuv_distfiles_native "$ENV{RUSTDESK_VCPKG_DISTFILES_DIR}")',
            'set(_libyuv_distfiles_native "")',
        ),
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
            "guest_setup",
            "New-ScheduledTaskPrincipal -UserId 'builder' -LogonType Interactive -RunLevel Highest",
            "New-ScheduledTaskPrincipal -UserId 'builder' -LogonType Password -RunLevel Highest",
        ),
        (
            "guest_setup",
            "-Principal $principal -Force",
            "-User 'builder' -Password 'untrusted' -Force",
        ),
        (
            "guest_setup",
            "$registeredTask.Principal.LogonType -cne 'Interactive'",
            "$registeredTask.Principal.LogonType -cne 'Password'",
        ),
        (
            "guest_setup",
            "$registeredTask.Principal.UserId -notmatch '(^|\\\\)builder$'",
            "$false",
        ),
        (
            "guest_setup",
            "$registeredTask.Principal.RunLevel -cne 'Highest'",
            "$false",
        ),
        (
            "golden_inspector",
            "builder-password-never-expires=true",
            "builder-password-never-expires=unchecked",
        ),
        (
            "golden_inspector",
            "builder-logon-task=interactive",
            "builder-logon-task=unchecked",
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
    return len(mutations)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=".", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        sources = load(args.repo.resolve())
        validate(sources)
        mutation_count = 0
        if args.self_test:
            mutation_count = self_test(sources)
    except (OSError, VerificationError) as error:
        print(f"verify-flutter-presentation-windows: FAIL: {error}")
        return 1
    suffix = f" ({mutation_count} mutations)" if args.self_test else ""
    print(f"verify-flutter-presentation-windows: ok{suffix}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
