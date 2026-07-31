#!/usr/bin/env python3
"""Verify exact asynchronous ownership of desktop Flutter textures."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
from typing import Dict, Tuple


class VerificationError(RuntimeError):
    pass


def require(source: str, needle: str, label: str) -> None:
    if needle not in source:
        raise VerificationError(f"missing {label}: {needle!r}")


def forbid(source: str, needle: str, label: str) -> None:
    if needle in source:
        raise VerificationError(f"forbidden {label} remains: {needle!r}")


def require_order(source: str, needles: Tuple[str, ...], label: str) -> None:
    position = -1
    for needle in needles:
        position = source.find(needle, position + 1)
        if position < 0:
            raise VerificationError(f"{label}: missing or misordered {needle!r}")


def extract_braced_item(source: str, signature: str, label: str) -> str:
    start = source.find(signature)
    if start < 0:
        raise VerificationError(f"missing {label}")
    open_brace = source.find("{", start + len(signature))
    if open_brace < 0:
        raise VerificationError(f"missing body for {label}")
    depth = 0
    for offset in range(open_brace, len(source)):
        character = source[offset]
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                return source[start : offset + 1]
    raise VerificationError(f"unterminated body for {label}")


def extract_between(source: str, start: str, end: str, label: str) -> str:
    begin = source.find(start)
    if begin < 0:
        raise VerificationError(f"missing start for {label}: {start!r}")
    finish = source.find(end, begin + len(start))
    if finish < 0:
        raise VerificationError(f"missing end for {label}: {end!r}")
    return source[begin:finish]


def load_sources(repo: Path) -> Dict[str, str]:
    paths = {
        "lifecycle": "flutter/lib/models/desktop_texture_lifecycle.dart",
        "render": "flutter/lib/models/desktop_render_texture.dart",
        "model": "flutter/lib/models/model.dart",
        "remote": "flutter/lib/desktop/pages/remote_page.dart",
        "camera": "flutter/lib/desktop/pages/view_camera_page.dart",
        "flutter": "src/flutter.rs",
        "ffi": "src/flutter_ffi.rs",
        "client": "src/client.rs",
        "io_loop": "src/client/io_loop.rs",
        "ui_session": "src/ui_session_interface.rs",
        "ui_interface": "src/ui_interface.rs",
        "native_model": "flutter/lib/models/native_model.dart",
        "web_model": "flutter/lib/models/web_model.dart",
        "web_bridge": "flutter/lib/web/bridge.dart",
        "windows_runner": "flutter/windows/runner/flutter_window.cpp",
        "desktop_settings": "flutter/lib/desktop/pages/desktop_setting_page.dart",
        "tests": "flutter/test/desktop_texture_lifecycle_test.dart",
        "pubspec": "flutter/pubspec.yaml",
        "pub_lock": "flutter/pubspec.lock",
        "online_fetch": "scripts/online-fetch.sh",
        "pub_cache_output": "scripts/online-pub-cache-output.py",
        "pub_cache_verifier": (
            "scripts/verify-online-fetch-pub-cache-output-authority.py"
        ),
        "dependency_inventory": "scripts/dependency-inventory.py",
        "plugin_pubspec": "flutter/third_party/texture_rgba_renderer/pubspec.yaml",
        "plugin_license": "flutter/third_party/texture_rgba_renderer/LICENSE",
        "plugin_upstream": "flutter/third_party/texture_rgba_renderer/UPSTREAM.md",
        "plugin_dart": (
            "flutter/third_party/texture_rgba_renderer/lib/"
            "texture_rgba_renderer.dart"
        ),
        "plugin_windows_texture_h": (
            "flutter/third_party/texture_rgba_renderer/windows/texture_rgba.h"
        ),
        "plugin_windows_texture": (
            "flutter/third_party/texture_rgba_renderer/windows/texture_rgba.cpp"
        ),
        "plugin_windows": (
            "flutter/third_party/texture_rgba_renderer/windows/"
            "texture_rgba_renderer_plugin.cpp"
        ),
        "plugin_windows_c_api": (
            "flutter/third_party/texture_rgba_renderer/windows/"
            "texture_rgba_renderer_plugin_c_api.cpp"
        ),
        "plugin_linux": (
            "flutter/third_party/texture_rgba_renderer/linux/"
            "texture_rgba_renderer_plugin.cc"
        ),
        "plugin_macos_texture": (
            "flutter/third_party/texture_rgba_renderer/macos/Classes/"
            "TextRgba.swift"
        ),
        "plugin_macos": (
            "flutter/third_party/texture_rgba_renderer/macos/Classes/"
            "TextureRgbaRendererPlugin.swift"
        ),
        "plugin_macos_c_api": (
            "flutter/third_party/texture_rgba_renderer/macos/Classes/"
            "TextureRgbaApi.m"
        ),
        "plugin_macos_podspec": (
            "flutter/third_party/texture_rgba_renderer/macos/"
            "texture_rgba_renderer.podspec"
        ),
        "macos_pod_lock": "flutter/macos/Podfile.lock",
        "requirements": "requirements.html",
        "hardening": "HARDENING_STATUS.md",
        "verify": "scripts/verify.sh",
        "dart_verify": "scripts/dart-verify.sh",
        "apple": "scripts/apple-conform-check.sh",
        "workspace": "scripts/verify-verifier-workspace.py",
    }
    return {
        key: (repo / relative).read_text(encoding="utf-8")
        for key, relative in paths.items()
    }


def validate(sources: Dict[str, str]) -> None:
    lifecycle = sources["lifecycle"]
    owner = extract_braced_item(
        lifecycle,
        "class DesktopTextureLifecycle",
        "desktop texture lifecycle",
    )
    require_order(
        owner,
        (
            "bool _retireRequested = false;",
            "bool _publicationAttempted = false;",
            "bool _unpublicationAttempted = false;",
            "late Future<void> _startFuture;",
            "Future<void>? _retireFuture;",
            "Future<void>? _releaseFuture;",
        ),
        "explicit lifecycle state",
    )
    initialize = extract_braced_item(
        owner,
        "Future<void> _initializeAndPublish()",
        "initialization/publication transition",
    )
    require_order(
        initialize,
        (
            "ready = await _initialize();",
            "_onError('initialize', error, stackTrace);",
            "await _releaseOnce();",
            "if (!ready)",
            "if (_retireRequested)",
            "_publicationAttempted = true;",
            "_publish();",
            "_onError('publish', error, stackTrace);",
            "_unpublishOnce();",
            "await _releaseOnce();",
        ),
        "failed-allocation cleanup, late-publication exclusion, and visible errors",
    )
    retire = extract_braced_item(
        owner, "Future<void> retire()", "synchronous retirement invalidation"
    )
    require_order(
        retire,
        (
            "_retireRequested = true;",
            "start();",
            "return _retireFuture ??= _retire();",
        ),
        "invalidate-before-wait and exact finality",
    )
    finality = extract_braced_item(
        owner, "Future<void> _retire()", "owned retirement"
    )
    require_order(
        finality,
        (
            "await _startFuture;",
            "_unpublishOnce();",
            "await _releaseOnce();",
        ),
        "initialization drain, unpublication, and release",
    )
    unpublish = extract_braced_item(
        owner, "void _unpublishOnce()", "one exact unpublication"
    )
    require_order(
        unpublish,
        (
            "if (!_publicationAttempted || _unpublicationAttempted)",
            "_unpublicationAttempted = true;",
            "_unpublish();",
            "_onError('unpublish', error, stackTrace);",
        ),
        "at-most-once unpublication with visible failure",
    )
    release = extract_braced_item(
        owner,
        "Future<void> _releaseAndReportFailure()",
        "one exact release",
    )
    require(
        owner,
        "_releaseFuture ??= _releaseAndReportFailure()",
        "at-most-once release future",
    )
    require_order(
        release,
        ("await _release();", "_onError('release', error, stackTrace);"),
        "release finality with visible failure",
    )

    slot = extract_braced_item(
        lifecycle,
        "class LatestDesktopTextureSlot",
        "serialized display texture slot",
    )
    reconcile = extract_braced_item(
        slot, "Future<void> _reconcile()", "serialized replacement transition"
    )
    require_order(
        reconcile,
        (
            "if (_wanted)",
            "try {",
            "_current = _create();",
            "_creationFailed = true;",
            "_onError('create', error, stackTrace);",
            "final retiring = _current;",
            "await retiring.retire();",
            "if (identical(_current, retiring))",
            "_current = null;",
        ),
        "replacement only after exact predecessor retirement",
    )
    require(
        slot,
        "if (_disposed && wanted)",
        "post-dispose creation refusal",
    )
    require(
        slot,
        "_wanted ? _current != null || _creationFailed : _current == null",
        "failed creation settles one demand transition without retry spin",
    )
    require_order(
        extract_braced_item(slot, "Future<void> dispose()", "slot disposal"),
        ("_disposed = true;", "_wanted = false;", "_ensureReconcile();", "return drain();"),
        "slot terminal retirement",
    )

    render = sources["render"]
    for forbidden, label in (
        (".then((id)", "detached texture initialization"),
        ("_destroying", "field-dependent teardown guard"),
        (
            "Future.delayed(Duration(milliseconds: 100))",
            "fixed-delay texture ownership",
        ),
        ("onRemotePageDispose", "split RemoteDesktop teardown"),
        ("onViewCameraPageDispose", "split ViewCamera teardown"),
    ):
        forbid(render, forbidden, label)

    pixel = extract_braced_item(
        render, "class _PixelbufferTexture", "pixelbuffer texture owner"
    )
    require_order(
        pixel,
        (
            "_lifecycle = DesktopTextureLifecycle(",
            "initialize: _initialize,",
            "publish: _publish,",
            "unpublish: _unpublish,",
            "release: _release,",
            "_lifecycle.start();",
            "await textureRenderer.createTexture(_textureKey);",
            "await textureRenderer.getTexturePtr(_textureKey);",
            "_ffi.textureModel.setTextureId",
            "platformFFI.registerPixelbufferTexture(",
            "_sessionId, _clientOwnerId, _display, ptr",
            "_sessionId, _clientOwnerId, _display, 0",
            "_ffi.textureModel.clearTextureId(display: _display, id: id);",
            "await textureRenderer.closeTexture(_textureKey);",
            "Future<void> retire() => _lifecycle.retire();",
        ),
        "pixelbuffer lifecycle wiring",
    )
    texture_model = extract_braced_item(
        render, "class TextureModel", "desktop texture model"
    )
    require(
        texture_model,
        "Map<int, LatestDesktopTextureSlot<_PixelbufferTexture>>",
        "one serialized slot per display",
    )
    require_order(
        extract_braced_item(
            texture_model,
            "updateCurrentDisplay(int curDisplay)",
            "display reconciliation",
        ),
        (
            "final desired = <int>{};",
            "_textureSlots.putIfAbsent(",
            "create: () => _PixelbufferTexture(",
            "display, ffi.sessionId, ffi.clientOwnerId, ffi)",
            "slot.setWanted(true);",
            "_control.remove(entry.key);",
            "entry.value.setWanted(false);",
        ),
        "desired-set display reconciliation",
    )
    require_order(
        extract_braced_item(texture_model, "Future<void> dispose()", "model disposal"),
        ("_disposed = true;", "return _disposeFuture ??= _dispose();"),
        "idempotent model disposal",
    )
    require(
        texture_model,
        "_textureSlots.values.map((slot) => slot.dispose())",
        "complete display-slot drain",
    )
    clear = extract_braced_item(
        texture_model,
        "clearTextureId({required int display, required int id})",
        "exact software texture ID clearing",
    )
    require_order(
        clear,
        (
            "if (_disposed) return;",
            "final control = _control[display];",
            "if (control?.nativeTextureId == id)",
            "control!.setTextureId(-1);",
        ),
        "exact software texture ID clearing without control recreation",
    )

    model = sources["model"]
    require(
        model,
        "clientOwnerId = isMobile ? _mobileClientOwnerId : Uuid().v4obj();",
        "fresh desktop UI owner independent of connection UUID",
    )

    for key, signature in (
        ("remote", "Future<void> dispose()"),
        ("camera", "Future<void> dispose()"),
    ):
        page_dispose = extract_braced_item(
            sources[key], signature, f"{key} page disposal"
        )
        require_order(
            page_dispose,
            (
                "final textureDisposal = _ffi.textureModel.dispose();",
                "await textureDisposal;",
                "await _ffi.close(closeSession: closeSession);",
            ),
            f"{key} texture finality before native close",
        )

    flutter = sources["flutter"]
    admission = extract_braced_item(
        flutter,
        "fn with_exact_ui_owner_renderer",
        "exact desktop UI-owner renderer admission",
    )
    require_order(
        admission,
        (
            "let handler = handlers.get(session_id)?;",
            "if handler.client_owner_id.as_ref() != Some(client_owner_id)",
            "return Some(false);",
            "operation(&handler.renderer);",
            "Some(true)",
        ),
        "owner check before renderer mutation",
    )
    exported_pixel = extract_braced_item(
        flutter,
        "pub fn session_register_pixelbuffer_texture(",
        "pixelbuffer registration export",
    )
    require_order(
        exported_pixel,
        (
            "client_owner_id: SessionID,",
            ".register_pixelbuffer_texture(",
            "&session_id,",
            "&client_owner_id,",
            "if !admitted",
        ),
        "exact-owner pixelbuffer export",
    )
    require(
        flutter,
        "fn r_s11ex_retired_desktop_ui_owner_cannot_replace_or_clear_texture()",
        "native same-session owner-replacement regression",
    )

    ffi = sources["ffi"]
    wrapper = extract_braced_item(
        ffi,
        "pub fn session_register_pixelbuffer_texture(",
        "pixelbuffer bridge wrapper",
    )
    require(
        wrapper,
        "client_owner_id: SessionID,",
        "pixelbuffer bridge wrapper exact UI-owner argument",
    )
    require_order(
        wrapper,
        ("session_id,", "client_owner_id,", "display,", "ptr,"),
        "pixelbuffer bridge wrapper exact argument propagation",
    )

    for key in ("native_model", "web_model"):
        wrapper = sources[key]
        pixel_start = wrapper.find("void registerPixelbufferTexture(")
        init_start = wrapper.find("Future<void> init(", pixel_start + 1)
        if min(pixel_start, init_start) < 0:
            raise VerificationError(f"{key} texture wrapper boundaries are missing")
        pixel_wrapper = wrapper[pixel_start:init_start]
        require(
            pixel_wrapper,
            "SessionID clientOwnerId, int display, int ptr",
            f"{key} pixelbuffer owner signature",
        )
        require(
            pixel_wrapper,
            "clientOwnerId: clientOwnerId",
            f"{key} pixelbuffer generated-bridge owner propagation",
        )
    web_bridge = sources["web_bridge"]
    stub = extract_braced_item(
        web_bridge,
        "void sessionRegisterPixelbufferTexture(",
        "web texture stub",
    )
    require(
        stub,
        "required UuidValue clientOwnerId,",
        "web exact UI-owner parity",
    )

    for key in (
        "render",
        "model",
        "native_model",
        "web_model",
        "web_bridge",
        "windows_runner",
        "flutter",
        "ffi",
        "client",
        "io_loop",
        "ui_session",
        "ui_interface",
        "pubspec",
        "pub_lock",
        "online_fetch",
        "dependency_inventory",
    ):
        for token in (
            "flutter_gpu_texture_renderer",
            "FlutterGpuTextureRenderer",
            "session_register_gpu_texture",
            "sessionRegisterGpuTexture",
            "main_has_gpu_texture_render",
            "mainHasGpuTextureRender",
            "register_gpu_texture",
            "registerGpuTexture",
            "gpu_output_ptr",
            "get_adapter_luid",
            "adapter_luid",
            "main_has_hwcodec",
            "mainHasHwcodec",
            "main_has_vram",
            "mainHasVram",
        ):
            forbid(sources[key], token, f"retired GPU/VRAM surface in {key}")
    for token in (
        "class _GpuTexture",
        "gpuTextureRenderer",
        "gpuTextureId",
        "setTextureType",
    ):
        forbid(render, token, "second desktop texture mode")
    forbid(flutter, 'feature = "vram"', "Flutter VRAM feature branch")
    forbid(sources["io_loop"], "handler.on_texture", "viewer GPU texture dispatch")
    forbid(sources["ui_session"], "fn on_texture", "viewer GPU texture interface")
    forbid(sources["ui_interface"], "pub fn has_vram", "VRAM capability query")
    forbid(sources["ui_interface"], "pub fn has_hwcodec", "hardware-codec capability query")
    require(ffi, "Texture(usize),   // display", "one-field software texture event")
    require(
        flutter,
        "stream.add(EventToUI::Texture(display));",
        "software texture-ready publication",
    )
    require_order(
        extract_between(
            model,
            "} else if (message is EventToUI_Texture) {",
            "onError: (Object error, StackTrace stackTrace)",
            "software texture event consumer",
        ),
        (
            "final display = message.field0;",
            'debugPrint("EventToUI_Texture display:$display");',
            "onEvent2UIRgba(activeSessionId);",
        ),
        "one-field software texture event consumption",
    )
    forbid(
        extract_between(
            web_bridge,
            "const factory EventToUI.texture(",
            ") = EventToUI_Texture;",
            "web software texture event",
        ),
        "bool field1",
        "web GPU texture event discriminator",
    )
    require_order(
        sources["windows_runner"],
        (
            "#include <texture_rgba_renderer/texture_rgba_renderer_plugin_c_api.h>",
            "TextureRgbaRendererPluginCApiRegisterWithRegistrar(",
        ),
        "sole child-window software texture plugin registration",
    )
    require(sources["pub_cache_output"], "EXPECTED_GIT_DEPENDENCIES = 6", "six-dependency Pub-cache output contract")
    require(sources["pub_cache_output"], "exact six locked Git dependencies", "six-dependency Pub-cache diagnostic")
    require(sources["pub_cache_verifier"], "EXPECTED_GIT_DEPENDENCIES = 6", "six-dependency Pub-cache verifier contract")
    require(sources["online_fetch"], '[ "${#git_specs[@]}" -eq 6 ]', "six-dependency acquisition inventory")
    for token in (
        '"dependencies_entries": 57',
        '"union_entries": 63',
        '"git_hosted_records": 6',
        '"package_records": 198',
        '"rustdesk_org_git_records": 5',
    ):
        require(sources["dependency_inventory"], token, "updated Flutter dependency inventory")

    require_order(
        sources["pubspec"],
        (
            "  texture_rgba_renderer:\n",
            "    path: third_party/texture_rgba_renderer\n",
        ),
        "repository-owned RGBA package dependency",
    )
    forbid(
        extract_between(
            sources["pub_lock"],
            "  texture_rgba_renderer:\n",
            "  timing:\n",
            "locked RGBA package record",
        ),
        "source: git",
        "remote RGBA package lock authority",
    )
    require_order(
        extract_between(
            sources["pub_lock"],
            "  texture_rgba_renderer:\n",
            "  timing:\n",
            "locked RGBA package record",
        ),
        (
            '      path: "third_party/texture_rgba_renderer"\n',
            "      relative: true\n",
            "    source: path\n",
            '    version: "0.0.16+rustdesk.1"\n',
        ),
        "locked in-tree RGBA package identity",
    )
    require_order(
        sources["plugin_pubspec"],
        (
            "name: texture_rgba_renderer\n",
            "version: 0.0.16+rustdesk.1\n",
            "publish_to: none\n",
            "pluginClass: TextureRgbaRendererPlugin\n",
            "pluginClass: TextureRgbaRendererPlugin\n",
            "pluginClass: TextureRgbaRendererPluginCApi\n",
        ),
        "non-publishable three-platform RGBA package",
    )
    if (
        hashlib.sha256(sources["plugin_license"].encode("utf-8")).hexdigest()
        != "fefead96af0a800baf3345d29856979f8e8467abe7d4828837a400cafdd15b53"
    ):
        raise VerificationError("in-tree RGBA package Apache-2.0 license differs")
    for needle, label in (
        (
            "42797e0f03141dc2b585f76c64a13974508058b4",
            "exact upstream RGBA revision",
        ),
        ("upstream Apache-2.0 license", "upstream RGBA license provenance"),
        (
            "did not give texture teardown one exact owner",
            "upstream ownership rationale",
        ),
    ):
        require(sources["plugin_upstream"], needle, label)
    require_order(
        sources["plugin_dart"],
        (
            "Future<int> createTexture(int key)",
            "Future<bool> closeTexture(int key)",
            "Future<bool> onRgba(",
            "Future<int> getTexturePtr(int key)",
        ),
        "typed RGBA method-channel API",
    )

    windows_texture_h = sources["plugin_windows_texture_h"]
    windows_texture = sources["plugin_windows_texture"]
    windows_plugin = sources["plugin_windows"]
    windows_c_api = sources["plugin_windows_c_api"]
    require(
        windows_texture_h,
        "~TextureRgba() = default;",
        "Windows texture object has no second unregister owner",
    )
    forbid(
        windows_texture,
        "UnregisterTexture",
        "Windows texture-object unregister",
    )
    windows_mark = extract_braced_item(
        windows_texture,
        "bool TextureRgba::MarkVideoFrameAvailable(",
        "Windows RGBA frame admission",
    )
    require_order(
        windows_mark,
        (
            "copied.resize(packed_size);",
            "} catch (...) {",
            "if (retired_ || texture_id_ <= 0)",
            "buffers_[background_index].swap(copied);",
            "const bool notification_needed = !buffer_ready_;",
            "buffer_ready_ = true;",
            "if (!notification_needed)",
            "if (texture_registrar_->MarkTextureFrameAvailable(texture_id_))",
            "buffer_ready_ = false;",
            "buffers_[background_index].clear();",
        ),
        "Windows latest-wins coalescing, retirement, and failed-mark rollback",
    )
    windows_close = extract_braced_item(
        windows_plugin,
        'if (method_call.method_name() == "closeTexture")',
        "Windows asynchronous texture close",
    )
    windows_create = extract_braced_item(
        windows_plugin,
        'if (method_call.method_name() == "createTexture")',
        "Windows exception-safe texture creation",
    )
    require_order(
        windows_create,
        (
            "auto [slot, inserted] = textures_.try_emplace(key);",
            "if (!inserted)",
            "std::shared_ptr<TextureRgba> texture;",
            "std::make_shared<TextureRgba>(texture_registrar_);",
            "} catch (...) {",
            "textures_.erase(slot);",
            "throw;",
            "if (texture->texture_id() <= 0)",
            "textures_.erase(slot);",
            "slot->second = std::move(texture);",
            "return result->Success(flutter::EncodableValue(texture_id));",
        ),
        "Windows owning slot exists before callback registration",
    )
    require_order(
        windows_close,
        (
            "auto texture_node = textures_.extract(found);",
            "texture_node.mapped();",
            "texture->Retire();",
            "auto async_result = std::shared_ptr<EncodableResult>",
            "texture_registrar_->UnregisterTexture(",
            "[texture, async_result]()",
            "async_result->Success(flutter::EncodableValue(true));",
            "textures_.insert(std::move(texture_node));",
            'async_result->Error("native-error", error.what());',
        ),
        "Windows retire/unregister completion owns texture and Dart result",
    )
    forbid(
        windows_plugin,
        "UnregisterTexture(texture->texture_id());",
        "deprecated synchronous-looking Windows unregister overload",
    )
    require_order(
        extract_braced_item(
            windows_plugin,
            "TextureRgbaRendererPlugin::~TextureRgbaRendererPlugin()",
            "Windows plugin teardown",
        ),
        (
            "texture->Retire();",
            "texture_registrar_->UnregisterTexture(texture->texture_id(),",
            "[texture]() {}",
        ),
        "Windows plugin teardown retains each texture through unregister completion",
    )
    require_order(
        extract_braced_item(
            windows_c_api,
            "void FlutterRgbaRendererPluginOnRgba(",
            "Windows Rust C-ABI frame entry",
        ),
        (
            "if (texture_rgba == nullptr",
            "try {",
            "->MarkVideoFrameAvailable(",
            "} catch (...) {",
            "Exceptions must never cross the C ABI used by Rust.",
        ),
        "Windows C-ABI validation and exception containment",
    )

    linux = sources["plugin_linux"]
    require(
        linux,
        "std::unordered_map<int64_t, TextureRgba*>* renderers;",
        "Linux per-plugin renderer ownership",
    )
    for needle, label in (
        ("static std::unordered_map", "process-global Linux renderer map"),
        ("g_renderer_map", "legacy Linux renderer map"),
        ("renderers)[", "inserting Linux map lookup"),
    ):
        forbid(linux, needle, label)
    require_order(
        extract_braced_item(
            linux,
            "static void release_texture(",
            "Linux exact texture release",
        ),
        (
            "texture_rgba_retire(texture);",
            "fl_texture_registrar_unregister_texture(",
            "g_object_unref(texture);",
        ),
        "Linux retire/unregister/owning-reference release order",
    )
    linux_close = extract_between(
        linux,
        '} else if (std::strcmp(method, "closeTexture") == 0) {',
        '} else if (std::strcmp(method, "onRgba") == 0) {',
        "Linux close method",
    )
    require_order(
        linux_close,
        (
            "self->renderers->erase(found);",
            "texture_rgba_retire(texture);",
            "fl_texture_registrar_unregister_texture(",
            "g_object_unref(texture);",
        ),
        "Linux map removal, retirement, registrar removal, and own-ref release",
    )
    require_order(
        extract_braced_item(
            linux,
            "static void texture_rgba_finalize(",
            "Linux texture finalizer",
        ),
        (
            "self->retired = TRUE;",
            "self->buffer = nullptr;",
            "self->prior_buffer = nullptr;",
            "delete[] buffer;",
            "delete[] prior_buffer;",
            "g_mutex_clear(&self->mutex);",
        ),
        "Linux buffer and mutex finality",
    )
    linux_mark = extract_braced_item(
        linux,
        "static gboolean texture_rgba_mark_frame(",
        "Linux frame admission",
    )
    require_order(
        linux_mark,
        (
            "if (self->retired)",
            "uint8_t* superseded = self->buffer;",
            "self->buffer = copied.release();",
            "self->buffer_width = static_cast<uint32_t>(width);",
            "self->buffer_height = static_cast<uint32_t>(height);",
            "const gboolean notification_needed = !self->buffer_ready;",
            "self->buffer_ready = TRUE;",
            "delete[] superseded;",
            "if (!notification_needed)",
            "fl_texture_registrar_mark_texture_frame_available(",
            "if (!marked)",
            "delete[] self->buffer;",
            "self->buffer_width = 0;",
            "self->buffer_height = 0;",
            "self->buffer_ready = FALSE;",
        ),
        "Linux retired/latest-wins frame admission and failed-mark rollback",
    )
    require_order(
        extract_braced_item(
            linux,
            "static gboolean texture_rgba_copy_pixels(",
            "Linux pixel callback",
        ),
        (
            "if (self->buffer_ready)",
            "self->prior_buffer = self->buffer;",
            "self->prior_width = self->buffer_width;",
            "self->prior_height = self->buffer_height;",
            "self->buffer_width = 0;",
            "self->buffer_height = 0;",
            "*out_buffer = self->prior_buffer;",
            "*width = self->prior_width;",
            "*height = self->prior_height;",
            "if (self->retired)",
            "if (self->prior_buffer != nullptr)",
            "*width = self->prior_width;",
            "*height = self->prior_height;",
            '"texture has no frame"',
            "return FALSE;",
        ),
        "Linux pixel callback keeps presented metadata independent of pending rollback",
    )
    require_order(
        extract_braced_item(
            linux,
            "static void texture_rgba_renderer_plugin_dispose(",
            "Linux plugin disposal",
        ),
        (
            "for (const auto& entry : *self->renderers)",
            "release_texture(self, entry.second);",
            "delete self->renderers;",
            "self->renderers = nullptr;",
        ),
        "Linux plugin disposal drains exact owned textures",
    )
    require(
        linux,
        "args == nullptr || fl_value_get_type(args) != FL_VALUE_TYPE_MAP",
        "Linux data lookup map-type validation",
    )
    require_order(
        extract_braced_item(
            linux,
            "void FlutterRgbaRendererPluginOnRgba(",
            "Linux Rust C-ABI frame entry",
        ),
        (
            "int stride_align)",
            "texture_rgba_mark_frame(",
            "len, width, height, stride_align",
        ),
        "Linux C declaration/definition stride contract",
    )

    macos_texture = sources["plugin_macos_texture"]
    macos_plugin = sources["plugin_macos"]
    macos_c_api = sources["plugin_macos_c_api"]
    require_order(
        extract_braced_item(
            macos_texture,
            "public func retire() -> Int64",
            "macOS texture retirement",
        ),
        (
            "queue.sync",
            "let retiredId = textureId",
            "textureId = 0",
            "registry = nil",
            "data = nil",
            "return retiredId",
        ),
        "macOS serialized retirement invalidates all frame admission state",
    )
    require_order(
        extract_braced_item(
            macos_texture,
            "private func markFrameAvailable(",
            "macOS frame admission",
        ),
        (
            "guard textureId > 0, let registry,",
            "CVPixelBufferGetBytesPerRow(pixelBuffer)",
            "for row in 0..<height",
            "buffer.advanced(by: row * layout.sourceRowBytes)",
            "data = pixelBuffer",
            "let notificationNeeded = !framePending",
            "framePending = true",
            "if notificationNeeded",
            "registry.textureFrameAvailable(textureId)",
        ),
        "macOS retired admission, stride-aware latest-wins copy, and publication",
    )
    require_order(
        extract_braced_item(
            macos_texture,
            "public func copyPixelBuffer()",
            "macOS pixel callback",
        ),
        (
            "guard let data",
            "framePending = false",
            "return Unmanaged.passRetained(data)",
        ),
        "macOS pixel callback consumes the one pending notification",
    )
    require_order(
        extract_braced_item(
            macos_plugin,
            "private func integer(",
            "macOS method integer decoding",
        ),
        (
            "CFGetTypeID(number) != CFBooleanGetTypeID()",
            "!CFNumberIsFloatType(number)",
            "return number.int64Value",
        ),
        "macOS integer decoding rejects booleans and floating point",
    )
    macos_close = extract_between(
        macos_plugin,
        'case "closeTexture":',
        'case "onRgba":',
        "macOS close method",
    )
    require_order(
        macos_close,
        (
            "renderers.removeValue(forKey: key)",
            "let textureId = texture.retire()",
            "textureRegistry.unregisterTexture(textureId)",
            "result(true)",
        ),
        "macOS map removal, serialized retirement, and registrar removal",
    )
    require_order(
        extract_braced_item(
            macos_c_api,
            "void FlutterRgbaRendererPluginOnRgba(",
            "macOS Rust C-ABI frame entry",
        ),
        (
            "texture_rgba_ptr == NULL",
            "buffer == NULL",
            "len <= 0",
            "width <= 0",
            "height <= 0",
            "stride_align < 0",
        ),
        "macOS C-ABI pointer and dimension validation",
    )
    if (
        hashlib.sha256(
            sources["plugin_macos_podspec"].encode("utf-8")
        ).hexdigest()
        != "2896b68e62e75102a2af925e53c7adec5cb5609274f1b7ed23501f525284e63f"
    ):
        raise VerificationError("macOS RGBA podspec differs from locked upstream input")
    require(
        sources["macos_pod_lock"],
        "texture_rgba_renderer: 6661f577ea5d4990e964c7e3840e544ac798e6da",
        "unchanged macOS RGBA CocoaPods checksum",
    )

    tests = sources["tests"]
    for test in (
        "retirement before initialization completes prevents late publication",
        "published texture is unpublished before one exact release",
        "initialization failure is reported and the allocation is released",
        "failed publication is unpublished and released immediately",
        "unpublication failure cannot prevent exact release",
        "failed slot creation is bounded and a later demand can retry",
        "replacement waits for exact predecessor retirement",
    ):
        require(tests, f"test('{test}'", f"{test} behavior regression")
    require(tests, "expect(identical(first, second), isTrue);", "exact finality regression")
    require(
        tests,
        "expect(errors, ['unpublish', 'release']);",
        "failure-visible finality regression",
    )

    for key, needle, label in (
        (
            "requirements",
            '<div class="req"><span class="id">R-S11ex</span>',
            "R-S11ex requirement",
        ),
        (
            "requirements",
            '<div class="req"><span class="id">R-S11ey</span>',
            "R-S11ey software-only presentation requirement",
        ),
        ("requirements", "<tr><td>306</td>", "Appendix C #306"),
        ("requirements", "<tr><td>307</td>", "Appendix C #307"),
        (
            "hardening",
            "**R-S11ex/R-S11e-185 exact desktop Flutter texture lifecycle and UI-owner registration",
            "desktop texture hardening ledger",
        ),
        (
            "hardening",
            "**R-S11ey/R-S11e-186 software-RGBA-only desktop presentation",
            "software-only texture hardening ledger",
        ),
        (
            "verify",
            "cargo test --lib --features linux-pkg-config,flutter r_s11ex_ --color never",
            "shared native behavior gate",
        ),
        (
            "dart_verify",
            "flutter test --no-pub test/desktop_texture_lifecycle_test.dart",
            "confined Dart behavior gate",
        ),
        (
            "verify",
            "python3 scripts/verify-desktop-texture-lifecycle.py --repo . --self-test",
            "shared focused-verifier wiring",
        ),
        (
            "apple",
            "python3 scripts/verify-desktop-texture-lifecycle.py --repo . --self-test",
            "Apple/shared focused-verifier wiring",
        ),
        (
            "workspace",
            '"desktop_texture_lifecycle_verifier": (',
            "independent verifier source binding",
        ),
        (
            "workspace",
            "validate_desktop_texture_lifecycle_contract(sources)",
            "independent verifier dispatch",
        ),
    ):
        require(sources[key], needle, label)

    requirements_digest = hashlib.sha256(
        sources["requirements"].encode("utf-8")
    ).hexdigest()
    require(
        sources["hardening"],
        f"{requirements_digest}  requirements.html",
        "exact requirements digest binding",
    )


Mutation = Tuple[str, str, str, str]

MUTATIONS: Tuple[Mutation, ...] = (
    ("lifecycle", "_retireRequested = true;", "_retireRequested = false;", "synchronous retirement invalidation"),
    ("lifecycle", "if (!ready)", "if (false)", "failed-initialization cleanup"),
    ("lifecycle", "if (_retireRequested)", "if (false)", "late-publication exclusion"),
    ("lifecycle", "_publicationAttempted = true;", "_publicationAttempted = false;", "publication ownership"),
    ("lifecycle", "return _retireFuture ??= _retire();", "return _retire();", "exact retirement finality"),
    ("lifecycle", "await _startFuture;", "start();", "initialization drain"),
    ("lifecycle", "_unpublicationAttempted = true;", "_unpublicationAttempted = false;", "exact unpublication"),
    ("lifecycle", "_releaseFuture ??= _releaseAndReportFailure()", "_releaseAndReportFailure()", "exact release future"),
    ("lifecycle", "await _release();", "_release();", "release finality"),
    ("lifecycle", "_creationFailed = true;", "_creationFailed = false;", "bounded creation failure"),
    ("lifecycle", "await retiring.retire();", "retiring.retire();", "predecessor finality"),
    ("lifecycle", "if (identical(_current, retiring))", "if (_current != null)", "exact predecessor removal"),
    ("lifecycle", "if (_disposed && wanted)", "if (false)", "post-dispose refusal"),
    ("render", "    _lifecycle.start();", "    // lifecycle start removed", "software texture start"),
    ("render", "_sessionId, _clientOwnerId, _display, ptr", "_sessionId, _sessionId, _display, ptr", "pixel owner publication"),
    ("render", "_sessionId, _clientOwnerId, _display, 0", "_sessionId, _sessionId, _display, 0", "pixel owner unpublication"),
    ("render", "control?.nativeTextureId == id", "control != null", "exact software UI-ID clearing"),
    ("render", "await textureRenderer.closeTexture(_textureKey);", "textureRenderer.closeTexture(_textureKey);", "pixel release finality"),
    ("render", "Map<int, LatestDesktopTextureSlot<_PixelbufferTexture>>", "Map<int, _PixelbufferTexture>", "serialized display slots"),
    ("render", "entry.value.setWanted(false);", "_textureSlots.remove(entry.key);", "serialized display retirement"),
    (
        "render",
        "import 'package:flutter/material.dart';",
        "import 'package:flutter_gpu_texture_renderer/flutter_gpu_texture_renderer.dart';",
        "retired GPU Dart dependency",
    ),
    (
        "pubspec",
        "  uuid: ^3.0.7",
        "  flutter_gpu_texture_renderer:\n    path: forbidden",
        "retired GPU package dependency",
    ),
    (
        "windows_runner",
        "#include <texture_rgba_renderer/texture_rgba_renderer_plugin_c_api.h>",
        "#include <flutter_gpu_texture_renderer/flutter_gpu_texture_renderer_plugin_c_api.h>",
        "retired GPU Windows registration surface",
    ),
    (
        "flutter",
        "pub(super) type TextureRgbaPtr = usize;",
        "pub(super) type TextureRgbaPtr = usize;\n    gpu_output_ptr: usize,",
        "retired native GPU pointer",
    ),
    (
        "ffi",
        "    Texture(usize),   // display",
        "    Texture(usize, bool), // display, gpu",
        "retired GPU event discriminator",
    ),
    (
        "client",
        "impl VideoHandler {",
        "impl VideoHandler {\n    pub fn get_adapter_luid() -> Option<i64> { None }",
        "retired decoder adapter identity",
    ),
    (
        "io_loop",
        "handler.on_rgba(display, data);",
        "handler.on_texture(display, _texture);",
        "retired viewer GPU dispatch",
    ),
    (
        "ui_session",
        "fn on_rgba(&self, display: usize, rgba: &mut scrap::ImageRgb);",
        "fn on_texture(&self, display: usize, texture: usize);",
        "retired viewer GPU interface",
    ),
    (
        "ui_interface",
        "pub fn is_root() -> bool {",
        "pub fn has_vram() -> bool { false }\n\npub fn is_root() -> bool {",
        "retired VRAM capability query",
    ),
    (
        "model",
        'debugPrint("EventToUI_Texture display:$display");',
        "final gpuTexture = message.field1;",
        "retired GPU event consumption",
    ),
    (
        "online_fetch",
        '[ "${#git_specs[@]}" -eq 6 ]',
        '[ "${#git_specs[@]}" -eq 7 ]',
        "six-dependency acquisition inventory",
    ),
    (
        "pub_cache_output",
        "EXPECTED_GIT_DEPENDENCIES = 6",
        "EXPECTED_GIT_DEPENDENCIES = 7",
        "six-dependency Pub-cache output inventory",
    ),
    (
        "dependency_inventory",
        '"package_records": 198',
        '"package_records": 199',
        "updated Flutter package inventory",
    ),
    ("model", "clientOwnerId = isMobile ? _mobileClientOwnerId : Uuid().v4obj();", "clientOwnerId = isMobile ? _mobileClientOwnerId : sessionId;", "fresh desktop UI owner"),
    ("remote", "await textureDisposal;", "textureDisposal;", "RemoteDesktop texture finality"),
    ("camera", "await textureDisposal;", "textureDisposal;", "ViewCamera texture finality"),
    ("flutter", "if handler.client_owner_id.as_ref() != Some(client_owner_id)", "if false", "native exact owner admission"),
    ("flutter", "&client_owner_id,", "&session_id,", "native owner propagation"),
    (
        "ffi",
        "pub fn session_register_pixelbuffer_texture(\n"
        "    session_id: SessionID,\n"
        "    client_owner_id: SessionID,",
        "pub fn session_register_pixelbuffer_texture(\n"
        "    session_id: SessionID,\n"
        "    client_owner_id: usize,",
        "bridge owner type",
    ),
    (
        "native_model",
        "_ffiBind.sessionRegisterPixelbufferTexture(\n"
        "          sessionId: sessionId,\n"
        "          clientOwnerId: clientOwnerId,",
        "_ffiBind.sessionRegisterPixelbufferTexture(\n"
        "          sessionId: sessionId,\n"
        "          clientOwnerId: sessionId,",
        "native Dart owner propagation",
    ),
    (
        "web_model",
        "_ffiBind.sessionRegisterPixelbufferTexture(\n"
        "          sessionId: sessionId,\n"
        "          clientOwnerId: clientOwnerId,",
        "_ffiBind.sessionRegisterPixelbufferTexture(\n"
        "          sessionId: sessionId,\n"
        "          clientOwnerId: sessionId,",
        "web Dart owner propagation",
    ),
    (
        "web_bridge",
        "void sessionRegisterPixelbufferTexture(\n"
        "      {required UuidValue sessionId,\n"
        "      required UuidValue clientOwnerId,",
        "void sessionRegisterPixelbufferTexture(\n"
        "      {required UuidValue sessionId,\n"
        "      required int clientOwnerId,",
        "web owner parity",
    ),
    ("tests", "expect(identical(first, second), isTrue);", "expect(identical(first, second), isFalse);", "exact finality regression"),
    ("tests", "expect(errors, ['unpublish', 'release']);", "expect(errors, isEmpty);", "failure-visible finality regression"),
    ("flutter", "fn r_s11ex_retired_desktop_ui_owner_cannot_replace_or_clear_texture()", "fn retired_desktop_ui_owner_cannot_replace_or_clear_texture()", "native owner regression"),
    (
        "pubspec",
        "  texture_rgba_renderer:\n"
        "    path: third_party/texture_rgba_renderer\n",
        "  texture_rgba_renderer:\n"
        "    git: https://example.invalid/texture_rgba_renderer\n",
        "repository-owned RGBA dependency",
    ),
    (
        "pub_lock",
        "    source: path\n"
        '    version: "0.0.16+rustdesk.1"\n',
        "    source: git\n"
        '    version: "0.0.16+rustdesk.1"\n',
        "locked RGBA source authority",
    ),
    (
        "plugin_license",
        "Apache License",
        "Unknown License",
        "RGBA package license identity",
    ),
    (
        "plugin_upstream",
        "42797e0f03141dc2b585f76c64a13974508058b4",
        "0000000000000000000000000000000000000000",
        "RGBA package upstream revision",
    ),
    (
        "plugin_dart",
        "Future<bool> closeTexture(int key)",
        "Future<dynamic> closeTexture(int key)",
        "typed RGBA close result",
    ),
    (
        "plugin_windows_texture",
        "buffer_ready_ = false;\n"
        "  width_[background_index] = 0;",
        "buffer_ready_ = true;\n"
        "  width_[background_index] = 0;",
        "Windows failed-mark rollback",
    ),
    (
        "plugin_windows_texture",
        "const bool notification_needed = !buffer_ready_;",
        "const bool notification_needed = true;",
        "Windows latest-wins pending-frame coalescing",
    ),
    (
        "plugin_windows",
        "auto texture_node = textures_.extract(found);",
        "textures_.erase(found);",
        "Windows exact close owner extraction",
    ),
    (
        "plugin_windows",
        "auto [slot, inserted] = textures_.try_emplace(key);",
        "auto slot = textures_.find(key);\n"
        "      const bool inserted = slot == textures_.end();",
        "Windows pre-registration owner-slot reservation",
    ),
    (
        "plugin_windows",
        "texture_registrar_->UnregisterTexture(\n"
        "            texture->texture_id(), [texture, async_result]()",
        "texture_registrar_->UnregisterTexture(texture->texture_id());\n"
        "        if (false",
        "Windows unregister completion ownership",
    ),
    (
        "plugin_windows_c_api",
        "  try {\n"
        "    static_cast<TextureRgba*>(texture_rgba)",
        "  static_cast<TextureRgba*>(texture_rgba)",
        "Windows C-ABI exception containment",
    ),
    (
        "plugin_linux",
        "std::unordered_map<int64_t, TextureRgba*>* renderers;",
        "static std::unordered_map<int64_t, TextureRgba*> renderers;",
        "Linux per-plugin renderer ownership",
    ),
    (
        "plugin_linux",
        "  g_object_unref(texture);\n"
        "}",
        "  // owning reference leaked\n"
        "}",
        "Linux owning-reference release",
    ),
    (
        "plugin_linux",
        "  if (!marked) {\n"
        "    delete[] self->buffer;",
        "  if (false) {\n"
        "    delete[] self->buffer;",
        "Linux failed-mark rollback",
    ),
    (
        "plugin_linux",
        "const gboolean notification_needed = !self->buffer_ready;",
        "const gboolean notification_needed = TRUE;",
        "Linux latest-wins pending-frame coalescing",
    ),
    (
        "plugin_linux",
        "    *width = self->prior_width;\n"
        "    *height = self->prior_height;\n"
        "    g_mutex_unlock(&self->mutex);\n"
        "    return TRUE;",
        "    *width = self->buffer_width;\n"
        "    *height = self->buffer_height;\n"
        "    g_mutex_unlock(&self->mutex);\n"
        "    return TRUE;",
        "Linux prior-frame metadata survives failed pending publication",
    ),
    (
        "plugin_macos_texture",
        "            registry = nil\n",
        "            registry = registry\n",
        "macOS retired registry invalidation",
    ),
    (
        "plugin_macos",
        "CFGetTypeID(number) != CFBooleanGetTypeID()",
        "CFGetTypeID(number) == CFBooleanGetTypeID()",
        "macOS boolean argument rejection",
    ),
    (
        "plugin_macos",
        "renderers.removeValue(forKey: key)",
        "renderers[key]",
        "macOS renderer-map release",
    ),
    (
        "plugin_macos_texture",
        "let notificationNeeded = !framePending",
        "let notificationNeeded = true",
        "macOS latest-wins pending-frame coalescing",
    ),
    ("requirements", '<div class="req"><span class="id">R-S11ex</span>', '<div class="req"><span class="id">R-S11ex-disabled</span>', "normative requirement"),
    ("requirements", '<div class="req"><span class="id">R-S11ey</span>', '<div class="req"><span class="id">R-S11ey-disabled</span>', "software-only normative requirement"),
    ("requirements", "<tr><td>306</td>", "<tr><td>306-disabled</td>", "Appendix disposition"),
    ("requirements", "<tr><td>307</td>", "<tr><td>307-disabled</td>", "software-only Appendix disposition"),
    ("hardening", "**R-S11ex/R-S11e-185 exact desktop Flutter texture lifecycle and UI-owner registration", "**R-S11ex-disabled/R-S11e-185 exact desktop Flutter texture lifecycle and UI-owner registration", "hardening ledger"),
    ("hardening", "**R-S11ey/R-S11e-186 software-RGBA-only desktop presentation", "**R-S11ey-disabled/R-S11e-186 software-RGBA-only desktop presentation", "software-only hardening ledger"),
    ("dart_verify", "flutter test --no-pub test/desktop_texture_lifecycle_test.dart", "true # desktop texture lifecycle test disabled", "Dart behavior gate"),
    ("verify", "python3 scripts/verify-desktop-texture-lifecycle.py --repo . --self-test", "python3 scripts/verify-desktop-texture-lifecycle.py --repo .", "shared mutation gate"),
    ("apple", "python3 scripts/verify-desktop-texture-lifecycle.py --repo . --self-test", "python3 scripts/verify-desktop-texture-lifecycle.py --repo .", "Apple mutation gate"),
    ("workspace", '"desktop_texture_lifecycle_verifier": (', '"desktop_texture_lifecycle_verifier_disabled": (', "independent source binding"),
)


def run_self_test(sources: Dict[str, str]) -> None:
    for key, old, new, label in MUTATIONS:
        if old not in sources[key]:
            raise VerificationError(f"self-test fixture missing for {label}")
        mutated = dict(sources)
        mutated[key] = sources[key].replace(old, new, 1)
        try:
            validate(mutated)
        except VerificationError:
            continue
        raise VerificationError(f"self-test mutation survived: {label}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path("."))
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    sources = load_sources(args.repo.resolve())
    validate(sources)
    if args.self_test:
        run_self_test(sources)
        print(
            "desktop texture lifecycle verifier self-test passed "
            f"({len(MUTATIONS)} mutations)"
        )
    else:
        print("desktop texture lifecycle verifier passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VerificationError as error:
        print(f"desktop texture lifecycle verifier failed: {error}")
        raise SystemExit(1)
