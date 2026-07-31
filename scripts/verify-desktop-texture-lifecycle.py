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


def load_sources(repo: Path) -> Dict[str, str]:
    paths = {
        "lifecycle": "flutter/lib/models/desktop_texture_lifecycle.dart",
        "render": "flutter/lib/models/desktop_render_texture.dart",
        "model": "flutter/lib/models/model.dart",
        "remote": "flutter/lib/desktop/pages/remote_page.dart",
        "camera": "flutter/lib/desktop/pages/view_camera_page.dart",
        "flutter": "src/flutter.rs",
        "ffi": "src/flutter_ffi.rs",
        "native_model": "flutter/lib/models/native_model.dart",
        "web_model": "flutter/lib/models/web_model.dart",
        "web_bridge": "flutter/lib/web/bridge.dart",
        "tests": "flutter/test/desktop_texture_lifecycle_test.dart",
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
            "await textureRenderer.createTexture(_textureKey);",
            "await textureRenderer.getTexturePtr(_textureKey);",
            "_ffi.textureModel.setRgbaTextureId",
            "platformFFI.registerPixelbufferTexture(",
            "_sessionId, _clientOwnerId, _display, ptr",
            "_sessionId, _clientOwnerId, _display, 0",
            "_ffi.textureModel.clearRgbaTextureId(display: _display, id: id);",
            "await textureRenderer.closeTexture(_textureKey);",
            "Future<void> retire() => _lifecycle.retire();",
        ),
        "pixelbuffer lifecycle wiring",
    )
    gpu = extract_braced_item(render, "class _GpuTexture", "GPU texture owner")
    require_order(
        gpu,
        (
            "_lifecycle = DesktopTextureLifecycle(",
            "await gpuTextureRenderer.registerTexture();",
            "await gpuTextureRenderer.output(id);",
            "platformFFI.registerGpuTexture(",
            "_sessionId, _clientOwnerId, _display, output",
            "_sessionId, _clientOwnerId, _display, 0",
            "_ffi.textureModel.clearGpuTextureId(display: _display, id: id);",
            "await gpuTextureRenderer.unregisterTexture(id);",
            "Future<void> retire() => _lifecycle?.retire()",
        ),
        "GPU lifecycle wiring",
    )
    display_textures = extract_braced_item(
        render, "class _DisplayTextures", "paired display texture owner"
    )
    require_order(
        display_textures,
        (
            "_PixelbufferTexture(display, ffi.sessionId, ffi.clientOwnerId, ffi)",
            "_GpuTexture(display, ffi.sessionId, ffi.clientOwnerId, ffi)",
            "_pixelbuffer.start();",
            "_gpu.start();",
        ),
        "both exact texture owners exist before either starts",
    )
    texture_model = extract_braced_item(
        render, "class TextureModel", "desktop texture model"
    )
    require(
        texture_model,
        "Map<int, LatestDesktopTextureSlot<_DisplayTextures>>",
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
            "create: () => _DisplayTextures(display, ffi)",
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
    for method, field in (
        ("clearRgbaTextureId", "rgbaTextureId"),
        ("clearGpuTextureId", "gpuTextureId"),
    ):
        clear = extract_braced_item(
            texture_model,
            f"{method}({{required int display, required int id}})",
            f"exact {field} clearing",
        )
        require_order(
            clear,
            (
                "if (_disposed) return;",
                "final control = _control[display];",
                f"if (control?.{field} == id)",
                "(-1);",
            ),
            f"exact {field} clearing without control recreation",
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
    exported_gpu = extract_braced_item(
        flutter,
        "pub fn session_register_gpu_texture(",
        "GPU registration export",
    )
    require_order(
        exported_gpu,
        (
            "_client_owner_id: SessionID,",
            "s.ui_handler.register_gpu_texture(",
            "&_session_id,",
            "&_client_owner_id,",
            "if !admitted",
        ),
        "exact-owner GPU export",
    )
    require(
        flutter,
        "fn r_s11ex_retired_desktop_ui_owner_cannot_replace_or_clear_texture()",
        "native same-session owner-replacement regression",
    )

    ffi = sources["ffi"]
    for signature, label in (
        (
            "pub fn session_register_pixelbuffer_texture(",
            "pixelbuffer bridge wrapper",
        ),
        ("pub fn session_register_gpu_texture(", "GPU bridge wrapper"),
    ):
        wrapper = extract_braced_item(ffi, signature, label)
        require(
            wrapper,
            "client_owner_id: SessionID,",
            f"{label} exact UI-owner argument",
        )
        require_order(
            wrapper,
            ("session_id,", "client_owner_id,", "display,", "ptr,"),
            f"{label} exact argument propagation",
        )

    for key in ("native_model", "web_model"):
        wrapper = sources[key]
        pixel_start = wrapper.find("void registerPixelbufferTexture(")
        gpu_start = wrapper.find("void registerGpuTexture(", pixel_start + 1)
        init_start = wrapper.find("Future<void> init(", gpu_start + 1)
        if min(pixel_start, gpu_start, init_start) < 0:
            raise VerificationError(f"{key} texture wrapper boundaries are missing")
        pixel_wrapper = wrapper[pixel_start:gpu_start]
        gpu_wrapper = wrapper[gpu_start:init_start]
        for method, body in (
            ("pixelbuffer", pixel_wrapper),
            ("GPU", gpu_wrapper),
        ):
            require(
                body,
                "SessionID clientOwnerId, int display, int ptr",
                f"{key} {method} owner signature",
            )
            require(
                body,
                "clientOwnerId: clientOwnerId",
                f"{key} {method} generated-bridge owner propagation",
            )
    web_bridge = sources["web_bridge"]
    for signature in (
        "void sessionRegisterPixelbufferTexture(",
        "void sessionRegisterGpuTexture(",
    ):
        stub = extract_braced_item(web_bridge, signature, "web texture stub")
        require(
            stub,
            "required UuidValue clientOwnerId,",
            "web exact UI-owner parity",
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
        ("requirements", "<tr><td>306</td>", "Appendix C #306"),
        (
            "hardening",
            "**R-S11ex/R-S11e-185 exact desktop Flutter texture lifecycle and UI-owner registration",
            "desktop texture hardening ledger",
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
    ("render", "_pixelbuffer.start();", "_gpu.start();", "paired texture start"),
    ("render", "_sessionId, _clientOwnerId, _display, ptr", "_sessionId, _sessionId, _display, ptr", "pixel owner publication"),
    ("render", "_sessionId, _clientOwnerId, _display, 0", "_sessionId, _sessionId, _display, 0", "pixel owner unpublication"),
    ("render", "control?.rgbaTextureId == id", "control != null", "exact pixel UI-ID clearing"),
    ("render", "await textureRenderer.closeTexture(_textureKey);", "textureRenderer.closeTexture(_textureKey);", "pixel release finality"),
    ("render", "_sessionId, _clientOwnerId, _display, output", "_sessionId, _sessionId, _display, output", "GPU owner publication"),
    ("render", "control?.gpuTextureId == id", "control != null", "exact GPU UI-ID clearing"),
    ("render", "await gpuTextureRenderer.unregisterTexture(id);", "gpuTextureRenderer.unregisterTexture(id);", "GPU release finality"),
    ("render", "Map<int, LatestDesktopTextureSlot<_DisplayTextures>>", "Map<int, _DisplayTextures>", "serialized display slots"),
    ("render", "entry.value.setWanted(false);", "_textureSlots.remove(entry.key);", "serialized display retirement"),
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
    ("requirements", '<div class="req"><span class="id">R-S11ex</span>', '<div class="req"><span class="id">R-S11ex-disabled</span>', "normative requirement"),
    ("requirements", "<tr><td>306</td>", "<tr><td>306-disabled</td>", "Appendix disposition"),
    ("hardening", "**R-S11ex/R-S11e-185 exact desktop Flutter texture lifecycle and UI-owner registration", "**R-S11ex-disabled/R-S11e-185 exact desktop Flutter texture lifecycle and UI-owner registration", "hardening ledger"),
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
