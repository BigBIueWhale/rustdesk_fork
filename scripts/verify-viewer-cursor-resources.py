#!/usr/bin/env python3
"""Verify exact, bounded remote-cursor shape ownership from capture to teardown."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
from typing import Dict, Iterable, Tuple


class VerificationError(RuntimeError):
    pass


def require(source: str, needle: str, label: str) -> None:
    if needle not in source:
        raise VerificationError(f"missing {label}: {needle!r}")


def forbid(source: str, needle: str, label: str) -> None:
    if needle in source:
        raise VerificationError(f"forbidden {label} remains: {needle!r}")


def require_order(source: str, needles: Iterable[str], label: str) -> None:
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
        raise VerificationError(f"missing start for {label}")
    finish = source.find(end, begin + len(start))
    if finish < 0:
        raise VerificationError(f"missing end for {label}")
    return source[begin:finish]


def load_sources(repo: Path) -> Dict[str, str]:
    paths = {
        "platform": "src/platform/mod.rs",
        "windows": "src/platform/windows.rs",
        "linux": "src/platform/linux.rs",
        "macos": "src/platform/macos.rs",
        "input": "src/server/input_service.rs",
        "compress": "libs/hbb_common/src/compress.rs",
        "compress_test": "libs/compress_it/tests/compress.rs",
        "flutter": "src/flutter.rs",
        "ffi": "src/flutter_ffi.rs",
        "model": "flutter/lib/models/model.dart",
        "registry": "flutter/lib/models/custom_cursor_registry.dart",
        "native_cursor": "flutter/lib/native/custom_cursor.dart",
        "web_cursor": "flutter/lib/web/custom_cursor.dart",
        "native_model": "flutter/lib/models/native_model.dart",
        "web_model": "flutter/lib/models/web_model.dart",
        "web_bridge": "flutter/lib/web/bridge.dart",
        "desktop_remote": "flutter/lib/desktop/pages/remote_page.dart",
        "desktop_camera": "flutter/lib/desktop/pages/view_camera_page.dart",
        "mobile_remote": "flutter/lib/mobile/pages/remote_page.dart",
        "mobile_camera": "flutter/lib/mobile/pages/view_camera_page.dart",
        "dart_test": "flutter/test/custom_cursor_registry_test.dart",
        "requirements": "requirements.html",
        "hardening": "HARDENING_STATUS.md",
        "native_watch": "docs/NATIVE-CODEC-WATCH.md",
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
    platform = sources["platform"]
    require(
        platform,
        "pub(crate) const MAX_CURSOR_RGBA_BYTES: usize = 4 * 1024 * 1024;",
        "4 MiB platform cursor allocation ceiling",
    )
    rgba_len = extract_braced_item(
        platform, "pub(crate) fn cursor_rgba_len(", "checked cursor RGBA length"
    )
    require_order(
        rgba_len,
        (
            "usize::try_from(width).ok()?",
            "usize::try_from(height).ok()?",
            "if width == 0 || height == 0",
            ".checked_mul(height)?",
            ".checked_mul(4)",
            ".filter(|bytes| *bytes <= MAX_CURSOR_RGBA_BYTES)",
        ),
        "checked positive cursor geometry before allocation",
    )
    require(
        platform,
        "fn r_s11gv_cursor_allocation_bound_is_checked_before_platform_copy()",
        "platform allocation-bound regression",
    )

    windows = extract_braced_item(
        sources["windows"], "pub fn get_cursor_data(hcursor: u64)", "Windows cursor capture"
    )
    require_order(
        windows,
        (
            "let cbits_size = super::cursor_rgba_len(width, height)",
            "let mask_size = mask_width\n            .checked_mul(mask_height)",
            ".filter(|size| *size <= super::MAX_CURSOR_RGBA_BYTES)",
            "let mut cbits = vec![0; cbits_size];",
            "let mut mbits = vec![0; mask_size];",
            "if r != mask_size_i32",
            "let outlined_width = width\n                .checked_add(2)",
            "let outline_size = super::cursor_rgba_len(outlined_width, outlined_height)",
            "checked_add(1)",
            "if hotx >= width || hoty >= height",
            "colors: cbits.into()",
        ),
        "Windows exact mask, outline, hotspot, and pixel capture bounds",
    )

    linux = extract_braced_item(
        sources["linux"], "pub fn get_cursor_data(hcursor: u64)", "Linux cursor capture"
    )
    require_order(
        linux,
        (
            "let Some(rgba_len) = super::cursor_rgba_len(cd.width, cd.height)",
            "if (*img).pixels.is_null()",
            "std::slice::from_raw_parts((*img).pixels, rgba_len / 4)",
            "let mut cd_colors = vec![0_u8; rgba_len];",
        ),
        "Linux checked geometry and pointer before slice/copy",
    )

    macos = sources["macos"]
    mac_geometry = extract_braced_item(
        macos, "fn cursor_image_geometry(", "macOS cursor pixel geometry"
    )
    require_order(
        mac_geometry,
        (
            "!size.width.is_finite()",
            "hotspot.x >= size.width",
            "i32::try_from(pixels_wide)",
            "super::cursor_rgba_len(width, height)",
            "hotspot.x * f64::from(width) / size.width",
            "if hotx < 0 || hoty < 0 || hotx >= width || hoty >= height",
        ),
        "macOS point-to-pixel geometry and hotspot validation",
    )
    bitmap_rep = extract_braced_item(
        macos, "fn cursor_bitmap_rep(", "macOS bounded bitmap representation selection"
    )
    require(bitmap_rep, "class!(NSBitmapImageRep)", "macOS bitmap representation class")
    require(bitmap_rep, "isKindOfClass: bitmap_class", "macOS existing representation check")
    capture = extract_braced_item(
        macos, "fn unsafe_get_cursor_data(", "macOS cursor capture body"
    )
    require_order(
        capture,
        (
            "let rep = cursor_bitmap_rep(img)?;",
            "pixelsWide",
            "pixelsHigh",
            "cursor_image_geometry(size, hotspot, pixels_wide, pixels_high)?",
            "Vec::with_capacity(rgba_len)",
            "colors.extend_from_slice(&[0, 0, 0, 0]);",
        ),
        "macOS bounded existing-representation materialization",
    )
    forbid(capture, "TIFFRepresentation", "unbounded macOS TIFF materialization")

    input_source = sources["input"]
    require(
        input_source,
        "const CURSOR_CACHE_MAX_ENTRIES: usize = 64;",
        "controlled cursor cache count bound",
    )
    require(
        input_source,
        "const CURSOR_CACHE_MAX_RGBA_BYTES: usize = 16 * 1024 * 1024;",
        "controlled cursor cache raw-byte bound",
    )
    digest = extract_braced_item(
        input_source, "fn cursor_data_digest(", "content-derived cursor identity"
    )
    require_order(
        digest,
        (
            "digest.update(data.hotx.to_le_bytes())",
            "digest.update(data.hoty.to_le_bytes())",
            "digest.update(data.width.to_le_bytes())",
            "digest.update(data.height.to_le_bytes())",
            "digest.update(&data.colors)",
        ),
        "cursor digest covers geometry, hotspot, and exact pixels",
    )
    state = extract_braced_item(input_source, "struct StateCursor", "controlled cursor state")
    require_order(
        state,
        (
            "hcursor: Option<u64>",
            "cursor_digest: Option<[u8; 32]>",
            "next_protocol_cursor_id: u64",
            "cached_cursor_data: BoundedCursorCache<[u8; 32], Arc<Message>>",
        ),
        "OS hint, content identity, protocol identity, and bounded cache separation",
    )
    next_id = extract_braced_item(
        input_source, "fn next_protocol_cursor_id(&mut self)", "protocol cursor ID allocation"
    )
    require_order(
        next_id,
        (".checked_add(1)", ".filter(|next| *next != 0)", "cursor identity space exhausted"),
        "checked nonzero cursor protocol identity",
    )
    run_cursor = extract_braced_item(input_source, "fn run_cursor(", "cursor producer")
    require_order(
        run_cursor,
        (
            'cfg!(any(target_os = "windows", target_os = "macos"))',
            "cursor_rgba_bytes(data.width, data.height)",
            ".filter(|expected| *expected == data.colors.len())",
            "let digest = cursor_data_digest(&data);",
            "data.id = state.next_protocol_cursor_id()?;",
            "if compressed.is_empty()",
            ".insert(digest, msg.clone(), rgba_bytes)",
            "state.cursor_digest = Some(digest);",
        ),
        "bounded sampled content identity and publication",
    )
    subscriber = extract_braced_item(
        input_source, "impl Subscriber for MouseCursorSub", "per-subscriber cursor knowledge"
    )
    require_order(
        subscriber,
        (
            "if let Some(cached) = self.cached.get_cloned(&cd.id)",
            "tmp.set_cursor_id(cd.id);",
            "cursor_rgba_bytes(cd.width, cd.height)",
            "self.cached.insert(cd.id, Arc::new(tmp), rgba_bytes)",
        ),
        "bounded per-subscriber ID-only knowledge",
    )
    for test in (
        "r_s11gv_cursor_cache_bounds_count_bytes_and_touches_lru",
        "r_s11gv_cursor_cache_counter_exhaustion_discards_old_identity_state",
        "r_s11gv_cursor_content_identity_covers_geometry_hotspot_and_rgba",
    ):
        require(input_source, test, f"controlled cursor regression {test}")

    decompress = extract_braced_item(
        sources["compress"], "pub fn decompress_with_limit(", "caller-bounded decompression"
    )
    require_order(
        decompress,
        (
            "max_decompressed.checked_add(1)",
            "decoder.take(read_limit)",
            "limited.read_to_end(&mut out).is_err()",
            "length > max_decompressed",
            "return Vec::new();",
        ),
        "exact over-limit decompression rejection",
    )
    require(
        sources["compress_test"],
        "fn caller_specific_limit_rejects_before_the_global_ceiling()",
        "caller-specific decompression regression",
    )

    flutter = sources["flutter"]
    require(
        flutter,
        "const CURSOR_SHAPE_CACHE_MAX_ENTRIES: usize = 64;",
        "viewer cursor shape count bound",
    )
    require(
        flutter,
        "const CURSOR_SHAPE_CACHE_MAX_RGBA_BYTES: usize = 16 * 1024 * 1024;",
        "viewer cursor shape raw-byte bound",
    )
    remote_rgba = extract_braced_item(
        flutter, "fn remote_cursor_rgba_for_ui(", "viewer exact cursor decompression"
    )
    require_order(
        remote_rgba,
        (
            "remote_cursor_rgba_len(cd.width, cd.height)?",
            "cd.hotx < 0 || cd.hoty < 0 || cd.hotx >= cd.width || cd.hoty >= cd.height",
            "decompress_with_limit(&cd.colors, expected)",
            "colors.len() != expected",
        ),
        "viewer exact geometry, hotspot, and decompression admission",
    )
    handler = extract_braced_item(flutter, "struct SessionHandler", "exact UI handler")
    require_order(
        handler,
        (
            "cursor_shape: CursorShapeMailbox",
            "known_cursor_shapes: CursorShapeKnowledge",
        ),
        "handler-local shape publication and acknowledged knowledge",
    )
    shape_mailbox = extract_braced_item(
        flutter, "struct CursorShapeMailbox", "cursor shape mailbox"
    )
    fields = [line.strip() for line in shape_mailbox.splitlines()[1:-1] if line.strip()]
    if fields != [
        "published: Option<CursorShapePublication>,",
        "current: Option<CursorShapeValue>,",
        "delivery_failed: bool,",
    ]:
        raise VerificationError(f"cursor shape mailbox is not exactly bounded: {fields!r}")
    post_shape = extract_braced_item(flutter, "fn post_cursor_shape(", "typed cursor shape post")
    for event in ("EventToUI::CursorData(", "EventToUI::CursorId(", "EventToUI::CursorUnavailable("):
        require(post_shape, event, f"typed cursor shape event {event}")
    take_shape = extract_braced_item(
        flutter, "fn take_cursor_shape(", "exact cursor shape acknowledgement"
    )
    require_order(
        take_shape,
        (
            ".filter(|handler| handler.client_owner_id.as_ref() == Some(client_owner_id))",
            "published.value.state.identity() == (id, revision)",
            "published.publication == publication",
            "CursorShapeState::Available(shape) if accepted",
            "known_cursor_shapes.insert(shape)",
            "known_cursor_shapes\n                    .remove(&shape.id, Some(shape.revision))",
            "handler.cursor_shape.require_data_for(&acknowledged);",
            "handler.cursor_shape.acknowledge(",
            ".bind_to_knowledge(&mut handler.known_cursor_shapes)",
            "handler.cursor_shape.delivery_failed();",
        ),
        "exact positive/negative acknowledgement and one-step repair",
    )
    set_shape = extract_braced_item(
        flutter, "fn set_cursor_data(&self, cd: CursorData)", "viewer cursor data admission"
    )
    require_order(
        set_shape,
        (
            "remote_cursor_rgba_for_ui(&cd)",
            "self.next_cursor_shape_revision()",
            "self.cursor_shapes.write().unwrap().insert(Arc::clone(&shape))",
            "self.offer_cursor_shape(CursorShapeValue",
        ),
        "validated cached cursor shape publication",
    )
    for test in (
        "r_s11gv_cursor_shape_mailbox_is_exact_latest_wins_and_replayable",
        "r_s11gv_cursor_shape_mailbox_bounds_failure_unavailable_and_exhaustion",
        "r_s11gv_negative_id_ack_republishes_full_data_exactly_once",
        "r_s11gv_cursor_shape_cache_evicts_by_count_bytes_and_recency",
        "r_s11gv_cursor_shape_id_is_used_only_after_exact_decoded_knowledge",
        "r_s11gv_cursor_shape_knowledge_is_metadata_only_and_bounded",
        "r_s11gv_new_ui_handler_inherits_current_shape_and_position_for_replay",
    ):
        require(flutter, test, f"viewer cursor regression {test}")

    ffi = sources["ffi"]
    require(
        ffi,
        "CursorData(String, u64, i32, i32, i32, i32, Vec<u8>, u64)",
        "typed full cursor FFI event",
    )
    require(ffi, "CursorId(String, u64, u64)", "typed ID-only cursor FFI event")
    require(ffi, "CursorUnavailable(String, u64)", "typed unavailable cursor FFI event")
    require(ffi, "pub fn session_take_cursor_shape(", "exact generated cursor acknowledgement source")
    for wrapper in ("native_model", "web_model"):
        require(
            sources[wrapper],
            "bool takeCursorShape(SessionID sessionId, SessionID clientOwnerId, String id,",
            f"{wrapper} exact cursor acknowledgement wrapper",
        )
        require(
            sources[wrapper],
            "revision: revision,\n          publication: publication,\n          accepted: accepted",
            f"{wrapper} exact acknowledgement forwarding",
        )
    for event in (
        "class EventToUI_CursorData implements EventToUI",
        "class EventToUI_CursorId implements EventToUI",
        "class EventToUI_CursorUnavailable implements EventToUI",
    ):
        require(sources["web_bridge"], event, f"hand-written web bridge parity {event}")

    model = sources["model"]
    require(model, "const int kCursorShapeCacheMaxEntries = 64;", "Dart shape count bound")
    require(
        model,
        "const int kCursorShapeCacheMaxRgbaBytes = 16 * 1024 * 1024;",
        "Dart shape raw-byte bound",
    )
    require(model, "const String _maxRemoteCursorId = '18446744073709551615';", "u64 Dart cursor ID ceiling")
    remote_id = extract_braced_item(model, "bool _isRemoteCursorId(", "canonical Dart cursor ID")
    require_order(
        remote_id,
        (
            "id.isEmpty || id.length > _maxRemoteCursorId.length",
            "codeUnit < 0x30 || codeUnit > 0x39",
            "id.codeUnitAt(0) == 0x30",
            "id.compareTo(_maxRemoteCursorId) <= 0",
        ),
        "canonical unsigned-64-bit cursor ID admission",
    )
    retire = extract_braced_item(model, "void retireCursorResources()", "Dart cursor owner retirement")
    require_order(
        retire,
        (
            "_customCursorOwnerRetired = true;",
            "retireCustomCursorOwner(_customCursorOwner);",
            "_image = null;",
            "_disposeImages();",
            "_webShapeSources.clear();",
            "_webShapeSourceRgbaBytes = 0;",
        ),
        "owner retirement before local image/source teardown",
    )
    prepare = extract_between(
        model,
        "Future<_PreparedCursorShape?> _prepareCursorShape(",
        "\n  bool commitCursorShape(",
        "Dart cursor preparation",
    )
    require_order(
        prepare,
        (
            "_customCursorOwnerRetired",
            "final expectedLen = _remoteCursorRgbaLen(width, height);",
            "final ownedRgba = Uint8List.fromList(rgba);",
            "decodedImage = await img.decodeImageFromPixels",
            "if (_customCursorOwnerRetired ||",
            "final baseData = isWindows",
            "if (_customCursorOwnerRetired ||",
            "return _PreparedCursorShape(",
        ),
        "owned bytes and post-await/post-encoding owner checks",
    )
    commit = extract_braced_item(model, "bool commitCursorShape(", "Dart shape commit")
    require_order(
        commit,
        (
            "_customCursorOwnerRetired",
            "previous.image.dispose();",
            "_shapeCacheRgbaBytes += prepared.rgbaBytes;",
            "_evictCursorShapes();",
            "return _activateCursorShape(prepared.id, prepared.revision);",
        ),
        "exact commit accounting and decoded-image retirement",
    )
    forbid(model, "cursorDataList", "unbounded cached peer cursor payload history")
    forbid(model, "lastCursorId", "implicit last cursor identity")
    for page in ("desktop_remote", "desktop_camera", "mobile_remote", "mobile_camera"):
        require(
            sources[page],
            "cursorModel.retireCursorResources();",
            f"{page} cursor owner retirement",
        )

    registry = sources["registry"]
    require(
        registry,
        "class CustomCursorPresentationCoordinator",
        "process-global presentation coordinator",
    )
    activate = extract_between(
        registry,
        "Future<bool> activate({",
        "\n  Future<void> activateFallback({",
        "serialized cursor activation",
    )
    require_order(
        activate,
        (
            "_desiredRequest = request;",
            "_desiredPresenter = presenter;",
            "final ready = await lease.ready;",
            "await _activations.schedule(() async",
            "!identical(_desiredRequest, request) || !mayPresent()",
            "if (!ready)",
            "await present(lease.platformKey);",
            "final previous = _lease;",
            "_lease = lease;",
            "previous?.release();",
        ),
        "desire-before-registration and replacement-before-release ordering",
    )
    if activate.count("previous?.release();") != 1:
        raise VerificationError(
            "serialized cursor activation must release its predecessor exactly once"
        )
    fallback = extract_braced_item(registry, "Future<bool> _fallback(", "cursor fallback finality")
    require_order(
        fallback,
        (
            "await fallback();",
            "return false;",
            "final previous = _lease;",
            "_lease = null;",
            "previous?.release();",
            "_releaseUncertainLeases();",
        ),
        "fallback-before-possibly-displayed lease release",
    )
    ensure = extract_between(
        registry,
        "CustomCursorHandle? ensure({",
        "\n  Future<bool> _initializeEntry(",
        "global cursor registry admission",
    )
    require_order(
        ensure,
        (
            "_resourceStateUncertain",
            "owner.length > _maxOwnerLength",
            "logicalKey.length > _maxLogicalKeyLength",
            "rgbaBytes > maxRgbaBytes",
            "while (_entryCount >= maxEntries || _rgbaBytes + rgbaBytes > maxRgbaBytes)",
            "final victim = _oldestInactiveEntry();",
            "retiredResources.add(_remove(victim.owner, victimOwner, victim));",
            "_entryCount += 1;",
            "_rgbaBytes += rgbaBytes;",
            "_initializeEntry(",
        ),
        "global logical capacity, inactive eviction, and pending accounting",
    )
    initialize = extract_braced_item(registry, "Future<bool> _initializeEntry(", "exact cursor registration")
    require_order(
        initialize,
        (
            "for (final retired in retiredResources)",
            "if (!await retired)",
            "if (_resourceStateUncertain ||",
            "registered = await register(entry.platformKey);",
            "_resourceStateUncertain = true;",
            "entry.registrationUncertain = true;",
        ),
        "deletion-before-registration and uncertain-registration fail close",
    )
    remove = extract_braced_item(registry, "Future<bool> _remove(", "exact platform cursor deletion")
    require_order(
        remove,
        (
            "!entry.registrationFinished",
            "entry.activeSessions != 0",
            "entry.ready.then<bool>((registered) async",
            "if (!registered && !entry.registrationUncertain)",
            "await entry.delete(entry.platformKey);",
            "_resourceStateUncertain = true;",
        ),
        "pending/active exclusion and uncertain-delete fail close",
    )
    require(
        registry,
        "void _reportCustomCursorError(",
        "diagnostic isolation helper",
    )
    require(
        registry,
        "Zone.current.scheduleMicrotask(() {\n      Zone.current.handleUncaughtError(reportError, reportStackTrace);",
        "throwing diagnostic asynchronous surfacing",
    )
    token = extract_braced_item(
        registry, "class CustomCursorPresentationToken", "finalizer-safe presentation token"
    )
    forbid(token, "MouseCursorSession", "presentation token session back-reference")
    require(token, "Future<void>? _retirement;", "idempotent retirement future")
    require_order(token, ("final retirement = _retirement;", "_retired = true;", "_retirement = started;"), "idempotent token retirement")

    for cursor_impl in ("native_cursor", "web_cursor"):
        source = sources[cursor_impl]
        require(source, "final _customCursors = CustomCursorRegistry(", f"{cursor_impl} process-global registry")
        require(source, "final _cursorPresentations = CustomCursorPresentationCoordinator(", f"{cursor_impl} shared presentation coordinator")
        require(source, "Finalizer<CustomCursorPresentationToken>", f"{cursor_impl} missing-dispose finalizer")
        require(source, "_cursorPresentationFinalizer.attach(this, _presentation, detach: this);", f"{cursor_impl} constructor finalizer attachment")
        require_order(
            source,
            (
                "void dispose() {",
                "_disposed = true;",
                "_cursorPresentationFinalizer.detach(this);",
                "unawaited(_presentation.retire());",
            ),
            f"{cursor_impl} explicit idempotent presentation retirement",
        )

    dart_tests = sources["dart_test"]
    for test in (
        "activation queue preserves issue order across asynchronous turns",
        "replacement owns display before old lease deletion",
        "slow obsolete registration cannot block a newer activation",
        "partial presentation failure retains both possible displays",
        "entry and byte limits are global across UI owners",
        "pending registration remains globally accounted until finality",
        "replacement registration waits for exact eviction deletion",
        "uncertain deletion fails closed for all later registrations",
        "throwing presentation diagnostics cannot interrupt fallback finality",
        "throwing registry diagnostics cannot strand registration finality",
    ):
        require(dart_tests, f"test('{test}'", f"Dart cursor resource regression {test}")

    requirements = sources["requirements"]
    require(requirements, '<div class="req"><span class="id">R-S11gv</span>', "normative cursor resource requirement")
    require(requirements, "Diagnostic callbacks <span class=\"kw\">MUST NOT</span> interrupt registration, fallback, release, or retirement finality", "normative diagnostic finality")
    require(requirements, "<tr><td>357</td>", "Appendix C cursor resource disposition")
    require(requirements, "consistent with the reported recovery shape; it is not proof", "Appendix causation boundary")
    hardening = sources["hardening"]
    require(hardening, "### R-S11gv/R-S11e-234 — exact bounded cursor-shape identity, publication, presentation, and retirement", "cursor resource hardening ledger")
    require(hardening, "the whole initial connection,", "explicit complete connection-flow request")
    require(hardening, "all remain open release obligations", "explicit open evidence ledger")

    requirement_hash = hashlib.sha256(requirements.encode("utf-8")).hexdigest()
    hash_line = f"Requirements hash: {requirement_hash}"
    require(sources["native_watch"], hash_line, "native-codec ledger requirements hash")
    require(hardening, f"{requirement_hash}  requirements.html", "hardening requirements hash")
    require(sources["native_watch"], "The same identity additionally binds R-S11gv and Appendix C #357.", "native watch cursor resource identity")

    gate_command = "python3 scripts/verify-viewer-cursor-resources.py --repo . --self-test"
    for gate in ("verify", "dart_verify", "apple"):
        if sources[gate].count(gate_command) != 1:
            raise VerificationError(f"{gate} must invoke the cursor-resource verifier exactly once")
    require(sources["verify"], "r_s11gv_ --color never", "shared Rust cursor resource test filter")
    require(sources["workspace"], '"scripts/verify-viewer-cursor-resources.py"', "independent workspace cursor verifier source")
    require(sources["workspace"], "viewer cursor resources", "independent cursor-resource dispatch binding")


MUTATIONS: Tuple[Tuple[str, str, str, str], ...] = (
    ("platform", "MAX_CURSOR_RGBA_BYTES: usize = 4 * 1024 * 1024", "MAX_CURSOR_RGBA_BYTES: usize = 8 * 1024 * 1024", "platform byte ceiling"),
    ("platform", ".checked_mul(height)?", ".wrapping_mul(height)", "platform checked pixel multiplication"),
    ("platform", ".filter(|bytes| *bytes <= MAX_CURSOR_RGBA_BYTES)", ".filter(|bytes| *bytes > MAX_CURSOR_RGBA_BYTES)", "platform ceiling direction"),
    ("windows", "if r != mask_size_i32", "if r > mask_size_i32", "Windows exact mask copy"),
    ("windows", "let outline_size = super::cursor_rgba_len(outlined_width, outlined_height)", "let outline_size = cbits_size.checked_add(8)", "Windows checked outline size"),
    ("windows", "if hotx >= width || hoty >= height", "if hotx > width || hoty > height", "Windows in-bitmap hotspot"),
    ("linux", "if (*img).pixels.is_null()", "if false && (*img).pixels.is_null()", "Linux native pointer check"),
    ("linux", "std::slice::from_raw_parts((*img).pixels, rgba_len / 4)", "std::slice::from_raw_parts((*img).pixels, rgba_len)", "Linux exact pixel slice"),
    ("macos", "let size: NSSize = msg_send![img, size];\n        let rep = cursor_bitmap_rep(img)?;\n        /*", "let size: NSSize = msg_send![img, size];\n        let rep: id = msg_send![img, TIFFRepresentation];\n        /*", "macOS bounded representation"),
    ("macos", "hotspot.x * f64::from(width) / size.width", "hotspot.x", "macOS point-to-pixel hotspot"),
    ("macos", "colors.extend_from_slice(&[0, 0, 0, 0]);", "colors.push(0);", "macOS exact transparent pixel"),
    ("input", "CURSOR_CACHE_MAX_ENTRIES: usize = 64", "CURSOR_CACHE_MAX_ENTRIES: usize = 640", "controller cache count"),
    ("input", "CURSOR_CACHE_MAX_RGBA_BYTES: usize = 16 * 1024 * 1024", "CURSOR_CACHE_MAX_RGBA_BYTES: usize = usize::MAX", "controller cache bytes"),
    ("input", "digest.update(data.hotx.to_le_bytes())", "digest.update(data.id.to_le_bytes())", "content hotspot identity"),
    ("input", "digest.update(&data.colors)", "digest.update(data.id.to_le_bytes())", "content pixel identity"),
    ("input", ".checked_add(1)\n            .filter(|next| *next != 0)", ".wrapping_add(1)", "protocol ID exhaustion"),
    ("input", 'cfg!(any(target_os = "windows", target_os = "macos"))', 'cfg!(target_os = "macos")', "Windows reusable-handle sampling"),
    ("input", ".filter(|expected| *expected == data.colors.len())", ".filter(|expected| *expected <= data.colors.len())", "controller exact capture length"),
    ("input", "data.id = state.next_protocol_cursor_id()?;", "data.id = hcursor;", "content/protocol identity separation"),
    ("input", "self.cached.insert(cd.id, Arc::new(tmp), rgba_bytes)", "self.cached.entries.insert(cd.id, Default::default())", "subscriber bounded knowledge"),
    ("compress", "max_decompressed.checked_add(1)", "max_decompressed.checked_add(0)", "decompression overflow sentinel"),
    ("compress", "length > max_decompressed", "length >= max_decompressed", "exact decompression limit"),
    ("compress_test", "fn caller_specific_limit_rejects_before_the_global_ceiling()", "fn caller_specific_limit_is_unchecked()", "caller limit regression"),
    ("flutter", "CURSOR_SHAPE_CACHE_MAX_ENTRIES: usize = 64", "CURSOR_SHAPE_CACHE_MAX_ENTRIES: usize = 640", "viewer cache count"),
    ("flutter", "decompress_with_limit(&cd.colors, expected)", "hbb_common::compress::decompress(&cd.colors)", "viewer exact decompression"),
    ("flutter", "cursor_shape: CursorShapeMailbox", "cursor_shape: Vec<CursorShapeValue>", "handler bounded mailbox"),
    ("flutter", "known_cursor_shapes: CursorShapeKnowledge", "known_cursor_shapes: HashMap<String, u64>", "handler bounded knowledge"),
    ("flutter", "current: Option<CursorShapeValue>", "pending: Vec<CursorShapeValue>", "shape mailbox latest state"),
    ("flutter", "published.value.state.identity() == (id, revision)", "published.value.state.identity().0 == id", "exact identity acknowledgement"),
    ("flutter", "published.publication == publication", "published.publication <= publication", "exact token acknowledgement"),
    ("flutter", "handler.cursor_shape.require_data_for(&acknowledged);", "handler.cursor_shape.clear();", "negative ID full-data repair"),
    ("flutter", ".bind_to_knowledge(&mut handler.known_cursor_shapes)", ".clone()", "promotion knowledge binding"),
    ("flutter", "fn r_s11gv_cursor_shape_knowledge_is_metadata_only_and_bounded()", "fn cursor_shape_knowledge_is_unbounded()", "knowledge regression"),
    ("ffi", "CursorData(String, u64, i32, i32, i32, i32, Vec<u8>, u64)", "CursorData(String, Vec<u8>)", "typed full-data event"),
    ("ffi", "CursorId(String, u64, u64)", "CursorId(String)", "typed ID event"),
    ("native_model", "accepted: accepted", "accepted: true", "native acknowledgement outcome"),
    ("web_model", "accepted: accepted", "accepted: true", "web acknowledgement outcome"),
    ("web_bridge", "class EventToUI_CursorUnavailable implements EventToUI", "class EventToUI_CursorUnavailableDisabled implements EventToUI", "web bridge parity"),
    ("model", "_maxRemoteCursorId = '18446744073709551615'", "_maxRemoteCursorId = '99999999999999999999'", "Dart u64 ID bound"),
    ("model", "id.codeUnitAt(0) == 0x30", "false", "canonical positive ID"),
    ("model", "_customCursorOwnerRetired = true;", "_customCursorOwnerRetired = false;", "retirement admission boundary"),
    ("model", "retireCustomCursorOwner(_customCursorOwner);", "// platform owner retained", "platform owner retirement"),
    ("model", "final ownedRgba = Uint8List.fromList(rgba);", "final ownedRgba = rgba;", "Dart owned cursor bytes"),
    ("model", "_shapeCacheRgbaBytes += prepared.rgbaBytes;", "_shapeCacheRgbaBytes = 0;", "Dart cache byte accounting"),
    ("desktop_remote", "cursorModel.retireCursorResources();", "cursorModel.notifyListeners();", "desktop remote teardown"),
    ("desktop_camera", "cursorModel.retireCursorResources();", "cursorModel.notifyListeners();", "desktop camera teardown"),
    ("mobile_remote", "cursorModel.retireCursorResources();", "cursorModel.notifyListeners();", "mobile remote teardown"),
    ("mobile_camera", "cursorModel.retireCursorResources();", "cursorModel.notifyListeners();", "mobile camera teardown"),
    ("registry", "_desiredRequest = request;", "// desired request delayed", "desired-before-readiness"),
    ("registry", "final ready = await lease.ready;", "final ready = true;", "registration readiness"),
    ("registry", "await present(lease.platformKey);", "unawaited(present(lease.platformKey));", "awaited platform presentation"),
    ("registry", "previous?.release();", "previous?.release(); previous?.release();", "exact predecessor release"),
    ("registry", "while (_entryCount >= maxEntries || _rgbaBytes + rgbaBytes > maxRgbaBytes)", "while (_entryCount > maxEntries)", "global registry capacity"),
    ("registry", "retiredResources.add(_remove(victim.owner, victimOwner, victim));", "unawaited(_remove(victim.owner, victimOwner, victim));", "replacement deletion ordering"),
    ("registry", "entry.activeSessions != 0", "entry.activeSessions < 0", "active lease deletion guard"),
    ("registry", "entry.registrationUncertain = true;", "entry.registrationUncertain = false;", "registration uncertainty"),
    ("registry", "_resourceStateUncertain = true;\n        _reportError('delete", "_reportError('delete", "delete uncertainty fail close"),
    ("registry", "void _reportCustomCursorError(", "void _reportCustomCursorErrorDisabled(", "diagnostic isolation"),
    ("registry", "Future<void>? _retirement;", "Future<void>? _retirementDisabled;", "idempotent token retirement"),
    ("native_cursor", "Finalizer<CustomCursorPresentationToken>", "Finalizer<Object>", "native finalizer token"),
    ("native_cursor", "_cursorPresentationFinalizer.detach(this);", "// finalizer remains attached", "native explicit finalizer detach"),
    ("web_cursor", "Finalizer<CustomCursorPresentationToken>", "Finalizer<Object>", "web finalizer token"),
    ("web_cursor", "unawaited(_presentation.retire());", "// presentation retained", "web explicit retirement"),
    ("dart_test", "slow obsolete registration cannot block a newer activation", "slow obsolete registration blocks a newer activation", "slow registration regression"),
    ("dart_test", "throwing registry diagnostics cannot strand registration finality", "throwing registry diagnostics may strand registration finality", "throwing diagnostic regression"),
    ("requirements", '<div class="req"><span class="id">R-S11gv</span>', '<div class="req"><span class="id">R-S11gv-disabled</span>', "normative requirement"),
    ("requirements", "<tr><td>357</td>", "<tr><td>357-disabled</td>", "Appendix disposition"),
    ("hardening", "### R-S11gv/R-S11e-234 — exact bounded cursor-shape identity, publication, presentation, and retirement", "### R-S11gv-disabled/R-S11e-234 — exact bounded cursor-shape identity, publication, presentation, and retirement", "hardening ledger"),
    ("native_watch", "The same identity additionally binds R-S11gv and Appendix C #357.", "The same identity does not bind R-S11gv.", "native watch identity"),
    ("verify", "python3 scripts/verify-viewer-cursor-resources.py --repo . --self-test", "true # cursor resource verifier disabled", "shared verifier wiring"),
    ("dart_verify", "python3 scripts/verify-viewer-cursor-resources.py --repo . --self-test", "true # cursor resource verifier disabled", "Dart verifier wiring"),
    ("apple", "python3 scripts/verify-viewer-cursor-resources.py --repo . --self-test", "true # cursor resource verifier disabled", "Apple verifier wiring"),
    ("workspace", '"scripts/verify-viewer-cursor-resources.py"', '"scripts/verify-viewer-cursor-resources-disabled.py"', "workspace verifier source"),
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
            "viewer cursor resources verifier self-test passed "
            f"({len(MUTATIONS)} mutations)"
        )
    else:
        print("viewer cursor resources verifier passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VerificationError as error:
        print(f"viewer cursor resources verifier failed: {error}")
        raise SystemExit(1)
