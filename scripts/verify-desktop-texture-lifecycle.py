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
        "presentation_recovery": "flutter/lib/models/presentation_recovery.dart",
        "render": "flutter/lib/models/desktop_render_texture.dart",
        "model": "flutter/lib/models/model.dart",
        "common": "flutter/lib/common.dart",
        "toolbar": "flutter/lib/common/widgets/toolbar.dart",
        "remote": "flutter/lib/desktop/pages/remote_page.dart",
        "remote_tab": "flutter/lib/desktop/pages/remote_tab_page.dart",
        "camera": "flutter/lib/desktop/pages/view_camera_page.dart",
        "camera_tab": "flutter/lib/desktop/pages/view_camera_tab_page.dart",
        "mobile_remote": "flutter/lib/mobile/pages/remote_page.dart",
        "mobile_camera": "flutter/lib/mobile/pages/view_camera_page.dart",
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
        "presentation_tests": "flutter/test/presentation_recovery_test.dart",
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
        "plugin_windows_cmake": (
            "flutter/third_party/texture_rgba_renderer/windows/CMakeLists.txt"
        ),
        "plugin_windows_texture": (
            "flutter/third_party/texture_rgba_renderer/windows/texture_rgba.cpp"
        ),
        "plugin_windows_test": (
            "flutter/third_party/texture_rgba_renderer/windows/test/"
            "texture_rgba_test.cc"
        ),
        "plugin_windows_test_stub": (
            "flutter/third_party/texture_rgba_renderer/windows/test/include/"
            "flutter/texture_registrar.h"
        ),
        "build_windows": "scripts/build-windows.ps1",
        "plugin_windows": (
            "flutter/third_party/texture_rgba_renderer/windows/"
            "texture_rgba_renderer_plugin.cpp"
        ),
        "plugin_windows_c_api": (
            "flutter/third_party/texture_rgba_renderer/windows/"
            "texture_rgba_renderer_plugin_c_api.cpp"
        ),
        "plugin_windows_c_api_h": (
            "flutter/third_party/texture_rgba_renderer/windows/include/"
            "texture_rgba_renderer/texture_rgba_renderer_plugin_c_api.h"
        ),
        "plugin_linux_h": (
            "flutter/third_party/texture_rgba_renderer/linux/include/"
            "texture_rgba_renderer/texture_rgba_renderer_plugin.h"
        ),
        "plugin_linux": (
            "flutter/third_party/texture_rgba_renderer/linux/"
            "texture_rgba_renderer_plugin.cc"
        ),
        "plugin_linux_test": (
            "flutter/third_party/texture_rgba_renderer/linux/test/"
            "texture_rgba_renderer_plugin_test.cc"
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
    ffi = sources["ffi"]
    recovery = extract_braced_item(
        sources["presentation_recovery"],
        "class PresentationRecovery",
        "presentation recovery owner",
    )
    require_order(
        recovery,
        (
            "bool _refreshPending = false;",
            "bool _resumeDemanded = false;",
            "bool _refreshInFlight = false;",
            "bool _retired = false;",
        ),
        "explicit presentation-recovery state",
    )
    suspension = extract_braced_item(
        recovery, "void suspend()", "presentation suspension"
    )
    require_order(
        suspension,
        (
            "if (_retired) return;",
            "_refreshPending = true;",
            "_resumeDemanded = false;",
        ),
        "retirement-safe one-shot suspension",
    )
    resumption = extract_braced_item(
        recovery, "Future<void> resume({", "presentation resumption"
    )
    require_order(
        resumption,
        (
            "if (_retired || !selected) return;",
            "_resumeDemanded = true;",
            "if (_refreshInFlight) return;",
            "_refreshInFlight = true;",
            "while (!_retired && _refreshPending && _resumeDemanded)",
            "_refreshPending = false;",
            "_resumeDemanded = false;",
            "await refresh();",
            "final followUpDemanded = _refreshPending && _resumeDemanded;",
            "_refreshPending = true;",
            "_resumeDemanded = followUpDemanded;",
            "onError(error, stackTrace);",
            "if (!followUpDemanded) return;",
            "_refreshInFlight = false;",
        ),
        "selected, coalesced, failure-visible presentation recovery",
    )
    retirement = extract_braced_item(
        recovery, "void retire()", "presentation recovery retirement"
    )
    require_order(
        retirement,
        (
            "_retired = true;",
            "_refreshPending = false;",
            "_resumeDemanded = false;",
        ),
        "synchronous presentation recovery retirement",
    )

    for key, label in (
        ("mobile_remote", "mobile remote viewer"),
        ("mobile_camera", "mobile camera viewer"),
    ):
        lifecycle_callback = extract_braced_item(
            sources[key],
            "void didChangeAppLifecycleState(AppLifecycleState state)",
            f"{label} application lifecycle callback",
        )
        require_order(
            lifecycle_callback,
            (
                "if (!mounted || !gFFI.isCurrentSession(sessionId)) return;",
                "if (state == AppLifecycleState.resumed)",
                (
                    "_resumePresentation();"
                    if key == "mobile_remote"
                    else "_presentationRecovery.resume("
                ),
                "_presentationRecovery.suspend();",
            ),
            f"{label} exact-session suspend/resume recovery",
        )
        refresh_source = (
            extract_braced_item(
                sources[key],
                "void _resumePresentation()",
                f"{label} presentation refresh",
            )
            if key == "mobile_remote"
            else lifecycle_callback
        )
        require_order(
            refresh_source,
            (
                "selected: true,",
                "if (!mounted || !gFFI.isCurrentSession(sessionId)) return;",
                "sessionRefreshVideo(sessionId, gFFI.clientOwnerId);",
            ),
            f"{label} exact-session presentation refresh",
        )
        dispose = extract_braced_item(
            sources[key], "Future<void> dispose()", f"{label} disposal"
        )
        require_order(
            dispose,
            (
                "WidgetsBinding.instance.removeObserver(this);",
                "_presentationRecovery.retire();",
                "final closeFuture = gFFI.close(expectedSessionId: sessionId);",
            ),
            f"{label} recovery retirement before native close",
        )

    for key, label in (
        ("remote", "desktop remote viewer"),
        ("camera", "desktop camera viewer"),
    ):
        page = sources[key]
        for signature, action, transition in (
            ("void onWindowBlur()", "_presentationRecovery.suspend();", "blur"),
            ("void onWindowMinimize()", "_presentationRecovery.suspend();", "minimize"),
            ("void onWindowFocus()", "_resumePresentationIfNeeded();", "focus"),
            ("void onWindowRestore()", "_resumePresentationIfNeeded();", "restore"),
            ("void onWindowMaximize()", "_resumePresentationIfNeeded();", "maximize"),
        ):
            callback = extract_braced_item(
                page, signature, f"{label} {transition} callback"
            )
            require(callback, action, f"{label} {transition} recovery transition")
        pointer_region = extract_braced_item(
            page,
            "Widget _buildRawPointerMouseRegion(",
            f"{label} pointer region",
        )
        require_order(
            pointer_region,
            (
                "onPointerDown: (event)",
                "if (_isWindowBlur)",
                "_isWindowBlur = false;",
                "_resumePresentationIfNeeded();",
                "if (!_rawKeyFocusNode.hasFocus)",
            ),
            f"{label} pointer-evidenced missing-focus recovery",
        )
        selection = extract_braced_item(
            page,
            "void _setPresentationSelected(bool selected)",
            f"{label} tab-selection transition",
        )
        require_order(
            selection,
            (
                "if (selected)",
                "_resumePresentationIfNeeded();",
                "_presentationRecovery.suspend();",
            ),
            f"{label} selected/deselected recovery",
        )
        resume = extract_braced_item(
            page,
            "void _resumePresentationIfNeeded()",
            f"{label} presentation resumption",
        )
        require_order(
            resume,
            (
                "_presentationRecovery.resume(",
                "selected: _isPresentationSelected,",
                "if (!mounted || !_ffi.isCurrentSession(sessionId)) return;",
                "sessionRefreshVideo(sessionId, _ffi.clientOwnerId);",
            ),
            f"{label} selected exact-session refresh",
        )
        cleanup = extract_braced_item(
            page,
            "Future<void> _cleanupResources({required bool closeSession}) async",
            f"{label} cleanup",
        )
        require_order(
            cleanup,
            (
                "_presentationRecovery.retire();",
                "final textureDisposal = _ffi.textureModel.dispose();",
                "await _awaitCleanup('texture retirement', textureDisposal);",
                "'session retirement', _ffi.close(closeSession: closeSession)",
            ),
            f"{label} recovery/texture/session retirement order",
        )
        require(page, "void dispose() {", f"{label} synchronous State disposal")
        forbid(page, "Future<void> dispose() async", f"{label} asynchronous State disposal")

    for key, page_type, label in (
        ("remote_tab", "RemotePage", "desktop remote tabs"),
        ("camera_tab", "ViewCameraPage", "desktop camera tabs"),
    ):
        tab_selection = extract_between(
            sources[key],
            "tabController.onSelected = (id) {",
            "        final " + ("remotePage" if key == "remote_tab" else "viewCameraPage"),
            f"{label} selection propagation",
        )
        require_order(
            tab_selection,
            (
                "final selectedKey = selected >= 0 && selected < state.tabs.length",
                "for (final tab in state.tabs)",
                f"if (page is {page_type})",
                "page.setPresentationSelected(tab.key == selectedKey);",
            ),
            f"{label} exact selected-page propagation",
        )

    presentation_tests = sources["presentation_tests"]
    for test in (
        "initial and duplicate resume notifications do not request a refresh",
        "one suspended presentation produces one refresh",
        "a hidden desktop tab retains recovery until it is selected",
        "a failed refresh is rearmed for a later resume transition",
        "suspend and resume during a request preserve one follow-up refresh",
        "retirement cancels pending and in-flight follow-up recovery",
        "retirement still reports an in-flight refresh failure",
    ):
        require(
            presentation_tests,
            f"test('{test}'",
            f"{test} behavior regression",
        )
    require(
        sources["dart_verify"],
        "flutter test --no-pub test/presentation_recovery_test.dart",
        "confined presentation recovery behavior gate",
    )
    for path in (
        "lib/models/presentation_recovery.dart",
        "lib/mobile/pages/remote_page.dart",
        "lib/mobile/pages/view_camera_page.dart",
        "test/presentation_recovery_test.dart",
    ):
        require(
            sources["dart_verify"],
            path,
            f"confined presentation source formatting gate for {path}",
        )

    refresh_helper = extract_braced_item(
        sources["common"], "sessionRefreshVideo(", "viewer video refresh Dart helper"
    )
    require_order(
        refresh_helper,
        (
            "SessionID sessionId, SessionID clientOwnerId",
            "bind.sessionRefresh(",
            "sessionId: sessionId, clientOwnerId: clientOwnerId",
        ),
        "single exact-owner Dart refresh bridge",
    )
    forbid(refresh_helper, "PeerInfo", "Dart-owned refresh display inventory")
    forbid(refresh_helper, "display:", "Dart-supplied refresh display policy")
    require(
        sources["toolbar"],
        "sessionRefreshVideo(sessionId, ffi.clientOwnerId)",
        "manual refresh exact UI owner",
    )
    for needle, label in (
        (
            "sessionRefreshVideo(sessionId, ffi.clientOwnerId)",
            "recording refresh exact UI owner",
        ),
        (
            "sessionRefreshVideo(activeSessionId, clientOwnerId)",
            "transferred-session refresh exact UI owner",
        ),
    ):
        require(sources["model"], needle, label)
    web_refresh = extract_braced_item(
        sources["web_bridge"],
        "Future<void> sessionRefresh(",
        "web refresh compatibility bridge",
    )
    require(
        web_refresh,
        "required UuidValue clientOwnerId",
        "web refresh exact-owner API shape",
    )
    forbid(web_refresh, "required int display", "web caller-supplied refresh display")

    refresh_state = extract_braced_item(
        sources["io_loop"],
        "struct ViewerVideoRefreshState",
        "viewer video refresh bounded state",
    )
    require_order(
        refresh_state,
        ("all: bool", "displays: VecDeque<usize>", "closed: bool"),
        "fixed refresh state",
    )
    require(
        sources["io_loop"],
        "let (wake, receiver) = mpsc::channel(1);",
        "capacity-one refresh wake",
    )
    refresh_admission = extract_braced_item(
        sources["io_loop"],
        "pub(crate) fn request(",
        "viewer video refresh admission",
    )
    require_order(
        refresh_admission,
        (
            "if state.closed",
            "ViewerVideoRefreshRequest::All =>",
            "state.displays.clear();",
            "if !state.all && !state.displays.contains(&display)",
            "state.displays.len() >= MAX_PEER_VIDEO_DISPLAYS",
            "ViewerVideoRefreshAdmissionError::Capacity",
            "state.displays.push_back(display);",
            "self.wake.try_send(())",
            "TrySendError::Full(_)",
            "TrySendError::Closed(_)",
        ),
        "nonblocking bounded/coalescing refresh admission",
    )
    forbid(
        refresh_admission,
        "return Ok(())",
        "duplicate refresh bypass of exact receiver-closure observation",
    )
    refresh_receive = extract_braced_item(
        sources["io_loop"],
        "async fn recv(&mut self)",
        "viewer video refresh receive",
    )
    require_order(
        refresh_receive,
        ("self.take_next()", "self.wake.recv().await?"),
        "event-driven refresh receive",
    )
    refresh_drop = extract_braced_item(
        sources["io_loop"],
        "impl Drop for ViewerVideoRefreshReceiver",
        "viewer refresh receiver teardown",
    )
    require_order(
        refresh_drop,
        ("state.closed = true;", "self.wake.close();"),
        "refresh state closure before wake closure",
    )
    refresh_dispatch = extract_braced_item(
        sources["io_loop"],
        "async fn handle_video_refresh(",
        "viewer video refresh dispatch",
    )
    require_order(
        refresh_dispatch,
        (
            "ViewerVideoRefreshRequest::All =>",
            "if !thread.media_thread.begin_refresh()",
            'self.handler.on_error("Video decoder stopped unexpectedly");',
            "return false;",
            "LoginConfigHandler::refresh()",
            "ViewerVideoRefreshRequest::Display(display) =>",
            "if !thread.media_thread.begin_refresh()",
            'self.handler.on_error("Video decoder stopped unexpectedly");',
            "return false;",
            "LoginConfigHandler::refresh_display(display)",
            "peer.send(&message).await",
        ),
        "invalidate-before-peer-request refresh dispatch",
    )
    if refresh_dispatch.count("if !thread.media_thread.begin_refresh()") != 2:
        raise VerificationError(
            "viewer refresh dispatch must preserve both endpoint-liveness checks"
        )
    require(
        sources["io_loop"],
        "if is_video_refresh_message(&msg)",
        "generic command-queue refresh refusal",
    )
    forbid(
        sources["ui_session"],
        "self.send(Data::Message(LoginConfigHandler::refresh",
        "refresh on generic unbounded command queue",
    )
    request_sink = extract_braced_item(
        sources["ui_session"],
        "fn request_video_refresh(&self",
        "result-bearing viewer refresh sink",
    )
    require_order(
        request_sink,
        (
            "let sender = self.video_refresh_sender.read().unwrap();",
            "sender.as_ref().ok_or_else",
            "sender.request(request)",
            "ViewerVideoRefreshAdmissionError::Capacity",
            "ViewerVideoRefreshAdmissionError::Closed",
        ),
        "failure-visible round-locked refresh admission",
    )
    refresh_api = extract_braced_item(
        sources["ui_session"],
        "pub fn refresh_video(&self",
        "range-checked viewer refresh API",
    )
    require_order(
        refresh_api,
        (
            "ConnType::DEFAULT_CONN | ConnType::VIEW_CAMERA",
            ".peer_info",
            "viewer video refresh peer display inventory is unavailable",
            "if display >= display_count",
            "ViewerVideoRefreshRequest::Display(display)",
            "self.request_video_refresh(request)",
        ),
        "viewer-kind and live-display refresh admission",
    )
    forbid(
        refresh_api,
        "drop(lc);",
        "peer inventory unlocked before exact-round refresh admission",
    )
    activation = extract_braced_item(
        sources["ui_session"],
        "fn activate_video_refresh_round(",
        "viewer refresh round activation",
    )
    require_order(
        activation,
        (
            "let mut slot = self.video_refresh_sender.write().unwrap();",
            "self.close_requested.load(Ordering::Acquire)",
            "*slot = Some(sender);",
            "start.send(receiver)",
            "*slot = None;",
        ),
        "spawn-owned refresh publication before worker release",
    )
    close_round = extract_braced_item(
        sources["ui_session"], "pub fn close(&self)", "viewer owner retirement"
    )
    require_order(
        close_round,
        (
            "let mut video_refresh_sender = self.video_refresh_sender.write().unwrap();",
            "self.connection_round_owner.retire();",
            "self.close_requested.store(true, Ordering::Release);",
            "*video_refresh_sender = None;",
            "drop(video_refresh_sender);",
            "self.send(Data::Close);",
        ),
        "refresh publication/retirement serialization",
    )
    worker_start = extract_braced_item(
        sources["ui_session"], "fn spawn_io_thread(", "gated viewer I/O spawn"
    )
    require_order(
        worker_start,
        (
            "std::sync::mpsc::sync_channel(1)",
            "wait_for_start.recv()",
            "io_loop(session, round, video_refresh);",
        ),
        "capacity-one viewer worker start gate",
    )
    start_round = extract_braced_item(
        sources["ui_session"],
        "pub(crate) fn start_io_thread_with_lock(",
        "viewer I/O round start",
    )
    require_order(
        start_round,
        (
            "let (video_refresh_sender, video_refresh_receiver) = viewer_video_refresh_channel();",
            "Self::spawn_io_thread(self.clone(), round)",
            "self.activate_video_refresh_round(",
        ),
        "spawn-owned refresh sender activation before worker release",
    )
    start_wrapper = extract_braced_item(
        sources["ui_session"],
        "pub fn start_io_thread(&self)",
        "public viewer I/O start wrapper",
    )
    require_order(
        start_wrapper,
        (
            "let mut thread_lock = self.thread.lock().unwrap();",
            "self.start_io_thread_with_lock(&mut thread_lock)",
        ),
        "public viewer start takes the worker slot before delegated activation",
    )
    reconnect_round = extract_braced_item(
        sources["ui_session"], "pub fn reconnect(&self)", "viewer I/O reconnect"
    )
    require_order(
        reconnect_round,
        (
            "*self.video_refresh_sender.write().unwrap() = None;",
            "let (video_refresh_sender, video_refresh_receiver) = viewer_video_refresh_channel();",
            "Self::spawn_io_thread(self.clone(), round)",
            "self.activate_video_refresh_round(",
        ),
        "predecessor refresh closure before replacement-round publication",
    )
    exact_owner = extract_braced_item(
        sources["flutter"],
        "pub fn request_video_refresh_for_exact_ui_owner(",
        "exact UI-owner refresh admission",
    )
    require_order(
        exact_owner,
        (
            "let sessions = SESSIONS.read().unwrap();",
            "let handlers = session.ui_handler.session_handlers.read().unwrap();",
            "handler.client_owner_id.as_ref() != Some(client_owner_id)",
            "if handler.displays.is_empty()",
            "for display in &handler.displays",
            "session.ui_handler.rearm_rgba_for_presentation_recovery(",
            "*display",
            "handler.event_stream.as_ref()",
            "handler.renderer.notify_pending_frame(*display)?;",
            "for display in &handler.displays",
            "let display = i32::try_from(*display)",
            "session.refresh_video(display)?;",
            "return Ok(());",
        ),
        "UI-owner lock held while its complete native display set is re-armed, re-notified, and admitted",
    )
    forbid(exact_owner, "display: i32", "caller-selected native refresh display")
    ffi_refresh = extract_braced_item(
        sources["ffi"], "pub fn session_refresh(", "result-bearing refresh FFI"
    )
    require_order(
        ffi_refresh,
        (
            "client_owner_id: SessionID",
            ") -> Result<()>",
            "sessions::request_video_refresh_for_exact_ui_owner",
            "&session_id, &client_owner_id",
        ),
        "typed exact-owner refresh FFI",
    )
    forbid(ffi_refresh, "display:", "FFI caller-selected refresh display")
    require(
        sources["requirements"],
        '<div class="req"><span class="id">R-S11gs</span>',
        "native refresh-display authority requirement",
    )
    require(
        sources["requirements"],
        "<tr><td>354</td>",
        "native refresh-display authority Appendix C row",
    )
    require(
        sources["hardening"],
        "### R-S11gs/R-S11e-231 — exact-owner presentation-refresh display authority",
        "native refresh-display authority hardening ledger",
    )
    require(
        sources["requirements"],
        '<div class="req"><span class="id">R-S11gt</span>',
        "explicit native display-owner requirement",
    )
    require(
        sources["requirements"],
        "<tr><td>355</td>",
        "explicit native display-owner Appendix C row",
    )
    require(
        sources["hardening"],
        "### R-S11gt/R-S11e-232 — explicit initial and ongoing native display ownership",
        "explicit native display-owner hardening ledger",
    )
    require(
        sources["verify"],
        "cargo test --lib --features linux-pkg-config,flutter r_s11gt_ --color never",
        "explicit native display-owner behavior-test wiring",
    )
    for key, test, label in (
        (
            "io_loop",
            "r_s11ff_refresh_mailbox_coalesces_duplicates_and_preserves_distinct_order",
            "refresh duplicate/coalescing regression",
        ),
        (
            "io_loop",
            "r_s11ff_all_displays_supersedes_pending_display_refreshes",
            "all-display supersession regression",
        ),
        (
            "io_loop",
            "r_s11ff_refresh_mailbox_has_a_fixed_display_identity_cap",
            "refresh capacity regression",
        ),
        (
            "io_loop",
            "r_s11ff_refresh_mailbox_fails_after_its_exact_round_receiver_drops",
            "refresh closure regression",
        ),
        (
            "io_loop",
            "r_s11ff_refresh_mailbox_wakes_without_polling",
            "refresh wake regression",
        ),
        (
            "flutter",
            "r_s11ff_r_s11gs_video_refresh_derives_the_current_exact_ui_owner_displays",
            "refresh UI-owner/display-authority regression",
        ),
        (
            "ui_session",
            "r_s11ff_retired_owner_never_releases_the_refresh_worker_start_gate",
            "retired-owner refresh worker start-gate regression",
        ),
    ):
        require(sources[key], test, label)

    lifecycle = sources["lifecycle"]
    owner = extract_braced_item(
        lifecycle,
        "class DesktopTextureLifecycle",
        "desktop texture lifecycle",
    )
    require(
        lifecycle,
        "Future<bool> activate();",
        "result-bearing texture activation contract",
    )
    require_order(
        owner,
        (
            "bool _retireRequested = false;",
            "bool _publicationAttempted = false;",
            "bool _unpublicationAttempted = false;",
            "late Future<bool> _activationFuture;",
            "Future<void>? _retireFuture;",
            "Future<void>? _releaseFuture;",
        ),
        "explicit lifecycle state",
    )
    activation = extract_braced_item(
        owner,
        "Future<bool> activate()",
        "shared result-bearing texture activation",
    )
    require_order(
        activation,
        (
            "if (!_started)",
            "_started = true;",
            "_activationFuture = _initializeAndPublish();",
            "return _activationFuture;",
        ),
        "one exact activation future",
    )
    initialize = extract_braced_item(
        owner,
        "Future<bool> _initializeAndPublish()",
        "initialization/publication transition",
    )
    require_order(
        initialize,
        (
            "ready = await _initialize();",
            "_onError('initialize', error, stackTrace);",
            "await _releaseOnce();",
            "return false;",
            "if (!ready)",
            "StateError('Desktop texture initialization was rejected')",
            "await _releaseOnce();",
            "return false;",
            "if (_retireRequested)",
            "return false;",
            "_publicationAttempted = true;",
            "_publish();",
            "return true;",
            "_onError('publish', error, stackTrace);",
            "_unpublishOnce();",
            "await _releaseOnce();",
            "return false;",
        ),
        "result-bearing cleanup, late-publication exclusion, and visible errors",
    )
    retire = extract_braced_item(
        owner, "Future<void> retire()", "synchronous retirement invalidation"
    )
    require_order(
        retire,
        (
            "_retireRequested = true;",
            "activate();",
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
            "await _activationFuture;",
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
    require_order(
        extract_braced_item(slot, "void setWanted(bool wanted)", "display demand transition"),
        (
            "if (_wanted == wanted)",
            "_wanted = wanted;",
            "_creationFailed = false;",
            "_demandRevision += 1;",
            "_ensureReconcile();",
        ),
        "one revision per distinct display demand transition",
    )
    require_order(
        slot,
        (
            "bool _creationFailed = false;",
            "int _demandRevision = 0;",
            "T? _current;",
        ),
        "explicit display-slot activation state",
    )
    reconcile = extract_braced_item(
        slot, "Future<void> _reconcile()", "serialized replacement transition"
    )
    require_order(
        reconcile,
        (
            "if (_wanted)",
            "final demandRevision = _demandRevision;",
            "late final T candidate;",
            "try {",
            "candidate = _create();",
            "_creationFailed = true;",
            "_onError('create', error, stackTrace);",
            "_current = candidate;",
            "var activated = false;",
            "activated = await candidate.activate();",
            "_onError('activate', error, stackTrace);",
            "if (!activated)",
            "await candidate.retire();",
            "if (identical(_current, candidate))",
            "_current = null;",
            "if (_wanted && _demandRevision == demandRevision)",
            "_creationFailed = true;",
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
            "_ffi.textureModel.setTextureId",
            "platformFFI.registerPixelbufferTexture(",
            "_sessionId, _clientOwnerId, _display, ptr",
            "_sessionId, _clientOwnerId, _display, 0",
            "_ffi.textureModel.clearTextureId(display: _display, id: id);",
            "await textureRenderer.closeTexture(_textureKey);",
            "Future<bool> activate() => _lifecycle.activate();",
            "Future<void> retire() => _lifecycle.retire();",
        ),
        "pixelbuffer lifecycle wiring",
    )
    forbid(pixel, "_lifecycle.start();", "detached constructor activation")
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

    for key in ("remote", "camera"):
        page_cleanup = extract_braced_item(
            sources[key],
            "Future<void> _cleanupResources({required bool closeSession}) async",
            f"{key} page cleanup",
        )
        require_order(
            page_cleanup,
            (
                "final textureDisposal = _ffi.textureModel.dispose();",
                "await _awaitCleanup('texture retirement', textureDisposal);",
                "'session retirement', _ffi.close(closeSession: closeSession)",
            ),
            f"{key} texture finality before native close",
        )
        require(
            sources[key],
            "void dispose() {",
            f"{key} synchronous State disposal",
        )
        forbid(
            sources[key],
            "Future<void> dispose() async",
            f"{key} asynchronous State disposal",
        )

    flutter = sources["flutter"]
    require(
        flutter,
        'const LINUX_TEXTURE_RGBA_RENDERER_PLUGIN: &str = "libtexture_rgba_renderer_plugin.so";',
        "fixed Linux texture-plugin basename",
    )
    linux_plugin_path = extract_braced_item(
        flutter,
        "fn linux_texture_plugin_path(",
        "Linux application-relative texture-plugin path",
    )
    require_order(
        linux_plugin_path,
        (
            "if !executable.is_absolute()",
            "executable.file_name().is_none()",
            "std::path::Component::RootDir | std::path::Component::Normal(_)",
            "let parent = executable.parent().ok_or_else",
            '.join("lib")',
            ".join(LINUX_TEXTURE_RGBA_RENDERER_PLUGIN)",
        ),
        "clean absolute application-relative Linux texture-plugin path",
    )
    linux_plugin_loader = extract_braced_item(
        flutter,
        "fn load_linux_texture_plugin()",
        "Linux texture-plugin loader",
    )
    require_order(
        linux_plugin_loader,
        (
            "std::env::current_exe()",
            "linux_texture_plugin_path(&executable)",
            "Library::open(path)",
        ),
        "current-application Linux texture-plugin loader",
    )
    require(
        flutter,
        "pub static ref TEXTURE_RGBA_RENDERER_PLUGIN: Result<Library, LibError> =\n"
        "        load_linux_texture_plugin();",
        "Linux texture-plugin loader wiring",
    )
    forbid(
        flutter,
        'Library::open("libtexture_rgba_renderer_plugin.so")',
        "ambient Linux texture-plugin soname load",
    )
    require(
        flutter,
        "fn r_s11gf_linux_texture_plugin_is_exactly_application_relative()",
        "application-relative Linux texture-plugin regression",
    )
    require(
        flutter,
        "fn r_s11gf_linux_texture_plugin_rejects_ambient_or_unclean_roots()",
        "unclean Linux texture-plugin root rejection regression",
    )
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
    notification_commit = extract_braced_item(
        flutter,
        "fn commit_first_texture_notification",
        "native and UI texture-notification admission",
    )
    require_order(
        notification_commit,
        (
            "if !frame_admitted || *render_notified || !notify()",
            "return false;",
            "*render_notified = true;",
            "true",
        ),
        "texture notification commits only after native and UI admission",
    )
    renderer_loader = extract_braced_item(
        flutter,
        "impl Default for VideoRenderer",
        "desktop native admission-symbol loader",
    )
    require_order(
        renderer_loader,
        (
            "lib.symbol::<FlutterRgbaRendererPluginTryOnRgba>(",
            '"FlutterRgbaRendererPluginTryOnRgba",',
            "Ok(sym) => Some(sym)",
            "Err(e) =>",
            "None",
        ),
        "versioned native admission symbol loads fail closed",
    )
    require_order(
        renderer_loader,
        (
            "lib.symbol::<FlutterRgbaRendererPluginTryNotifyPending>(",
            '"FlutterRgbaRendererPluginTryNotifyPending",',
            "Ok(sym) => Some(sym)",
            "Err(e) =>",
            "None",
        ),
        "versioned native pending-frame notifier loads fail closed",
    )
    pending_notification = extract_braced_item(
        flutter,
        "fn notify_pending_frame(&self, display: usize)",
        "desktop pending-frame re-notification",
    )
    require_order(
        pending_notification,
        (
            "let sessions = self.map_display_sessions.read().unwrap();",
            "sessions.get(&display)",
            "return Ok(());",
            "if info.texture_rgba_ptr == usize::default()",
            "let Some(func) = &self.notify_pending_func else",
            'bail!("desktop texture pending-frame notifier is unavailable")',
            "if unsafe { func(info.texture_rgba_ptr as _) } == 0",
            'bail!("desktop texture pending-frame notification failed")',
            "Ok(())",
        ),
        "exact display/native-owner pending-frame re-notification",
    )
    forbid(
        pending_notification,
        "values().next()",
        "arbitrary first texture slot for pending-frame notification",
    )
    renderer_admission = extract_braced_item(
        flutter,
        "pub fn on_rgba<F>",
        "desktop native frame admission",
    )
    require_order(
        renderer_admission,
        (
            "let mut write_lock = self.map_display_sessions.write().unwrap();",
            "write_lock.get_mut(&display)",
            "let Some(func) = &self.on_rgba_func else",
            "let frame_admitted = unsafe",
            ") != 0",
            "commit_first_texture_notification(",
        ),
        "versioned native admission result reaches first-image notification",
    )
    forbid(
        renderer_admission,
        "values_mut().next()",
        "arbitrary first texture slot for decoded-frame delivery",
    )
    texture_dispatch = extract_braced_item(
        flutter,
        "fn on_rgba_flutter_texture_render(",
        "desktop texture event dispatch",
    )
    require_order(
        texture_dispatch,
        (
            "if !session.displays.contains(&display)",
            "continue;",
            "let Some(stream) = &session.event_stream else",
            ".renderer",
            ".on_rgba(display, rgba, || stream.add(EventToUI::Texture(display)))",
        ),
        "UI stream admission is inside the one-time notification transaction",
    )
    forbid(
        flutter,
        "renderer.is_support_multi_ui_session",
        "peer-version local texture/display authority",
    )
    initial_owner = extract_braced_item(
        flutter, "fn bind_initial_display_owner(", "initial display-owner binding"
    )
    require_order(
        initial_owner,
        (
            "usize::try_from(current_display)",
            "if display >= display_count",
            ".flat_map(|handler| handler.displays.iter())",
            ".any(|owned_display| *owned_display >= display_count)",
            "handler.awaiting_initial_display.then_some(*session_id)",
            "if pending.len() > 1",
            "if handlers.is_empty() || handlers.values().any(|handler| handler.displays.is_empty())",
            "return Ok(());",
            "other_session_id != session_id && handler.displays.is_empty()",
            "let handler = handlers",
            ".get_mut(session_id)",
            "if !handler.displays.is_empty()",
            "handler.displays.push(display);",
            "handler.awaiting_initial_display = false;",
        ),
        "bounded fresh binding or reconnect preservation of explicit display ownership",
    )
    forbid(
        initial_owner,
        "handlers.values_mut()",
        "reconnect mutation of already-explicit display owners",
    )
    login_peer_info = sources["io_loop"].find(
        "Some(login_response::Union::PeerInfo(pi)) =>"
    )
    sync_peer_info = sources["io_loop"].find(
        "Some(message::Union::PeerInfo(pi)) =>", login_peer_info + 1
    )
    if login_peer_info < 0 or sync_peer_info < 0:
        raise VerificationError("missing initial/synchronized peer-information dispatch")
    require_order(
        sources["io_loop"][login_peer_info:sync_peer_info],
        (
            "let initial_display = pi.current_display;",
            "let pi = bound_peer_info(pi);",
            ".bind_initial_display_owner(initial_display, pi.displays.len())",
            "self.handler.on_error(&message);",
            "return false;",
            "self.set_peer_info(&pi);",
        ),
        "raw initial display admission before peer-state consumption",
    )
    renderer_size = extract_braced_item(
        flutter, "fn set_owned_display_size(", "owned-display renderer sizing"
    )
    require_order(
        renderer_size,
        (
            "if !self.displays.contains(&display)",
            "return false;",
            "self.renderer.set_size(display, width, height);",
            "true",
        ),
        "renderer sizing cannot create display ownership",
    )
    session_size = extract_braced_item(
        flutter, "pub fn session_set_size(", "session renderer sizing"
    )
    require_order(
        session_size,
        (
            "client_owner_id: SessionID",
            "display: usize",
            "width: usize",
            "height: usize",
            "-> ResultType<()>",
            "s.ui_handler.set_exact_owned_display_size(",
            "&session_id",
            "&client_owner_id",
            "display",
            "width",
            "height",
            "if admitted",
            "return Ok(());",
            "bail!(",
        ),
        "session result-bearing exact-owner renderer-size admission",
    )
    forbid(session_size, "h.displays.push(display)", "renderer-size-created ownership")
    exact_owned_size = extract_braced_item(
        flutter,
        "fn set_exact_owned_display_size(",
        "exact-owner renderer sizing",
    )
    require_order(
        exact_owned_size,
        (
            "let handler = handlers.get_mut(session_id)?;",
            "if handler.client_owner_id.as_ref() != Some(client_owner_id)",
            "return Some(false);",
            "Some(handler.set_owned_display_size(display, width, height))",
        ),
        "renderer sizing requires the exact current UI owner",
    )
    ffi_size = extract_braced_item(ffi, "pub fn session_set_size(", "renderer-size FFI")
    require_order(
        ffi_size,
        (
            "client_owner_id: SessionID",
            "-> Result<()>",
            "super::flutter::session_set_size(session_id, client_owner_id, display, width, height)",
        ),
        "renderer-size FFI exact-owner forwarding",
    )
    dart_size_region = extract_between(
        sources["model"],
        "Future<bool> updateCurDisplay(",
        "/// Handle the peer info event",
        "Dart exact-owner renderer sizing",
    )
    require_order(
        dart_size_region,
        (
            "final expectedClientOwnerId = ffi.clientOwnerId;",
            "ffi.isCurrentSessionOwner(sessionId, expectedClientOwnerId)",
            "await _updateSessionWidthHeight(sessionId, expectedClientOwnerId);",
            "SessionID sessionId",
            "SessionID expectedClientOwnerId",
            "async {",
        ),
        "Dart renderer sizing retains and rechecks the exact UI owner",
    )
    if dart_size_region.count("clientOwnerId: expectedClientOwnerId") != 2:
        raise VerificationError(
            "Dart renderer sizing must pass the exact UI owner in both display shapes"
        )
    if dart_size_region.count("await bind.sessionSetSize(") != 2:
        raise VerificationError(
            "Dart renderer sizing must await both bounded bridge-call shapes"
        )
    dart_peer_info = extract_between(
        sources["model"],
        "Future<void> handlePeerInfo(",
        "Future<void> tryUseAllMyDisplaysForTheRemoteSession(",
        "Dart peer information",
    )
    require_order(
        dart_peer_info,
        (
            "final previousCurrentDisplay = _pi.currentDisplay;",
            "final restoreDisplaySelection = !isCache && _pi.isSet.value;",
            "final preserveDisplaySelection = isCache || restoreDisplaySelection;",
            "if (!preserveDisplaySelection &&",
            "_pi.currentDisplay = currentDisplay;",
            "_pi.displays.value = newDisplays;",
            "if (restoreDisplaySelection)",
            "previousCurrentDisplay == kAllDisplayValue",
            "List.generate(_pi.displays.length, (index) => index)",
            "!await selectRemoteDisplays(",
            "'The previous display selection could not be restored'",
            "if (_pi.currentDisplay < _pi.displays.length)",
            "await updateCurDisplay(",
        ),
        "established reconnect restores exact display selection before geometry",
    )
    web_size = extract_between(
        sources["web_bridge"],
        "Future<void> sessionSetSize(",
        "\n  Future<void> sessionSendSelectedSessionId(",
        "web renderer sizing",
    )
    require_order(
        web_size,
        (
            "required UuidValue sessionId",
            "required UuidValue clientOwnerId",
        ),
        "web renderer-size exact-owner parity",
    )
    session_start = extract_between(
        flutter,
        "pub fn session_start_(",
        "\nfn rollback_failed_session_start",
        "exact-owner UI stream start",
    )
    require_order(
        session_start,
        (
            "let mut thread_lock = s.thread.lock().unwrap();",
            "let mut handlers = s.session_handlers.write().unwrap();",
            "if let Some(h) = handlers.get_mut(session_id)",
        ),
        "worker-slot before handler-owner session-start lock order",
    )
    start_admission = extract_braced_item(
        flutter,
        "fn admit_session_start(",
        "display-owned session-start admission",
    )
    require_order(
        start_admission,
        (
            "let starts_peer_connection =",
            "!has_ui_stream",
            "&& is_first_ui_session",
            "&& is_unselected_ui_session",
            "&& !is_awaiting_initial_display",
            "if is_video_session",
            "&& is_unselected_ui_session",
            "&& !starts_peer_connection",
            "&& !is_awaiting_initial_display",
            'bail!("Outgoing video UI session has no explicit display owner")',
            "Ok(starts_peer_connection)",
        ),
        "fresh, pending-marker, or explicit-owner session-start admission",
    )
    start_guard = extract_braced_item(
        session_start,
        "if let Some(h) = handlers.get_mut(session_id)",
        "exact-owner session-start critical section",
    )
    require_order(
        start_guard,
        (
            "h.client_owner_id.as_ref() != Some(client_owner_id)",
            'bail!("Outgoing session is not owned by the active mobile/desktop client owner")',
            "let starts_peer_connection = match admit_session_start(",
            "is_video_session",
            "h.event_stream.is_some()",
            "is_first_ui_session",
            "h.displays.is_empty()",
            "h.awaiting_initial_display",
            "Err(error)",
            "start_failure = Some(error);",
            "try_send_close_event(&h.event_stream);",
            "h.event_stream = Some(event_stream);",
            "if start_failure.is_none() && starts_peer_connection && is_video_session",
            "h.awaiting_initial_display = true;",
            "match s.start_io_thread_with_lock(&mut thread_lock)",
            "Ok(false)",
            "Err(error) => start_failure = Some(error.into())",
        ),
        "under-guard exact-owner and display-owned stream admission through peer-I/O start",
    )
    require_order(
        session_start,
        (
            "if let Some(error) = start_failure",
            "rollback_failed_session_start(session_id, client_owner_id);",
            "return Err(error);",
            ".replay_ready_rgba(session_id, client_owner_id)",
            "rollback_failed_session_start(session_id, client_owner_id);",
        ),
        "exact-owner failed-start and replay rollback",
    )
    require(
        flutter,
        "r_s11gt_initial_peer_info_binds_one_exact_display_owner_once",
        "one-time initial display-owner regression",
    )
    require(
        flutter,
        "r_s11gt_initial_display_binding_refuses_ambiguous_or_invalid_authority",
        "invalid initial display-owner regression",
    )
    require(
        flutter,
        "r_s11gt_reconnect_preserves_explicit_display_owners_without_rebinding",
        "reconnect display-owner preservation regression",
    )
    require(
        flutter,
        "r_s11gt_session_start_requires_fresh_or_explicit_display_authority",
        "display-owned session-start admission regression",
    )
    require(
        flutter,
        "r_s11gt_capture_authority_excludes_renderer_resource_keys",
        "renderer resource/capture-authority separation regression",
    )
    require(
        flutter,
        "r_s11gt_renderer_size_requires_exact_current_ui_owner",
        "renderer-size exact-owner regression",
    )
    require(
        flutter,
        "r_s11fc_texture_notification_commits_only_after_native_and_ui_admission",
        "native/UI rejection and retry behavior regression",
    )

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
        "stream.add(EventToUI::Texture(display))",
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
            "_observeSessionTask(",
            "_handleTextureRgba(sessionEvents, streamOwner, activeSessionId,",
            "message.field0)",
            "'Texture presentation'",
        ),
        "one-field topology-checked software texture event consumption",
    )
    texture_handler = extract_braced_item(
        model, "Future<void> _handleTextureRgba(", "software texture event handler"
    )
    require_order(
        texture_handler,
        (
            "_displayTopologyAfterCheckpoint(",
            "sessionEvents, streamOwner, activeSessionId",
            "if (topologyRevision == null) return;",
            'debugPrint(\'EventToUI_Texture display:$display\');',
            "onEvent2UIRgba(activeSessionId, topologyRevision,",
            "imageGeometryInitialized: false",
        ),
        "software texture topology checkpoint and first-image admission",
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
    require(sources["pub_cache_output"], "EXPECTED_GIT_DEPENDENCIES = 3", "three-dependency Pub-cache output contract")
    require(sources["pub_cache_output"], "exact three locked Git dependencies", "three-dependency Pub-cache diagnostic")
    require(sources["pub_cache_verifier"], "EXPECTED_GIT_DEPENDENCIES = 3", "three-dependency Pub-cache verifier contract")
    require(sources["online_fetch"], '[ "${#git_specs[@]}" -eq 3 ]', "three-dependency acquisition inventory")
    for token in (
        '"dependencies_entries": 57',
        '"union_entries": 63',
        '"git_hosted_records": 3',
        '"package_records": 198',
        '"rustdesk_org_git_records": 2',
    ):
        require(sources["dependency_inventory"], token, "updated Flutter dependency inventory")
    if sources["dependency_inventory"].count('"rustdesk_org_git_records": 2') != 2:
        raise VerificationError(
            "updated RustDesk Git dependency inventory must bind current and fixture expectations"
        )

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
    windows_cmake = sources["plugin_windows_cmake"]
    windows_texture = sources["plugin_windows_texture"]
    windows_plugin = sources["plugin_windows"]
    windows_c_api = sources["plugin_windows_c_api"]
    windows_c_api_h = sources["plugin_windows_c_api_h"]
    require(
        windows_c_api_h,
        "FLUTTER_PLUGIN_EXPORT int FlutterRgbaRendererPluginTryOnRgba(",
        "Windows versioned frame-admission export declaration",
    )
    require(
        windows_c_api_h,
        "FLUTTER_PLUGIN_EXPORT int FlutterRgbaRendererPluginTryNotifyPending(",
        "Windows versioned pending-frame notifier declaration",
    )
    require(
        windows_c_api_h,
        "FLUTTER_PLUGIN_EXPORT void FlutterRgbaRendererPluginOnRgba(",
        "Windows legacy frame export compatibility declaration",
    )
    require(
        windows_texture_h,
        "~TextureRgba() = default;",
        "Windows texture object has no second unregister owner",
    )
    require_order(
        windows_cmake,
        (
            '"texture_rgba_renderer_plugin.cpp"',
            '"texture_rgba.cpp"',
            '"texture_rgba.h"',
            '"texture_rgba_renderer_plugin.h"',
        ),
        "explicit Windows production plugin source list",
    )
    windows_plugin_sources = extract_between(
        windows_cmake,
        "list(APPEND PLUGIN_SOURCES",
        ")\n\n# Define the plugin library target",
        "Windows production plugin source list",
    )
    forbid(
        windows_plugin_sources,
        "test/",
        "test-only Windows texture source packaging",
    )
    forbid(windows_cmake, "file(GLOB", "globbed Windows plugin source authority")
    windows_native_test = extract_between(
        windows_cmake,
        'set(CORE_TEST_NAME "texture_rgba_renderer_windows_core_test")',
        "\n\n# List of absolute paths",
        "native Windows pinned-wrapper callback-core target",
    )
    require_order(
        windows_native_test,
        (
            "add_executable(${CORE_TEST_NAME} EXCLUDE_FROM_ALL",
            '"test/texture_rgba_test.cc"',
            '"texture_rgba.cpp"',
            '"texture_rgba.h"',
            "apply_standard_settings(${CORE_TEST_NAME})",
            "target_link_libraries(${CORE_TEST_NAME} PRIVATE flutter flutter_wrapper_plugin)",
            "RUNTIME_OUTPUT_DIRECTORY_RELEASE",
            '"${CMAKE_BINARY_DIR}/texture_rgba_renderer_core_test"',
        ),
        "non-shipping native Windows test against the pinned Flutter wrapper",
    )
    forbid(
        windows_native_test,
        "test/include",
        "portable registrar shim on the native Windows include path",
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
    require_order(
        extract_braced_item(
            windows_texture,
            "bool TextureRgba::NotifyPendingFrame()",
            "Windows pending-frame re-notification",
        ),
        (
            "const std::lock_guard<std::mutex> lock(mutex_);",
            "if (retired_ || texture_id_ <= 0 || texture_registrar_ == nullptr)",
            "return false;",
            "return !buffer_ready_ ||",
            "texture_registrar_->MarkTextureFrameAvailable(texture_id_);",
        ),
        "Windows pending-only re-notification and native failure propagation",
    )
    require_order(
        extract_braced_item(
            windows_texture,
            "void TextureRgba::Retire()",
            "Windows texture retirement",
        ),
        (
            "retired_ = true;",
            "if (buffer_ready_)",
            "const int background_index = foreground_index_ ^ 1;",
            "buffers_[background_index].clear();",
            "width_[background_index] = 0;",
            "height_[background_index] = 0;",
            "buffer_ready_ = false;",
        ),
        "Windows retirement cancels only the unconsumed pending frame",
    )
    require_order(
        extract_braced_item(
            windows_texture,
            "const FlutterDesktopPixelBuffer* TextureRgba::CopyBuffer()",
            "Windows pixel callback",
        ),
        (
            "if (retired_)",
            "return nullptr;",
            "if (buffer_ready_)",
            "foreground_index_ ^= 1;",
        ),
        "Windows pixel callback refuses publication after retirement",
    )
    windows_test = sources["plugin_windows_test"]
    windows_test_stub = sources["plugin_windows_test_stub"]
    require_order(
        windows_test_stub,
        (
            "class PixelBufferTexture",
            "using CopyBufferCallback =",
            "CopyPixelBuffer(size_t width,",
            "class GpuSurfaceTexture",
            "using TextureVariant = std::variant<PixelBufferTexture, GpuSurfaceTexture>;",
            "class TextureRegistrar",
            "virtual int64_t RegisterTexture(TextureVariant* texture) = 0;",
            "virtual bool MarkTextureFrameAvailable(int64_t texture_id) = 0;",
            "virtual void UnregisterTexture(int64_t texture_id,",
            "virtual bool UnregisterTexture(int64_t texture_id) = 0;",
        ),
        "portable Windows test-only registrar parity with the pinned Flutter wrapper",
    )
    for needle, label in (
        (
            '#include "../texture_rgba.h"',
            "portable Windows test uses the production texture class",
        ),
        (
            "TextureRgba texture(&registrar);",
            "portable Windows production texture construction",
        ),
        (
            "std::get_if<flutter::PixelBufferTexture>(texture_)",
            "portable and native tests use the pinned Flutter texture variant shape",
        ),
        (
            '"a pending frame crossed the retirement boundary"',
            "portable Windows pending-frame retirement regression",
        ),
        (
            '"retirement released the presented frame too early"',
            "portable Windows presented-storage lifetime regression",
        ),
        (
            '"a retired texture accepted a new frame"',
            "portable Windows post-retirement admission regression",
        ),
        (
            '"pending-frame re-notification did not reach the registrar"',
            "portable Windows pending-frame re-notification regression",
        ),
        (
            '"idle texture emitted a spurious frame notification"',
            "portable Windows idle re-notification regression",
        ),
        (
            '"failed pending-frame re-notification was accepted"',
            "portable Windows re-notification failure regression",
        ),
        (
            '"failed re-notification consumed the pending frame"',
            "portable Windows pending-frame preservation regression",
        ),
        (
            '"a retired texture accepted re-notification"',
            "portable Windows retired re-notification regression",
        ),
    ):
        require(windows_test, needle, label)
    require_order(
        sources["build_windows"],
        (
            "$textureCoreTest = Join-Path $flutterBuildRoot",
            "$textureCoreTest,",
            "& $PYTHON_EXE build.py --flutter",
            "$vsw = 'C:\\Program Files (x86)\\Microsoft Visual Studio\\Installer\\vswhere.exe'",
            "[void](Get-OrdinaryPathItem $vsw $true)",
            "$vsPath = (& $vsw -products * -latest -property installationPath",
            "[void](Get-OrdinaryPathItem $vsPath $false)",
            "$cmakeExe = Join-Path $vsPath 'Common7\\IDE\\CommonExtensions\\Microsoft\\CMake\\CMake\\bin\\cmake.exe'",
            "[void](Get-OrdinaryPathItem $cmakeExe $true)",
            "& $cmakeExe --build $flutterBuildRoot --config Release --target texture_rgba_renderer_windows_core_test -- /p:BuildProjectReferences=false",
            "if (-not (Test-Path -LiteralPath $textureCoreTest -PathType Leaf))",
            "[void](Get-OrdinaryPathItem $textureCoreTest $true)",
            "$textureCoreExit = Invoke-BoundedNativeProcess",
            "-Path $textureCoreTest",
            "-ArgumentList ([string[]]@())",
            "-WorkingDirectory (Split-Path -Parent $textureCoreTest)",
            "-TimeoutSeconds 60",
            "-Description 'native Windows texture callback-core test'",
            "if ($textureCoreExit -ne 0)",
            'Die "native Windows texture callback-core test failed',
        ),
        "stale-safe native Windows pinned-wrapper callback-core build and execution",
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
            "int FlutterRgbaRendererPluginTryOnRgba(",
            "Windows Rust C-ABI frame-admission entry",
        ),
        (
            "if (texture_rgba == nullptr",
            "return 0;",
            "try {",
            "return static_cast<TextureRgba*>(texture_rgba)",
            "->MarkVideoFrameAvailable(",
            "? 1",
            ": 0;",
            "} catch (...) {",
            "Exceptions must never cross the C ABI used by Rust.",
            "return 0;",
        ),
        "Windows C-ABI validation, admission result, and exception containment",
    )
    require_order(
        extract_braced_item(
            windows_c_api,
            "int FlutterRgbaRendererPluginTryNotifyPending(",
            "Windows Rust C-ABI pending-frame notifier",
        ),
        (
            "if (texture_rgba == nullptr)",
            "return 0;",
            "try {",
            "->NotifyPendingFrame()",
            "? 1",
            ": 0;",
            "} catch (...) {",
            "return 0;",
        ),
        "Windows C-ABI pending-frame result and exception containment",
    )
    require_order(
        extract_braced_item(
            windows_c_api,
            "void FlutterRgbaRendererPluginOnRgba(",
            "Windows legacy C-ABI frame entry",
        ),
        (
            "FlutterRgbaRendererPluginTryOnRgba(",
            "height, stride_align);",
        ),
        "Windows legacy frame entry delegates to versioned admission",
    )

    linux = sources["plugin_linux"]
    linux_h = sources["plugin_linux_h"]
    require(
        linux_h,
        "FLUTTER_PLUGIN_EXPORT int FlutterRgbaRendererPluginTryOnRgba(",
        "Linux versioned frame-admission export declaration",
    )
    require(
        linux_h,
        "FLUTTER_PLUGIN_EXPORT int FlutterRgbaRendererPluginTryNotifyPending(",
        "Linux versioned pending-frame notifier declaration",
    )
    require(
        linux_h,
        "FLUTTER_PLUGIN_EXPORT void FlutterRgbaRendererPluginOnRgba(",
        "Linux legacy frame export compatibility declaration",
    )
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
            "static gboolean texture_rgba_notify_pending(",
            "Linux pending-frame re-notification",
        ),
        (
            "if (self == nullptr)",
            "g_mutex_lock(&self->mutex);",
            "if (self->retired || self->texture_registrar == nullptr ||",
            "self->texture_id <= 0)",
            "g_mutex_unlock(&self->mutex);",
            "return FALSE;",
            "!self->buffer_ready || fl_texture_registrar_mark_texture_frame_available(",
            "g_mutex_unlock(&self->mutex);",
            "return marked;",
        ),
        "Linux pending-only re-notification and native failure propagation",
    )
    require_order(
        extract_braced_item(
            linux,
            "static void texture_rgba_retire(",
            "Linux texture retirement",
        ),
        (
            "self->retired = TRUE;",
            "uint8_t* pending_buffer = self->buffer;",
            "self->buffer = nullptr;",
            "self->buffer_width = 0;",
            "self->buffer_height = 0;",
            "self->buffer_ready = FALSE;",
            "g_mutex_unlock(&self->mutex);",
            "delete[] pending_buffer;",
        ),
        "Linux retirement cancels only the unconsumed pending frame",
    )
    require_order(
        extract_braced_item(
            linux,
            "static gboolean texture_rgba_copy_pixels(",
            "Linux pixel callback",
        ),
        (
            "if (self->retired)",
            '"texture is retired"',
            "return FALSE;",
            "if (self->buffer_ready)",
            "self->prior_buffer = self->buffer;",
            "self->prior_width = self->buffer_width;",
            "self->prior_height = self->buffer_height;",
            "self->buffer_width = 0;",
            "self->buffer_height = 0;",
            "*out_buffer = self->prior_buffer;",
            "*width = self->prior_width;",
            "*height = self->prior_height;",
            "if (self->prior_buffer != nullptr)",
            "*width = self->prior_width;",
            "*height = self->prior_height;",
            '"texture has no frame"',
            "return FALSE;",
        ),
        "Linux pixel callback keeps presented metadata independent of pending rollback",
    )
    linux_test = sources["plugin_linux_test"]
    for needle, label in (
        (
            '#include "../texture_rgba_renderer_plugin.cc"',
            "native test uses the production Linux callback implementation",
        ),
        (
            "texture->texture_id = 17;",
            "native test models the production registration sentinel",
        ),
        (
            '"a pending frame crossed the retirement boundary"',
            "native pending-frame retirement regression",
        ),
        (
            '"retirement retained pending frame state"',
            "native pending-storage cancellation regression",
        ),
        (
            '"retirement released the presented frame too early"',
            "native presented-storage lifetime regression",
        ),
        (
            'std::strcmp(error->message, "texture is retired") == 0',
            "native retired-callback diagnostic regression",
        ),
        (
            '"C-ABI first frame was rejected"',
            "native exported admission-success regression",
        ),
        (
            '"C-ABI failed registrar notification was accepted"',
            "native exported admission-failure regression",
        ),
        (
            '"a retired texture accepted a new frame"',
            "native post-retirement admission regression",
        ),
        (
            '"pending-frame re-notification did not reach the registrar"',
            "native pending-frame re-notification regression",
        ),
        (
            '"idle texture emitted a spurious frame notification"',
            "native idle re-notification regression",
        ),
        (
            '"failed pending-frame re-notification was accepted"',
            "native re-notification failure regression",
        ),
        (
            '"failed re-notification consumed the pending frame"',
            "native pending-frame preservation regression",
        ),
        (
            '"a retired texture accepted re-notification"',
            "native retired re-notification regression",
        ),
    ):
        require(linux_test, needle, label)
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
            "int FlutterRgbaRendererPluginTryOnRgba(",
            "Linux Rust C-ABI frame-admission entry",
        ),
        (
            "int stride_align)",
            "return texture_rgba_mark_frame(",
            "len, width, height, stride_align",
            "? 1",
            ": 0;",
        ),
        "Linux C frame-admission result and stride contract",
    )
    require_order(
        extract_braced_item(
            linux,
            "int FlutterRgbaRendererPluginTryNotifyPending(",
            "Linux Rust C-ABI pending-frame notifier",
        ),
        (
            "return texture_rgba_notify_pending(",
            "reinterpret_cast<TextureRgba*>(texture_rgba)",
            "? 1",
            ": 0;",
        ),
        "Linux C pending-frame result contract",
    )
    require_order(
        extract_braced_item(
            linux,
            "void FlutterRgbaRendererPluginOnRgba(",
            "Linux legacy C-ABI frame entry",
        ),
        (
            "FlutterRgbaRendererPluginTryOnRgba(",
            "height, stride_align);",
        ),
        "Linux legacy frame entry delegates to versioned admission",
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
            macos_texture,
            "public func notifyPendingFrame() -> Bool",
            "macOS pending-frame re-notification",
        ),
        (
            "queue.sync",
            "guard textureId > 0, let registry",
            "return false",
            "if framePending",
            "registry.textureFrameAvailable(textureId)",
            "return true",
        ),
        "macOS serialized pending-only re-notification",
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
            "int FlutterRgbaRendererPluginTryOnRgba(",
            "macOS Rust C-ABI frame-admission entry",
        ),
        (
            "texture_rgba_ptr == NULL",
            "buffer == NULL",
            "len <= 0",
            "width <= 0",
            "height <= 0",
            "stride_align < 0",
            "return 0;",
            "return [texture_rgba markFrameAvaliableRawWithBuffer:",
            "? 1 : 0;",
        ),
        "macOS C-ABI validation and native frame-admission result",
    )
    require_order(
        extract_braced_item(
            macos_c_api,
            "int FlutterRgbaRendererPluginTryNotifyPending(",
            "macOS Rust C-ABI pending-frame notifier",
        ),
        (
            "if (texture_rgba_ptr == NULL)",
            "return 0;",
            "return [texture_rgba notifyPendingFrame] ? 1 : 0;",
        ),
        "macOS C-ABI pending-frame result contract",
    )
    require_order(
        extract_braced_item(
            macos_c_api,
            "void FlutterRgbaRendererPluginOnRgba(",
            "macOS legacy C-ABI frame entry",
        ),
        (
            "FlutterRgbaRendererPluginTryOnRgba(",
            "stride_align);",
        ),
        "macOS legacy frame entry delegates to versioned admission",
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
        "rejected initialization is reported and the allocation is released",
        "failed publication is unpublished and released immediately",
        "unpublication failure cannot prevent exact release",
        "failed slot creation is bounded and a later demand can retry",
        "failed asynchronous activation is retired and retry is bounded",
        "new demand during failed activation receives a fresh exact attempt",
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
        (
            "requirements",
            '<div class="req"><span class="id">R-S11ez</span>',
            "R-S11ez native retirement-finality requirement",
        ),
        (
            "requirements",
            '<div class="req"><span class="id">R-S11fa</span>',
            "R-S11fa presentation-resume requirement",
        ),
        (
            "requirements",
            '<div class="req"><span class="id">R-S11fc</span>',
            "R-S11fc exact first-image admission requirement",
        ),
        (
            "requirements",
            '<div class="req"><span class="id">R-S11ff</span>',
            "R-S11ff exact viewer refresh admission requirement",
        ),
        (
            "requirements",
            '<div class="req"><span class="id">R-S11fm</span>',
            "R-S11fm texture activation finality requirement",
        ),
        (
            "requirements",
            '<div class="req"><span class="id">R-S11fp</span>',
            "R-S11fp pending-texture re-notification requirement",
        ),
        (
            "requirements",
            '<div class="req"><span class="id">R-S11fr</span>',
            "R-S11fr software-RGBA recovery requirement",
        ),
        (
            "requirements",
            '<div class="req"><span class="id">R-S11fs</span>',
            "R-S11fs pointer-evidenced presentation recovery requirement",
        ),
        (
            "requirements",
            '<div class="req"><span class="id">R-S11gf</span>',
            "R-S11gf Linux texture-plugin load-authority requirement",
        ),
        ("requirements", "<tr><td>306</td>", "Appendix C #306"),
        ("requirements", "<tr><td>307</td>", "Appendix C #307"),
        ("requirements", "<tr><td>308</td>", "Appendix C #308"),
        ("requirements", "<tr><td>309</td>", "Appendix C #309"),
        ("requirements", "<tr><td>311</td>", "Appendix C #311"),
        ("requirements", "<tr><td>314</td>", "Appendix C #314"),
        ("requirements", "<tr><td>321</td>", "Appendix C #321"),
        ("requirements", "<tr><td>324</td>", "Appendix C #324"),
        ("requirements", "<tr><td>326</td>", "Appendix C #326"),
        ("requirements", "<tr><td>327</td>", "Appendix C #327"),
        ("requirements", "<tr><td>341</td>", "Appendix C #341"),
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
            "hardening",
            "**R-S11ez/R-S11e-187 pending desktop frame retirement finality",
            "native retirement-finality hardening ledger",
        ),
        (
            "hardening",
            "**R-S11fa/R-S11e-188 exact viewer presentation-resume recovery",
            "presentation-resume hardening ledger",
        ),
        (
            "hardening",
            "**R-S11fc/R-S11e-190 exact desktop first-image admission",
            "first-image admission hardening ledger",
        ),
        (
            "hardening",
            "**R-S11ff/R-S11e-193 exact viewer refresh admission",
            "viewer refresh admission hardening ledger",
        ),
        (
            "hardening",
            "**R-S11fm/R-S11e-200 desktop texture activation finality",
            "texture activation finality hardening ledger",
        ),
        (
            "hardening",
            "**R-S11fp/R-S11e-203 exact desktop pending-texture re-notification",
            "pending-texture re-notification hardening ledger",
        ),
        (
            "hardening",
            "**R-S11fr/R-S11e-205 exact software-RGBA presentation recovery",
            "software-RGBA recovery hardening ledger",
        ),
        (
            "hardening",
            "**R-S11fs/R-S11e-206 pointer-evidenced desktop presentation recovery",
            "pointer-evidenced presentation recovery hardening ledger",
        ),
        (
            "hardening",
            "**R-S11gf/R-S11e-218 Linux Flutter texture-plugin load authority",
            "Linux texture-plugin load-authority hardening ledger",
        ),
        (
            "verify",
            "cargo test --lib --features linux-pkg-config,flutter r_s11ex_ --color never",
            "shared native behavior gate",
        ),
        (
            "verify",
            "cargo test --lib --features linux-pkg-config,flutter r_s11gf_ --color never",
            "shared Linux texture-plugin path behavior gate",
        ),
        (
            "verify",
            "cargo test --lib --features linux-pkg-config,flutter r_s11fc_ --color never",
            "shared first-image admission behavior gate",
        ),
        (
            "verify",
            "cargo test --lib --features linux-pkg-config,flutter r_s11ff_ --color never",
            "shared viewer refresh admission behavior gate",
        ),
        (
            "dart_verify",
            "flutter::mobile_session_lifecycle_tests::r_s11ff_r_s11gs_video_refresh_derives_the_current_exact_ui_owner_displays",
            "fresh-bridge exact UI-owner/display-authority refresh behavior gate",
        ),
        (
            "dart_verify",
            "flutter::linux_texture_plugin_path_tests::r_s11gf_",
            "fresh-bridge Linux texture-plugin path behavior gate",
        ),
        (
            "dart_verify",
            "flutter::mobile_session_lifecycle_tests::r_s11fr_",
            "fresh-bridge software-RGBA recovery behavior gate",
        ),
        (
            "dart_verify",
            "flutter test --no-pub test/rgba_publication_order_test.dart",
            "Dart publication-order behavior gate",
        ),
        (
            "dart_verify",
            "flutter test --no-pub test/desktop_texture_lifecycle_test.dart",
            "confined Dart behavior gate",
        ),
        (
            "dart_verify",
            "\n    /tmp/texture_rgba_renderer_plugin_test\n",
            "confined Linux native callback behavior gate",
        ),
        (
            "dart_verify",
            "\n    /tmp/texture_rgba_windows_core_test\n",
            "portable Windows callback-core behavior gate",
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
    (
        "flutter",
        "let Some(info) = write_lock.get_mut(&display) else {",
        "let Some(info) = write_lock.values_mut().next() else {",
        "exact decoded-display texture slot",
    ),
    (
        "flutter",
        "let Some(info) = sessions.get(&display) else {",
        "let Some(info) = sessions.values().next() else {",
        "exact pending-frame texture slot",
    ),
    (
        "flutter",
        "if !session.displays.contains(&display) {",
        "if false {",
        "texture dispatch exact display membership",
    ),
    (
        "flutter",
        "fn bind_initial_display_owner(\n    handlers: &mut HashMap<SessionID, SessionHandler>,",
        "fn bind_initial_display_owner_disabled(\n    handlers: &mut HashMap<SessionID, SessionHandler>,",
        "initial display-owner binding",
    ),
    (
        "flutter",
        "if handlers.is_empty() || handlers.values().any(|handler| handler.displays.is_empty())",
        "if false",
        "missing explicit initial display-owner refusal",
    ),
    (
        "flutter",
        "if pending.len() > 1",
        "if false",
        "ambiguous initial display-owner refusal",
    ),
    (
        "flutter",
        "other_session_id != session_id && handler.displays.is_empty()",
        "false",
        "unmarked empty initial display-owner refusal",
    ),
    (
        "flutter",
        "if display >= display_count {\n        bail!(\n            \"initial peer display",
        "if display > display_count {\n        bail!(\n            \"initial peer display",
        "initial display inventory bound",
    ),
    (
        "flutter",
        "handler.awaiting_initial_display = false;",
        "handler.awaiting_initial_display = true;",
        "initial display-owner finality",
    ),
    (
        "flutter",
        "r_s11gt_initial_peer_info_binds_one_exact_display_owner_once",
        "initial_peer_info_implicitly_selects_a_display",
        "initial display-owner behavior regression",
    ),
    (
        "flutter",
        "r_s11gt_initial_display_binding_refuses_ambiguous_or_invalid_authority",
        "initial_display_binding_accepts_ambiguous_authority",
        "initial display-owner refusal regression",
    ),
    (
        "flutter",
        "r_s11gt_reconnect_preserves_explicit_display_owners_without_rebinding",
        "reconnect_implicitly_rebinds_display_owners",
        "reconnect display-owner preservation regression",
    ),
    (
        "flutter",
        "fn admit_session_start(\n    is_video_session: bool,",
        "fn admit_session_start_disabled(\n    is_video_session: bool,",
        "display-owned session-start admission",
    ),
    (
        "flutter",
        "let starts_peer_connection = !has_ui_stream\n        && is_first_ui_session\n        && is_unselected_ui_session\n        && !is_awaiting_initial_display;",
        "let starts_peer_connection = !has_ui_stream\n        && is_first_ui_session\n        && !is_awaiting_initial_display;",
        "first unselected peer-connection start",
    ),
    (
        "flutter",
        "&& is_unselected_ui_session\n        && !is_awaiting_initial_display;\n    if is_video_session",
        "&& is_unselected_ui_session;\n    if is_video_session",
        "pending initial owner cannot restart peer connection",
    ),
    (
        "flutter",
        "&& !starts_peer_connection\n        && !is_awaiting_initial_display",
        "&& !starts_peer_connection\n        && false",
        "unselected video-route refusal",
    ),
    (
        "flutter",
        "r_s11gt_session_start_requires_fresh_or_explicit_display_authority",
        "session_start_accepts_unselected_existing_video_routes",
        "display-owned session-start regression",
    ),
    (
        "flutter",
        "match s.start_io_thread_with_lock(&mut thread_lock)",
        "match session.start_io_thread()",
        "peer-I/O start inside exact-owner guard",
    ),
    (
        "ui_session",
        "pub(crate) fn start_io_thread_with_lock(",
        "fn start_io_thread_without_lock(",
        "prelocked viewer worker-start helper",
    ),
    (
        "ui_session",
        "self.start_io_thread_with_lock(&mut thread_lock)",
        "self.start_io_thread()",
        "public viewer-start worker-slot delegation",
    ),
    (
        "flutter",
        "let mut thread_lock = s.thread.lock().unwrap();\n        let mut handlers = s.session_handlers.write().unwrap();",
        "let mut handlers = s.session_handlers.write().unwrap();\n        let mut thread_lock = s.thread.lock().unwrap();",
        "worker-slot before handler-owner lock order",
    ),
    (
        "flutter",
        ".any(|owned_display| *owned_display >= display_count)",
        ".any(|_| false)",
        "preserved display-owner inventory bound",
    ),
    (
        "flutter",
        ".replay_ready_rgba(session_id, client_owner_id)",
        ".replay_ready_rgba(session_id, session_id)",
        "exact-owner stream replay",
    ),
    (
        "flutter",
        "rollback_failed_session_start(session_id, client_owner_id);",
        "rollback_failed_session_start(session_id, session_id);",
        "exact-owner failed-start rollback",
    ),
    (
        "io_loop",
        "let initial_display = pi.current_display;",
        "let initial_display = 0;",
        "raw claimed initial display preservation",
    ),
    (
        "io_loop",
        ".bind_initial_display_owner(initial_display, pi.displays.len())",
        ".bind_initial_display_owner(pi.current_display, pi.displays.len())",
        "initial display admission before normalized use",
    ),
    (
        "flutter",
        "if !self.displays.contains(&display)",
        "if false",
        "renderer size exact display ownership",
    ),
    (
        "flutter",
        "let handler = handlers.get_mut(session_id)?;\n        if handler.client_owner_id.as_ref() != Some(client_owner_id)",
        "let handler = handlers.get_mut(session_id)?;\n        if false",
        "renderer size exact UI owner",
    ),
    (
        "flutter",
        "s.ui_handler.set_exact_owned_display_size(\n            &session_id,\n            &client_owner_id,",
        "s.ui_handler.set_exact_owned_display_size(\n            &session_id,\n            &session_id,",
        "renderer size exact owner forwarding",
    ),
    (
        "flutter",
        ") -> ResultType<()> {\n    for s in sessions::get_sessions() {\n        if let Some(admitted) = s.ui_handler.set_exact_owned_display_size(",
        ") {\n    for s in sessions::get_sessions() {\n        if let Some(admitted) = s.ui_handler.set_exact_owned_display_size(",
        "result-bearing renderer size admission",
    ),
    (
        "ffi",
        "super::flutter::session_set_size(session_id, client_owner_id, display, width, height)",
        "super::flutter::session_set_size(session_id, session_id, display, width, height)",
        "renderer size FFI owner forwarding",
    ),
    (
        "ffi",
        ") -> Result<()> {\n    super::flutter::session_set_size(session_id, client_owner_id, display, width, height)",
        ") {\n    super::flutter::session_set_size(session_id, client_owner_id, display, width, height)",
        "result-bearing renderer size FFI",
    ),
    (
        "model",
        "await _updateSessionWidthHeight(sessionId, expectedClientOwnerId);",
        "await _updateSessionWidthHeight(sessionId, sessionId);",
        "Dart renderer size owner propagation",
    ),
    (
        "model",
        "await bind.sessionSetSize(",
        "bind.sessionSetSize(",
        "awaited Dart renderer size finality",
    ),
    (
        "model",
        "clientOwnerId: expectedClientOwnerId",
        "clientOwnerId: sessionId",
        "Dart renderer size owner bridge argument",
    ),
    (
        "model",
        "final restoreDisplaySelection = !isCache && _pi.isSet.value;",
        "final restoreDisplaySelection = false;",
        "established reconnect display restoration",
    ),
    (
        "model",
        "if (!preserveDisplaySelection &&",
        "if (true &&",
        "reconnect display-state preservation",
    ),
    (
        "model",
        "!await selectRemoteDisplays(\n                ffi, expectedSessionId, reconnectDisplays)",
        "false",
        "awaited reconnect display restoration",
    ),
    (
        "model",
        "'The previous display selection could not be restored'",
        "'Reconnect display failure ignored'",
        "terminal reconnect display restoration failure",
    ),
    (
        "web_bridge",
        "Future<void> sessionSetSize(\n      {required UuidValue sessionId,\n      required UuidValue clientOwnerId",
        "Future<void> sessionSetSize(\n      {required UuidValue sessionId,\n      required UuidValue retiredClientOwnerId",
        "web renderer size owner parity",
    ),
    (
        "flutter",
        "if let Some(h) = handlers.get_mut(session_id) {\n            if h.client_owner_id.as_ref() != Some(client_owner_id)",
        "if let Some(h) = handlers.get_mut(session_id) {\n            if false",
        "under-guard exact-owner stream admission",
    ),
    (
        "flutter",
        "r_s11gt_capture_authority_excludes_renderer_resource_keys",
        "renderer_resources_create_capture_authority",
        "renderer resource/capture-authority regression",
    ),
    (
        "flutter",
        "r_s11gt_renderer_size_requires_exact_current_ui_owner",
        "renderer_size_accepts_a_reused_session_id",
        "renderer-size exact-owner regression",
    ),
    (
        "presentation_recovery",
        "if (_retired || !selected) return;",
        "if (_retired) return;",
        "hidden presentation selection guard",
    ),
    (
        "presentation_recovery",
        "if (_refreshInFlight) return;",
        "if (false) return;",
        "duplicate refresh coalescing",
    ),
    (
        "presentation_recovery",
        "final followUpDemanded = _refreshPending && _resumeDemanded;",
        "final followUpDemanded = false;",
        "in-flight suspend/resume preservation",
    ),
    (
        "presentation_recovery",
        "onError(error, stackTrace);",
        "// refresh failure hidden",
        "presentation refresh failure visibility",
    ),
    (
        "presentation_recovery",
        "_retired = true;",
        "_retired = false;",
        "presentation recovery retirement",
    ),
    (
        "mobile_remote",
        "      _resumePresentation();\n      trySyncClipboard();",
        "      trySyncClipboard();",
        "mobile remote foreground recovery",
    ),
    (
        "mobile_camera",
        "          await sessionRefreshVideo(sessionId, gFFI.clientOwnerId);",
        "          return;",
        "mobile camera exact-session refresh",
    ),
    (
        "remote",
        "  void onWindowBlur() {\n    super.onWindowBlur();\n    _presentationRecovery.suspend();",
        "  void onWindowBlur() {\n    super.onWindowBlur();",
        "desktop remote blur suspension",
    ),
    (
        "camera",
        "  void onWindowFocus() {\n    super.onWindowFocus();\n    _resumePresentationIfNeeded();",
        "  void onWindowFocus() {\n    super.onWindowFocus();",
        "desktop camera focus recovery",
    ),
    (
        "remote",
        "          _isWindowBlur = false;\n          _resumePresentationIfNeeded();",
        "          _isWindowBlur = false;",
        "desktop remote pointer-evidenced missing-focus recovery",
    ),
    (
        "camera",
        "          _isWindowBlur = false;\n          _resumePresentationIfNeeded();",
        "          _isWindowBlur = false;",
        "desktop camera pointer-evidenced missing-focus recovery",
    ),
    (
        "remote_tab",
        "            page.setPresentationSelected(tab.key == selectedKey);",
        "            page.setPresentationSelected(true);",
        "desktop remote exact selected-tab propagation",
    ),
    (
        "camera_tab",
        "            page.setPresentationSelected(tab.key == selectedKey);",
        "            page.setPresentationSelected(true);",
        "desktop camera exact selected-tab propagation",
    ),
    (
        "presentation_tests",
        "retirement still reports an in-flight refresh failure",
        "retirement hides an in-flight refresh failure",
        "retired in-flight failure regression",
    ),
    (
        "dart_verify",
        "flutter test --no-pub test/presentation_recovery_test.dart",
        "true # presentation recovery test disabled",
        "presentation recovery behavior gate",
    ),
    (
        "common",
        "sessionRefreshVideo(SessionID sessionId, SessionID clientOwnerId)",
        "sessionRefreshVideo(SessionID sessionId, SessionID ignoredOwnerId)",
        "Dart refresh exact UI owner",
    ),
    (
        "toolbar",
        "sessionRefreshVideo(sessionId, ffi.clientOwnerId)",
        "sessionRefreshVideo(sessionId, sessionId)",
        "manual refresh exact UI owner",
    ),
    (
        "io_loop",
        "    displays: VecDeque<usize>,",
        "    displays: Vec<usize>,",
        "bounded refresh display state",
    ),
    (
        "io_loop",
        "let (wake, receiver) = mpsc::channel(1);",
        "let (wake, receiver) = mpsc::unbounded_channel();",
        "capacity-one refresh wake",
    ),
    (
        "io_loop",
        "state.displays.len() >= MAX_PEER_VIDEO_DISPLAYS",
        "state.displays.len() == usize::MAX",
        "fixed refresh identity cap",
    ),
    (
        "io_loop",
        "if !state.all && !state.displays.contains(&display)",
        "if state.all || state.displays.contains(&display) { return Ok(()); }\n                    if true",
        "duplicate refresh observes receiver closure",
    ),
    (
        "io_loop",
        "if is_video_refresh_message(&msg)",
        "if false && is_video_refresh_message(&msg)",
        "generic command-queue refresh refusal",
    ),
    (
        "ui_session",
        "let sender = self.video_refresh_sender.read().unwrap();",
        "let sender = self.video_refresh_sender.read().unwrap().clone();",
        "round lock held through refresh admission",
    ),
    (
        "ui_session",
        "std::sync::mpsc::sync_channel(1)",
        "std::sync::mpsc::channel()",
        "capacity-one viewer worker start gate",
    ),
    (
        "ui_session",
        "if display >= display_count",
        "if false",
        "live peer-display refresh range",
    ),
    (
        "ui_session",
        "        self.request_video_refresh(request)\n    }\n\n    fn refresh_all_video",
        "        drop(lc);\n        self.request_video_refresh(request)\n    }\n\n    fn refresh_all_video",
        "peer inventory lock held through exact-round admission",
    ),
    (
        "ui_session",
        "if start.send(receiver).is_err()",
        "if false",
        "refresh publication before worker release",
    ),
    (
        "ui_session",
        "        let mut video_refresh_sender = self.video_refresh_sender.write().unwrap();\n"
        "        self.connection_round_owner.retire();",
        "        self.connection_round_owner.retire();\n"
        "        let mut video_refresh_sender = self.video_refresh_sender.write().unwrap();",
        "refresh publication/retirement serialization",
    ),
    (
        "flutter",
        "if handler.client_owner_id.as_ref() != Some(client_owner_id)",
        "if false",
        "refresh exact UI-owner admission",
    ),
    (
        "ffi",
        "pub fn session_refresh(session_id: SessionID, client_owner_id: SessionID)",
        "pub fn session_refresh(session_id: SessionID, ignored_owner_id: SessionID)",
        "result-bearing exact-owner refresh FFI",
    ),
    (
        "flutter",
        "if handler.displays.is_empty()",
        "if false",
        "empty exact-owner refresh display refusal",
    ),
    (
        "flutter",
        "for display in &handler.displays {\n                    session.ui_handler.rearm_rgba_for_presentation_recovery(",
        "for display in &[0usize] {\n                    session.ui_handler.rearm_rgba_for_presentation_recovery(",
        "native exact-owner refresh display derivation",
    ),
    (
        "io_loop",
        "r_s11ff_refresh_mailbox_has_a_fixed_display_identity_cap",
        "refresh_mailbox_has_no_display_identity_cap",
        "refresh capacity behavior regression",
    ),
    (
        "flutter",
        "r_s11ff_r_s11gs_video_refresh_derives_the_current_exact_ui_owner_displays",
        "video_refresh_accepts_a_stale_ui_owner",
        "refresh exact-owner/display-authority behavior regression",
    ),
    (
        "ui_session",
        "r_s11ff_retired_owner_never_releases_the_refresh_worker_start_gate",
        "viewer_refresh_worker_start_gate_test_disabled",
        "retired-owner refresh worker start-gate behavior regression",
    ),
    ("lifecycle", "Future<bool> activate();", "Future<void> activate();", "result-bearing activation API"),
    ("lifecycle", "_retireRequested = true;", "_retireRequested = false;", "synchronous retirement invalidation"),
    ("lifecycle", "if (!ready)", "if (false)", "failed-initialization cleanup"),
    (
        "lifecycle",
        "StateError('Desktop texture initialization was rejected')",
        "StateError('')",
        "rejected initialization visibility",
    ),
    ("lifecycle", "if (_retireRequested)", "if (false)", "late-publication exclusion"),
    ("lifecycle", "_publicationAttempted = true;", "_publicationAttempted = false;", "publication ownership"),
    ("lifecycle", "return true;", "return false;", "successful activation result"),
    ("lifecycle", "return _retireFuture ??= _retire();", "return _retire();", "exact retirement finality"),
    ("lifecycle", "await _activationFuture;", "activate();", "activation drain"),
    ("lifecycle", "_unpublicationAttempted = true;", "_unpublicationAttempted = false;", "exact unpublication"),
    ("lifecycle", "_releaseFuture ??= _releaseAndReportFailure()", "_releaseAndReportFailure()", "exact release future"),
    ("lifecycle", "await _release();", "_release();", "release finality"),
    ("lifecycle", "_creationFailed = true;", "_creationFailed = false;", "bounded creation failure"),
    ("lifecycle", "_demandRevision += 1;", "_demandRevision += 0;", "distinct demand revision"),
    (
        "lifecycle",
        "activated = await candidate.activate();",
        "activated = true;",
        "awaited candidate activation",
    ),
    ("lifecycle", "await candidate.retire();", "candidate.retire();", "failed candidate retirement finality"),
    (
        "lifecycle",
        "if (_wanted && _demandRevision == demandRevision)",
        "if (_wanted)",
        "newer demand preservation",
    ),
    ("lifecycle", "await retiring.retire();", "retiring.retire();", "predecessor finality"),
    ("lifecycle", "if (identical(_current, retiring))", "if (_current != null)", "exact predecessor removal"),
    ("lifecycle", "if (_disposed && wanted)", "if (false)", "post-dispose refusal"),
    (
        "render",
        "Future<bool> activate() => _lifecycle.activate();",
        "Future<bool> activate() async => true;",
        "slot-owned software texture activation",
    ),
    (
        "tests",
        "rejected initialization is reported and the allocation is released",
        "rejected initialization is ignored",
        "rejected initialization behavior regression",
    ),
    (
        "tests",
        "failed asynchronous activation is retired and retry is bounded",
        "failed asynchronous activation is retained",
        "failed activation behavior regression",
    ),
    (
        "tests",
        "new demand during failed activation receives a fresh exact attempt",
        "new demand during failed activation is discarded",
        "newer demand behavior regression",
    ),
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
        "debugPrint('EventToUI_Texture display:$display');",
        "final gpuTexture = message.field1;",
        "retired GPU event consumption",
    ),
    (
        "online_fetch",
        '[ "${#git_specs[@]}" -eq 3 ]',
        '[ "${#git_specs[@]}" -eq 4 ]',
        "three-dependency acquisition inventory",
    ),
    (
        "pub_cache_output",
        "EXPECTED_GIT_DEPENDENCIES = 3",
        "EXPECTED_GIT_DEPENDENCIES = 4",
        "three-dependency Pub-cache output inventory",
    ),
    (
        "dependency_inventory",
        '"package_records": 198',
        '"package_records": 199',
        "updated Flutter package inventory",
    ),
    (
        "dependency_inventory",
        '"git_hosted_records": 3',
        '"git_hosted_records": 4',
        "updated Flutter Git dependency inventory",
    ),
    (
        "dependency_inventory",
        '"rustdesk_org_git_records": 2',
        '"rustdesk_org_git_records": 3',
        "updated RustDesk Git dependency inventory",
    ),
    ("model", "clientOwnerId = isMobile ? _mobileClientOwnerId : Uuid().v4obj();", "clientOwnerId = isMobile ? _mobileClientOwnerId : sessionId;", "fresh desktop UI owner"),
    ("remote", "await _awaitCleanup('texture retirement', textureDisposal);", "unawaited(textureDisposal);", "RemoteDesktop texture finality"),
    ("camera", "await _awaitCleanup('texture retirement', textureDisposal);", "unawaited(textureDisposal);", "ViewCamera texture finality"),
    ("flutter", "if handler.client_owner_id.as_ref() != Some(client_owner_id)", "if false", "native exact owner admission"),
    ("flutter", ".register_pixelbuffer_texture(&session_id, &client_owner_id, display, ptr)", ".register_pixelbuffer_texture(&session_id, &session_id, display, ptr)", "native owner propagation"),
    (
        "flutter",
        "if !frame_admitted || *render_notified || !notify()",
        "if *render_notified || !notify()",
        "native frame rejection cannot consume first-image notification",
    ),
    (
        "flutter",
        "if !frame_admitted || *render_notified || !notify()",
        "if !frame_admitted || *render_notified",
        "UI stream rejection cannot consume first-image notification",
    ),
    (
        "flutter",
        "*render_notified = true;",
        "*render_notified = false;",
        "successful notification commit",
    ),
    (
        "flutter",
        '"FlutterRgbaRendererPluginTryOnRgba",',
        '"FlutterRgbaRendererPluginOnRgba",',
        "versioned native admission symbol",
    ),
    (
        "flutter",
        '"FlutterRgbaRendererPluginTryNotifyPending",',
        '"FlutterRgbaRendererPluginNotifyPending",',
        "versioned native pending-frame notifier symbol",
    ),
    (
        "flutter",
        "handler.renderer.notify_pending_frame(*display)?;",
        "// pending texture was not re-notified\n",
        "exact-owner pending-frame re-notification ordering",
    ),
    (
        "flutter",
        "        load_linux_texture_plugin();",
        '        Library::open("libtexture_rgba_renderer_plugin.so");',
        "Linux ambient-soname loader exclusion",
    ),
    (
        "flutter",
        "if !executable.is_absolute()",
        "if false",
        "Linux absolute executable-path requirement",
    ),
    (
        "flutter",
        "executable.file_name().is_none()",
        "false",
        "Linux executable file-identity requirement",
    ),
    (
        "flutter",
        '.join("lib")',
        '.join("plugins")',
        "Linux exact application library directory",
    ),
    (
        "flutter",
        "Library::open(path)",
        "Library::open(LINUX_TEXTURE_RGBA_RENDERER_PLUGIN)",
        "Linux exact-path dynamic-library open",
    ),
    (
        "flutter",
        "fn r_s11gf_linux_texture_plugin_is_exactly_application_relative()",
        "fn linux_texture_plugin_path_is_not_tested()",
        "Linux application-relative path regression",
    ),
    (
        "flutter",
        "fn r_s11gf_linux_texture_plugin_rejects_ambient_or_unclean_roots()",
        "fn linux_texture_plugin_rejection_is_not_tested()",
        "Linux unclean-root rejection regression",
    ),
    (
        "flutter",
        "session.ui_handler.rearm_rgba_for_presentation_recovery(\n",
        "// software publication was not re-armed\n",
        "exact-owner software publication re-arm ordering",
    ),
    (
        "io_loop",
        "if !thread.media_thread.begin_refresh()",
        "if false",
        "viewer refresh endpoint-liveness checks",
    ),
    (
        "flutter",
        "if unsafe { func(info.texture_rgba_ptr as _) } == 0",
        "if false",
        "native pending-frame failure propagation",
    ),
    (
        "flutter",
        "r_s11fc_texture_notification_commits_only_after_native_and_ui_admission",
        "texture_notification_behavior_test_disabled",
        "native and UI notification retry behavior proof",
    ),
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
        "plugin_windows_texture",
        "texture_registrar_->MarkTextureFrameAvailable(texture_id_);\n}",
        "true;\n}",
        "Windows pending-frame registrar re-notification",
    ),
    (
        "plugin_windows_texture",
        "  if (buffer_ready_) {\n"
        "    const int background_index = foreground_index_ ^ 1;\n",
        "  if (false) {\n"
        "    const int background_index = foreground_index_ ^ 1;\n",
        "Windows retirement cancels pending frame",
    ),
    (
        "plugin_windows_texture",
        "  if (retired_) {\n"
        "    return nullptr;\n"
        "  }\n"
        "  if (buffer_ready_) {",
        "  if (false) {\n"
        "    return nullptr;\n"
        "  }\n"
        "  if (buffer_ready_) {",
        "Windows callback retirement refusal",
    ),
    (
        "plugin_windows_test_stub",
        "class TextureRegistrar {",
        "class DisabledTextureRegistrar {",
        "portable Windows test registrar interface",
    ),
    (
        "plugin_windows_test_stub",
        "using TextureVariant = std::variant<PixelBufferTexture, GpuSurfaceTexture>;",
        "class TextureVariant {};",
        "portable Windows pinned-wrapper variant parity",
    ),
    (
        "plugin_windows_cmake",
        '  "texture_rgba.h"\n  "texture_rgba_renderer_plugin.h"\n',
        '  "texture_rgba.h"\n  "test/texture_rgba_test.cc"\n'
        '  "texture_rgba_renderer_plugin.h"\n',
        "test-only Windows source packaging exclusion",
    ),
    (
        "plugin_windows_cmake",
        "add_executable(${CORE_TEST_NAME} EXCLUDE_FROM_ALL",
        "add_executable(${CORE_TEST_NAME}",
        "native Windows test excluded from the product build",
    ),
    (
        "build_windows",
        "& $cmakeExe --build $flutterBuildRoot --config Release --target texture_rgba_renderer_windows_core_test -- /p:BuildProjectReferences=false",
        "true # native Windows texture callback-core build disabled",
        "native Windows pinned-wrapper callback-core build gate",
    ),
    (
        "build_windows",
        "    $textureCoreExit = Invoke-BoundedNativeProcess `\n        -Path $textureCoreTest `",
        "    $textureCoreExit = 0 # native Windows texture callback-core execution disabled",
        "native Windows pinned-wrapper callback-core execution gate",
    ),
    (
        "plugin_windows_test",
        '"a pending frame crossed the retirement boundary"',
        '"pending frame publication was accepted"',
        "portable Windows native retirement regression",
    ),
    (
        "plugin_windows_test",
        '"retirement released the presented frame too early"',
        '"presented frame lifetime was not checked"',
        "portable Windows presented-storage regression",
    ),
    (
        "plugin_windows_test",
        '"pending-frame re-notification did not reach the registrar"',
        '"pending-frame re-notification was not checked"',
        "portable Windows pending-frame re-notification regression",
    ),
    (
        "plugin_windows_test",
        '"failed re-notification consumed the pending frame"',
        '"pending-frame preservation was not checked"',
        "portable Windows pending-frame preservation regression",
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
        "    return static_cast<TextureRgba*>(texture_rgba)",
        "  return static_cast<TextureRgba*>(texture_rgba)",
        "Windows C-ABI exception containment",
    ),
    (
        "plugin_windows_c_api",
        "               ? 1\n"
        "               : 0;",
        "               ? 0\n"
        "               : 0;",
        "Windows C-ABI native admission propagation",
    ),
    (
        "plugin_windows_c_api_h",
        "FLUTTER_PLUGIN_EXPORT int FlutterRgbaRendererPluginTryOnRgba(",
        "FLUTTER_PLUGIN_EXPORT void FlutterRgbaRendererPluginTryOnRgba(",
        "Windows versioned admission declaration result",
    ),
    (
        "plugin_windows_c_api",
        "->NotifyPendingFrame()",
        "->NotifyPendingFrameDisabled()",
        "Windows C-ABI pending-frame result",
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
        "!self->buffer_ready || fl_texture_registrar_mark_texture_frame_available(",
        "!self->buffer_ready || TRUE || fl_texture_registrar_mark_texture_frame_available(",
        "Linux pending-frame registrar re-notification",
    ),
    (
        "plugin_linux",
        "  self->buffer_ready = FALSE;\n"
        "  g_mutex_unlock(&self->mutex);\n"
        "  delete[] pending_buffer;\n",
        "  g_mutex_unlock(&self->mutex);\n",
        "Linux retirement cancels pending frame",
    ),
    (
        "plugin_linux",
        "  if (self->retired) {\n"
        "    g_mutex_unlock(&self->mutex);\n"
        "    g_set_error(error, g_quark_from_static_string(\"TextureRgbaRenderer\"), -1,\n",
        "  if (false) {\n"
        "    g_mutex_unlock(&self->mutex);\n"
        "    g_set_error(error, g_quark_from_static_string(\"TextureRgbaRenderer\"), -1,\n",
        "Linux callback retirement refusal",
    ),
    (
        "plugin_linux_test",
        '"a pending frame crossed the retirement boundary"',
        '"pending frame publication was accepted"',
        "Linux native retirement regression",
    ),
    (
        "plugin_linux_test",
        '"retirement released the presented frame too early"',
        '"presented frame lifetime was not checked"',
        "Linux native presented-storage regression",
    ),
    (
        "plugin_linux_test",
        '"pending-frame re-notification did not reach the registrar"',
        '"pending-frame re-notification was not checked"',
        "Linux pending-frame re-notification regression",
    ),
    (
        "plugin_linux_test",
        "texture->texture_id = 17;",
        "texture->texture_id = 0;",
        "Linux test production registration sentinel",
    ),
    (
        "plugin_linux_test",
        '"failed re-notification consumed the pending frame"',
        '"pending-frame preservation was not checked"',
        "Linux pending-frame preservation regression",
    ),
    (
        "plugin_linux_test",
        '"C-ABI failed registrar notification was accepted"',
        '"C-ABI admission result was not checked"',
        "Linux exported admission-result regression",
    ),
    (
        "plugin_linux",
        "return texture_rgba_mark_frame(reinterpret_cast<TextureRgba*>(texture_rgba),",
        "texture_rgba_mark_frame(reinterpret_cast<TextureRgba*>(texture_rgba),",
        "Linux C-ABI native admission propagation",
    ),
    (
        "plugin_linux_h",
        "FLUTTER_PLUGIN_EXPORT int FlutterRgbaRendererPluginTryOnRgba(",
        "FLUTTER_PLUGIN_EXPORT void FlutterRgbaRendererPluginTryOnRgba(",
        "Linux versioned admission declaration result",
    ),
    (
        "plugin_linux",
        "return texture_rgba_notify_pending(\n",
        "return TRUE || texture_rgba_notify_pending(\n",
        "Linux C-ABI pending-frame result",
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
    (
        "plugin_macos_texture",
        "            if framePending {\n                registry.textureFrameAvailable(textureId)\n            }",
        "            if framePending {\n                _ = registry\n            }",
        "macOS pending-frame re-notification",
    ),
    (
        "plugin_macos_c_api",
        "return [texture_rgba markFrameAvaliableRawWithBuffer:buffer",
        "[texture_rgba markFrameAvaliableRawWithBuffer:buffer",
        "macOS C-ABI native admission propagation",
    ),
    (
        "plugin_macos_c_api",
        "return [texture_rgba notifyPendingFrame] ? 1 : 0;",
        "return [texture_rgba notifyPendingFrame] ? 0 : 0;",
        "macOS C-ABI pending-frame result",
    ),
    ("requirements", '<div class="req"><span class="id">R-S11ex</span>', '<div class="req"><span class="id">R-S11ex-disabled</span>', "normative requirement"),
    ("requirements", '<div class="req"><span class="id">R-S11ey</span>', '<div class="req"><span class="id">R-S11ey-disabled</span>', "software-only normative requirement"),
    ("requirements", '<div class="req"><span class="id">R-S11ez</span>', '<div class="req"><span class="id">R-S11ez-disabled</span>', "native retirement normative requirement"),
    ("requirements", '<div class="req"><span class="id">R-S11fa</span>', '<div class="req"><span class="id">R-S11fa-disabled</span>', "presentation-resume normative requirement"),
    ("requirements", '<div class="req"><span class="id">R-S11fc</span>', '<div class="req"><span class="id">R-S11fc-disabled</span>', "first-image admission normative requirement"),
    ("requirements", '<div class="req"><span class="id">R-S11ff</span>', '<div class="req"><span class="id">R-S11ff-disabled</span>', "viewer refresh admission normative requirement"),
    ("requirements", '<div class="req"><span class="id">R-S11fm</span>', '<div class="req"><span class="id">R-S11fm-disabled</span>', "texture activation normative requirement"),
    ("requirements", '<div class="req"><span class="id">R-S11fp</span>', '<div class="req"><span class="id">R-S11fp-disabled</span>', "pending-texture re-notification normative requirement"),
    ("requirements", '<div class="req"><span class="id">R-S11fr</span>', '<div class="req"><span class="id">R-S11fr-disabled</span>', "software-RGBA recovery normative requirement"),
    ("requirements", '<div class="req"><span class="id">R-S11fs</span>', '<div class="req"><span class="id">R-S11fs-disabled</span>', "pointer-evidenced presentation recovery normative requirement"),
    ("requirements", '<div class="req"><span class="id">R-S11gf</span>', '<div class="req"><span class="id">R-S11gf-disabled</span>', "Linux texture-plugin load-authority normative requirement"),
    ("requirements", "<tr><td>306</td>", "<tr><td>306-disabled</td>", "Appendix disposition"),
    ("requirements", "<tr><td>307</td>", "<tr><td>307-disabled</td>", "software-only Appendix disposition"),
    ("requirements", "<tr><td>308</td>", "<tr><td>308-disabled</td>", "native retirement Appendix disposition"),
    ("requirements", "<tr><td>309</td>", "<tr><td>309-disabled</td>", "presentation-resume Appendix disposition"),
    ("requirements", "<tr><td>311</td>", "<tr><td>311-disabled</td>", "first-image admission Appendix disposition"),
    ("requirements", "<tr><td>314</td>", "<tr><td>314-disabled</td>", "viewer refresh admission Appendix disposition"),
    ("requirements", "<tr><td>321</td>", "<tr><td>321-disabled</td>", "texture activation Appendix disposition"),
    ("requirements", "<tr><td>324</td>", "<tr><td>324-disabled</td>", "pending-texture re-notification Appendix disposition"),
    ("requirements", "<tr><td>327</td>", "<tr><td>327-disabled</td>", "pointer-evidenced presentation recovery Appendix disposition"),
    ("requirements", "<tr><td>341</td>", "<tr><td>341-disabled</td>", "Linux texture-plugin load-authority Appendix disposition"),
    ("hardening", "**R-S11ex/R-S11e-185 exact desktop Flutter texture lifecycle and UI-owner registration", "**R-S11ex-disabled/R-S11e-185 exact desktop Flutter texture lifecycle and UI-owner registration", "hardening ledger"),
    ("hardening", "**R-S11ey/R-S11e-186 software-RGBA-only desktop presentation", "**R-S11ey-disabled/R-S11e-186 software-RGBA-only desktop presentation", "software-only hardening ledger"),
    ("hardening", "**R-S11ez/R-S11e-187 pending desktop frame retirement finality", "**R-S11ez-disabled/R-S11e-187 pending desktop frame retirement finality", "native retirement hardening ledger"),
    ("hardening", "**R-S11fa/R-S11e-188 exact viewer presentation-resume recovery", "**R-S11fa-disabled/R-S11e-188 exact viewer presentation-resume recovery", "presentation-resume hardening ledger"),
    ("hardening", "**R-S11fc/R-S11e-190 exact desktop first-image admission", "**R-S11fc-disabled/R-S11e-190 exact desktop first-image admission", "first-image admission hardening ledger"),
    ("hardening", "**R-S11ff/R-S11e-193 exact viewer refresh admission", "**R-S11ff-disabled/R-S11e-193 exact viewer refresh admission", "viewer refresh admission hardening ledger"),
    ("hardening", "**R-S11fm/R-S11e-200 desktop texture activation finality", "**R-S11fm-disabled/R-S11e-200 desktop texture activation finality", "texture activation hardening ledger"),
    ("hardening", "**R-S11fp/R-S11e-203 exact desktop pending-texture re-notification", "**R-S11fp-disabled/R-S11e-203 exact desktop pending-texture re-notification", "pending-texture re-notification hardening ledger"),
    ("hardening", "**R-S11fr/R-S11e-205 exact software-RGBA presentation recovery", "**R-S11fr-disabled/R-S11e-205 exact software-RGBA presentation recovery", "software-RGBA recovery hardening ledger"),
    ("hardening", "**R-S11fs/R-S11e-206 pointer-evidenced desktop presentation recovery", "**R-S11fs-disabled/R-S11e-206 pointer-evidenced desktop presentation recovery", "pointer-evidenced presentation recovery hardening ledger"),
    ("requirements", '<div class="req"><span class="id">R-S11gs</span>', '<div class="req"><span class="id">R-S11gs-disabled</span>', "native refresh-display authority requirement"),
    ("requirements", "<tr><td>354</td>", "<tr><td>354-disabled</td>", "native refresh-display authority Appendix C row"),
    ("hardening", "### R-S11gs/R-S11e-231 — exact-owner presentation-refresh display authority", "### R-S11gs-disabled/R-S11e-231 — exact-owner presentation-refresh display authority", "native refresh-display authority hardening ledger"),
    ("requirements", '<div class="req"><span class="id">R-S11gt</span>', '<div class="req"><span class="id">R-S11gt-disabled</span>', "explicit native display-owner requirement"),
    ("requirements", "<tr><td>355</td>", "<tr><td>355-disabled</td>", "explicit native display-owner Appendix C row"),
    ("hardening", "### R-S11gt/R-S11e-232 — explicit initial and ongoing native display ownership", "### R-S11gt-disabled/R-S11e-232 — explicit initial and ongoing native display ownership", "explicit native display-owner hardening ledger"),
    ("verify", "cargo test --lib --features linux-pkg-config,flutter r_s11gt_ --color never", "cargo test --lib --features linux-pkg-config,flutter disabled_ --color never", "explicit native display-owner behavior gate"),
    ("hardening", "**R-S11gf/R-S11e-218 Linux Flutter texture-plugin load authority", "**R-S11gf-disabled/R-S11e-218 Linux Flutter texture-plugin load authority", "Linux texture-plugin load-authority hardening ledger"),
    ("verify", "cargo test --lib --features linux-pkg-config,flutter r_s11fc_ --color never", "true # first-image admission behavior gate disabled", "shared first-image admission behavior gate"),
    ("verify", "cargo test --lib --features linux-pkg-config,flutter r_s11gf_ --color never", "true # Linux texture-plugin path tests disabled", "shared Linux texture-plugin path behavior gate"),
    ("verify", "cargo test --lib --features linux-pkg-config,flutter r_s11ff_ --color never", "true # viewer refresh admission behavior gate disabled", "shared viewer refresh admission behavior gate"),
    ("dart_verify", "flutter::mobile_session_lifecycle_tests::r_s11ff_r_s11gs_video_refresh_derives_the_current_exact_ui_owner_displays", "flutter::mobile_session_lifecycle_tests::viewer_refresh_disabled", "fresh-bridge viewer refresh behavior gate"),
    ("dart_verify", "flutter::linux_texture_plugin_path_tests::r_s11gf_", "flutter::linux_texture_plugin_path_tests::disabled", "fresh-bridge Linux texture-plugin path behavior gate"),
    ("dart_verify", "flutter test --no-pub test/desktop_texture_lifecycle_test.dart", "true # desktop texture lifecycle test disabled", "Dart behavior gate"),
    ("dart_verify", "\n    /tmp/texture_rgba_renderer_plugin_test\n", "\n    true # Linux native callback behavior gate disabled\n", "Linux native callback behavior gate"),
    ("dart_verify", "\n    /tmp/texture_rgba_windows_core_test\n", "\n    true # portable Windows callback-core gate disabled\n", "portable Windows callback-core behavior gate"),
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
