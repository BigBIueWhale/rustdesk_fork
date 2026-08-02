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
                "sessionId, gFFI.clientOwnerId, gFFI.ffiModel.pi);",
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
                "sessionId, _ffi.clientOwnerId, _ffi.ffiModel.pi);",
            ),
            f"{label} selected exact-session refresh",
        )
        dispose = extract_braced_item(
            page, "Future<void> dispose()", f"{label} disposal"
        )
        require_order(
            dispose,
            (
                "_presentationRecovery.retire();",
                "super.dispose();",
                "final textureDisposal = _ffi.textureModel.dispose();",
                "await textureDisposal;",
                "await _ffi.close(closeSession: closeSession);",
            ),
            f"{label} recovery/texture/session retirement order",
        )

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
            "SessionID sessionId, SessionID clientOwnerId, PeerInfo pi",
            "if (pi.displays.isEmpty)",
            "throw StateError('Viewer display inventory is empty');",
            "bind.sessionRefresh(",
            "sessionId: sessionId, clientOwnerId: clientOwnerId, display: i",
            "bind.sessionRefresh(",
            "clientOwnerId: clientOwnerId,",
            "display: pi.currentDisplay",
        ),
        "result-bearing exact-owner Dart refresh bridge",
    )
    require(
        sources["toolbar"],
        "sessionRefreshVideo(sessionId, ffi.clientOwnerId, pi)",
        "manual refresh exact UI owner",
    )
    for needle, label in (
        (
            "sessionRefreshVideo(sessionId, ffi.clientOwnerId, pi)",
            "recording refresh exact UI owner",
        ),
        (
            "activeSessionId, clientOwnerId, ffiModel.pi",
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
            "thread.media_thread.begin_refresh();",
            "LoginConfigHandler::refresh()",
            "ViewerVideoRefreshRequest::Display(display) =>",
            "thread.media_thread.begin_refresh();",
            "LoginConfigHandler::refresh_display(display)",
            "peer.send(&message).await",
        ),
        "invalidate-before-peer-request refresh dispatch",
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
        "pub fn start_io_thread(&self)",
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
            "return session.refresh_video(display);",
        ),
        "UI-owner lock held through synchronous refresh admission",
    )
    ffi_refresh = extract_braced_item(
        sources["ffi"], "pub fn session_refresh(", "result-bearing refresh FFI"
    )
    require_order(
        ffi_refresh,
        (
            "client_owner_id: SessionID",
            ") -> Result<()>",
            "i32::try_from(display)",
            "sessions::request_video_refresh_for_exact_ui_owner",
            "&session_id, &client_owner_id, display",
        ),
        "typed exact-owner refresh FFI",
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
            "r_s11ff_video_refresh_requires_the_current_exact_ui_owner",
            "refresh UI-owner regression",
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
    renderer_admission = extract_braced_item(
        flutter,
        "pub fn on_rgba<F>",
        "desktop native frame admission",
    )
    require_order(
        renderer_admission,
        (
            "let Some(func) = &self.on_rgba_func else",
            "let frame_admitted = unsafe",
            ") != 0",
            "commit_first_texture_notification(",
        ),
        "versioned native admission result reaches first-image notification",
    )
    texture_dispatch = extract_braced_item(
        flutter,
        "fn on_rgba_flutter_texture_render(",
        "desktop texture event dispatch",
    )
    require_order(
        texture_dispatch,
        (
            "let Some(stream) = &session.event_stream else",
            ".renderer",
            ".on_rgba(display, rgba, || stream.add(EventToUI::Texture(display)))",
        ),
        "UI stream admission is inside the one-time notification transaction",
    )
    require(
        flutter,
        "r_s11fc_texture_notification_commits_only_after_native_and_ui_admission",
        "native/UI rejection and retry behavior regression",
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
    forbid(windows_cmake, "test/", "test-only Windows texture source packaging")
    forbid(windows_cmake, "file(GLOB", "globbed Windows plugin source authority")
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
            "class TextureVariant",
            "class TextureRegistrar",
            "virtual int64_t RegisterTexture(TextureVariant* texture) = 0;",
            "virtual bool MarkTextureFrameAvailable(int64_t texture_id) = 0;",
        ),
        "portable Windows test-only Flutter registrar interface",
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
    ):
        require(windows_test, needle, label)
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
        ("requirements", "<tr><td>306</td>", "Appendix C #306"),
        ("requirements", "<tr><td>307</td>", "Appendix C #307"),
        ("requirements", "<tr><td>308</td>", "Appendix C #308"),
        ("requirements", "<tr><td>309</td>", "Appendix C #309"),
        ("requirements", "<tr><td>311</td>", "Appendix C #311"),
        ("requirements", "<tr><td>314</td>", "Appendix C #314"),
        ("requirements", "<tr><td>321</td>", "Appendix C #321"),
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
            "verify",
            "cargo test --lib --features linux-pkg-config,flutter r_s11ex_ --color never",
            "shared native behavior gate",
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
            "flutter::mobile_session_lifecycle_tests::r_s11ff_video_refresh_requires_the_current_exact_ui_owner",
            "fresh-bridge exact UI-owner refresh behavior gate",
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
        "          await sessionRefreshVideo(\n"
        "              sessionId, gFFI.clientOwnerId, gFFI.ffiModel.pi);",
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
        "SessionID sessionId, SessionID clientOwnerId, PeerInfo pi",
        "SessionID sessionId, PeerInfo pi",
        "Dart refresh exact UI owner",
    ),
    (
        "toolbar",
        "sessionRefreshVideo(sessionId, ffi.clientOwnerId, pi)",
        "sessionRefreshVideo(sessionId, sessionId, pi)",
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
        "common",
        "if (pi.displays.isEmpty)",
        "if (false)",
        "empty viewer display inventory rejection",
    ),
    (
        "flutter",
        "if handler.client_owner_id.as_ref() != Some(client_owner_id)",
        "if false",
        "refresh exact UI-owner admission",
    ),
    (
        "ffi",
        "    client_owner_id: SessionID,\n    display: usize,\n) -> Result<()>",
        "    display: usize,\n) -> Result<()>",
        "result-bearing exact-owner refresh FFI",
    ),
    (
        "io_loop",
        "r_s11ff_refresh_mailbox_has_a_fixed_display_identity_cap",
        "refresh_mailbox_has_no_display_identity_cap",
        "refresh capacity behavior regression",
    ),
    (
        "flutter",
        "r_s11ff_video_refresh_requires_the_current_exact_ui_owner",
        "video_refresh_accepts_a_stale_ui_owner",
        "refresh exact-owner behavior regression",
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
        "plugin_windows_cmake",
        '  "texture_rgba.h"\n',
        '  "texture_rgba.h"\n  "test/texture_rgba_test.cc"\n',
        "test-only Windows source packaging exclusion",
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
        "plugin_macos_c_api",
        "return [texture_rgba markFrameAvaliableRawWithBuffer:buffer",
        "[texture_rgba markFrameAvaliableRawWithBuffer:buffer",
        "macOS C-ABI native admission propagation",
    ),
    ("requirements", '<div class="req"><span class="id">R-S11ex</span>', '<div class="req"><span class="id">R-S11ex-disabled</span>', "normative requirement"),
    ("requirements", '<div class="req"><span class="id">R-S11ey</span>', '<div class="req"><span class="id">R-S11ey-disabled</span>', "software-only normative requirement"),
    ("requirements", '<div class="req"><span class="id">R-S11ez</span>', '<div class="req"><span class="id">R-S11ez-disabled</span>', "native retirement normative requirement"),
    ("requirements", '<div class="req"><span class="id">R-S11fa</span>', '<div class="req"><span class="id">R-S11fa-disabled</span>', "presentation-resume normative requirement"),
    ("requirements", '<div class="req"><span class="id">R-S11fc</span>', '<div class="req"><span class="id">R-S11fc-disabled</span>', "first-image admission normative requirement"),
    ("requirements", '<div class="req"><span class="id">R-S11ff</span>', '<div class="req"><span class="id">R-S11ff-disabled</span>', "viewer refresh admission normative requirement"),
    ("requirements", '<div class="req"><span class="id">R-S11fm</span>', '<div class="req"><span class="id">R-S11fm-disabled</span>', "texture activation normative requirement"),
    ("requirements", "<tr><td>306</td>", "<tr><td>306-disabled</td>", "Appendix disposition"),
    ("requirements", "<tr><td>307</td>", "<tr><td>307-disabled</td>", "software-only Appendix disposition"),
    ("requirements", "<tr><td>308</td>", "<tr><td>308-disabled</td>", "native retirement Appendix disposition"),
    ("requirements", "<tr><td>309</td>", "<tr><td>309-disabled</td>", "presentation-resume Appendix disposition"),
    ("requirements", "<tr><td>311</td>", "<tr><td>311-disabled</td>", "first-image admission Appendix disposition"),
    ("requirements", "<tr><td>314</td>", "<tr><td>314-disabled</td>", "viewer refresh admission Appendix disposition"),
    ("requirements", "<tr><td>321</td>", "<tr><td>321-disabled</td>", "texture activation Appendix disposition"),
    ("hardening", "**R-S11ex/R-S11e-185 exact desktop Flutter texture lifecycle and UI-owner registration", "**R-S11ex-disabled/R-S11e-185 exact desktop Flutter texture lifecycle and UI-owner registration", "hardening ledger"),
    ("hardening", "**R-S11ey/R-S11e-186 software-RGBA-only desktop presentation", "**R-S11ey-disabled/R-S11e-186 software-RGBA-only desktop presentation", "software-only hardening ledger"),
    ("hardening", "**R-S11ez/R-S11e-187 pending desktop frame retirement finality", "**R-S11ez-disabled/R-S11e-187 pending desktop frame retirement finality", "native retirement hardening ledger"),
    ("hardening", "**R-S11fa/R-S11e-188 exact viewer presentation-resume recovery", "**R-S11fa-disabled/R-S11e-188 exact viewer presentation-resume recovery", "presentation-resume hardening ledger"),
    ("hardening", "**R-S11fc/R-S11e-190 exact desktop first-image admission", "**R-S11fc-disabled/R-S11e-190 exact desktop first-image admission", "first-image admission hardening ledger"),
    ("hardening", "**R-S11ff/R-S11e-193 exact viewer refresh admission", "**R-S11ff-disabled/R-S11e-193 exact viewer refresh admission", "viewer refresh admission hardening ledger"),
    ("hardening", "**R-S11fm/R-S11e-200 desktop texture activation finality", "**R-S11fm-disabled/R-S11e-200 desktop texture activation finality", "texture activation hardening ledger"),
    ("verify", "cargo test --lib --features linux-pkg-config,flutter r_s11fc_ --color never", "true # first-image admission behavior gate disabled", "shared first-image admission behavior gate"),
    ("verify", "cargo test --lib --features linux-pkg-config,flutter r_s11ff_ --color never", "true # viewer refresh admission behavior gate disabled", "shared viewer refresh admission behavior gate"),
    ("dart_verify", "flutter::mobile_session_lifecycle_tests::r_s11ff_video_refresh_requires_the_current_exact_ui_owner", "flutter::mobile_session_lifecycle_tests::viewer_refresh_disabled", "fresh-bridge viewer refresh behavior gate"),
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
