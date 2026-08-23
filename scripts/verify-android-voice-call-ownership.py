#!/usr/bin/env python3
"""Verify Android's exact controlled-capture and process-wide voice recorder owners."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Dict, Tuple


class VerificationError(RuntimeError):
    pass


def require(source: str, needle: str, label: str) -> None:
    if needle not in source:
        raise VerificationError(f"missing {label}")


def forbid(source: str, needle: str, label: str) -> None:
    if needle in source:
        raise VerificationError(f"forbidden {label}")


def require_count(source: str, needle: str, count: int, label: str) -> None:
    actual = source.count(needle)
    if actual != count:
        raise VerificationError(f"{label}: expected {count}, found {actual}")


def require_order(source: str, needles: Tuple[str, ...], label: str) -> None:
    position = -1
    for needle in needles:
        position = source.find(needle, position + 1)
        if position < 0:
            raise VerificationError(f"{label}: missing or misordered {needle!r}")


def extract_item(source: str, signature: str, label: str) -> str:
    start = source.find(signature)
    if start < 0:
        raise VerificationError(f"missing {label}")
    if signature.rstrip().endswith("{"):
        open_brace = start + signature.rfind("{")
    else:
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
    android = repo / "flutter/android/app/src/main/kotlin/com/carriez/flutter_hbb"
    return {
        "owners": (android / "VoiceCallOwnerState.kt").read_text(encoding="utf-8"),
        "coordinator": (android / "VoiceCallAudioCoordinator.kt").read_text(encoding="utf-8"),
        "audio": (android / "AudioRecordHandle.kt").read_text(encoding="utf-8"),
        "activity": (android / "MainActivity.kt").read_text(encoding="utf-8"),
        "service": (android / "MainService.kt").read_text(encoding="utf-8"),
        "connection_type": (android / "ControlledConnectionType.kt").read_text(
            encoding="utf-8"
        ),
        "capture_owners": (android / "ControlledCaptureOwnerState.kt").read_text(
            encoding="utf-8"
        ),
        "input_owner": (android / "ControlledInputOwner.kt").read_text(
            encoding="utf-8"
        ),
        "input_queue": (android / "ExactOwnerBoundedQueue.kt").read_text(
            encoding="utf-8"
        ),
        "input_service": (android / "InputService.kt").read_text(
            encoding="utf-8"
        ),
        "ffi_kt": (repo / "flutter/android/app/src/main/kotlin/ffi.kt").read_text(
            encoding="utf-8"
        ),
        "android_ffi": (repo / "libs/scrap/src/android/ffi.rs").read_text(
            encoding="utf-8"
        ),
        "direct_service": (repo / "src/direct_service.rs").read_text(encoding="utf-8"),
        "server_connection": (repo / "src/server/connection.rs").read_text(
            encoding="utf-8"
        ),
        "server_service": (repo / "src/server/service.rs").read_text(encoding="utf-8"),
        "video_service": (repo / "src/server/video_service.rs").read_text(
            encoding="utf-8"
        ),
        "transport_tcp": (repo / "libs/hbb_common/src/tcp.rs").read_text(
            encoding="utf-8"
        ),
        "transport_stream": (repo / "libs/hbb_common/src/stream.rs").read_text(
            encoding="utf-8"
        ),
        "hbb_common_lib": (repo / "libs/hbb_common/src/lib.rs").read_text(
            encoding="utf-8"
        ),
        "message_proto": (repo / "libs/hbb_common/protos/message.proto").read_text(
            encoding="utf-8"
        ),
        "peer_text": (repo / "src/peer_text.rs").read_text(encoding="utf-8"),
        "flutter_ffi": (repo / "src/flutter_ffi.rs").read_text(encoding="utf-8"),
        "ui_cm": (repo / "src/ui_cm_interface.rs").read_text(encoding="utf-8"),
        "flutter": (repo / "src/flutter.rs").read_text(encoding="utf-8"),
        "dart_main": (repo / "flutter/lib/main.dart").read_text(encoding="utf-8"),
        "dart_model": (repo / "flutter/lib/models/model.dart").read_text(
            encoding="utf-8"
        ),
        "dart_mobile_start_queue": (
            repo / "flutter/lib/models/mobile_session_start_queue.dart"
        ).read_text(encoding="utf-8"),
        "dart_stream_finality": (
            repo / "flutter/lib/models/session_stream_finality.dart"
        ).read_text(encoding="utf-8"),
        "dart_file_model": (
            repo / "flutter/lib/models/file_model.dart"
        ).read_text(encoding="utf-8"),
        "dart_input_model": (
            repo / "flutter/lib/models/input_model.dart"
        ).read_text(encoding="utf-8"),
        "dart_chat_model": (
            repo / "flutter/lib/models/chat_model.dart"
        ).read_text(encoding="utf-8"),
        "dart_relative_mouse": (
            repo / "flutter/lib/models/relative_mouse_model.dart"
        ).read_text(encoding="utf-8"),
        "dart_event_loop": (
            repo / "flutter/lib/utils/event_loop.dart"
        ).read_text(encoding="utf-8"),
        "mobile_remote": (
            repo / "flutter/lib/mobile/pages/remote_page.dart"
        ).read_text(encoding="utf-8"),
        "mobile_camera": (
            repo / "flutter/lib/mobile/pages/view_camera_page.dart"
        ).read_text(encoding="utf-8"),
        "mobile_files": (
            repo / "flutter/lib/mobile/pages/file_manager_page.dart"
        ).read_text(encoding="utf-8"),
        "web_bridge": (repo / "flutter/lib/web/bridge.dart").read_text(
            encoding="utf-8"
        ),
        "mobile_file_lifecycle_test": (
            repo / "flutter/test/mobile_file_session_lifecycle_test.dart"
        ).read_text(encoding="utf-8"),
        "mobile_start_queue_test": (
            repo / "flutter/test/mobile_session_start_queue_test.dart"
        ).read_text(encoding="utf-8"),
        "stream_finality_test": (
            repo / "flutter/test/session_stream_finality_test.dart"
        ).read_text(encoding="utf-8"),
        "client": (repo / "src/client.rs").read_text(encoding="utf-8"),
        "screenshot": (repo / "src/client/screenshot.rs").read_text(
            encoding="utf-8"
        ),
        "io_loop": (repo / "src/client/io_loop.rs").read_text(encoding="utf-8"),
        "ui_session": (repo / "src/ui_session_interface.rs").read_text(
            encoding="utf-8"
        ),
        "test": (repo / "scripts/android-voice-call-owner-state-test.kt").read_text(
            encoding="utf-8"
        ),
        "connection_type_test": (
            repo / "scripts/android-controlled-connection-type-test.kt"
        ).read_text(encoding="utf-8"),
        "input_owner_test": (
            repo / "scripts/android-controlled-input-owner-test.kt"
        ).read_text(encoding="utf-8"),
        "requirements": (repo / "requirements.html").read_text(encoding="utf-8"),
        "hardening": (repo / "HARDENING_STATUS.md").read_text(encoding="utf-8"),
        "verify": (repo / "scripts/verify.sh").read_text(encoding="utf-8"),
        "dart_verify": (repo / "scripts/dart-verify.sh").read_text(encoding="utf-8"),
    }


def validate(sources: Dict[str, str]) -> None:
    owners = sources["owners"]
    require(
        owners,
        "internal data class OutgoingVoiceCallOwner(\n    val generation: Long,\n    val sessionId: String,",
        "generation-and-session-bound outgoing owner",
    )
    require(
        owners,
        "fun isValid(): Boolean = generation > 0 && sessionId.isNotEmpty()",
        "outgoing owner validity predicate",
    )
    state = extract_item(owners, "internal class VoiceCallOwnerState", "voice-call owner state")
    for needle, label in (
        ("private val controlledConnections = mutableSetOf<Int>()", "registered controlled-owner set"),
        ("private val activeControlledConnections = mutableSetOf<Int>()", "active controlled-owner set"),
        (
            "private var greatestControlledServiceGeneration = 0L",
            "monotonic controlled-service generation",
        ),
        (
            "private var activeControlledServiceGeneration: Long? = null",
            "exact active controlled-service generation",
        ),
        ("private var outgoingOwner: OutgoingVoiceCallOwner? = null", "outgoing exact owner"),
        ("private var outgoingVoiceCallActive = false", "outgoing activity state"),
        (
            "get() = activeControlledConnections.isNotEmpty() || outgoingVoiceCallActive",
            "aggregate voice-capture demand",
        ),
    ):
        require(state, needle, label)

    begin_controlled = extract_item(
        state,
        "fun beginControlledServiceGeneration",
        "controlled-service generation admission",
    )
    require_order(
        begin_controlled,
        (
            "generation <= 0",
            "generation < greatestControlledServiceGeneration",
            "generation == greatestControlledServiceGeneration",
            "activeControlledServiceGeneration != generation",
            "return false",
            "if (activeControlledServiceGeneration == generation)",
            "return true",
            "greatestControlledServiceGeneration = generation",
            "activeControlledServiceGeneration = generation",
            "controlledConnections.clear()",
            "activeControlledConnections.clear()",
        ),
        "positive monotonic idempotent controlled-service generation admission",
    )
    forbid(
        begin_controlled,
        "outgoingOwner",
        "controlled-service generation replacement mutates outgoing ownership",
    )
    forbid(
        begin_controlled,
        "outgoingVoiceCallActive",
        "controlled-service generation replacement mutates outgoing activity",
    )
    is_controlled_generation = extract_item(
        state,
        "fun isControlledServiceGeneration",
        "controlled-service generation identity",
    )
    require(
        is_controlled_generation,
        "generation > 0 && activeControlledServiceGeneration == generation",
        "positive exact controlled-service generation identity",
    )
    register_controlled = extract_item(
        state, "fun registerControlledConnection", "controlled-owner registration"
    )
    require_order(
        register_controlled,
        (
            "if (!isControlledServiceGeneration(generation) || connectionId <= 0)",
            "return false",
            "controlledConnections.add(connectionId)",
        ),
        "generation-bound positive exact controlled-owner registration",
    )
    set_controlled = extract_item(
        state, "fun setControlledVoiceCallActive", "controlled-owner state update"
    )
    require_order(
        set_controlled,
        (
            "if (!isControlledServiceGeneration(generation)",
            "!controlledConnections.contains(connectionId)",
            "return false",
            "if (active)",
            "activeControlledConnections.add(connectionId)",
            "activeControlledConnections.remove(connectionId)",
        ),
        "generation-and-registration-bound exact controlled-owner update",
    )
    unregister_controlled = extract_item(
        state, "fun unregisterControlledConnection", "controlled-owner retirement"
    )
    require_order(
        unregister_controlled,
        (
            "if (!isControlledServiceGeneration(generation) || connectionId <= 0)",
            "return false",
            "controlledConnections.remove(connectionId)",
            "activeControlledConnections.remove(connectionId)",
        ),
        "generation-bound controlled-owner registration-and-activity retirement",
    )
    clear_controlled = extract_item(
        state, "fun clearControlledConnections", "controlled-owner service teardown"
    )
    require_order(
        clear_controlled,
        (
            "if (!isControlledServiceGeneration(generation))",
            "return false",
            "controlledConnections.clear()",
            "activeControlledConnections.clear()",
            "activeControlledServiceGeneration = null",
            "return true",
        ),
        "exact-generation complete controlled-owner teardown",
    )

    register_outgoing = extract_item(
        state, "fun registerOutgoingOwner", "outgoing-owner registration"
    )
    require_order(
        register_outgoing,
        (
            "if (!owner.isValid())",
            "return false",
            "val current = outgoingOwner",
            "if (current != null && current != owner)",
            "return false",
            "outgoingOwner = owner",
        ),
        "single exact outgoing-owner registration",
    )
    resume_outgoing = extract_item(state, "fun resumeOutgoingOwner", "outgoing-owner resume")
    require_order(
        resume_outgoing,
        (
            "if (!previous.isValid()",
            "!replacement.isValid()",
            "replacement.sessionId != previous.sessionId",
            "replacement.generation < previous.generation",
            "return false",
            "val current = outgoingOwner",
            "if (current == replacement)",
            "return true",
            "if (current != previous)",
            "return false",
            "outgoingOwner = replacement",
        ),
        "same-session nondecreasing idempotent outgoing-owner transfer",
    )
    forbid(
        resume_outgoing,
        "outgoingVoiceCallActive = false",
        "resume-time voice state loss",
    )
    set_outgoing = extract_item(
        state, "fun setOutgoingVoiceCallActive", "outgoing-owner state update"
    )
    require_order(
        set_outgoing,
        ("if (outgoingOwner != owner)", "return false", "outgoingVoiceCallActive = active"),
        "exact outgoing-owner update",
    )
    unregister_outgoing = extract_item(
        state, "fun unregisterOutgoingOwner", "outgoing-owner retirement"
    )
    require_order(
        unregister_outgoing,
        (
            "if (outgoingOwner != owner)",
            "return false",
            "outgoingOwner = null",
            "outgoingVoiceCallActive = false",
        ),
        "exact outgoing-owner retirement",
    )
    invalidate_outgoing = extract_item(
        state, "fun invalidateOutgoingOwner", "outgoing-owner isolate invalidation"
    )
    require_order(
        invalidate_outgoing,
        ("outgoingOwner = null", "outgoingVoiceCallActive = false"),
        "complete outgoing-owner invalidation",
    )

    coordinator = sources["coordinator"]
    require(coordinator, "internal object VoiceCallAudioCoordinator", "process-wide coordinator")
    require(coordinator, "private val owners = VoiceCallOwnerState()", "single owner state")
    require(
        coordinator,
        "private var playbackProjection: Pair<Long, MediaProjection>? = null",
        "generation-bound playback owner",
    )
    all_android = "\n".join(
        sources[key] for key in ("owners", "coordinator", "audio", "activity", "service")
    )
    require_count(all_android, "= AudioRecordHandle(", 1, "single Android AudioRecord construction")
    require(
        coordinator,
        "audioRecordHandle = AudioRecordHandle(context.applicationContext)",
        "application-context recorder construction",
    )
    for function in (
        "initialize",
        "beginControlledServiceGeneration",
        "registerControlledConnection",
        "setControlledVoiceCallActive",
        "unregisterControlledConnection",
        "clearControlledConnections",
        "invalidateOutgoingOwner",
        "registerOutgoingOwner",
        "resumeOutgoingOwner",
        "setOutgoingVoiceCallActive",
        "unregisterOutgoingOwner",
        "setPlaybackCaptureProjection",
    ):
        require(
            coordinator,
            f"@Synchronized\n    fun {function}",
            f"serialized coordinator entry {function}",
        )
    coordinator_begin = extract_item(
        coordinator,
        "fun beginControlledServiceGeneration",
        "coordinator controlled-service generation admission",
    )
    require_order(
        coordinator_begin,
        (
            "val alreadyCurrent = owners.isControlledServiceGeneration(generation)",
            "if (!owners.beginControlledServiceGeneration(generation))",
            "return false",
            "if (!alreadyCurrent)",
            "playbackProjection = null",
            "return reconcileRecorder()",
        ),
        "serialized replacement-only playback retirement",
    )
    coordinator_register = extract_item(
        coordinator,
        "fun registerControlledConnection",
        "coordinator controlled-owner registration",
    )
    require(
        coordinator_register,
        "owners.registerControlledConnection(generation, connectionId)",
        "coordinator exact-generation registration",
    )
    coordinator_set = extract_item(
        coordinator,
        "fun setControlledVoiceCallActive",
        "coordinator controlled-owner update",
    )
    require(
        coordinator_set,
        "owners.setControlledVoiceCallActive(generation, connectionId, active)",
        "coordinator exact-generation update",
    )
    coordinator_unregister = extract_item(
        coordinator,
        "fun unregisterControlledConnection",
        "coordinator controlled-owner retirement",
    )
    require(
        coordinator_unregister,
        "owners.unregisterControlledConnection(generation, connectionId)",
        "coordinator exact-generation retirement",
    )
    coordinator_clear = extract_item(
        coordinator,
        "fun clearControlledConnections",
        "coordinator controlled-service teardown",
    )
    require_order(
        coordinator_clear,
        (
            "if (!owners.clearControlledConnections(generation))",
            "return false",
            "if (playbackProjection?.first == generation)",
            "playbackProjection = null",
            "return reconcileRecorder()",
        ),
        "coordinator exact-generation teardown",
    )
    coordinator_projection = extract_item(
        coordinator,
        "fun setPlaybackCaptureProjection",
        "coordinator playback projection update",
    )
    require_order(
        coordinator_projection,
        (
            "if (!owners.isControlledServiceGeneration(generation))",
            "return false",
            "playbackProjection = projection?.let { generation to it }",
            "return reconcileRecorder()",
        ),
        "coordinator exact-generation playback update",
    )
    reconcile = extract_item(coordinator, "private fun reconcileRecorder", "recorder reconciliation")
    require_order(
        reconcile,
        (
            "if (owners.requiresVoiceCapture)",
            "return recorder.switchToVoiceCall()",
            "val projection = playbackProjection?.second",
            "if (projection != null)",
            "return recorder.switchToPlaybackCapture(projection)",
            "recorder.stopCapture()",
        ),
        "voice-over-playback-over-stopped recorder priority",
    )
    for function in (
        "beginControlledServiceGeneration",
        "setControlledVoiceCallActive",
        "unregisterControlledConnection",
        "clearControlledConnections",
        "invalidateOutgoingOwner",
        "setOutgoingVoiceCallActive",
        "unregisterOutgoingOwner",
        "setPlaybackCaptureProjection",
    ):
        body = extract_item(coordinator, f"fun {function}", f"coordinator {function}")
        require(body, "reconcileRecorder()", f"{function} recorder reconciliation")

    audio = sources["audio"]
    require(audio, "internal class AudioRecordHandle(private val context: Context)", "one-context recorder")
    require(audio, "private enum class AudioCaptureMode", "closed recorder-mode type")
    require(audio, "private var captureProjection: MediaProjection? = null", "exact playback projection")
    create = extract_item(audio, "private fun createAudioRecorder", "audio-recorder creation")
    for needle, label in (
        ("Build.VERSION.SDK_INT < Build.VERSION_CODES.Q", "platform floor"),
        ("Manifest.permission.RECORD_AUDIO", "record permission"),
        ("MediaRecorder.AudioSource.VOICE_COMMUNICATION", "voice source"),
        ("AudioPlaybackCaptureConfiguration.Builder(projection)", "playback projection"),
        ("recorder.state != AudioRecord.STATE_INITIALIZED", "initialized-state proof"),
        ("recorder.release()", "uninitialized recorder release"),
        (
            "captureProjection = if (mode == AudioCaptureMode.PLAYBACK) mediaProjection else null",
            "created projection identity",
        ),
    ):
        require(create, needle, f"audio creation {label}")
    reader = extract_item(audio, "private fun checkAudioReader", "audio-reader allocation")
    require_order(
        reader,
        (
            "AudioRecord.getMinBufferSize(",
            "if (platformMinBufferSize <= 0)",
            "platformMinBufferSize.toLong() * 2L * 4L",
            "if (requestedBufferSize > Int.MAX_VALUE)",
            "AudioReader(minBufferSize, 4)",
            "catch (e: OutOfMemoryError)",
            "minBufferSize = 0",
        ),
        "bounded fail-closed audio-reader allocation",
    )
    start = extract_item(audio, "private fun startAudioRecorder", "audio-recorder start")
    require_order(
        start,
        (
            "if (!checkAudioReader())",
            "stopAudioRecorder()",
            "FFI.setAudioFrameRawEnable(true)",
            "recorder.startRecording()",
            "recorder.recordingState != AudioRecord.RECORDSTATE_RECORDING",
            "audioRecordStat = true",
            "captureMode = mode",
            "thread(\n                start = false",
            "reader.readSync(recorder) ?: break",
            "audioThread = worker",
            "worker.start()",
        ),
        "transactional recorder start and owned worker publication",
    )
    require_order(
        start,
        (
            "finally",
            "recorder.recordingState == AudioRecord.RECORDSTATE_RECORDING",
            "recorder.stop()",
            "recorder.release()",
            "if (audioRecorder === recorder)",
            "audioRecordStat = false",
            "audioRecorder = null",
            "audioReader = null",
            "minBufferSize = 0",
            "captureMode = AudioCaptureMode.STOPPED",
            "captureProjection = null",
            "FFI.setAudioFrameRawEnable(false)",
        ),
        "spontaneous worker exact cleanup",
    )
    stop = extract_item(audio, "private fun stopAudioRecorder", "audio-recorder stop")
    require_order(
        stop,
        (
            "audioRecordStat = false",
            "if (recorder.recordingState == AudioRecord.RECORDSTATE_RECORDING)",
            "recorder.stop()",
            "while (worker.isAlive)",
            "worker.join()",
            "Thread.currentThread().interrupt()",
            "if (audioThread === worker)",
            "audioThread = null",
            "if ((worker == null || !worker.isAlive)",
            "recorder.release()",
            "captureMode = AudioCaptureMode.STOPPED",
            "captureProjection = null",
            "FFI.setAudioFrameRawEnable(false)",
        ),
        "stop-unblock-join-release ownership",
    )
    playback = extract_item(audio, "fun switchToPlaybackCapture", "playback capture switch")
    require_order(
        playback,
        (
            "captureMode == AudioCaptureMode.PLAYBACK",
            "captureProjection === mediaProjection",
            "recorder?.recordingState == AudioRecord.RECORDSTATE_RECORDING",
            "stopAudioRecorder()",
            "createAudioRecorder(AudioCaptureMode.PLAYBACK, mediaProjection)",
            "startAudioRecorder(AudioCaptureMode.PLAYBACK)",
        ),
        "exact-projection playback reuse",
    )
    for legacy in (
        "isVideoStart",
        "isAudioStart",
        "onVoiceCallStarted",
        "onVoiceCallClosed",
        "switchOutVoiceCall",
        "tryReleaseAudio",
    ):
        forbid(audio, legacy, f"legacy recorder ownership callback {legacy}")

    capture_owners = extract_item(
        sources["capture_owners"],
        "internal class ControlledCaptureOwnerState",
        "controlled capture-owner state",
    )
    for needle, label in (
        ("private val owners = mutableSetOf<Int>()", "exact capture-owner set"),
        ("get() = owners.isNotEmpty()", "aggregate capture demand"),
    ):
        require(capture_owners, needle, label)
    require_count(
        capture_owners,
        "owners.remove(connectionId)",
        2,
        "both exact capture-owner retirement paths",
    )
    capture_upsert = extract_item(
        capture_owners, "fun upsert(", "controlled capture-owner upsert"
    )
    require_order(
        capture_upsert,
        (
            "if (connectionId <= 0)",
            "return false",
            "if (authorized && connectionType.requiresDesktopCapture)",
            "owners.add(connectionId)",
            "owners.remove(connectionId)",
        ),
        "authorized exact-type capture-owner admission",
    )
    capture_unregister = extract_item(
        capture_owners, "fun unregister(", "controlled capture-owner retirement"
    )
    require_order(
        capture_unregister,
        ("if (connectionId <= 0)", "return false", "owners.remove(connectionId)"),
        "exact capture-owner retirement",
    )
    require(
        extract_item(capture_owners, "fun clear()", "capture-owner teardown"),
        "owners.clear()",
        "complete capture-owner teardown",
    )

    service = sources["service"]
    require(
        service,
        "@Keep\n    @Synchronized\n    fun rustSetByName",
        "serialized controlled-resource dispatch",
    )
    add_connection = extract_item(service, '"add_connection" ->', "controlled connection admission")
    require_order(
        add_connection,
        (
            "if (!acceptingControlledConnections)",
            "return",
            'jsonObject.getJSONObject("conn_type").getString("t")',
            "if (connectionType == null)",
            "return",
            "controlledCaptureOwners.upsert(id, authorized, connectionType)",
            "if (connectionType.allowsVoiceCall",
            "VoiceCallAudioCoordinator.registerControlledConnection(",
            "nativeServerGeneration",
            "id",
            "reconcileControlledCaptureDemand()",
        ),
        "serialized generation-and-AuthConnType-bound controlled-resource admission",
    )
    for legacy in (
        'jsonObject["is_file_transfer"]',
        'jsonObject["is_view_camera"]',
        'jsonObject["is_terminal"]',
        'jsonObject["port_forward"]',
        "val canUseVoiceCall",
    ):
        forbid(add_connection, legacy, f"reconstructed controlled connection type {legacy}")
    connection_type = extract_item(
        sources["connection_type"],
        "internal enum class ControlledConnectionType",
        "controlled connection type",
    )
    for wire_tag, enum_value in (
        ("Remote", "REMOTE"),
        ("FileTransfer", "FILE_TRANSFER"),
        ("ViewCamera", "VIEW_CAMERA"),
        ("Terminal", "TERMINAL"),
        ("PortForward", "PORT_FORWARD"),
    ):
        require(
            connection_type,
            f'"{wire_tag}" -> {enum_value}',
            f"exact {wire_tag} connection-type decoding",
        )
    require(
        connection_type,
        "get() = this == REMOTE || this == VIEW_CAMERA",
        "Remote-or-ViewCamera voice-call authority",
    )
    require(connection_type, "else -> null", "unknown connection-type refusal")
    connection_type_test = sources["connection_type_test"]
    for needle, label in (
        ('"Remote" to ControlledConnectionType.REMOTE', "Remote behavior fixture"),
        (
            '"PortForward" to ControlledConnectionType.PORT_FORWARD',
            "PortForward behavior fixture",
        ),
        ('"remote", "REMOTE", "Portforward", "Unknown"', "noncanonical refusal fixtures"),
        (
            "connectionType.allowsVoiceCall ==",
            "complete voice-call authority behavior assertion",
        ),
    ):
        require(connection_type_test, needle, label)
    remove_connection = extract_item(service, '"remove_connection" ->', "controlled connection removal")
    require_order(
        remove_connection,
        (
            "val id = arg1.toIntOrNull()",
            "controlledCaptureOwners.unregister(id)",
            "VoiceCallAudioCoordinator.unregisterControlledConnection(",
            "nativeServerGeneration",
            "id",
            "reconcileControlledCaptureDemand()",
            "cancelNotification(id)",
        ),
        "serialized exact-generation controlled-resource removal",
    )
    reconcile_capture = extract_item(
        service,
        "private fun reconcileControlledCaptureDemand",
        "controlled capture-demand reconciliation",
    )
    require_order(
        reconcile_capture,
        (
            "captureRequested = controlledCaptureOwners.requiresDesktopCapture",
            "if (captureRequested)",
            "startCapture()",
            "stopCapturePipeline()",
        ),
        "owner-set-derived capture reconciliation",
    )
    update_voice = extract_item(service, '"update_voice_call_state" ->', "controlled voice update")
    require_order(
        update_voice,
        (
            'val id = jsonObject["id"] as Int',
            'val inVoiceCall = jsonObject["in_voice_call"] as Boolean',
            "VoiceCallAudioCoordinator.setControlledVoiceCallActive(",
            "nativeServerGeneration",
            "id",
            "inVoiceCall",
        ),
        "service-generation-and-connection-ID-bound controlled voice update",
    )
    forbid(service, "AudioRecordHandle(", "service-local recorder")
    forbid(service, "fun onVoiceCallStarted", "service binding-time voice start")
    forbid(service, "fun onVoiceCallClosed", "service binding-time voice close")
    service_destroy = extract_item(service, "override fun onDestroy()", "service teardown")
    require_order(
        service_destroy,
        (
            "releaseControlledConnectionResources()",
            "FFI.stopServer(nativeServerGeneration)",
            "FFI.releaseService(this)",
            "super.onDestroy()",
        ),
        "service resource-and-callback-owner teardown",
    )
    service_create = extract_item(service, "override fun onCreate()", "service creation")
    require_order(
        service_create,
        (
            "FFI.init(this, applicationContext)",
            'nativeServerGeneration = FFI.startServer(this, configPath, "")',
            "if (nativeServerGeneration <= 0L)",
            "VoiceCallAudioCoordinator.beginControlledServiceGeneration(",
            "nativeServerGeneration",
            "acceptingControlledConnections = true",
        ),
        "closed-until-bound exact MainService generation ownership",
    )
    require(
        service,
        "private var acceptingControlledConnections = false",
        "closed-by-default controlled-resource admission",
    )
    require_count(
        service,
        "acceptingControlledConnections = true",
        1,
        "single post-generation controlled-resource admission",
    )
    resource_teardown = extract_item(
        service,
        "private fun releaseControlledConnectionResources",
        "controlled resource teardown",
    )
    require_order(
        resource_teardown,
        (
            "acceptingControlledConnections = false",
            "controlledCaptureOwners.clear()",
            "releaseCaptureResources()",
            "VoiceCallAudioCoordinator.clearControlledConnections(nativeServerGeneration)",
        ),
        "closed-admission exact-generation controlled resource teardown",
    )
    forbid(service, '"stop_capture"', "detached global capture-stop dispatch")
    task_removed = extract_item(service, "override fun onTaskRemoved", "task-removal teardown")
    require_order(
        task_removed,
        (
            "MainActivity.takeStoppedClientSessionOwners()",
            "VoiceCallAudioCoordinator.unregisterOutgoingOwner(owner.toVoiceCallOwner())",
            "FFI.retireClientSessions(owner.generation, owner.sessionId)",
        ),
        "task-removal native-before-Rust exact-owner retirement",
    )
    require(
        service,
        "VoiceCallAudioCoordinator.setPlaybackCaptureProjection(\n"
        "                        nativeServerGeneration,\n"
        "                        projection,",
        "generation-bound screen-start playback demand",
    )
    require(
        service,
        "VoiceCallAudioCoordinator.setPlaybackCaptureProjection(\n"
        "                nativeServerGeneration,\n"
        "                null,",
        "generation-bound screen-stop playback retirement",
    )

    activity = sources["activity"]
    require(
        activity,
        "internal data class ClientSessionOwner(val generation: Long, val sessionId: String)",
        "module-internal Activity session owner",
    )
    require(
        activity,
        "internal fun takeStoppedClientSessionOwners(): List<ClientSessionOwner>",
        "module-internal stopped-owner transfer",
    )
    require(
        activity,
        "fun toVoiceCallOwner() = OutgoingVoiceCallOwner(generation, sessionId)",
        "Activity-to-recorder owner conversion",
    )
    configure = extract_item(activity, "override fun configureFlutterEngine", "Activity engine configuration")
    require_order(
        configure,
        (
            "VoiceCallAudioCoordinator.initialize(applicationContext)",
            "super.configureFlutterEngine(flutterEngine)",
            "initFlutterChannel(channel)",
        ),
        "coordinator-before-Dart-channel initialization",
    )
    on_create = extract_item(activity, "override fun onCreate", "Activity creation")
    require_order(
        on_create,
        (
            "VoiceCallAudioCoordinator.invalidateOutgoingOwner()",
            "clientSessionOwnerGeneration = FFI.beginClientSessionOwner()",
            "super.onCreate(savedInstanceState)",
        ),
        "previous-isolate invalidation before engine startup",
    )
    registration = extract_item(
        activity, '"register_client_session_owner" ->', "Activity owner registration"
    )
    require_order(
        registration,
        (
            "FFI.registerClientSessionOwner(clientSessionOwnerGeneration, canonicalSessionId)",
            "val owner = ClientSessionOwner(clientSessionOwnerGeneration, canonicalSessionId)",
            "VoiceCallAudioCoordinator.registerOutgoingOwner(owner.toVoiceCallOwner())",
            "FFI.retireClientSessions(owner.generation, owner.sessionId)",
            "clientSessionOwner = owner",
        ),
        "Rust-then-native outgoing-owner admission with rollback",
    )
    require(
        activity,
        '"on_voice_call_started" -> {\n                    result.success(setOutgoingVoiceCallActive(true))',
        "completed outgoing voice-start platform result",
    )
    require(
        activity,
        '"on_voice_call_closed" -> {\n                    result.success(setOutgoingVoiceCallActive(false))',
        "completed outgoing voice-close platform result",
    )
    outgoing_update = extract_item(
        activity, "private fun setOutgoingVoiceCallActive", "outgoing voice update"
    )
    require_order(
        outgoing_update,
        (
            "val owner = clientSessionOwner",
            "if (owner == null)",
            "return false",
            "VoiceCallAudioCoordinator.setOutgoingVoiceCallActive(",
            "owner.toVoiceCallOwner()",
        ),
        "current exact Activity owner voice update",
    )
    activity_destroy = extract_item(activity, "override fun onDestroy()", "Activity teardown")
    require_order(
        activity_destroy,
        (
            "forgetClientSessionOwner(owner)",
            "VoiceCallAudioCoordinator.unregisterOutgoingOwner(owner.toVoiceCallOwner())",
            "FFI.retireClientSessions(owner.generation, owner.sessionId)",
        ),
        "Activity native-before-Rust exact-owner retirement",
    )
    on_start = extract_item(activity, "override fun onStart()", "Activity resume")
    require_order(
        on_start,
        (
            "FFI.resumeClientSessionOwner(owner.generation, owner.sessionId)",
            "if (resumedGeneration == 0L)",
            "val retiredRejectedOwner =",
            "VoiceCallAudioCoordinator.unregisterOutgoingOwner(owner.toVoiceCallOwner())",
            "forgetClientSessionOwner(owner)",
            "val resumedOwner = ClientSessionOwner(resumedGeneration, owner.sessionId)",
            "VoiceCallAudioCoordinator.resumeOutgoingOwner(",
            "owner.toVoiceCallOwner()",
            "resumedOwner.toVoiceCallOwner()",
            "val retiredUnreconciledOwner =",
            "VoiceCallAudioCoordinator.unregisterOutgoingOwner(owner.toVoiceCallOwner())",
            "val retiredUnreconciledSessions =",
            "FFI.retireClientSessions(owner.generation, owner.sessionId)",
            "clientSessionOwner = resumedOwner",
        ),
        "same-isolate Rust-and-recorder Activity resume with exact failure cleanup",
    )
    require(
        activity,
        "onServiceDisconnected(name: ComponentName?) {\n            Log.d(logTag, \"onServiceDisconnected\")\n            mainService = null\n            isServiceBound = false",
        "service-disconnect binding-state reset",
    )
    forbid(activity, "AudioRecordHandle(", "Activity-local recorder")
    forbid(activity, "mainService?.let {\n            ok = it.onVoiceCall", "binding-dependent voice ownership")

    flutter = sources["flutter"]
    android_owner_state = extract_item(
        flutter, "impl AndroidClientOwnerState", "Rust Android Activity owner state"
    )
    rust_resume = extract_item(
        android_owner_state, "fn resume(", "Rust Android Activity owner resume"
    )
    require(
        rust_resume,
        "fn resume(&self, generation: u64, session_id: SessionID) -> Option<u64>",
        "read-only Rust Activity resume",
    )
    require_order(
        rust_resume,
        (
            "generation == 0",
            "generation > self.generation",
            "self.session_id.as_ref() != Some(&session_id)",
            "return None",
            "Some(self.generation)",
        ),
        "Rust same-isolate non-future Activity resume",
    )
    forbid(rust_resume, "self.begin()", "Rust cross-isolate Activity takeover")
    forbid(rust_resume, "self.session_id = Some(session_id)", "Rust resume-time owner replacement")
    rust_resume_entry = extract_item(
        flutter, "pub fn resume_android_client_owner", "Rust Android Activity resume entry"
    )
    require_order(
        rust_resume_entry,
        (
            "ANDROID_CLIENT_OWNER",
            ".read()",
            ".resume(generation, session_id)",
        ),
        "read-only Rust Activity resume entry",
    )
    forbid(
        rust_resume_entry,
        "close_sessions_owned_by",
        "Rust resume-time replacement-session teardown",
    )
    require(
        flutter,
        "fn stale_android_activity_cannot_reclaim_the_replacement_owner()",
        "Rust stale-Activity replacement-owner regression",
    )
    require(
        flutter,
        "const ANDROID_CLIENT_DRAIN_QUEUE_CAPACITY: usize = 1;",
        "one-slot Android client lifecycle drain",
    )
    require(
        flutter,
        "_worker: std::thread::JoinHandle<()>",
        "retained Android client lifecycle drain worker",
    )
    require(
        flutter,
        "fn android_lifecycle_retirement_is_nonblocking_and_replacement_waits_for_exact_drain()",
        "nonblocking lifecycle and exact replacement-barrier regression",
    )
    require(
        flutter,
        "fn android_lifecycle_transition_does_not_wait_for_mobile_replacement_drain()",
        "nonblocking lifecycle during mobile replacement-drain regression",
    )
    require(
        flutter,
        "resume_android_client_owner(first_generation, first_session_id),\n            None",
        "Rust cross-isolate resume refusal regression",
    )

    session_handler = extract_item(
        flutter, "struct SessionHandler", "Rust outgoing session handler"
    )
    require(
        session_handler,
        "client_owner_id: Option<SessionID>",
        "stored mobile client-owner association",
    )
    session_add_existed = extract_item(
        flutter, "pub fn session_add_existed(", "Rust existing-session attachment"
    )
    require_order(
        session_add_existed,
        (
            "client_owner_id: SessionID",
            "acquire_android_client_owner(&client_owner_id)?",
            "let result = sessions::replace_peer_session_display_owner(",
            "session_id,",
            "client_owner_id,",
            "displays,",
            "drop(owner_admission)",
            "result",
        ),
        "owner-bound atomic existing-session attachment",
    )
    session_add = extract_item(
        flutter, "pub fn session_add(", "Rust outgoing-session insertion"
    )
    require_order(
        session_add,
        (
            "client_owner_id: &SessionID",
            "take_previous_android_mobile_client_sessions(client_owner_id, session_id)?",
            "close_client_owner_drain(previous_mobile_client_sessions)",
            "let owner_admission = acquire_android_client_owner(client_owner_id)?;",
            "sessions::insert_session(",
            "*client_owner_id,",
            "drop(owner_admission)",
        ),
        "owner-admitted replacement drain and insertion",
    )
    replacement_take = extract_item(
        flutter,
        "fn take_previous_android_mobile_client_sessions(",
        "Rust Android prior-mobile removal transaction",
    )
    require_order(
        replacement_take,
        (
            "acquire_android_client_owner(client_owner_id)?",
            "sessions::take_mobile_sessions_except(client_owner_id, session_id)",
            "drop(owner_admission)",
            "Ok(drain)",
        ),
        "Android exact owner removal before unlocked predecessor finality",
    )
    forbid(
        replacement_take,
        "close_client_owner_drain",
        "Android predecessor finality under owner admission",
    )
    forbid(
        replacement_take,
        "close_and_join",
        "Android predecessor join under owner admission",
    )
    session_start = extract_item(
        flutter, "pub fn session_start_(", "Rust outgoing-session start"
    )
    require_order(
        session_start,
        (
            "client_owner_id: &SessionID",
            "acquire_android_client_owner(client_owner_id)?",
            "sessions::session_has_client_owner(session_id, client_owner_id)",
            "let mut thread_lock = s.thread.lock().unwrap();",
            "let mut handlers = s.session_handlers.write().unwrap();",
            "h.client_owner_id.as_ref() != Some(client_owner_id)",
            "match s.start_io_thread_with_lock(&mut thread_lock)",
            "rollback_failed_session_start(session_id, client_owner_id);",
            "drop(owner_admission)",
        ),
        "owner-guarded outgoing worker start and rollback",
    )
    require_count(
        session_start,
        "rollback_failed_session_start(session_id, client_owner_id);",
        2,
        "admission/start and replay exact-owner session-start rollback",
    )
    failed_start_rollback = extract_item(
        flutter,
        "fn rollback_failed_session_start(",
        "exact failed-session-start rollback",
    )
    require_order(
        failed_start_rollback,
        (
            "client_owner_id: &SessionID",
            "remove_failed_start_by_exact_ui_owner(session_id, client_owner_id)",
            "session.close_and_join();",
        ),
        "exact-owner handler removal and worker join after start failure",
    )
    exact_failed_start_removal = extract_item(
        flutter,
        "pub(super) fn remove_failed_start_by_exact_ui_owner(",
        "exact-owner failed-session-start removal",
    )
    require_order(
        exact_failed_start_removal,
        (
            "handlers.get(id)",
            "handler.client_owner_id.as_ref() != Some(client_owner_id)",
            "return None;",
            "if handlers.remove(id).is_none()",
        ),
        "failed-start removal preserves a replacement UI owner",
    )
    forbid(
        failed_start_rollback,
        "close_event_stream",
        "normal-close marker that would hide failed-start stream error",
    )
    require(
        flutter,
        "fn failed_session_start_rolls_back_and_joins_only_the_exact_session()",
        "failed-start exact rollback/join behavior regression",
    )
    take_previous = extract_item(
        flutter,
        "pub(super) fn take_mobile_sessions_except(",
        "Rust exact replacement-session drain",
    )
    require(
        take_previous,
        "handler_session_id != session_id\n"
        "                        || handler.client_owner_id.as_ref() != Some(client_owner_id)",
        "exact owner-and-session preservation predicate",
    )
    require(
        take_previous,
        "check_remove_unused_displays(None, session, &handlers);",
        "replacement drain display reconciliation includes the preserved exact session",
    )
    take_owner = extract_item(
        flutter,
        "pub(super) fn take_sessions_owned_by(",
        "Rust associated Activity-owner drain",
    )
    require(
        take_owner,
        "handler.client_owner_id.as_ref() == Some(client_owner_id)",
        "stored-association Activity-owner selection",
    )
    require(
        take_owner,
        "check_remove_unused_displays(None, session, &handlers);",
        "Activity-owner drain display reconciliation includes every remaining session",
    )
    display_reconciliation = extract_item(
        flutter,
        "fn check_remove_unused_displays(",
        "Rust remaining-display reconciliation",
    )
    require(
        display_reconciliation,
        "excluded_session_id: Option<&SessionID>",
        "explicit optional live-handler exclusion",
    )
    require(
        display_reconciliation,
        "remaining_displays(excluded_session_id, handlers)",
        "optional live-handler exclusion delegated to exact derivation",
    )
    require(
        flutter,
        "fn stale_mobile_session_close_cannot_select_replacement_from_same_owner()",
        "stale-close versus same-owner replacement regression",
    )
    flutter_ffi = sources["flutter_ffi"]
    require(
        flutter_ffi,
        "session_id: SessionID,\n    client_owner_id: SessionID,",
        "authored Rust bridge dual-identity parameters",
    )
    require_count(
        flutter_ffi,
        "client_owner_id: SessionID,",
        9,
        "all authored Rust dual-identity bridge entries",
    )
    require(
        flutter_ffi,
        "static ref MOBILE_SESSION_ADD_TRANSACTION: Mutex<()> = Mutex::new(());",
        "serialized mobile-add transaction owner",
    )
    session_add_mobile = extract_item(
        flutter_ffi, "pub fn session_add_mobile(", "asynchronous mobile session add"
    )
    require_order(
        session_add_mobile,
        (
            'if !cfg!(any(target_os = "android", target_os = "ios"))',
            "MOBILE_SESSION_ADD_TRANSACTION",
            ".lock()",
            "flutter::wait_for_android_client_owner_drain(&client_owner_id)?;",
            "session_add(",
            "&session_id,",
            "&client_owner_id,",
            "Ok(())",
        ),
        "serialized mobile replacement drain and insertion bridge",
    )
    require(
        session_add_mobile,
        ") -> Result<()> {",
        "concrete codegen-compatible mobile-add result",
    )
    forbid(
        session_add_mobile,
        "SyncReturn",
        "synchronous mobile session-add return",
    )
    session_add_sync = extract_item(
        flutter_ffi, "pub fn session_add_sync(", "desktop synchronous session add"
    )
    require_order(
        session_add_sync,
        (
            'if cfg!(any(target_os = "android", target_os = "ios"))',
            "return SyncReturn(",
            "Synchronous session preparation is unavailable on mobile",
            "let add_res = session_add(",
        ),
        "mobile refusal before synchronous session mutation",
    )
    session_add_existed_sync = extract_item(
        flutter_ffi,
        "pub fn session_add_existed_sync(",
        "desktop synchronous existing-session attachment",
    )
    require_order(
        session_add_existed_sync,
        (
            'if cfg!(any(target_os = "android", target_os = "ios"))',
            "return SyncReturn(",
            "Existing-session attachment is unavailable on mobile",
            "session_add_existed(",
        ),
        "mobile refusal before synchronous existing-session mutation",
    )

    dart_model = sources["dart_model"]
    require(
        dart_model,
        "final _mobileClientOwnerId = Uuid().v4obj();",
        "canonical per-isolate mobile client-owner UUID",
    )
    require(
        dart_model,
        "late SessionID sessionId;\n  late final SessionID clientOwnerId;",
        "mutable connection identity and immutable client-owner identity",
    )
    require(
        dart_model,
        "clientOwnerId = isMobile ? _mobileClientOwnerId : Uuid().v4obj();",
        "mobile process owner versus fresh desktop view-owner identity selection",
    )
    require_count(
        dart_model,
        "SessionID get sessionId => parent.target!.sessionId;",
        3,
        "borrowed Ffi/Image/Canvas connection identity",
    )
    forbid(
        dart_model,
        "late final SessionID sessionId;",
        "cached long-lived model connection identity",
    )
    mobile_queue = extract_item(
        sources["dart_mobile_start_queue"],
        "class MobileSessionStartQueue<T>",
        "bounded mobile-session start coordinator",
    )
    require_order(
        mobile_queue,
        (
            "_MobileSessionStartEntry<T>? _running;",
            "_MobileSessionStartEntry<T>? _pending;",
        ),
        "one running plus one pending mobile-session capacity",
    )
    queue_submit = extract_item(
        mobile_queue,
        "  Future<MobileSessionStartDisposition> submit(",
        "mobile-session start submission",
    )
    require_order(
        queue_submit,
        (
            "if (running == null)",
            "_running = entry;",
            "unawaited(_drain());",
            "_pending?.complete(MobileSessionStartDisposition.superseded);",
            "_pending = entry;",
            "return entry.done.future;",
        ),
        "bounded latest-pending-wins admission",
    )
    queue_exact_finality = extract_item(
        mobile_queue,
        "  Future<MobileSessionStartDisposition>? cancelPendingOrGetRunning(",
        "exact pending cancellation or running finality lookup",
    )
    require_order(
        queue_exact_finality,
        (
            "if (pending != null && matches(pending.request))",
            "_pending = null;",
            "pending.complete(MobileSessionStartDisposition.cancelled);",
            "return pending.done.future;",
            "if (running != null && matches(running.request))",
            "return running.done.future;",
            "return null;",
        ),
        "exact pending cancellation before running-finality lookup",
    )
    queue_drain = extract_item(
        mobile_queue, "  Future<void> _drain()", "mobile-session start drain"
    )
    require_order(
        queue_drain,
        (
            "while (true)",
            "final entry = _running;",
            "if (entry == null)",
            "return;",
            "await _run(entry.request);",
            "entry.complete(MobileSessionStartDisposition.completed);",
            "entry.completeError(error, stackTrace);",
            "_running = _pending;",
            "_pending = null;",
        ),
        "failure-safe bounded successor drain",
    )
    for forbidden_collection in (
        "final List<",
        "final Queue<",
        "final Map<",
        "final Set<",
        "dart:collection",
    ):
        forbid(
            mobile_queue,
            forbidden_collection,
            "unbounded mobile-session request collection",
        )
    queue_test = sources["mobile_start_queue_test"]
    for needle, label in (
        (
            "retains one running request and only the latest pending request",
            "latest-pending replacement behavior test",
        ),
        (
            "cancels the exact pending request without interrupting finality",
            "exact pending cancellation behavior test",
        ),
        (
            "closing the running request waits while a newer request is pending",
            "running exact-finality behavior test",
        ),
        (
            "a failed running request does not wedge the bounded successor",
            "failed-running successor behavior test",
        ),
        (
            "expect(firstFinalityCompleted, isFalse);",
            "running close remains incomplete before native finality",
        ),
    ):
        require(queue_test, needle, label)

    stream_finality = extract_item(
        sources["dart_stream_finality"],
        "class SessionStreamFinality",
        "session-stream termination discriminator",
    )
    require_order(
        stream_finality,
        (
            "bool _expectedCloseReceived = false;",
            "bool _unexpectedTerminationReported = false;",
            "void acceptExpectedClose()",
            "_expectedCloseReceived = true;",
            "bool acceptUnexpectedTermination()",
            "if (_expectedCloseReceived || _unexpectedTerminationReported)",
            "_unexpectedTerminationReported = true;",
            "return true;",
        ),
        "expected-close versus unexpected-termination finality",
    )
    stream_finality_test = sources["stream_finality_test"]
    require(
        stream_finality_test,
        "an exact normal-close event suppresses later stream termination",
        "expected-close stream-finality behavior test",
    )
    require(
        stream_finality_test,
        "unexpected stream termination is admitted exactly once",
        "one-shot unexpected-termination behavior test",
    )

    mobile_run = extract_item(
        dart_model,
        "  Future<void> _runMobileSessionStart(",
        "asynchronous Dart mobile-session preparation",
    )
    require_order(
        mobile_run,
        (
            "await bind.sessionAddMobile(",
            "sessionId: request.sessionId,",
            "clientOwnerId: clientOwnerId,",
            "if (!isCurrentSession(request.sessionId))",
            "await _closeNativeSession(request.sessionId);",
            "stream = bind.sessionStart(",
            "_listenToSessionStream(",
            "qualityMonitorModel.checkShowQualityMonitor(request.sessionId)",
        ),
        "off-UI add, stale exact close, stream start, and post-add option read",
    )
    forbid(
        mobile_run,
        "sessionAddSync",
        "synchronous mobile preparation call",
    )
    close_native_session = extract_item(
        dart_model,
        "  Future<void> _closeNativeSession(",
        "captured native-session retirement",
    )
    require(
        close_native_session,
        "await bind.sessionClose(sessionId: closingSessionId);",
        "exact captured native close",
    )
    mobile_start_finality = extract_item(
        dart_model,
        "  Future<void> _awaitMobileSessionStart(",
        "Dart exact mobile-session close finality",
    )
    require_order(
        mobile_start_finality,
        (
            "_mobileSessionStarts.cancelPendingOrGetRunning(",
            "(request) => request.sessionId == closingSessionId",
            "if (preparation == null)",
            "await preparation;",
        ),
        "exact pending cancellation or running-preparation wait",
    )
    stream_failure = extract_item(
        dart_model,
        "  void _reportSessionStreamFailure(",
        "exact visible session-stream failure",
    )
    require_order(
        stream_failure,
        (
            "if (!isCurrentSession(expectedSessionId))",
            "closed = true;",
            "_retireSessionOwner(expectedSessionId);",
            "dialogManager.dismissAll();",
            "'title': 'Connection Error',",
            "'hasRetry': 'false',",
            "expectedSessionId, peerId",
            "_closeNativeSession(expectedSessionId)",
        ),
        "current-exact bounded visible failure and native retirement",
    )
    stream_listener = extract_item(
        dart_model,
        "  void _listenToSessionStream(",
        "exact session stream listener",
    )
    require_order(
        stream_listener,
        (
            "final streamFinality = SessionStreamFinality();",
            "stream.listen((message)",
            "if (closed || sessionId != activeSessionId) return;",
            "if (message.field0 == 'close')",
            "streamFinality.acceptExpectedClose();",
            "sessionEvents.retire(streamOwner);",
            "if (isCurrentSessionOwner(",
            "activeSessionId, streamOwner.clientOwnerId)",
            "closed = true;",
            "_retireSessionOwner(activeSessionId);",
            "onError: (Object error, StackTrace stackTrace)",
            "streamFinality.acceptUnexpectedTermination()",
            "_reportSessionStreamFailure(",
            "onDone: ()",
            "streamFinality.acceptUnexpectedTermination()",
            "_reportSessionStreamFailure(",
        ),
        "expected close and one-shot error/end visibility",
    )
    require_count(
        stream_listener,
        "streamFinality.acceptUnexpectedTermination()",
        2,
        "error and end unexpected-termination admission",
    )

    dart_start_begin = dart_model.find("  SessionID start(")
    dart_start_end = dart_model.find(
        "\n  Future<bool> onEvent2UIRgba(", dart_start_begin
    )
    if dart_start_begin < 0 or dart_start_end < 0:
        raise VerificationError("missing Dart outgoing start")
    dart_start = dart_model[dart_start_begin:dart_start_end]
    require_order(
        dart_start,
        (
            "if (isMobile)",
            "final previousSessionId = sessionId;",
            "mobileReset(previousSessionId);",
            "sessionId = Uuid().v4obj();",
            "final activeSessionId = sessionId;",
            "fileModel.beginSession(activeSessionId);",
            "if (isMobile && isNewPeer)",
            "_scheduleMobileSessionStart(_MobileSessionStartRequest(",
            "return activeSessionId;",
            "sessionId: activeSessionId,\n        clientOwnerId: clientOwnerId,",
            "_listenToSessionStream(",
            "return activeSessionId;",
        ),
        "fresh mobile identity, asynchronous mobile admission, and desktop start",
    )
    mobile_start_begin = dart_start.find("if (isMobile && isNewPeer)")
    mobile_start_end = dart_start.find("\n\n    // If tabWindowId", mobile_start_begin)
    if mobile_start_begin < 0 or mobile_start_end < 0:
        raise VerificationError("missing isolated Dart mobile start branch")
    forbid(
        dart_start[mobile_start_begin:mobile_start_end],
        "sessionAddSync",
        "synchronous add in Dart mobile start branch",
    )
    dart_close_begin = dart_model.find("  Future<void> close(")
    dart_close_end = dart_model.find("\n  void setMethodCallHandler(", dart_close_begin)
    if dart_close_begin < 0 or dart_close_end < 0:
        raise VerificationError("missing Dart exact outgoing close")
    dart_close = dart_model[dart_close_begin:dart_close_end]
    require_order(
        dart_close,
        (
            "final closingSessionId = expectedSessionId ?? sessionId;",
            "await setCanvasConfig(",
            "await bind.sessionClose(sessionId: closingSessionId);",
            "if (sessionId != closingSessionId)",
            "await imageModel.update(null,",
            "expectedSessionId: closingSessionId",
        ),
        "exact state-persist then native-close and stale shared-model refusal",
    )
    require_count(
        dart_close,
        "await bind.sessionClose(sessionId: closingSessionId);",
        2,
        "both stale-entry and persisted-current exact native closes",
    )
    require_count(
        dart_close,
        "await _awaitMobileSessionStart(closingSessionId);",
        2,
        "both exact mobile close paths await or cancel preparation",
    )
    require_order(
        dart_close,
        (
            "await _awaitMobileSessionStart(closingSessionId);",
            "await bind.sessionClose(sessionId: closingSessionId);",
            "await _awaitMobileSessionStart(closingSessionId);",
            "await bind.sessionClose(sessionId: closingSessionId);",
        ),
        "preparation finality precedes both exact native closes",
    )
    forbid(
        sources["mobile_remote"],
        "qualityMonitorModel.checkShowQualityMonitor(sessionId)",
        "pre-add mobile remote quality-option read",
    )
    forbid(
        sources["mobile_camera"],
        "qualityMonitorModel.checkShowQualityMonitor(sessionId)",
        "pre-add mobile camera quality-option read",
    )
    require(
        sources["web_bridge"],
        "Future<void> sessionAddMobile(",
        "web bridge mobile-add interface parity",
    )
    require(
        sources["web_bridge"],
        "UnsupportedError('Mobile session preparation is unavailable on web')",
        "web bridge mobile-add refusal",
    )
    mobile_add_gate_start = sources["dart_verify"].find(
        'mobile_add_line="$(grep -nF "  Future<void> sessionAddMobile("'
    )
    mobile_add_gate_end = sources["dart_verify"].find(
        'display_selection_line="$(grep -nF "  Future<void> sessionSwitchDisplay("',
        mobile_add_gate_start,
    )
    if mobile_add_gate_start < 0 or mobile_add_gate_end <= mobile_add_gate_start:
        raise VerificationError("missing bounded generated mobile-add bridge gate")
    mobile_add_bridge_gate = sources["dart_verify"][
        mobile_add_gate_start:mobile_add_gate_end
    ]
    require(
        mobile_add_bridge_gate,
        'Future<void> sessionAddMobile(',
        "generated asynchronous mobile-add bridge gate",
    )
    require(
        mobile_add_bridge_gate,
        'printf "%s\\n" "$mobile_add_impl" | grep -qF '
        '"_platform.executeNormal(FlutterRustBridgeTask("',
        "generated normal worker-pool mobile-add gate",
    )
    require(
        sources["dart_verify"],
        "_platform.executeSync(",
        "generated synchronous mobile-add refusal gate",
    )
    require_count(
        sources["dart_verify"],
        "test/mobile_session_start_queue_test.dart",
        2,
        "mobile-session queue behavior gate",
    )
    require_count(
        sources["dart_verify"],
        "test/session_stream_finality_test.dart",
        2,
        "session-stream finality behavior gate",
    )
    require(
        sources["requirements"],
        '<span class="id">R-S11eo</span>',
        "mobile outgoing-session preparation requirement",
    )
    require(
        sources["requirements"],
        "<tr><td>297</td>",
        "mobile outgoing-session preparation disposition",
    )
    require(
        sources["hardening"],
        "R-S11eo/R-S11e-176",
        "mobile outgoing-session preparation hardening ledger",
    )
    require(
        sources["requirements"],
        '<span class="id">R-S11eq</span>',
        "Android component-thread lifecycle-drain requirement",
    )
    require(
        sources["requirements"],
        "<tr><td>299</td>",
        "Android component-thread lifecycle-drain disposition",
    )
    require(
        sources["hardening"],
        "R-S11eq/R-S11e-178 Android component-thread outgoing-owner retirement",
        "Android component-thread lifecycle-drain hardening ledger",
    )
    require(
        sources["verify"],
        "python3 scripts/verify-android-client-lifecycle-drain.py --repo . --self-test",
        "shared Android lifecycle-drain focused gate",
    )
    require(
        sources["verify"],
        "grep -qF 'test/mobile_session_start_queue_test.dart' scripts/dart-verify.sh",
        "shared mobile-session queue behavior gate",
    )
    require(
        sources["verify"],
        'and session_start.count("rollback_failed_session_start(session_id, client_owner_id);") == 2',
        "shared failed-start rollback-count gate",
    )
    require(
        sources["verify"],
        'and dart_close.count("await _awaitMobileSessionStart(closingSessionId);") == 2',
        "shared dual close-preparation finality gate",
    )
    mobile_reset = extract_item(
        dart_model, "  void mobileReset(", "mobile reusable-model reset"
    )
    require_order(
        mobile_reset,
        (
            "chatModel.close();",
            "imageModel.disposeImage();",
            "cursorModel.clear();",
            "ffiModel.clear();",
            "canvasModel.clear();",
            "qualityMonitorModel.reset();",
            "recordingModel.reset();",
            "inputModel.resetForSession(previousSessionId);",
        ),
        "complete pre-rotation reusable-model reset",
    )
    ffi_model = extract_item(dart_model, "class FfiModel", "reused FFI model")
    ffi_clear = extract_item(ffi_model, "  clear() {", "reused FFI-state reset")
    require_order(
        ffi_clear,
        (
            "cachedPeerData = CachedPeerData();",
            "_pi = PeerInfo();",
            "_rect = null;",
            "_touchMode = false;",
            "_offlineReconnectStartTime = null;",
            "_viewOnly = false;",
            "_showMyCursor = false;",
            "cachedPeerData.permissions = _permissions;",
            "waitForImageTimer = null;",
            "waitForFirstImage.value = true;",
            "timerScreenshot = null;",
        ),
        "complete reused FFI-state reset",
    )
    canvas_model = extract_item(
        dart_model, "class CanvasModel", "reused canvas model"
    )
    canvas_clear = extract_item(
        canvas_model, "  clear() {", "reused canvas-state reset"
    )
    require_order(
        canvas_clear,
        (
            "_x = 0;",
            "_y = 0;",
            "_scrollX = 0;",
            "_scrollY = 0;",
            "_scrollStyle = ScrollStyle.scrollauto;",
            "_edgeScrollFallbackState?.stop();",
            "_edgeScrollFallbackState = null;",
            "_imageOverflow.value = false;",
            "isMobileCanvasChanged = false;",
        ),
        "complete reused canvas-state reset",
    )
    mobile_canvas_focus = extract_item(
        canvas_model,
        "  void mobileFocusCanvasCursor()",
        "delayed mobile canvas focus",
    )
    require_order(
        mobile_canvas_focus,
        (
            "final expectedSessionId = parent.target?.sessionId;",
            "Timer(Duration(milliseconds: 100), () async {",
            "if (parent.target?.isCurrentSession(expectedSessionId) != true) return;",
            "_resetCanvasOffset(",
            "notifyListeners();",
        ),
        "delayed mobile canvas-focus exact-session refusal",
    )
    mobile_canvas_restore = extract_item(
        canvas_model,
        "  void restoreMobileOffsetAfterSoftKeyboard()",
        "delayed mobile canvas restore",
    )
    require_order(
        mobile_canvas_restore,
        (
            "final expectedSessionId = parent.target?.sessionId;",
            "_timerMobileRestoreCanvasOffset = Timer(",
            "if (parent.target?.isCurrentSession(expectedSessionId) != true) return;",
            "_x = targetOffset.dx;",
            "notifyListeners();",
        ),
        "delayed mobile canvas-restore exact-session refusal",
    )
    cursor_model = extract_item(
        dart_model, "class CursorModel", "reused cursor model"
    )
    cursor_clear = extract_item(
        cursor_model, "  clear() {", "reused cursor-state reset"
    )
    require_order(
        cursor_clear,
        (
            "retireCursorResources();",
            "_x = -10000;",
            "_y = -10000;",
            '_id = "-1";',
            "_windowRect = null;",
            "_remoteWindowCoords.clear();",
            "_blockedRects.clear();",
        ),
        "complete reused cursor-state reset",
    )
    cursor_coords = extract_item(
        cursor_model,
        "  trySetRemoteWindowCoords()",
        "delayed cursor window-coordinate refresh",
    )
    require_order(
        cursor_coords,
        (
            "final expectedSessionId = parent.target?.sessionId;",
            "final remoteWindowCoords = <RemoteWindowCoords>[];",
            "await InputModel.fillRemoteCoordsAndGetCurFrame(remoteWindowCoords);",
            "if (parent.target?.isCurrentSession(expectedSessionId) != true) return;",
            "_remoteWindowCoords",
            "..addAll(remoteWindowCoords);",
            "_windowRect = windowRect;",
        ),
        "cursor-coordinate staging before exact-session publication",
    )
    quality_monitor = extract_item(
        dart_model, "class QualityMonitorModel", "reused quality-monitor model"
    )
    require(
        quality_monitor,
        "if (parent.target?.isCurrentSession(sessionId) != true) return;",
        "quality-monitor post-await exact-session refusal",
    )
    require(
        dart_model,
        "if (!_isCurrentSession(sessionId)) return;\n"
        "      showMsgBox(sessionId, type, title, text, link, hasRetry, dialogManager);",
        "delayed privacy-dialog exact-session refusal",
    )
    require(
        dart_model,
        "void reconnect(OverlayDialogManager dialogManager, SessionID sessionId) {\n"
        "    if (!_isCurrentSession(sessionId)) return;",
        "delayed reconnect exact-session refusal",
    )
    require_order(
        dart_model,
        (
            "tryShowAndroidActionsOverlay(SessionID expectedSessionId,",
            "Timer(Duration(milliseconds: delayMSecs), () {",
            "if (!_isCurrentSession(expectedSessionId)) return;",
            ".showMobileActionsOverlay(ffi: parent.target!);",
        ),
        "delayed Android overlay exact-session refusal",
    )
    require(
        dart_model,
        "bool isCurrentSession(SessionID expectedSessionId) =>\n"
        "      !closed && sessionId == expectedSessionId;",
        "Dart current-connection predicate",
    )
    require(
        dart_model,
        "if (parent.target?.isCurrentSession(expectedSessionId) != true)",
        "post-await frame/cursor stale-session refusal",
    )
    require(
        sources["dart_input_model"],
        "SessionID get sessionId => parent.target!.sessionId;",
        "borrowed input-model connection identity",
    )
    require_order(
        sources["dart_input_model"],
        (
            "void resetForSession(SessionID expectedSessionId)",
            "disposeSideButtonTracking(expectedSessionId: expectedSessionId);",
            "_relativeMouse.resetForSession(expectedSessionId);",
            "_flingTimer?.cancel();",
            "_lastScale = 1.0;",
            "lastMousePos = Offset.zero;",
            "_remoteWindowCoords.clear();",
            "toReleaseKeys.reset();",
            "resetModifiers();",
        ),
        "reusable input-model exact-session retirement",
    )
    input_pointer_move = extract_item(
        sources["dart_input_model"],
        "  void onPointMoveImage(",
        "delayed input window-coordinate refresh",
    )
    require_order(
        input_pointer_move,
        (
            "final expectedSessionId = sessionId;",
            "final remoteWindowCoords = <RemoteWindowCoords>[];",
            "await fillRemoteCoordsAndGetCurFrame(remoteWindowCoords);",
            "if (parent.target?.isCurrentSession(expectedSessionId) != true) return;",
            "_remoteWindowCoords = remoteWindowCoords;",
            "_windowRect = windowRect;",
        ),
        "input-coordinate staging before exact-session publication",
    )
    input_mouse_pair = extract_item(
        sources["dart_input_model"],
        "  Future<void> _sendMousePair(",
        "mobile paired-mouse input",
    )
    require_order(
        input_mouse_pair,
        (
            "final expectedSessionId = sessionId;",
            "_sendMouseUnchecked('down', button,",
            "expectedSessionId: expectedSessionId",
            "await Future.delayed(hold);",
            "_sendMouseUnchecked('up', button,",
            "expectedSessionId: expectedSessionId",
        ),
        "paired mobile mouse input exact-session ownership",
    )
    input_hid_tap = extract_item(
        sources["dart_input_model"],
        "  Future<void> tapHidKey(",
        "mobile paired-HID input",
    )
    require_order(
        input_hid_tap,
        (
            "final expectedSessionId = sessionId;",
            "newKeyboardMode(kKeyFlutterKey, usbHidUsage, true, false,",
            "expectedSessionId: expectedSessionId",
            "await Future.delayed(Duration(milliseconds: 100));",
            "newKeyboardMode(kKeyFlutterKey, usbHidUsage, false, false,",
            "expectedSessionId: expectedSessionId",
        ),
        "paired mobile HID input exact-session ownership",
    )
    require(
        sources["dart_chat_model"],
        "SessionID get sessionId => parent.target!.sessionId;",
        "borrowed chat-model connection identity",
    )
    require_order(
        sources["dart_relative_mouse"],
        (
            "final SessionID Function() getSessionId;",
            "required this.getSessionId,",
            "sessionId: expectedSessionId ?? getSessionId(),",
        ),
        "borrowed relative-mouse connection identity",
    )
    require_count(
        sources["dart_relative_mouse"],
        "_performCleanupCore(expectedSessionId: expectedSessionId);",
        2,
        "relative-mouse exact retired-session cleanup count",
    )
    relative_mouse_reset = extract_item(
        sources["dart_relative_mouse"],
        "void resetForSession",
        "relative-mouse session reset",
    )
    require_order(
        relative_mouse_reset,
        (
            "void resetForSession(SessionID expectedSessionId)",
            "_performCleanupCore(expectedSessionId: expectedSessionId);",
            "enabled.value = false;",
            "onDisabled?.call();",
        ),
        "reusable relative-mouse exact-session retirement",
    )
    relative_mouse_dispose = extract_item(
        sources["dart_relative_mouse"],
        "void dispose({SessionID? expectedSessionId})",
        "relative-mouse final disposal",
    )
    require_order(
        relative_mouse_dispose,
        (
            "void dispose({SessionID? expectedSessionId})",
            "_disposed = true;",
            "_performCleanupCore(expectedSessionId: expectedSessionId);",
            "enabled.value = false;",
            "onDisabled?.call();",
        ),
        "relative-mouse final exact-session retirement",
    )
    dart_file_model = sources["dart_file_model"]
    file_session_start = extract_item(
        dart_file_model,
        "void beginSession(SessionID expectedSessionId)",
        "file-transfer connection start",
    )
    require_order(
        file_session_start,
        (
            "void beginSession(SessionID expectedSessionId)",
            "unawaited(evtLoop.close());",
            "parent.target?.dialogManager.dismissAll();",
            "fileFetcher.cancelPending();",
            "jobController.clear();",
            "localController.resetForSession();",
            "remoteController.resetForSession();",
            "fileConfirmCheckboxRemember = false;",
        ),
        "file-transfer pending-resource retirement at connection start",
    )
    forbid(
        file_session_start,
        "evtLoop.clear();",
        "second pending-event retirement owner",
    )
    file_controller = extract_item(
        dart_file_model, "class FileController", "reused file controller"
    )
    file_controller_reset = extract_item(
        file_controller, "  void resetForSession()", "file-controller session reset"
    )
    require_order(
        file_controller_reset,
        (
            "directory.value.clear();",
            "options.value.clear();",
            "history.clear();",
            "selectedItems.clear();",
        ),
        "file-controller prior-peer state retirement",
    )
    file_controller_ready = extract_item(
        file_controller,
        "  Future<void> onReady(SessionID expectedSessionId)",
        "file-controller session initialization",
    )
    require_order(
        file_controller_ready,
        (
            "final home = await bind.mainGetHomeDir();",
            "if (!_isCurrentSession(expectedSessionId)) return;",
            "options.value.home = home;",
            "final showHidden = (await bind.sessionGetPeerOption(",
            "if (!_isCurrentSession(expectedSessionId)) return;",
            "options.value.showHidden = showHidden;",
        ),
        "file-controller post-await exact-session state publication",
    )
    require_order(
        file_controller,
        (
            "Future<bool> _openDirectoryPath(String path,",
            "final selectedSessionId = expectedSessionId ?? sessionId;",
            "if (!_isCurrentSession(selectedSessionId)) return false;",
            "expectedSessionId: selectedSessionId",
            "if (!_isCurrentSession(selectedSessionId)) return false;",
            "directory.value = fd;",
        ),
        "file-controller captured-session directory publication",
    )
    require_count(
        dart_file_model,
        "if (!identical(tasks[key], pending)) return;",
        1,
        "file-fetch timeout exact-completer retirement",
    )
    file_fetcher = extract_item(
        dart_file_model,
        "class FileFetcher {",
        "connection-aware file fetcher",
    )
    require_order(
        file_fetcher,
        (
            "Future<FileDirectory> fetchDirectory(",
            "{SessionID? expectedSessionId}) async {",
            "final selectedSessionId = expectedSessionId ?? sessionId;",
            "final pending = _reserve(_remoteTasks, path, selectedSessionId, false,",
            "return _dispatchAndWait(_remoteTasks, path, pending,",
            "_requests.readDirectory(selectedSessionId, path, showHidden)",
        ),
        "file-fetcher captured-session native operations",
    )
    file_dialog_loop = extract_item(
        dart_file_model,
        "class FileDialogEventLoop",
        "file-dialog event loop",
    )
    file_dialog_retirement = extract_item(
        file_dialog_loop,
        "  void onEventsRetired()",
        "file-dialog synchronous reset",
    )
    require_order(
        file_dialog_retirement,
        (
            "void onEventsRetired()",
            "_overrideConfirm = null;",
            "_skip = false;",
        ),
        "file-dialog remembered-policy retirement",
    )
    require(
        dart_file_model,
        "Future<void> close(SessionID expectedSessionId)",
        "connection-scoped file-model cleanup",
    )
    require(
        dart_file_model,
        "return evtLoop.pushEvent(_FileDialogEvent(WeakReference(this),\n"
        "        expectedSessionId, FileDialogType.overwrite, confirmation));",
        "file-dialog exact-session event identity",
    )
    require(
        dart_file_model,
        "if (model == null || !model._isCurrentSession(expectedSessionId))",
        "file-dialog stale-session callback refusal",
    )
    require_order(
        sources["dart_event_loop"],
        (
            "var _generation = 0;",
            "_generation += 1;",
            "bool _isCurrent(int generation)",
            "void _scheduleDrain(int generation)",
            "_scheduledGeneration = generation;",
            "scheduleMicrotask(()",
            "unawaited(_drain(generation));",
            "if (!_isCurrent(generation)) return;",
        ),
        "event-loop exact-generation restart and callback retirement",
    )
    require(
        sources["dart_event_loop"],
        "!_closed && generation == _generation;",
        "event-loop exact generation comparison",
    )
    require_order(
        sources["dart_event_loop"],
        (
            "Future<void> close() async",
            "_closed = true;",
            "_generation += 1;",
            "_scheduledGeneration = null;",
            "_events.clear();",
            "onEventsRetired();",
        ),
        "event-loop synchronous generation retirement",
    )
    require(
        sources["dart_main"],
        "'register_client_session_owner', gFFI.clientOwnerId.toString())",
        "Activity registration with owner rather than connection UUID",
    )

    for source_name, label in (
        ("mobile_remote", "mobile remote-control page"),
        ("mobile_camera", "mobile camera page"),
        ("mobile_files", "mobile file-transfer page"),
    ):
        page = sources[source_name]
        require(page, "late final SessionID sessionId;", f"{label} exact session field")
        require(
            page,
            "sessionId = gFFI.start(",
            f"{label} captures start identity",
        )
        require(
            page,
            "gFFI.close(expectedSessionId: sessionId)",
            f"{label} exact close path",
        )
        require(
            page,
            "if (gFFI.sessionId == sessionId)",
            f"{label} stale shared-state cleanup guard",
        )
    require_order(
        sources["mobile_files"],
        (
            "await model.close(sessionId);",
            "await gFFI.close(expectedSessionId: sessionId);",
        ),
        "file-page exact state persistence before native close",
    )
    for source_name, label in (
        ("mobile_remote", "mobile remote-control page"),
        ("mobile_camera", "mobile camera page"),
    ):
        page = sources[source_name]
        require(
            page,
            ".tryShowAndroidActionsOverlay(sessionId);",
            f"{label} exact delayed-overlay identity",
        )
        orientation_timer = extract_item(
            page,
            "Timer(const Duration(milliseconds: 200), ()",
            f"{label} delayed orientation callback",
        )
        require_order(
            orientation_timer,
            (
                "!gFFI.isCurrentSession(sessionId)",
                ".resetMobileActionsOverlay(ffi: gFFI);",
                "expectedSessionId: sessionId",
            ),
            f"{label} delayed orientation exact-session refusal",
        )
    require(
        sources["web_bridge"],
        "required UuidValue clientOwnerId,",
        "authored web bridge dual-identity compatibility",
    )
    require(
        sources["requirements"],
        '<span class="id">R-S11eb</span>',
        "mobile owner/connection normative requirement",
    )
    require(
        sources["requirements"],
        "<tr><td>281</td>",
        "mobile owner/connection Appendix C disposition",
    )
    require(
        sources["hardening"],
        "R-S11eb/R-S11e-146",
        "mobile owner/connection hardening ledger",
    )

    remove_rust = extract_item(
        flutter,
        "fn remove_connection(&self, id: i32, close: bool)",
        "Rust connection-removal dispatch",
    )
    require_order(
        remove_rust,
        (
            '#[cfg(target_os = "android")]',
            "call_main_service_set_by_name_for_generation(",
            "self.service_generation",
            '"remove_connection"',
            'self.push_event(\n                "on_client_remove"',
        ),
        "native owner retirement before UI connection removal",
    )
    forbid(
        sources["ui_cm"],
        'call_main_service_set_by_name("stop_capture"',
        "Rust detached global capture-stop edge",
    )
    forbid(
        sources["ui_cm"],
        "android_connection_requires_desktop_capture",
        "Rust capture-demand snapshot classifier",
    )

    ffi_kt = sources["ffi_kt"]
    require(
        ffi_kt,
        "external fun init(service: Context, applicationContext: Context)",
        "separate service/application JNI initialization",
    )
    require(
        ffi_kt,
        "external fun releaseService(service: Context): Boolean",
        "exact service callback-owner release declaration",
    )
    require(
        ffi_kt,
        "external fun startServer(service: Context, app_dir: String, custom_client_config: String): Long",
        "exact native server generation return",
    )
    require(
        ffi_kt,
        "external fun stopServer(generation: Long): Boolean",
        "exact native server generation stop",
    )
    android_ffi = sources["android_ffi"]
    service_init = extract_item(
        android_ffi, "Java_ffi_FFI_init(", "MainService JNI initialization"
    )
    require_order(
        service_init,
        (
            "service: JObject",
            "application_context: JObject",
            "env.new_global_ref(service)",
            "env.new_global_ref(application_context)",
            "install_application_context_once(java_vm, application_context)",
            "Some(MainServiceContext",
            "generation: None",
            "owner: service",
        ),
        "service callback versus application-context ownership",
    )
    application_context_install = extract_item(
        android_ffi,
        "fn install_application_context_once",
        "process application-context installation",
    )
    require_order(
        application_context_install,
        (
            "let mut current = APPLICATION_CONTEXT.write().unwrap()",
            "if current.is_some()",
            "context.as_obj().as_raw() as *mut c_void",
            "init_ndk_context(java_vm, context_jobject)",
            "*current = Some(context)",
        ),
        "global application-context retention before NDK publication",
    )
    service_release = extract_item(
        android_ffi, "Java_ffi_FFI_releaseService(", "MainService callback-owner release"
    )
    require_order(
        service_release,
        (
            "let mut current = MAIN_SERVICE_CTX.write().unwrap()",
            "let Some(owner) = current.as_ref()",
            "env.is_same_object(owner.owner.as_obj(), &service)",
            "if is_current",
            "current.take()",
        ),
        "exact MainService callback-owner release",
    )
    generation_binding = extract_item(
        android_ffi, "pub fn bind_main_service_generation", "MainService generation binding"
    )
    require_order(
        generation_binding,
        (
            "if generation == 0 || service.is_null()",
            "let mut current = MAIN_SERVICE_CTX.write().unwrap()",
            "env.is_same_object(current.owner.as_obj(), service)",
            "if current.generation.is_some()",
            "current.generation = Some(generation)",
        ),
        "single exact-object MainService generation binding",
    )
    generation_dispatch = extract_item(
        android_ffi,
        "pub fn call_main_service_set_by_name_for_generation",
        "generation-bound controlled callback dispatch",
    )
    require_order(
        generation_dispatch,
        (
            "let context = MAIN_SERVICE_CTX.read().unwrap()",
            "if generation == 0 || context.generation != Some(generation)",
            "env.call_method(",
            "&context.owner",
        ),
        "generation comparison before controlled Java dispatch",
    )

    flutter_handler = extract_item(
        flutter, "\n    struct FlutterHandler", "generation-bound Flutter handler"
    )
    require(
        flutter_handler,
        "service_generation: u64",
        "connection-manager callback generation owner",
    )
    start_channel = extract_item(
        flutter, "pub fn start_channel", "generation-bound Android connection channel"
    )
    require_order(
        start_channel,
        (
            "service_generation: u64",
            "FlutterHandler { service_generation }",
            "start_listen(cm, rx, terminal, tx)",
        ),
        "connection generation transfer into callback handler",
    )
    server_connection = sources["server_connection"]
    require(
        server_connection,
        "android_server_generation: u64",
        "Android connection generation owner",
    )
    for helper, expected_count, label in (
        (
            "call_main_service_pointer_input_for_generation",
            5,
            "generation-bound pointer dispatch",
        ),
        (
            "call_main_service_key_event_for_generation",
            2,
            "generation-bound key dispatch",
        ),
    ):
        require_count(server_connection, helper, expected_count, label)
    require(
        server_connection,
        "start_channel(\n"
        "            rx_to_cm,\n"
        "            cm_terminal_rx,\n"
        "            tx_from_cm,\n"
        "            conn.android_server_generation,\n"
        "        )",
        "generation-bound connection-manager channel start",
    )
    direct_service = sources["direct_service"]
    exact_stop = extract_item(
        direct_service, "pub fn android_request_stop", "exact Android server stop"
    )
    require_order(
        exact_stop,
        (
            "ANDROID_LISTENER_LIFECYCLE.lock().unwrap()",
            "if lifecycle.stop_generation(expected_generation)",
            "deactivated owned listener generation",
            "true",
            "else",
            "false",
        ),
        "exact serialized generation stop",
    )
    flutter_ffi = sources["flutter_ffi"]
    start_server = extract_item(
        flutter_ffi, "Java_ffi_FFI_startServer", "MainService native generation start"
    )
    require_order(
        start_server,
        (
            "service: JObject",
            "android_begin_generation()",
            "bind_main_service_generation(&env, &service, generation)",
            "start_server(true, generation)",
            "generation as jlong",
        ),
        "listener and callback generation binding",
    )
    stop_server = extract_item(
        flutter_ffi, "Java_ffi_FFI_stopServer", "MainService exact generation stop"
    )
    require_order(
        stop_server,
        (
            "generation: jlong",
            "if generation <= 0",
            "android_request_stop(",
            "generation as u64",
        ),
        "positive exact native server generation stop",
    )

    io_loop = sources["io_loop"]
    accepted_voice_call = extract_item(
        io_loop,
        "Some(message::Union::VoiceCallResponse(response))",
        "accepted outgoing voice-call transition",
    )
    require_order(
        accepted_voice_call,
        (
            "if response.accepted",
            "self.stop_voice_call().await",
            "self.voice_call_audio = self.start_voice_call()",
            "if self.voice_call_audio.is_some()",
            "self.handler.on_voice_call_started()",
            ".on_voice_call_closed(\"Failed to start voice call audio\")",
            "let msg = new_voice_call_request(false)",
            "peer.send(&msg).await",
        ),
        "audio-owner-before-native outgoing voice-call activation",
    )

    behavior = sources["test"]
    for needle, label in (
        (
            "controlled owner without a live service generation was admitted",
            "closed-before-service-generation admission",
        ),
        (
            "replacement generation retained the prior controlled voice owner",
            "replacement-generation retirement",
        ),
        (
            "stale generation registered a same-number controlled owner",
            "same-ID generation-ABA registration refusal",
        ),
        (
            "stale generation changed controlled voice state",
            "stale-generation update refusal",
        ),
        (
            "stale generation cleared replacement controlled owners",
            "stale-generation teardown refusal",
        ),
        (
            "stale generation teardown retired replacement voice capture",
            "replacement capture preservation",
        ),
        (
            "current generation idempotent begin cleared live owners",
            "idempotent current-generation preservation",
        ),
        (
            "controlled-service replacement cleared the outgoing owner",
            "controlled replacement preserves outgoing ownership",
        ),
        (
            "controlled-service replacement retained predecessor controlled voice state",
            "controlled replacement retires predecessor voice state",
        ),
        (
            "superseded controlled generation was reactivated",
            "superseded-generation refusal",
        ),
        ("retired generation was reactivated", "retired-generation refusal"),
        ("unregistered controlled owner was activated", "unregistered rejection"),
        ("invalid outgoing owner was admitted", "invalid outgoing rejection"),
        ("one controlled teardown cleared another owner", "controlled aggregation"),
        ("stale outgoing owner changed live state", "stale outgoing refusal"),
        ("same-generation resume was rejected", "idempotent resume"),
        ("lost-response resume retry was rejected", "lost-response retry idempotence"),
        ("older generation resumed outgoing owner", "generation regression refusal"),
        ("different isolate resumed outgoing owner", "cross-isolate resume refusal"),
        ("owner resume lost active voice state", "resume state retention"),
        ("pre-resume owner retired the replacement generation", "old-generation refusal"),
        ("controlled teardown cleared an outgoing owner", "domain overlap"),
        ("outgoing invalidation retained voice capture", "isolate invalidation"),
        ("controlled owner clear retained voice capture", "service teardown"),
    ):
        require(behavior, needle, f"behavior regression {label}")

    capture_behavior = sources["connection_type_test"]
    for needle, label in (
        ("unauthorized Remote created capture demand", "unauthorized Remote refusal"),
        ("one Remote teardown cleared another live owner", "concurrent Remote aggregation"),
        ("remove-then-add ordering lost new Remote demand", "remove-before-add convergence"),
        ("add-then-remove ordering lost new Remote demand", "add-before-remove convergence"),
        ("non-Remote replacement retained capture demand", "exact-type owner replacement"),
        ("owner clear retained capture demand", "service owner teardown"),
    ):
        require(capture_behavior, needle, f"capture behavior regression {label}")

    require(
        sources["requirements"],
        '<span class="id">R-S11br</span>',
        "Android recorder exact-owner requirement",
    )
    require(
        sources["requirements"],
        '<span class="id">R-S11ek</span>',
        "Android controlled-service audio generation requirement",
    )
    require(
        sources["requirements"],
        "<tr><td>290</td>",
        "Android controlled-service audio generation Appendix C disposition",
    )
    require(
        sources["requirements"],
        "generation that is equal (idempotent ordinary resume) or newer (lost-response recovery)",
        "Android idempotent same-generation resume requirement",
    )
    require(
        sources["requirements"],
        "only then publish native/UI started state",
        "Android audio-owner-before-native start requirement",
    )
    require(
        sources["requirements"],
        "service-owned set of exact positive connection IDs",
        "Android service-owned capture-demand requirement",
    )
    require(
        sources["requirements"],
        "detached global stop edge",
        "Android stale capture-stop prohibition",
    )
    require(
        sources["requirements"],
        "gate its controlled-state and input JNI callbacks against the exact live Service generation",
        "Android stale-generation callback prohibition",
    )
    require(
        sources["requirements"],
        "bind that generation only after JNI proves that its caller is the exact currently retained <code>MainService</code> object",
        "Android exact-object listener-generation binding",
    )
    require(
        sources["requirements"],
        "a retained global <code>applicationContext</code> reference",
        "Android application-context global-reference lifetime",
    )
    require(
        sources["requirements"],
        "<tr><td>211</td>",
        "Android recorder Appendix C disposition",
    )
    require(
        sources["hardening"],
        "R-S11br/R-S11e-84 — Android native voice-call capture has exact process-wide owners",
        "Android recorder hardening ledger",
    )
    require(
        sources["hardening"],
        "R-S11ek/R-S11e-169",
        "Android controlled-service audio generation hardening ledger",
    )
    require(
        sources["hardening"],
        "same-or-newer resume with active-state retention plus older/cross-isolate refusal",
        "Android idempotent same-generation resume ledger",
    )
    require(
        sources["hardening"],
        "it never mints a generation, replaces an owner, or drains sessions",
        "Android read-only Activity-resume summary",
    )
    forbid(
        sources["hardening"],
        "allocating a fresh generation and draining a different",
        "superseded cross-isolate Activity takeover summary",
    )
    require(
        sources["hardening"],
        "publishes `on_voice_call_started` only after that complete owner exists",
        "Android audio-owner-before-native start ledger",
    )
    require(
        sources["hardening"],
        "service-owned exact Remote connection-ID set",
        "Android exact capture-owner hardening ledger",
    )
    require(
        sources["hardening"],
        "exact-object JNI release",
        "Android MainService callback-owner release ledger",
    )
    require(
        sources["hardening"],
        "refuses a zero, stopped, or replaced generation before entering Java",
        "Android callback-generation hardening ledger",
    )
    require(
        sources["hardening"],
        "`startServer(this, ...)` returns that exact generation only after JNI proves",
        "Android exact-object listener-generation hardening ledger",
    )
    require(
        sources["verify"],
        "grep -qF 'stale_android_activity_cannot_reclaim_the_replacement_owner' src/flutter.rs",
        "shared stale-Activity takeover-refusal regression gate",
    )
    forbid(
        sources["verify"],
        "resumed_android_activity_reclaims_owner_without_reusing_a_stale_generation",
        "shared superseded Activity-takeover regression gate",
    )
    require(
        sources["verify"],
        'and owner_resume.index("ANDROID_CLIENT_OWNER")\n'
        '        < owner_resume.index(".read()")\n'
        '        < owner_resume.index(".resume(generation, session_id)")',
        "shared read-only Rust Activity-resume gate",
    )
    require(
        sources["verify"],
        'and "ANDROID_CLIENT_OWNER.write()" not in owner_resume\n'
        '    and "close_sessions_owned_by" not in owner_resume',
        "shared resume-without-takeover gate",
    )
    require(
        sources["verify"],
        "python3 scripts/verify-android-voice-call-ownership.py --repo . --self-test",
        "shared Android recorder gate wiring",
    )
    require(
        sources["verify"],
        "grep -qF 'take_previous_android_mobile_client_sessions(client_owner_id, session_id)?' src/flutter.rs",
        "shared mobile replacement-drain gate",
    )
    require(
        sources["verify"],
        "if [ \"$(grep -cF 'check_remove_unused_displays(None, session, &handlers);' src/flutter.rs)\" -ne 2 ]; then",
        "shared post-drain all-remaining-display reconciliation gate",
    )
    require(
        sources["verify"],
        "grep -qF 'flutter::mobile_session_lifecycle_tests:: -- --test-threads=1' scripts/dart-verify.sh",
        "shared generated-bridge mobile lifecycle gate",
    )
    require(
        sources["dart_verify"],
        "cargo test --offline --locked --lib --features flutter,unix-file-copy-paste \\\n"
        "      flutter::mobile_session_lifecycle_tests:: -- --test-threads=1",
        "generated-bridge mobile lifecycle behavior gate",
    )
    require(
        sources["dart_verify"],
        "flutter test --no-pub test/mobile_file_session_lifecycle_test.dart",
        "mobile file-session lifecycle behavior gate",
    )
    require_order(
        sources["mobile_file_lifecycle_test"],
        (
            "final retired = fetcher.fetchDirectory('/same-path', false, false,",
            "await firstDispatchEntered.future;",
            "fetcher.cancelPending();",
            "await retiredResult;",
            "currentSession = replacementSession;",
            "final replacement = fetcher.fetchDirectory('/same-path', false, false,",
            "releaseFirstDispatch.complete();",
            "retiredSession, directoryResponse('/same-path'), 'false'",
            "replacementSession, directoryResponse('/same-path'), 'false'",
            "expect((await replacement).path, '/same-path');",
        ),
        "reserve-before-dispatch retirement versus replacement behavior proof",
    )
    remote_keyboard = extract_item(
        sources["mobile_remote"],
        "  void onSoftKeyboardChanged(bool visible)",
        "remote-page delayed keyboard lifecycle",
    )
    require_order(
        remote_keyboard,
        (
            "void onSoftKeyboardChanged(bool visible)",
            "if (!mounted || !gFFI.isCurrentSession(sessionId)) return;",
            "if (!visible)",
        ),
        "remote-page keyboard callback exact-session refusal",
    )
    require(
        sources["mobile_remote"],
        "class KeyHelpTools extends StatefulWidget {\n  final SessionID sessionId;",
        "remote-page key-help captured session identity",
    )
    remote_key_help = extract_item(
        sources["mobile_remote"],
        "class _KeyHelpToolsState",
        "remote-page delayed key-help resource",
    )
    require_order(
        remote_key_help,
        (
            "if (!mounted || !gFFI.isCurrentSession(widget.sessionId)) return;",
            "Future.delayed(Duration(milliseconds: 500), () {",
            "if (!mounted || !gFFI.isCurrentSession(widget.sessionId)) return;",
            "_updateRect();",
        ),
        "remote-page key-help exact-session timer refusal",
    )
    camera_metrics = extract_item(
        sources["mobile_camera"],
        "  void didChangeMetrics()",
        "camera-page delayed metrics lifecycle",
    )
    require_count(
        camera_metrics,
        "if (!mounted || !gFFI.isCurrentSession(sessionId)) return;",
        2,
        "camera-page metrics and timer exact-session refusal",
    )
    file_view = extract_item(
        sources["mobile_files"],
        "class _FileManagerViewState",
        "mobile file-view resource lifecycle",
    )
    require_order(
        file_view,
        (
            "late final StreamSubscription<FileDirectory> _directorySubscription;",
            "_directorySubscription =",
            "controller.directory.listen((e) => breadCrumbScrollToEnd());",
            "void dispose()",
            "unawaited(_directorySubscription.cancel());",
            "_breadCrumbTimer?.cancel();",
            "_listScrollController.dispose();",
            "_breadCrumbScroller.dispose();",
            "super.dispose();",
        ),
        "mobile file-view subscription/timer/controller retirement",
    )

    client = sources["client"]
    io_loop = sources["io_loop"]
    lease_set = extract_item(
        client, "impl ClipboardLeaseSet", "outgoing clipboard exact lease set"
    )
    require_order(
        lease_set,
        (
            "let next = self.next.checked_add(1)?;",
            "self.next = next;",
            "self.active.insert(next)",
        ),
        "monotonic outgoing clipboard lease acquisition",
    )
    require_order(
        lease_set,
        (
            "if !self.active.remove(&lease)",
            "ClipboardLeaseRelease::Missing",
            "self.active.is_empty()",
            "ClipboardLeaseRelease::Last",
            "ClipboardLeaseRelease::Remaining",
        ),
        "exact outgoing clipboard lease retirement",
    )
    require(
        client,
        "worker: Option<ClientClipboardWorker>,",
        "retained outgoing clipboard worker owner",
    )
    require(
        client,
        "struct ClientClipboardWorker {\n"
        "    stop_requested: Arc<AtomicBool>,\n"
        "    #[cfg(not(any(target_os = \"android\", target_os = \"ios\")))]\n"
        "    subscription: clipboard_listener::ClipboardSubscription,\n"
        "    thread: std::thread::JoinHandle<()>,\n"
        "}",
        "clipboard stop, subscription, and join authority",
    )
    acquire_clipboard = extract_item(
        client,
        "pub(crate) fn acquire_clipboard_session()",
        "outgoing clipboard round acquisition",
    )
    require_order(
        acquire_clipboard,
        (
            "state.leases.acquire()",
            "ContextSend::enable(true)",
            "ClientClipboardSession { lease: Some(lease) }",
        ),
        "lease-owned Windows clipboard context acquisition",
    )
    start_clipboard = extract_item(
        client,
        "fn try_start_clipboard(",
        "outgoing clipboard worker start admission",
    )
    require_order(
        start_clipboard,
        (
            "state.leases.contains(lease)",
            "state.pending_start = Some(context);",
            "if state.worker_transition",
            "worker.thread.is_finished()",
            "Self::start_client_clipboard_worker_locked(&mut state, true)",
            "handoff_client_clipboard_worker(worker);",
        ),
        "exact-lease clipboard start and prior-worker transition",
    )
    retire_clipboard = extract_item(
        client,
        "fn retire_client_clipboard_worker_locked(",
        "outgoing clipboard worker retirement",
    )
    require_order(
        retire_clipboard,
        (
            "let worker = state.worker.take()?;",
            "worker.stop_requested.store(true, Ordering::Release);",
            "state.worker_transition = true;",
            "worker.subscription.close();",
            "Some(worker)",
        ),
        "clipboard admission close before exact-handle transfer",
    )
    release_clipboard = extract_item(
        client,
        "fn release_clipboard_session(lease: u64)",
        "outgoing clipboard exact lease release",
    )
    require_order(
        release_clipboard,
        (
            "state.leases.release(lease)",
            "ClipboardLeaseRelease::Missing",
            "ClipboardLeaseRelease::Remaining",
            "ClipboardLeaseRelease::Last",
            "state.pending_start = None;",
            "if state.worker_transition",
            "Self::retire_client_clipboard_worker_locked(&mut state)",
            "handoff_client_clipboard_worker(worker);",
        ),
        "last-exact-lease clipboard worker retirement",
    )
    finish_clipboard = extract_item(
        client,
        "fn finish_client_clipboard_worker_transition()",
        "outgoing clipboard completion transition",
    )
    require_order(
        finish_clipboard,
        (
            "if !state.worker_transition",
            "state.worker_transition = false;",
            "if state.leases.is_empty()",
            "Self::finish_client_clipboard_runtime_locked(&mut state);",
            "state.pending_start.is_some()",
            "Self::start_client_clipboard_worker_locked(&mut state, false)",
        ),
        "join-complete zero-owner cleanup or replacement restart",
    )
    handoff_clipboard = extract_item(
        client,
        "fn handoff_client_clipboard_worker(worker: ClientClipboardWorker)",
        "bounded outgoing clipboard join handoff",
    )
    require_order(
        handoff_clipboard,
        (
            'workers: vec![("client clipboard", worker.thread)]',
            "completed: None",
            "on_complete: Some(MediaWorkerCompletion::ClientClipboard)",
        ),
        "exact clipboard worker fixed-pool completion handoff",
    )
    require_order(
        io_loop,
        (
            ".then(Client::acquire_clipboard_session);",
            ".run_start(",
            "self.shutdown_workers().await;",
            "self.handler.connection_round_owner.finish(round)",
            "drop(clipboard_session.take());",
        ),
        "clipboard lease spans the exact outgoing network round",
    )
    require_order(
        io_loop,
        (
            ".handle_msg_from_peer(",
            "clipboard_session.as_ref(),",
            "#[cfg(not(target_os = \"ios\"))] clipboard_session: Option<&ClientClipboardSession>",
            "let rx = clipboard_session.and_then(|session|",
        ),
        "clipboard peer handler receives the exact network-round lease",
    )
    require_order(
        io_loop,
        (
            "let rx = clipboard_session.and_then(|session|",
            "Client::try_start_clipboard(",
            "session, Default::default()",
        ),
        "peer-info clipboard start consumes the exact round lease",
    )
    require(
        client,
        "clipboard_leases_track_exact_network_rounds_without_stale_stop",
        "outgoing clipboard stale-release/ABA regression",
    )
    for source_name in ("client", "io_loop", "flutter"):
        forbid(
            sources[source_name],
            "has_sessions_running",
            f"{source_name} UI-registry clipboard liveness",
        )
    forbid(client, "running: bool", "global Boolean clipboard worker ownership")
    require(
        sources["requirements"],
        '<span class="id">R-S11ec</span>',
        "outgoing clipboard network-round requirement",
    )
    require(
        sources["requirements"],
        "<tr><td>282</td>",
        "outgoing clipboard Appendix C disposition",
    )
    require(
        sources["hardening"],
        "R-S11ec/R-S11e-147",
        "outgoing clipboard hardening ledger",
    )
    require(
        sources["verify"],
        "client::tests::clipboard_leases_track_exact_network_rounds_without_stale_stop",
        "shared outgoing clipboard lifecycle test wiring",
    )
    require(
        sources["dart_verify"],
        "client::tests::clipboard_leases_track_exact_network_rounds_without_stale_stop",
        "generated-bridge outgoing clipboard lifecycle test wiring",
    )

    ui_session = sources["ui_session"]
    input_request = extract_item(
        ui_session,
        "pub fn input_os_password(&self",
        "typed current-round OS-password input request",
    )
    require_order(
        input_request,
        (
            "self.send(Data::InputOsPassword {",
            "password: pass,",
            "activate,",
        ),
        "OS-password request enters the currently installed round channel",
    )
    forbid(
        input_request,
        "std::thread",
        "detached OS-password input thread at UI admission",
    )
    require(
        client,
        "InputOsPassword {\n        password: String,\n        activate: bool,\n    },",
        "typed OS-password in-process command",
    )
    prepared_sequence = extract_item(
        client,
        "pub(crate) fn prepare_input_os_password_sequence(",
        "synchronous exact-round OS-password message preparation",
    )
    require_order(
        prepared_sequence,
        (
            "interface: &impl Interface",
            "let activation = activate.then(",
            "new_mouse_message(",
            "let password = input_password.then(",
            "key_event.set_seq(p);",
            "key_event.set_control_key(ControlKey::Return);",
            "InputOsPasswordSequence {",
        ),
        "OS-password messages are prepared synchronously at exact-round admission",
    )
    forbid(
        prepared_sequence,
        "async fn",
        "delayed OS-password message preparation",
    )
    activate_os = extract_item(
        client,
        "async fn activate_os(",
        "exact-round OS-password activation sequence",
    )
    require(
        activate_os,
        "sender: &ViewerCommandSender",
        "activation bounded exact-round sender",
    )
    forbid(
        activate_os,
        "UnboundedSender<Data>",
        "unbounded OS-password activation sender",
    )
    forbid(
        activate_os,
        "Interface",
        "mutable Session capability in delayed activation sequence",
    )
    require_count(
        activate_os,
        "hbb_common::tokio::time::sleep(Duration::from_millis(50)).await;",
        3,
        "three asynchronous activation delays",
    )
    require_count(
        activate_os,
        "send_os_password_input(",
        5,
        "all activation messages use exact-round admission",
    )
    input_sequence = extract_item(
        client,
        "pub(crate) async fn run_input_os_password_sequence(",
        "exact-round OS-password sequence",
    )
    forbid(
        input_sequence,
        "UnboundedSender<Data>",
        "unbounded delayed OS-password sender",
    )
    require_order(
        input_sequence,
        (
            "sequence: InputOsPasswordSequence",
            "sender: ViewerCommandSender",
            "if let Some(activation) = sequence.activation",
            "activate_os(activation, &sender).await",
            "hbb_common::tokio::time::sleep(Duration::from_millis(1200)).await;",
            "let Some((password, enter)) = sequence.password",
            "send_os_password_input(&sender, password)",
            "send_os_password_input(&sender, enter)",
        ),
        "OS-password sequence remains on its captured exact sender",
    )
    forbid(
        input_sequence,
        "interface.send(",
        "mutable Session sender lookup inside delayed OS-password sequence",
    )
    forbid(
        input_sequence,
        "Interface",
        "mutable Session capability retained by delayed OS-password sequence",
    )
    forbid(
        input_sequence,
        "handler",
        "mutable handler capability retained by delayed OS-password sequence",
    )
    forbid(
        input_sequence,
        "std::thread",
        "native OS-password sequence thread",
    )
    forbid(client, "fn _input_os_password(", "legacy detached OS-password helper")
    require(
        io_loop,
        "struct OwnedInputOsPasswordTask {\n"
        "    task: Option<tokio::task::JoinHandle<()>>,\n"
        "}",
        "sole retained OS-password JoinHandle",
    )
    owned_input_task = extract_item(
        io_loop,
        "impl OwnedInputOsPasswordTask",
        "sole OS-password task owner",
    )
    require_order(
        owned_input_task,
        (
            "self.stop_and_join().await;",
            "self.task = Some(tokio::spawn(future));",
            "let Some(task) = self.task.take()",
            "task.abort();",
            "match task.await",
            "Err(err) if err.is_cancelled()",
            'log::error!("OS-password input task failed: {err}")',
        ),
        "OS-password task replacement and final cancellation ownership",
    )
    forbid(
        owned_input_task,
        "std::process::abort",
        "process-wide abort for a joined OS-password helper failure",
    )
    owned_input_drop = extract_item(
        io_loop,
        "impl Drop for OwnedInputOsPasswordTask",
        "OS-password task hard-drop owner",
    )
    require_order(
        owned_input_drop,
        ("self.task.take()", "task.abort();"),
        "OS-password hard-drop cancellation",
    )
    require(
        io_loop,
        "input_os_password_task: OwnedInputOsPasswordTask,",
        "Remote-retained sole OS-password task owner",
    )
    shutdown_workers = extract_item(
        io_loop,
        "async fn shutdown_workers(&mut self)",
        "outgoing Remote worker shutdown",
    )
    require_order(
        shutdown_workers,
        (
            "self.input_os_password_task.stop_and_join().await;",
            "self.voice_call_audio.take()",
            "self.video_threads.drain()",
            "self.audio_thread.close()",
            "Self::join_workers(workers).await;",
        ),
        "OS-password task is cancelled before Remote round teardown completes",
    )
    ui_dispatch = extract_item(
        io_loop,
        "async fn handle_msg_from_ui(&mut self",
        "outgoing Remote UI dispatch",
    )
    require_order(
        ui_dispatch,
        (
            "Data::InputOsPassword { password, activate }",
            "let sequence =",
            "client::prepare_input_os_password_sequence(",
            "password,",
            "activate,",
            "&self.handler)",
            "let sender = self.sender.clone();",
            "self.input_os_password_task",
            ".replace(client::run_input_os_password_sequence(sequence, sender))",
            ".await;",
        ),
        "connected Remote synchronously prepares and admits one exact-sender OS-password task",
    )
    require(
        io_loop,
        "r_s11e148_os_password_input_is_cancelled_and_joined_before_round_replacement",
        "OS-password replacement cancellation behavior regression",
    )
    require(
        sources["requirements"],
        '<span class="id">R-S11ed</span>',
        "OS-password exact-round normative requirement",
    )
    require(
        sources["requirements"],
        "<tr><td>283</td>",
        "OS-password exact-round Appendix C disposition",
    )
    require(
        sources["hardening"],
        "R-S11ed/R-S11e-148",
        "OS-password exact-round hardening ledger",
    )
    require(
        sources["verify"],
        "client::io_loop::tests::r_s11e148_os_password_input_is_cancelled_and_joined_before_round_replacement",
        "shared OS-password exact-round behavior gate wiring",
    )
    require(
        sources["dart_verify"],
        "client::io_loop::tests::r_s11e148_os_password_input_is_cancelled_and_joined_before_round_replacement",
        "generated-bridge OS-password exact-round behavior gate wiring",
    )

    screenshot = sources["screenshot"]
    forbid(screenshot, "lazy_static", "process-global screenshot cache")
    forbid(screenshot, "Mutex", "process-global screenshot cache lock")
    forbid(screenshot, "struct Screenshot", "process-global screenshot cache type")
    forbid(screenshot, "set_screenshot", "process-global screenshot setter")
    forbid(
        io_loop,
        "crate::client::screenshot::set_screenshot(",
        "process-global screenshot setter call",
    )
    require(
        screenshot,
        "pub fn handle_screenshot(data: bytes::Bytes, action: String) -> String",
        "value-owned screenshot action",
    )
    pending_screenshots = extract_item(
        io_loop,
        "impl PendingScreenshotRequests",
        "exact screenshot request owner",
    )
    require_order(
        pending_screenshots,
        (
            "fn replace(&mut self, owner_sid: String)",
            ".retain(|_, existing_owner_sid| existing_owner_sid != &owner_sid);",
            "if self.owners.len() >= MAX_PENDING_SCREENSHOT_RESPONSES",
            ".next_sequence",
            ".checked_add(1)",
            "let request_id = format!(\"{owner_sid}:{sequence}\");",
            "self.owners.insert(request_id.clone(), owner_sid);",
            "fn complete(&mut self, request_id: &str) -> Option<String>",
            "self.owners.remove(request_id)",
        ),
        "bounded replacement-safe screenshot request identity",
    )
    require(
        io_loop,
        "pending_screenshot_requests: PendingScreenshotRequests,",
        "Remote-owned screenshot request map",
    )
    require(
        io_loop,
        "self.pending_screenshot_requests.replace(sid.clone())",
        "fresh screenshot request admission",
    )
    require(
        io_loop,
        "sid: request_id.clone(),",
        "exact screenshot wire request ID",
    )
    require_count(
        io_loop,
        "self.pending_screenshot_requests.complete(&request_id)",
        3,
        "exact screenshot response/send-failure retirement",
    )
    forbid(
        io_loop,
        "pending_screenshot_sids",
        "session-UUID-only screenshot pending set",
    )
    require(
        io_loop,
        "r_s11e149_screenshot_responses_require_the_current_exact_request",
        "exact screenshot request replacement behavior regression",
    )

    flutter = sources["flutter"]
    require(
        flutter,
        "screenshot: Option<OwnedScreenshot>,",
        "exact-handler screenshot owner",
    )
    require(
        flutter,
        "struct OwnedScreenshot {\n    request_id: String,\n    data: bytes::Bytes,\n}",
        "request-bound screenshot value",
    )
    begin_screenshot = extract_item(
        flutter,
        "pub(crate) fn begin_screenshot_request",
        "exact-handler screenshot request start",
    )
    require_order(
        begin_screenshot,
        (
            "handlers.get_mut(session_id)",
            "handler.screenshot = None;",
        ),
        "new screenshot request retires only its exact handler value",
    )
    take_screenshot = extract_item(
        flutter,
        "pub(crate) fn take_screenshot(",
        "exact screenshot action",
    )
    require_order(
        take_screenshot,
        (
            "let handler = handlers.get_mut(session_id)?;",
            ".map(|screenshot| screenshot.request_id.as_str())",
            "!= Some(request_id)",
            "return None;",
            "handler.screenshot.take().map(|screenshot| screenshot.data)",
        ),
        "session-and-request double-match before one-time screenshot consumption",
    )
    screenshot_response = extract_item(
        flutter,
        "fn handle_screenshot_resp(",
        "exact screenshot response publication",
    )
    require_order(
        screenshot_response,
        (
            "let Some(handler) = handlers.get_mut(&sid)",
            "handler.screenshot = data.map(|data| OwnedScreenshot",
            "request_id: request_id.clone()",
            '("screenshot_id", json!(request_id))',
            "&[&sid]",
        ),
        "live exact-handler screenshot storage and targeted request event",
    )
    require(
        flutter,
        "r_s11e149_screenshot_data_is_owned_by_the_exact_ui_session",
        "exact screenshot handler behavior regression",
    )

    flutter_ffi = sources["flutter_ffi"]
    take_screenshot_ffi = extract_item(
        flutter_ffi,
        "pub fn session_take_screenshot(",
        "screenshot request FFI",
    )
    require_order(
        take_screenshot_ffi,
        (
            "begin_screenshot_request(&session_id)",
            "s.take_screenshot(display as _, session_id.to_string());",
        ),
        "clear exact handler before screenshot request",
    )
    handle_screenshot_ffi = extract_item(
        flutter_ffi,
        "pub fn session_handle_screenshot(",
        "screenshot action FFI",
    )
    require_order(
        handle_screenshot_ffi,
        (
            "session_id: SessionID,",
            "screenshot_id: String,",
            "sessions::get_session_by_session_id(&session_id)",
            ".take_screenshot(&session_id, &screenshot_id)",
            "crate::client::screenshot::handle_screenshot(data, action)",
        ),
        "session-and-request-bound screenshot action FFI",
    )
    forbid(
        handle_screenshot_ffi,
        "#[allow(unused_variables)]",
        "ignored screenshot session ID",
    )
    dart_screenshot = extract_item(
        sources["dart_model"],
        "_handleScreenshot(\n      Map<String, dynamic> evt",
        "Dart screenshot response handler",
    )
    require(
        dart_screenshot,
        "final screenshotId = evt['screenshot_id'] ?? '';",
        "Dart exact screenshot request ID capture",
    )
    require_count(
        dart_screenshot,
        "screenshotId: screenshotId,",
        4,
        "all Dart screenshot actions carry the exact request ID",
    )
    require(
        sources["web_bridge"],
        "required String screenshotId,",
        "web bridge screenshot action signature parity",
    )
    require(
        sources["requirements"],
        '<span class="id">R-S11ee</span>',
        "exact-session screenshot normative requirement",
    )
    require(
        sources["requirements"],
        "<tr><td>284</td>",
        "exact-session screenshot Appendix C disposition",
    )
    require(
        sources["hardening"],
        "R-S11ee/R-S11e-149",
        "exact-session screenshot hardening ledger",
    )
    require(
        sources["verify"],
        "client::io_loop::tests::r_s11e149_screenshot_responses_require_the_current_exact_request",
        "shared exact screenshot request behavior gate wiring",
    )
    require(
        sources["dart_verify"],
        "client::io_loop::tests::r_s11e149_screenshot_responses_require_the_current_exact_request",
        "generated-bridge exact screenshot request behavior gate wiring",
    )

    video_service = sources["video_service"]
    require(
        video_service,
        "const MAX_SCREENSHOT_REQUEST_OWNERS: usize = 64;",
        "controlled screenshot exact-owner capacity",
    )
    require(
        video_service,
        "const SCREENSHOT_ENCODE_QUEUE_CAPACITY: usize = 2;",
        "controlled screenshot encoder queue capacity",
    )
    require(
        video_service,
        "static ref SCREENSHOTS: Mutex<PendingScreenshots> = Default::default();",
        "controlled screenshot exact-owner registry",
    )
    require(
        video_service,
        "static ref SCREENSHOT_ENCODER: Result<ScreenshotEncoder, String> = ScreenshotEncoder::new();",
        "retained controlled screenshot encoder owner",
    )
    require(
        video_service,
        "_worker: std::thread::JoinHandle<()>,",
        "retained controlled screenshot encoder handle",
    )
    bounded_png = extract_item(
        video_service,
        "impl std::io::Write for BoundedScreenshotPng",
        "bounded controlled screenshot PNG writer",
    )
    require_order(
        bounded_png,
        (
            ".checked_add(buf.len())",
            "if next_len > self.max_bytes",
            "return Err(std::io::Error::new(",
            "self.data.extend_from_slice(buf);",
        ),
        "screenshot PNG allocation stops before the encoded-byte limit",
    )
    forbid(
        video_service,
        "Mutex<HashMap<(VideoSource, usize), Screenshot>>",
        "source/display-only controlled screenshot singleton",
    )
    pending_controlled_screenshots = extract_item(
        video_service,
        "impl PendingScreenshots",
        "controlled screenshot ownership manager",
    )
    require_order(
        pending_controlled_screenshots,
        (
            "fn replace(",
            "if owner.tx.same_channel(&tx)",
            "owner.pending = Some(request);",
            "self.owners.len() >= MAX_SCREENSHOT_REQUEST_OWNERS",
            "fn take_for_frame(",
            "let matches_frame = !owner.in_flight",
            "request.source == source && request.display_idx == display_idx",
            "owner.in_flight = true;",
            "fn complete(",
            "owner.tx.same_channel(tx) && owner.in_flight",
            "fn retry_after_texture(",
            "!owner.tx.same_channel(&screenshot.tx) || !owner.in_flight",
            "if owner.pending.is_none()",
            "screenshot.request.restore_vram = true;",
            "fn cancel(",
            "owner.tx.same_channel(tx)",
            "fn is_in_flight(",
            "owner.in_flight && owner.tx.same_channel(&screenshot.tx)",
        ),
        "exact controlled screenshot pending/in-flight/ABA transitions",
    )
    screenshot_encoder = extract_item(
        video_service,
        "impl ScreenshotEncoder",
        "retained controlled screenshot encoder",
    )
    require_order(
        screenshot_encoder,
        (
            "std::sync::mpsc::sync_channel::<ScreenshotEncodeJob>(SCREENSHOT_ENCODE_QUEUE_CAPACITY)",
            '.name("screenshot-encoder".to_owned())',
            "while let Ok(job) = receiver.recv()",
            "handle_screenshot_job(job);",
            "_worker: worker,",
        ),
        "one retained bounded screenshot encoder worker",
    )
    require_order(
        video_service,
        (
            ".take_for_frame(source, display_idx)",
            ".partition(|screenshot| !screenshot.request.restore_vram)",
            "submit_screenshot_job(ScreenshotEncodeJob",
            "pending.retry_after_texture(screenshot);",
            "match sender.try_send(job)",
            "TrySendError::Full(job)",
            "TrySendError::Disconnected(job)",
            "fn handle_screenshot_job(mut job: ScreenshotEncodeJob)",
            ".retain(|screenshot| pending.is_in_flight(screenshot));",
            "screenshot_dimensions_are_bounded(job.width, job.height)",
            "job.rgba.len() != expected_len",
            "png.len() > crate::peer_text::MAX_PEER_SCREENSHOT_RESPONSE_BYTES",
            "complete_screenshot_work(screenshot, \"\", &png);",
        ),
        "bounded shared-frame controlled screenshot capture and completion",
    )
    forbid(
        video_service,
        "std::thread::spawn(move || {\n                            handle_screenshot",
        "per-request detached screenshot encoder",
    )
    require_order(
        sources["server_connection"],
        (
            "Some(message::Union::ScreenshotRequest(request))",
            "is_bounded_peer_screenshot_request_id(&request.sid)",
            "if crate::video_service::set_take_screenshot(",
            "self.inner.id(),",
            "self.video_source(),",
            "request.sid.clone(),",
            "if !self.refresh_video_display(Some(display))",
            "return false;",
        ),
        "bounded exact-connection controlled screenshot admission",
    )
    connection_drop = extract_item(
        sources["server_connection"],
        "impl Drop for Connection",
        "connection drop cleanup",
    )
    require_order(
        connection_drop,
        (
            "let id = self.inner.id();",
            "if let Some(tx) = self.inner.tx.as_ref()",
            "video_service::cancel_take_screenshot(id, tx);",
        ),
        "exact-channel screenshot cancellation on connection drop",
    )
    require(
        sources["peer_text"],
        "pub fn is_bounded_peer_screenshot_request_id(request_id: &str) -> bool",
        "controlled screenshot request-ID predicate",
    )
    require_order(
        sources["peer_text"],
        (
            "!request_id.is_empty()",
            "request_id.len() <= MAX_PEER_SCREENSHOT_SID_BYTES",
            "!request_id.chars().any(char::is_control)",
        ),
        "nonempty bounded control-free screenshot request IDs",
    )
    for behavior_test in (
        "r_s11ef_concurrent_connections_keep_distinct_screenshot_requests",
        "r_s11ef_in_flight_request_has_one_replaceable_successor",
        "r_s11ef_stale_channel_cannot_cancel_reused_connection_id",
        "r_s11ef_disconnect_retires_pending_and_in_flight_authority",
        "r_s11ef_texture_retry_never_overwrites_newer_pending_request",
        "r_s11ef_texture_retry_is_owned_and_happens_only_once",
        "r_s11ef_screenshot_owner_table_is_bounded",
        "r_s11ef_screenshot_dimensions_and_pixels_are_bounded",
        "r_s11ef_png_writer_stops_at_encoded_byte_limit",
    ):
        require(video_service, behavior_test, f"controlled screenshot behavior proof {behavior_test}")
    require(
        sources["peer_text"],
        "screenshot_request_ids_are_nonempty_bounded_labels",
        "controlled screenshot request-ID behavior proof",
    )
    require(
        sources["requirements"],
        '<span class="id">R-S11ef</span>',
        "controlled screenshot ownership normative requirement",
    )
    require(
        sources["requirements"],
        "<tr><td>285</td>",
        "controlled screenshot ownership Appendix C disposition",
    )
    require(
        sources["hardening"],
        "R-S11ef/R-S11e-150",
        "controlled screenshot ownership hardening ledger",
    )
    require(
        sources["verify"],
        '"${RUN[@]}" cargo test --lib --features linux-pkg-config \\\n'
        "  server::video_service::screenshot_ownership_tests::r_s11ef_ -- --test-threads=1",
        "shared controlled screenshot behavior gate wiring",
    )
    require(
        sources["dart_verify"],
        "server::video_service::screenshot_ownership_tests::r_s11ef_",
        "generated-bridge controlled screenshot behavior gate wiring",
    )

    require(
        video_service,
        "const MAX_VIDEO_FRAME_ACK_CONTROLLERS: usize = 64;",
        "controlled video acknowledgement controller capacity",
    )
    require(
        video_service,
        "static ref VIDEO_FRAME_ACK_CONTROLLERS: Mutex<HashMap<VideoFrameStreamKey, Weak<VideoFrameAckState>>> = Default::default();",
        "exact source/display video acknowledgement registry",
    )
    video_ack_state = extract_item(
        video_service,
        "impl VideoFrameAckState",
        "controlled video acknowledgement round state",
    )
    require_order(
        video_service,
        (
            "enum VideoFrameTargetState {",
            "Pending,",
            "Retired,",
            "Acknowledged,",
            "targets: HashMap<i32, VideoFrameTargetState>,",
            "progressed: bool,",
            "fn capture_may_advance(&self) -> bool",
            "self.targets.is_empty() || self.progressed",
        ),
        "bounded per-target shared capture progress model",
    )
    require_order(
        video_ack_state,
        (
            "fn reset(&self)",
            "round.targets.clear();",
            "round.progressed = false;",
            "fn prepare(&self, connection_ids: &HashSet<i32>, generation: u64) -> ResultType<()>",
            "generation == 0 || generation <= round.generation",
            "round.generation = generation;",
            "round.targets.clear();",
            "round.targets.extend(",
            "VideoFrameTargetState::Pending",
            "round.progressed = false;",
            "fn acknowledge(&self, generation: u64, connection_id: i32)",
            "round.generation != generation",
            "round.targets.get_mut(&connection_id)",
            "*state != VideoFrameTargetState::Pending",
            "*state = VideoFrameTargetState::Acknowledged;",
            "round.progressed = true;",
            "fn retire_connection(&self, connection_id: i32)",
            "round.targets.remove(&connection_id).is_some()",
            "fn retire(&self, generation: u64, connection_id: i32)",
            "round.generation != generation",
            "round.targets.get_mut(&connection_id)",
            "*state = VideoFrameTargetState::Retired;",
            "fn wait_for_progress(&self, timeout: Duration)",
            ".wait_timeout_while(round, timeout, |round| !round.capture_may_advance())",
        ),
        "bounded generation-exact shared capture progress round",
    )
    video_ack_controller = extract_item(
        video_service,
        "impl VideoFrameController",
        "controlled video acknowledgement controller",
    )
    require_order(
        video_ack_controller,
        (
            "fn new(source: VideoSource, display_idx: usize)",
            "controllers.retain(|_, state| state.strong_count() != 0);",
            ".and_then(Weak::upgrade)",
            "controllers.len() >= MAX_VIDEO_FRAME_ACK_CONTROLLERS",
            "controllers.insert(key, Arc::downgrade(&state));",
            "fn prepare(&self, connection_ids: &HashSet<i32>, generation: u64)",
            "fn wait_for_progress(&self, timeout: Duration)",
        ),
        "bounded exact source/display video controller registration",
    )
    require_order(
        video_service,
        (
            "fn frame_wait_can_finish(",
            "sp.is_option_true(OPTION_REFRESH)",
            "frame_controller.wait_for_progress(timeout)",
        ),
        "refresh-interruptible shared video capture wait",
    )
    video_ack_drop = extract_item(
        video_service,
        "impl Drop for VideoFrameController",
        "controlled video acknowledgement controller cleanup",
    )
    require_order(
        video_ack_drop,
        (
            ".and_then(Weak::upgrade)",
            "Arc::ptr_eq(&state, &self.state)",
            "controllers.remove(&self.key);",
            "self.state.reset();",
        ),
        "exact-generation video controller retirement",
    )
    require_order(
        video_service,
        (
            "pub fn notify_video_frame_fetched(",
            "source: VideoSource,",
            "display_idx: usize,",
            "round: u64,",
            "conn_id: i32,",
            "state.acknowledge(round, conn_id)",
            "pub fn retire_video_frame_round(",
            "state.retire(round, conn_id);",
            "pub fn retire_video_frame_connection(conn_id: i32)",
            "controllers.retain(|_, state| state.strong_count() != 0);",
            ".filter_map(|(_, state)| state.upgrade())",
            "state.retire_connection(conn_id);",
        ),
        "generation-exact writer completion and trusted local retirement callbacks",
    )
    for retired_callback in (
        "notify_video_frame_fetched_by_conn_id",
        "Some(misc::Union::VideoReceived(_))",
    ):
        forbid(
            sources["server_connection"] + video_service,
            retired_callback,
            f"retired ambiguous video acknowledgement callback {retired_callback}",
        )
    video_run = extract_item(
        video_service,
        "fn run(vs: VideoService)",
        "controlled video capture loop",
    )
    require_order(
        video_run,
        (
            "let frame_controller = VideoFrameController::new(source, display_idx)?;",
            "frame_controller.reset();",
            "frame_wait_can_finish(&sp, &frame_controller, Duration::from_millis(300))",
        ),
        "source-exact progress-paced controlled video capture loop",
    )
    video_handle_one_frame = extract_item(
        video_service,
        "fn handle_one_frame",
        "controlled video frame sender",
    )
    require_order(
        video_handle_one_frame,
        (
            "sp.send_video_frame_with_targets(",
            "frame_controller.key.source,",
            "frame_controller.key.display_idx,",
            "|connection_ids, generation| frame_controller.prepare(connection_ids, generation)",
        ),
        "generation/source/display-exact video acknowledgement frame send",
    )
    for retired in (
        "FRAME_FETCHED_NOTIFIERS",
        "DISPLAY_CONN_IDS",
        "#[tokio::main",
        "FrameFetchedNotifierSender",
        "FrameFetchedNotifierReceiver",
    ):
        forbid(
            video_service,
            retired,
            f"retired unbounded/display-only video acknowledgement path {retired}",
        )
    service_video_send = extract_item(
        sources["server_service"],
        "pub fn send_video_frame_with_targets",
        "prepare-before-enqueue video service API",
    )
    require_order(
        service_video_send,
        (
            "frame.generation != 0",
            "let conn_ids = lock.subscribes.keys().copied().collect::<HashSet<_>>();",
            "lock.video_frame_generation.checked_add(1)",
            "lock.video_frame_generation = generation;",
            "prepare(&conn_ids, generation)?;",
            "frame.generation = generation;",
            "let msg = Arc::new(msg);",
            "for subscriber in lock.subscribes.values_mut()",
            "subscriber.send_video_frame(Arc::clone(&msg), source, display, generation);",
        ),
        "service-lifetime wire generation and acknowledgement ownership precede mailbox enqueue",
    )

    server_connection = sources["server_connection"]
    require(
        server_connection,
        "const VIDEO_EGRESS_WAKE_CAPACITY: usize = 1;",
        "controlled video egress wake capacity",
    )
    require(
        server_connection,
        "const VIDEO_EGRESS_MAX_DISPLAYS: usize = 32;",
        "controlled video egress display capacity",
    )
    video_egress_state = extract_item(
        server_connection,
        "struct VideoEgressState",
        "bounded controlled video egress state",
    )
    require_order(
        video_egress_state,
        (
            "switch_display: Option<(Instant, Arc<Message>)>",
            "displays: HashMap<usize, VideoDisplayEgress>",
            "ready_displays: VecDeque<usize>",
        ),
        "bounded per-display controlled video egress state",
    )
    video_display_default = extract_item(
        server_connection,
        "impl Default for VideoDisplayEgress",
        "fresh controlled video display state",
    )
    require_order(
        video_display_default,
        (
            "pending: None",
            "awaiting_independent: true",
            "ready: false",
        ),
        "fresh display waits for an independently decodable frame",
    )
    video_egress_sender = extract_item(
        server_connection,
        "impl VideoEgressSender",
        "controlled video egress sender",
    )
    require_count(
        video_egress_sender,
        "slot.pending = Some(PendingVideoEgress::RefreshRequired);",
        2,
        "both dependent suppression paths request an independent sequence",
    )
    require_order(
        video_egress_sender,
        (
            "self.wake.try_send(())",
            "fn mark_ready(state: &mut VideoEgressState, display: usize)",
            "fn send_video_frame(",
            "source: VideoSource,",
            "display: usize,",
            "generation: u64,",
            "frame.generation != generation",
            "starts_video_sequence(frame)",
            "state.displays.len() >= VIDEO_EGRESS_MAX_DISPLAYS",
            "let previous = slot.pending.take();",
            "retired.push(previous.identity());",
            "if independent",
            "slot.awaiting_independent = false;",
            "slot.awaiting_independent = true;",
            "slot.pending = Some(PendingVideoEgress::RefreshRequired);",
            "Self::mark_ready(&mut state, display);",
            "!self.wake_receiver()",
            "retired.push(identity);",
            "fn send_switch_display(&self, message: Arc<Message>)",
            "state.switch_display = Some((Instant::now(), message));",
            "state.displays.clear();",
        ),
        "bounded GOP-aware per-display controlled video enqueue",
    )
    video_egress_receiver = extract_item(
        server_connection,
        "impl VideoEgressReceiver",
        "controlled video egress receiver",
    )
    require_order(
        video_egress_receiver,
        (
            "fn with_connection_owner(mut self, connection_id: i32)",
            "self.connection_id = Some(connection_id);",
            "state.switch_display.take()",
            "state.ready_displays.pop_front()",
            "slot.pending.take()",
            "pub(crate) async fn recv(&mut self)",
            "self.wake.recv().await?",
        ),
        "switch-first fair event-driven controlled video dequeue",
    )
    video_egress_drop = extract_item(
        server_connection,
        "impl Drop for VideoEgressReceiver",
        "controlled video receiver retirement",
    )
    require_order(
        video_egress_drop,
        (
            "self.wake.close();",
            "state.displays.clear();",
            "drop(state);",
            "video_service::retire_video_frame_connection(connection_id);",
        ),
        "receiver closes admission before retiring exact connection ownership",
    )
    pending_video_delivery = extract_item(
        server_connection,
        "impl PendingVideoDelivery",
        "two-event exact peer video delivery",
    )
    require_order(
        pending_video_delivery,
        (
            "writer_receipt: Some(writer_receipt)",
            "writer_complete: false",
            "peer_received: false",
            "fn mark_writer_complete(&mut self)",
            "self.writer_complete = true;",
            "fn observe_peer_receipt(",
            "authenticated_source != Some(self.identity.source)",
            "usize::try_from(receipt.display).ok() != Some(self.identity.display)",
            "receipt.generation == 0",
            "receipt.generation != self.identity.generation",
            "self.peer_received = true;",
            "fn is_complete(&self)",
            "self.writer_complete && self.peer_received",
        ),
        "exact writer and authenticated peer receipt conjunction",
    )
    complete_video_delivery = extract_item(
        server_connection,
        "fn complete_video_delivery",
        "exact video delivery completion",
    )
    require_order(
        complete_video_delivery,
        (
            "PendingVideoDelivery::is_complete",
            "let Some(pending) = pending.take()",
            "video_service::notify_video_frame_fetched(",
            "pending.identity.source,",
            "pending.identity.display,",
            "pending.identity.generation,",
        ),
        "capture progress only after the two-event conjunction",
    )
    require_order(
        server_connection,
        (
            "let mut rx_video = rx_video.with_connection_owner(id);",
            "Some(message::Union::VideoFrameReceipt(receipt))",
            "conn.authenticated_video_source()",
            "complete_video_delivery(&mut pending_video_delivery, id);",
            "completion = wait_for_video_write(&mut pending_video_delivery)",
            "Ok(Ok(()))",
            "pending.mark_writer_complete();",
            "complete_video_delivery(&mut pending_video_delivery, id);",
            "item = rx_video.recv(), if pending_video_delivery.is_none()",
            "conn.stream.send_with_receipt(frame.message.as_ref()).await",
            "Some(PendingVideoDelivery::new(receipt, &frame))",
            "video_service::retire_video_frame_connection(id);",
        ),
        "either-order writer and exact peer receipt ownership before generation acknowledgement",
    )
    require_order(
        server_connection,
        (
            "fn login_video_frame_receipt_version_is_compatible",
            "login.video_frame_receipt_version == VIDEO_FRAME_RECEIPT_VERSION",
            "if !login_video_frame_receipt_version_is_compatible(&lr)",
            '"Incompatible remote video protocol. Upgrade both RustDesk peers."',
            "fn authenticated_video_source(&self) -> Option<VideoSource>",
            "Some(VideoSource::Monitor)",
            "Some(VideoSource::Camera)",
        ),
        "video capability refusal and authenticated source derivation",
    )

    viewer_receipts = extract_item(
        sources["io_loop"],
        "impl VideoFrameReceiptTracker",
        "viewer exact video receipt tracker",
    )
    require_order(
        viewer_receipts,
        (
            "display >= MAX_PEER_VIDEO_DISPLAYS",
            "generation == 0",
            "generation <= *last",
            "self.last_generation.insert(display, generation);",
            "VideoFrameReceipt {",
            "display: i32::try_from(display)",
            "generation,",
        ),
        "bounded nonzero monotonic per-display viewer receipt identity",
    )
    require_order(
        sources["io_loop"],
        (
            "self.video_frame_receipts_negotiated = false;",
            "self.video_frame_receipt_tracker.reset();",
            "Some(message::Union::VideoFrame(vf))",
            "if !self.video_frame_receipts_negotiated",
            "native_video_frame_runtime_supported(&vf)",
            "Self::native_video_frame_within_limit(&vf)",
            "let Ok(display) = usize::try_from(vf.display)",
            "self.accept_peer_video_display(display)",
            ".admit(display, vf.generation)",
            "receipt_message.set_video_frame_receipt(receipt);",
            "peer.send(&receipt_message).await",
            "if !self.first_frame",
            "if !self.video_threads.contains_key(&display) && !self.new_video_thread(display)",
            "return false;",
            "let Some(thread) = self.video_threads.get_mut(&display) else",
            '"video decoder ownership missing after admission for display {display}"',
            "return false;",
            "thread.media_thread.admit_frame(vf, is_keyframe)",
        ),
        "viewer receipt after keyed parse/identity validation and before decode publication",
    )
    require_order(
        sources["io_loop"],
        (
            "pi.video_frame_receipt_version != VIDEO_FRAME_RECEIPT_VERSION",
            '"Incompatible remote video protocol"',
            "self.video_frame_receipts_negotiated =",
        ),
        "viewer requires the echoed exact receipt capability",
    )
    require_order(
        sources["client"],
        (
            "video_frame_receipt_version: if matches!(",
            "ConnType::DEFAULT_CONN | ConnType::VIEW_CAMERA",
            "VIDEO_FRAME_RECEIPT_VERSION",
        ),
        "viewer advertises exact receipts only for video sessions",
    )

    transport_tcp = sources["transport_tcp"]
    writer_command = extract_item(
        transport_tcp,
        "enum WriterCommand",
        "sole transport writer command",
    )
    require_order(
        writer_command,
        (
            "Frame {",
            "bytes: Bytes,",
            "reservation: WriterFrameReservation,",
            "completion: Option<oneshot::Sender<io::Result<()>>>",
            "Drain(oneshot::Sender<io::Result<()>>)",
        ),
        "exact optional receipt on the existing writer FIFO",
    )
    send_with_receipt = extract_item(
        transport_tcp,
        "pub async fn send_with_receipt",
        "tracked transport send",
    )
    require_order(
        send_with_receipt,
        (
            "msg.write_to_bytes()?",
            "self.poison",
            "self.send_bytes_raw_with_receipt(bytes).await",
            "self.poison_and_retire_writer();",
        ),
        "tracked transport send preserves fatal poison ownership",
    )
    writer_task = extract_item(transport_tcp, "async fn writer_task", "sole writer task")
    require_order(
        writer_task,
        (
            "WriterCommand::Frame {",
            "bytes,",
            "reservation,",
            "completion,",
            "let result = sink.send(bytes).await;",
            "let failed = result.is_err();",
            "if failed",
            "drop(reservation);",
            "completion.send(result)",
            "return;",
            "drop(reservation);",
            "completion.send(result)",
        ),
        "exact sink result completes tracked writer receipt",
    )
    require(
        sources["transport_stream"],
        "pub async fn send_with_receipt(",
        "stream wrapper exposes exact writer receipt",
    )
    require(
        sources["message_proto"],
        "reserved 2, 9, 12, 14;",
        "retired login video acknowledgement tag reservation",
    )
    require(
        sources["message_proto"],
        "reserved 12; // retired displayless acknowledgement; versioned top-level exact receipts own peer progress",
        "retired displayless video acknowledgement tag reservation",
    )
    forbid(
        sources["message_proto"],
        "video_ack_required = 9",
        "unused peer video acknowledgement negotiation",
    )
    forbid(
        sources["message_proto"],
        "video_received = 12",
        "unused displayless peer video acknowledgement",
    )
    for exact_wire_field, label in (
        ("uint64 generation = 15;", "nonzero video wire generation"),
        ("message VideoFrameReceipt {", "typed exact video receipt"),
        ("uint32 video_frame_receipt_version = 18;", "viewer receipt capability"),
        ("uint32 video_frame_receipt_version = 14;", "controlled receipt capability echo"),
        ("VideoFrameReceipt video_frame_receipt = 33;", "top-level exact video receipt"),
    ):
        require(sources["message_proto"], exact_wire_field, label)
    require(
        sources["hbb_common_lib"],
        "pub const VIDEO_FRAME_RECEIPT_VERSION: u32 = 1;",
        "shared exact video receipt protocol version",
    )
    require(
        sources["hbb_common_lib"],
        "r_s11fk_wire_round_trips_exact_video_identity_and_capability",
        "exact video protocol wire round-trip behavior proof",
    )
    for behavior_test in (
        "r_s11eg_monitor_and_camera_acknowledgements_are_source_exact",
        "r_s11eg_controller_registration_is_bounded_and_exactly_retired",
        "r_s11eg_acknowledgement_round_is_installed_before_frame_enqueue",
        "r_s11fb_late_completion_cannot_satisfy_a_new_round",
        "r_s11fb_local_disconnect_retires_all_exact_pending_sources",
        "r_s11fk_controller_rejects_zero_and_reused_wire_generations",
        "r_s11fl_one_exact_peer_receipt_paces_shared_capture_without_the_slow_peer",
        "r_s11fl_blocked_capture_wait_wakes_on_one_exact_peer_receipt",
        "r_s11fl_superseded_frame_is_not_peer_progress_for_its_exact_round",
        "r_s11fl_empty_or_fully_disconnected_round_does_not_delay_capture",
        "r_s11fl_refresh_interrupts_an_obsolete_capture_wait",
    ):
        require(video_service, behavior_test, f"video acknowledgement behavior proof {behavior_test}")
    for blocked_wait_proof, label in (
        ("test_waiter_blocked: std::sync::atomic::AtomicBool", "test-only blocked-wait state"),
        (".store(true, std::sync::atomic::Ordering::SeqCst)", "blocked-wait entry proof"),
        ("while !wait_state", "blocked-wait observation before receipt"),
    ):
        require(video_service, blocked_wait_proof, label)
    for behavior_test in (
        "r_s11fb_latest_independent_frame_replaces_only_the_same_display",
        "r_s11fb_fresh_display_rejects_dependent_until_independent",
        "r_s11fb_dependent_replacement_requests_an_independent_sequence",
        "r_s11fb_displays_are_isolated_and_round_robin_ready",
        "r_s11fb_switch_display_precedes_new_video_and_retires_old_video",
        "r_s11fb_display_ownership_is_fixed_capacity",
        "r_s11fb_async_video_egress_waits_without_polling_and_closes",
        "r_s11fb_closed_receiver_retires_a_stale_subscriber_enqueue",
        "r_s11fk_local_write_then_exact_peer_receipt_completes_once",
        "r_s11fk_exact_peer_receipt_then_local_write_completes",
        "r_s11fk_wrong_scope_zero_stale_and_mismatched_receipts_are_inert",
        "r_s11fk_video_login_requires_exact_version_without_affecting_nonvideo_sessions",
    ):
        require(server_connection, behavior_test, f"video egress behavior proof {behavior_test}")
    for behavior_test in (
        "r_s11fk_viewer_receipts_are_nonzero_display_exact_and_monotonic",
        "r_s11fk_viewer_receipt_tracker_resets_only_at_connection_replacement",
    ):
        require(sources["io_loop"], behavior_test, f"viewer exact receipt behavior proof {behavior_test}")
    require(
        sources["client"],
        "r_s11fk_login_negotiates_exact_receipts_only_for_video_sessions",
        "viewer login capability behavior proof",
    )
    for behavior_test in (
        "r_s11fb_receipt_waits_for_the_exact_sink_send",
        "r_s11fb_receipt_reports_the_exact_sink_failure",
        "r_s11fb_tracked_keyed_send_round_trips_the_exact_frame",
        "r_s11fk_real_tcp_receipt_can_precede_peer_read",
    ):
        require(transport_tcp, behavior_test, f"writer receipt behavior proof {behavior_test}")
    require(
        sources["requirements"],
        '<span class="id">R-S11eg</span>',
        "controlled video acknowledgement normative requirement",
    )
    require(
        sources["requirements"],
        "<tr><td>286</td>",
        "controlled video acknowledgement Appendix C disposition",
    )
    require(
        sources["hardening"],
        "R-S11eg/R-S11e-151",
        "controlled video acknowledgement hardening ledger",
    )
    require(
        sources["requirements"],
        '<span class="id">R-S11fb</span>',
        "controlled video egress normative requirement",
    )
    require(
        sources["requirements"],
        "<tr><td>310</td>",
        "controlled video egress Appendix C disposition",
    )
    require(
        sources["hardening"],
        "**R-S11fb/R-S11e-189 controlled video exact-writer egress",
        "controlled video egress hardening ledger",
    )
    require(
        sources["requirements"],
        '<span class="id">R-S11fk</span>',
        "controlled video exact peer receipt normative requirement",
    )
    require(
        sources["requirements"],
        "<tr><td>319</td>",
        "controlled video exact peer receipt Appendix C disposition",
    )
    require(
        sources["hardening"],
        "R-S11fk/R-S11e-198 controlled-video exact peer receipt",
        "controlled video exact peer receipt hardening ledger",
    )
    require(
        sources["requirements"],
        '<span class="id">R-S11fl</span>',
        "controlled video shared capture pacing normative requirement",
    )
    require(
        sources["requirements"],
        "<tr><td>320</td>",
        "controlled video shared capture pacing Appendix C disposition",
    )
    require(
        sources["hardening"],
        "R-S11fl/R-S11e-199 controlled-video shared capture pacing",
        "controlled video shared capture pacing hardening ledger",
    )
    require(
        sources["verify"],
        '"${RUN[@]}" cargo test --lib --features linux-pkg-config \\\n'
        "  server::video_service::video_frame_ack_tests::r_s11eg_ -- --test-threads=1",
        "shared controlled video acknowledgement behavior gate wiring",
    )
    require(
        sources["verify"],
        '"${RUN[@]}" cargo test --lib --features linux-pkg-config \\\n'
        "  server::video_service::video_frame_ack_tests::r_s11fl_ -- --test-threads=1",
        "shared controlled video pacing behavior gate wiring",
    )
    require(
        sources["verify"],
        '"${RUN[@]}" cargo test --lib --features linux-pkg-config \\\n'
        "  server::connection::video_egress_tests::r_s11fb_ -- --test-threads=1",
        "shared controlled video egress behavior gate wiring",
    )
    require(
        sources["verify"],
        '"${RUN[@]}" cargo test -p hbb_common writer_receipt_tests::r_s11fb_ -- --test-threads=1',
        "shared exact writer receipt behavior gate wiring",
    )
    require(
        sources["verify"],
        '"${RUN[@]}" cargo test --lib --features linux-pkg-config r_s11fk_ -- --test-threads=1',
        "shared exact peer video receipt behavior gate wiring",
    )
    require(
        sources["verify"],
        '"${RUN[@]}" cargo test -p hbb_common exact_video_receipt_wire_tests::r_s11fk_ -- --test-threads=1',
        "shared exact video protocol wire behavior gate wiring",
    )
    require(
        sources["verify"],
        '"${RUN[@]}" cargo test -p hbb_common writer_receipt_tests::r_s11fk_real_tcp_receipt_can_precede_peer_read -- --test-threads=1',
        "shared real TCP local-receipt boundary behavior gate wiring",
    )
    require(
        sources["dart_verify"],
        "server::video_service::video_frame_ack_tests::r_s11eg_",
        "generated-bridge controlled video acknowledgement behavior gate wiring",
    )
    require(
        sources["dart_verify"],
        "server::video_service::video_frame_ack_tests::r_s11fl_",
        "generated-bridge controlled video pacing behavior gate wiring",
    )
    require(
        sources["dart_verify"],
        "server::connection::video_egress_tests::r_s11fb_",
        "generated-bridge controlled video egress behavior gate wiring",
    )
    require(
        sources["dart_verify"],
        "writer_receipt_tests::r_s11fb_",
        "generated-bridge exact writer receipt behavior gate wiring",
    )
    require(
        sources["dart_verify"],
        "      r_s11fk_ -- --test-threads=1",
        "generated-bridge exact peer video receipt behavior gate wiring",
    )
    require(
        sources["dart_verify"],
        "exact_video_receipt_wire_tests::r_s11fk_",
        "generated-bridge exact video protocol wire behavior gate wiring",
    )
    require(
        sources["dart_verify"],
        "writer_receipt_tests::r_s11fk_real_tcp_receipt_can_precede_peer_read",
        "generated-bridge real TCP local-receipt boundary behavior gate wiring",
    )

    require(
        server_connection,
        "const AUDIO_EGRESS_WAKE_CAPACITY: usize = 1;",
        "audio egress wake capacity",
    )
    audio_state = extract_item(
        server_connection,
        "struct AudioEgressState",
        "bounded audio egress state",
    )
    require_order(
        audio_state,
        (
            "format: Option<(Instant, Arc<Message>)>",
            "frame: Option<(Instant, Arc<Message>)>",
        ),
        "one-format one-frame audio state",
    )
    for retired in ("Vec<", "VecDeque", "HashMap", "Unbounded"):
        forbid(audio_state, retired, f"unbounded audio state shape {retired}")

    audio_channel = extract_item(
        server_connection,
        "pub(crate) fn audio_egress_channel()",
        "bounded audio egress channel",
    )
    require_order(
        audio_channel,
        (
            "AudioEgressState::default()",
            "mpsc::channel(AUDIO_EGRESS_WAKE_CAPACITY)",
            "AudioEgressSender",
            "AudioEgressReceiver",
        ),
        "bounded audio state plus capacity-one wake construction",
    )
    audio_sender = extract_item(
        server_connection,
        "impl AudioEgressSender",
        "nonblocking audio egress sender",
    )
    require_order(
        audio_sender,
        (
            "Some(message::Union::AudioFrame(_))",
            "state.frame = Some(queued);",
            "Some(message::Union::Misc(misc))",
            "Some(misc::Union::AudioFormat(_))",
            "state.format = Some(queued);",
            "state.frame = None;",
            "self.wake.try_send(())",
            "TrySendError::Full(_)",
            "TrySendError::Closed(_)",
            "state.format = None;",
            "state.frame = None;",
        ),
        "latest-frame format-generation and wake coalescing",
    )
    for retired in (
        "unbounded_channel",
        "tokio::spawn",
        "std::thread",
        "Runtime::new",
        "block_on",
        "thread::sleep",
    ):
        forbid(audio_sender, retired, f"retired audio sender shape {retired}")

    audio_receiver = extract_item(
        server_connection,
        "impl AudioEgressReceiver",
        "event-driven audio egress receiver",
    )
    require_order(
        audio_receiver,
        (
            "state.format.take().or_else(|| state.frame.take())",
            "pub(crate) async fn recv",
            "if let Some(queued) = self.take_next()",
            "self.wake.recv().await?",
            "fn blocking_recv",
            "self.wake.blocking_recv()?",
        ),
        "format-first async and blocking event-driven receive",
    )
    for retired in (
        "try_recv",
        "tokio::spawn",
        "std::thread",
        "Runtime::new",
        "block_on",
        "thread::sleep",
    ):
        forbid(audio_receiver, retired, f"retired audio receiver shape {retired}")
    audio_receiver_drop = extract_item(
        server_connection,
        "impl Drop for AudioEgressReceiver",
        "audio receiver retained-state retirement",
    )
    require_order(
        audio_receiver_drop,
        (
            "self.wake.close();",
            "lock_audio_egress_state(&self.state)",
            "state.format = None;",
            "state.frame = None;",
        ),
        "receiver close before retained audio release",
    )
    forbid(
        audio_receiver_drop,
        ".await",
        "asynchronous audio receiver Drop cleanup",
    )
    require_order(
        server_connection,
        (
            'log::error!("audio egress state was poisoned")',
            "poisoned.into_inner()",
        ),
        "diagnosed audio mutex poison recovery",
    )

    audio_constructor = extract_item(
        sources["client"],
        "pub fn start_audio_thread()",
        "sole owning audio constructor",
    )
    require_order(
        audio_constructor,
        (
            "-> OwnedMediaThread",
            "let (audio_sender, thread) = new_audio_thread();",
            'OwnedMediaThread::new("audio decoder", audio_sender, thread)',
        ),
        "sole owning audio constructor",
    )
    forbid(
        audio_constructor,
        "let (audio_sender, _thread) = new_audio_thread();",
        "detached audio constructor worker",
    )
    controlled_audio_owner = extract_item(
        server_connection,
        "struct ControlledAudioThread",
        "controlled audio exact owner",
    )
    require_order(
        controlled_audio_owner,
        (
            "format: (u32, u32)",
            "decoder: OwnedMediaThread",
        ),
        "controlled audio format and decoder owner",
    )
    connection_owner = extract_item(
        server_connection,
        "pub struct Connection",
        "controlled connection exact owner",
    )
    require(
        connection_owner,
        "controlled_audio: Option<ControlledAudioThread>",
        "controlled audio owner field",
    )
    for retired, label in (
        ("audio_sender:", "retired controlled audio sender field"),
        ("audio_format:", "retired controlled audio format field"),
        ("voice_calling:", "retired controlled voice-call boolean field"),
    ):
        forbid(connection_owner, retired, label)

    conn_inner = extract_item(server_connection, "pub struct ConnInner", "connection subscriber")
    require(
        conn_inner,
        "tx_audio: Option<AudioEgressSender>",
        "exact connection audio sender",
    )
    subscriber_send = extract_item(
        server_connection,
        "impl Subscriber for ConnInner",
        "connection service routing",
    )
    require_order(
        subscriber_send,
        (
            "let tx_by_audio = match &msg.union",
            "Some(message::Union::AudioFrame(_))",
            "Some(misc::Union::AudioFormat(_))",
            "if tx_by_audio",
            "self.tx_audio.as_ref()",
            "tx.send(msg);",
            "return;",
            "match &msg.union",
            "Some(message::Union::VideoFrame(_))",
            "video frame bypassed exact acknowledgement-round enqueue",
            "Some(misc::Union::SwitchDisplay(_))",
            "tx.send_switch_display(msg)",
        ),
        "audio route before video/general routes",
    )

    connection_start = extract_item(
        server_connection,
        "pub async fn start(",
        "controlled connection run loop",
    )
    require_order(
        connection_start,
        (
            "let (tx, mut rx) = control_egress_channel();",
            "let (tx_video, rx_video) = video_egress_channel();",
            "let (tx_audio, mut rx_audio) = audio_egress_channel();",
            "ConnInner::with_audio(id, Some(tx), Some(tx_video), Some(tx_audio))",
            "Some((instant, value)) = rx_audio.recv()",
            "instant.elapsed() > Duration::from_secs(1)",
            "Some(message::Union::AudioFrame(_))",
            "conn.stream.send(&value as &Message).await",
            "item = rx.recv()",
            "ControlEgressItem::Message(message) => message",
            "ControlEgressItem::Failed(failure)",
        ),
        "controlled bounded audio mailbox to sole stream writer",
    )
    general_start = connection_start.index("item = rx.recv()")
    general_end = connection_start.index("_ = second_timer.tick()", general_start)
    forbid(
        connection_start[general_start:general_end],
        "message::Union::AudioFrame",
        "audio handling in general unbounded connection queue",
    )
    for retired in (
        "let (tx, mut rx) = mpsc::unbounded_channel",
        "let (tx_audio, mut rx_audio) = mpsc::unbounded_channel",
        "Some((instant, value)) = rx.recv()",
    ):
        forbid(connection_start, retired, f"retired unbounded audio connection shape {retired}")

    io_loop = sources["io_loop"]
    voice_owner = extract_item(io_loop, "struct VoiceCallAudio", "outgoing voice-call audio owner")
    require_order(
        voice_owner,
        (
            "subscription: Option<ConnInner>",
            "input_lease: Option<audio_service::VoiceCallInputLease>",
            "receiver: AudioEgressReceiver",
        ),
        "exact outgoing subscription/input/receiver owner",
    )
    voice_stop = extract_item(io_loop, "fn stop(&mut self)", "outgoing voice-call stop")
    require_order(
        voice_stop,
        (
            "if let Some(subscription) = self.subscription.take()",
            ".subscribe(audio_service::NAME, subscription, false)",
            "drop(self.input_lease.take());",
        ),
        "exact unsubscribe before outgoing input release",
    )
    voice_receive = extract_item(
        io_loop,
        "async fn recv_voice_call_audio(",
        "outgoing event-driven audio receive",
    )
    require_order(
        voice_receive,
        (
            "voice_call.as_mut()",
            "voice_call.receiver.recv().await",
            "None => std::future::pending().await",
        ),
        "outgoing exact-owner async receive",
    )
    voice_start = extract_item(
        io_loop,
        "fn start_voice_call(&mut self) -> Option<VoiceCallAudio>",
        "outgoing voice-call audio start",
    )
    require_order(
        voice_start,
        (
            "acquire_voice_call_input(get_default_sound_input())",
            "let (tx_audio_data, rx_audio_data) = audio_egress_channel();",
            "ConnInner::with_audio(conn_id, None, None, Some(tx_audio_data))",
            "client_conn_inner.clone()",
            "true",
            "VoiceCallAudio::new(",
            "client_conn_inner",
            "input_lease",
            "rx_audio_data",
        ),
        "outgoing exact bounded audio owner construction",
    )
    outgoing_round = extract_item(io_loop, "pub async fn io_loop(", "outgoing connection round")
    require_order(
        outgoing_round,
        (
            "voice_call_audio = recv_voice_call_audio(&mut self.voice_call_audio)",
            "let Some(message) = voice_call_audio",
            "peer.send(&message as &Message).await",
        ),
        "outgoing bounded receiver to sole stream writer",
    )
    branch_start = outgoing_round.index(
        "voice_call_audio = recv_voice_call_audio(&mut self.voice_call_audio)"
    )
    branch_end = outgoing_round.index("clip_item = rx_clip_client.recv()", branch_start)
    for retired in ("self.sender.send", "Data::Message", "tokio::spawn", "std::thread"):
        forbid(
            outgoing_round[branch_start:branch_end],
            retired,
            f"outgoing audio intermediate path {retired}",
        )
    for retired in (
        "VoiceCallThread",
        "voice_call_thread",
        "rustdesk-viewer-voice-call",
        'reap_media_worker("voice-call"',
        "tx_audio.send(Data::Message",
    ):
        forbid(io_loop, retired, f"retired outgoing voice worker shape {retired}")

    for behavior_test in (
        "r_s11eh_audio_egress_retains_only_the_latest_frame",
        "r_s11eh_audio_format_precedes_its_latest_frame",
        "r_s11eh_new_audio_format_retires_an_old_pending_frame",
        "r_s11eh_conn_inner_routes_audio_away_from_control_and_video",
        "r_s11eh_audio_egress_closes_after_the_exact_sender_retires",
        "r_s11eh_async_audio_egress_waits_without_polling_and_closes",
    ):
        require(
            server_connection,
            behavior_test,
            f"bounded audio egress behavior proof {behavior_test}",
        )
    require(
        server_connection,
        "receiver retirement must release retained audio without another producer send",
        "receiver-retirement retained-audio behavior proof",
    )
    require(
        sources["requirements"],
        '<span class="id">R-S11eh</span>',
        "bounded audio egress normative requirement",
    )
    require(
        sources["requirements"],
        "<tr><td>287</td>",
        "bounded audio egress Appendix C disposition",
    )
    require(
        sources["hardening"],
        "R-S11eh/R-S11e-152",
        "bounded audio egress hardening ledger",
    )
    require(
        sources["verify"],
        '"${RUN[@]}" cargo test --lib --features linux-pkg-config \\\n'
        "  server::connection::audio_egress_tests::r_s11eh_ -- --test-threads=1",
        "shared bounded audio behavior gate wiring",
    )
    require(
        sources["dart_verify"],
        "server::connection::audio_egress_tests::r_s11eh_",
        "generated-bridge bounded audio behavior gate wiring",
    )

    input_owner = sources["input_owner"]
    require(
        input_owner,
        "internal data class ControlledInputOwner(\n"
        "    val serviceGeneration: Long,\n"
        "    val connectionId: Int,",
        "exact Android controlled-input owner",
    )
    require(
        input_owner,
        "get() = serviceGeneration > 0 && connectionId > 0",
        "controlled-input owner validity",
    )

    input_queue = sources["input_queue"]
    queue = extract_item(
        input_queue,
        "internal class ExactOwnerBoundedQueue",
        "exact-owner bounded Android input queue",
    )
    for needle, label in (
        (
            "private val entries = ArrayDeque<OwnedControlledInput<T>>()",
            "bounded queue storage",
        ),
        ("require(capacity > 0)", "positive queue capacity"),
        (
            "if (!owner.isValid || entries.size >= capacity)",
            "invalid-owner and capacity refusal",
        ),
        (
            "entries.addLast(OwnedControlledInput(owner, value))",
            "exact-owner queue admission",
        ),
        (
            "fun poll(): OwnedControlledInput<T>? = entries.pollFirst()",
            "FIFO queue consumption",
        ),
        ("if (iterator.next().owner == owner)", "exact-owner queue retirement"),
    ):
        require(queue, needle, label)
    forbid(input_queue, "LinkedList", "linked-list controlled input queue")

    capture_owner_state = sources["capture_owners"]
    require(
        capture_owner_state,
        "fun ownsRemoteInput(connectionId: Int): Boolean = owners.contains(connectionId)",
        "Remote-only service-owned input authority lookup",
    )

    main_service = sources["service"]
    pointer_entry = extract_item(
        main_service,
        "fun rustPointerInput(",
        "Android pointer JNI receiver",
    )
    require_order(
        pointer_entry,
        (
            "connectionId: Int",
            "val owner = controlledInputOwner(connectionId) ?: return false",
            "val inputService = InputService.ctx ?: return false",
            "if (!inputService.registerInputOwner(owner))",
            "return false",
            "inputService.onTouchInput(owner, mask, x, y)",
            "inputService.onMouseInput(owner, mask, x, y)",
        ),
        "exact-owner pointer admission and Boolean result",
    )
    key_entry = extract_item(
        main_service,
        "fun rustKeyEventInput(",
        "Android key JNI receiver",
    )
    require_order(
        key_entry,
        (
            "connectionId: Int",
            "val owner = controlledInputOwner(connectionId) ?: return false",
            "val inputService = InputService.ctx ?: return false",
            "if (!inputService.registerInputOwner(owner))",
            "return false",
            "return inputService.onKeyEvent(owner, input)",
        ),
        "exact-owner key admission and Boolean result",
    )
    controlled_input_owner = extract_item(
        main_service,
        "private fun controlledInputOwner(",
        "service-owned controlled-input authority",
    )
    require_order(
        controlled_input_owner,
        (
            "!acceptingControlledConnections",
            "nativeServerGeneration <= 0L",
            "!controlledCaptureOwners.ownsRemoteInput(connectionId)",
            "return null",
            "return ControlledInputOwner(nativeServerGeneration, connectionId)",
        ),
        "live generation and authenticated Remote input authority",
    )
    require_order(
        main_service,
        (
            "controlledCaptureOwners.upsert(id, authorized, connectionType)",
            "if (!controlledCaptureOwners.ownsRemoteInput(id))",
            "InputService.ctx?.retireInputOwner(inputOwner)",
        ),
        "authorization/type replacement input retirement",
    )
    require_order(
        main_service,
        (
            "val captureOwnerRemoved = controlledCaptureOwners.unregister(id)",
            "InputService.ctx?.retireInputOwner(",
            "ControlledInputOwner(nativeServerGeneration, id)",
        ),
        "connection-removal exact input retirement",
    )
    release_resources = extract_item(
        main_service,
        "private fun releaseControlledConnectionResources()",
        "controlled-service resource teardown",
    )
    require_order(
        release_resources,
        (
            "acceptingControlledConnections = false",
            "controlledCaptureOwners.clear()",
            "InputService.ctx?.retireServiceGeneration(nativeServerGeneration)",
            "releaseCaptureResources()",
        ),
        "admission-close then exact input-generation teardown",
    )

    input_service = sources["input_service"]
    for retired, label in (
        ("Timer()", "process-retained Timer thread"),
        ("TimerTask", "per-action Timer task"),
        ("wheelActionsQueue", "unbounded wheel linked list"),
        ("isWheelActionsPolling", "Timer-polled wheel state"),
        (
            "val handler = Handler(Looper.getMainLooper())",
            "per-key-event Handler allocation",
        ),
    ):
        forbid(input_service, retired, label)
    require_count(
        input_service,
        "Handler(Looper.getMainLooper())",
        1,
        "one retained Android input main Handler",
    )
    for needle, label in (
        (
            "private const val MAX_PENDING_WHEEL_ACTIONS = 32",
            "wheel queue capacity",
        ),
        (
            "private const val MAX_PENDING_KEY_ACTIONS = 64",
            "key queue capacity",
        ),
        (
            "private val activeInputOwners = mutableSetOf<ControlledInputOwner>()",
            "active exact input-owner set",
        ),
        (
            "ExactOwnerBoundedQueue<GestureDescription>(MAX_PENDING_WHEEL_ACTIONS)",
            "bounded wheel action queue",
        ),
        (
            "ExactOwnerBoundedQueue<KeyEvent>(MAX_PENDING_KEY_ACTIONS)",
            "bounded key action queue",
        ),
        (
            "private var wheelActionInFlight: OwnedControlledInput<GestureDescription>? = null",
            "one wheel gesture in flight",
        ),
        (
            "private var pendingLongPress: PendingOwnedAction? = null",
            "one delayed long press",
        ),
        (
            "private var pendingRecentAction: PendingOwnedAction? = null",
            "one delayed recents action",
        ),
        ("private enum class PointerSequence", "typed pointer sequence state"),
    ):
        require(input_service, needle, label)

    register_input_owner = extract_item(
        input_service,
        "internal fun registerInputOwner(",
        "controlled-input owner registration",
    )
    require_order(
        register_input_owner,
        (
            "if (destroyed || !owner.isValid)",
            "return false",
            "activeInputOwners.add(owner)",
            "return true",
        ),
        "valid live exact-owner registration",
    )
    retire_input_owner = extract_item(
        input_service,
        "internal fun retireInputOwner(",
        "controlled-input owner retirement",
    )
    require_order(
        retire_input_owner,
        (
            "activeInputOwners.remove(owner)",
            "wheelActions.removeOwner(owner)",
            "keyActions.removeOwner(owner)",
            "cancelLongPress(owner)",
            "cancelRecentAction(owner)",
            "if (pointerOwner == owner)",
            "finishAndResetPointerSequence()",
        ),
        "exact-owner delayed and pointer-state retirement",
    )
    retire_generation = extract_item(
        input_service,
        "internal fun retireServiceGeneration(",
        "controlled-input generation teardown",
    )
    require_order(
        retire_generation,
        (
            ".filter { it.serviceGeneration == serviceGeneration }",
            ".toList()",
            "for (owner in owners)",
            "retireInputOwner(owner)",
        ),
        "generation-scoped owner teardown",
    )

    mouse_input = extract_item(
        input_service,
        "internal fun onMouseInput(",
        "exact-owner mouse input",
    )
    require_order(
        mouse_input,
        (
            "if (destroyed || owner !in activeInputOwners)",
            "val activePointerOwner = pointerOwner",
            "if (activePointerOwner != null)",
            "activePointerOwner != owner",
            "pointerSequence != PointerSequence.MOUSE",
            "(mask != 0 && mask != LEFT_MOVE && mask != LEFT_UP)",
            "return false",
            "pointerOwner = owner",
            "pointerSequence = PointerSequence.MOUSE",
        ),
        "single exact mouse-sequence ownership",
    )
    require_order(
        mouse_input,
        (
            "if (pendingRecentAction != null)",
            "return false",
            "return scheduleRecentAction(owner)",
        ),
        "single delayed recents admission",
    )
    touch_input = extract_item(
        input_service,
        "internal fun onTouchInput(",
        "exact-owner touch input",
    )
    require_order(
        touch_input,
        (
            "if (destroyed || owner !in activeInputOwners)",
            "TOUCH_PAN_UPDATE",
            "pointerOwner != owner || pointerSequence != PointerSequence.TOUCH",
            "TOUCH_PAN_START",
            "if (pointerOwner != null)",
            "pointerOwner = owner",
            "pointerSequence = PointerSequence.TOUCH",
            "TOUCH_PAN_END",
            "pointerOwner = null",
            "pointerSequence = null",
        ),
        "single exact touch-sequence ownership",
    )
    finish_pointer = extract_item(
        input_service,
        "private fun finishAndResetPointerSequence()",
        "retired pointer-sequence finalization",
    )
    require_order(
        finish_pointer,
        (
            "cancelLongPress(pointerOwner)",
            "Build.VERSION.SDK_INT >= Build.VERSION_CODES.O && stroke != null",
            "endGesture(mouseX, mouseY)",
            "leftIsDown = false",
            "pointerOwner = null",
            "pointerSequence = null",
            "stroke = null",
            "touchPath.reset()",
        ),
        "finish admitted continuation before local pointer reset",
    )

    enqueue_wheel = extract_item(
        input_service,
        "private fun enqueueWheelAction(",
        "bounded wheel admission",
    )
    require_order(
        enqueue_wheel,
        (
            "if (!wheelActions.offer(owner, gesture))",
            "return false",
            "if (scheduleWheelDrain())",
            "return true",
            "wheelActions.removeOwner(owner)",
            "return false",
        ),
        "wheel capacity and post-failure exact-owner cleanup",
    )
    drain_wheel = extract_item(
        input_service,
        "private fun drainWheelAction()",
        "wheel queue drain",
    )
    require_order(
        drain_wheel,
        (
            "wheelDrainPosted = false",
            "wheelActionInFlight != null",
            "while (next != null && next.owner !in activeInputOwners)",
            "val admitted = next ?: return",
            "wheelActionInFlight = admitted",
            "override fun onCompleted",
            "completeWheelAction(admitted)",
            "override fun onCancelled",
            "completeWheelAction(admitted)",
            "dispatchGesture(admitted.value, callback, mainHandler)",
        ),
        "one exact live wheel action driven by platform completion",
    )

    schedule_long_press = extract_item(
        input_service,
        "private fun scheduleLongPress(",
        "exact delayed long-press admission",
    )
    require_order(
        schedule_long_press,
        (
            "cancelLongPress(null)",
            "val sequence = nextDelayedActionSequence() ?: return false",
            "pendingLongPress = PendingOwnedAction(owner, sequence, runnable)",
            "mainHandler.postDelayed(runnable, longPressDuration)",
        ),
        "single sequenced long-press slot",
    )
    run_long_press = extract_item(
        input_service,
        "private fun runLongPress(",
        "exact delayed long-press execution",
    )
    require_order(
        run_long_press,
        (
            "pending?.owner != owner || pending.sequence != sequence",
            "pendingLongPress = null",
            "owner !in activeInputOwners",
            "pointerOwner != owner",
            "!leftIsDown",
            "!isWaitingLongPress",
            "continueGesture(mouseX, mouseY)",
        ),
        "owner/sequence/current-pointer long-press validation",
    )
    run_recent = extract_item(
        input_service,
        "private fun runRecentAction(",
        "exact delayed recents execution",
    )
    require_order(
        run_recent,
        (
            "pending?.owner != owner",
            "pending.sequence != sequence",
            "owner !in activeInputOwners",
            "pendingRecentAction = null",
            "performGlobalAction(GLOBAL_ACTION_RECENTS)",
        ),
        "owner/sequence recents validation",
    )

    key_input = extract_item(
        input_service,
        "internal fun onKeyEvent(",
        "bounded exact-owner key admission",
    )
    require_order(
        key_input,
        (
            "if (destroyed || owner !in activeInputOwners)",
            "KeyEvent.parseFrom(data)",
            "if (!keyActions.offer(owner, keyEvent))",
            "return false",
            "if (scheduleKeyDrain())",
            "return true",
            "keyActions.removeOwner(owner)",
            "return false",
        ),
        "key parse, capacity, and post-failure cleanup",
    )
    drain_key = extract_item(
        input_service,
        "private fun drainKeyAction()",
        "bounded key drain",
    )
    require_order(
        drain_key,
        (
            "keyDrainPosted = false",
            "while (next != null && next.owner !in activeInputOwners)",
            "processKeyEvent(next.value)",
            "scheduleKeyDrain()",
        ),
        "one posted key drain with stale-owner filtering",
    )
    input_destroy = extract_item(
        input_service,
        "override fun onDestroy()",
        "AccessibilityService input teardown",
    )
    require_order(
        input_destroy,
        (
            "destroyed = true",
            "activeInputOwners.clear()",
            "wheelActions.clear()",
            "keyActions.clear()",
            "wheelActionInFlight = null",
            "cancelLongPress(null)",
            "cancelRecentAction(null)",
            "pointerOwner = null",
            "pointerSequence = null",
            "mainHandler.removeCallbacks(wheelDrain)",
            "mainHandler.removeCallbacks(keyDrain)",
            "if (ctx === this)",
            "ctx = null",
        ),
        "complete persistent AccessibilityService input teardown",
    )

    android_ffi = sources["android_ffi"]
    pointer_ffi = extract_item(
        android_ffi,
        "pub fn call_main_service_pointer_input_for_generation(",
        "Android pointer JNI sender",
    )
    require_order(
        pointer_ffi,
        (
            "generation: u64",
            "connection_id: i32",
            ") -> JniResult<bool>",
            "generation == 0 || connection_id <= 0",
            "context.generation != Some(generation)",
            '"(IIIII)Z"',
            "JValue::Int(connection_id)",
            ".z()",
        ),
        "generation-and-connection-bound Boolean pointer JNI",
    )
    key_ffi = extract_item(
        android_ffi,
        "pub fn call_main_service_key_event_for_generation(",
        "Android key JNI sender",
    )
    require_order(
        key_ffi,
        (
            "generation: u64",
            "connection_id: i32",
            ") -> JniResult<bool>",
            "generation == 0 || connection_id <= 0",
            "context.generation != Some(generation)",
            '"(I[B)Z"',
            "JValue::Int(connection_id)",
            ".z()",
        ),
        "generation-and-connection-bound Boolean key JNI",
    )

    server_connection = sources["server_connection"]
    require_count(
        server_connection,
        "call_main_service_pointer_input_for_generation(\n"
        "                            self.android_server_generation,\n"
        "                            self.inner.id(),",
        1,
        "mouse input exact connection-ID JNI handoff",
    )
    require_count(
        server_connection,
        "call_main_service_pointer_input_for_generation(\n"
        "                                            self.android_server_generation,\n"
        "                                            self.inner.id(),",
        3,
        "touch input exact connection-ID JNI handoff",
    )
    require(
        server_connection,
        "call_main_service_key_event_for_generation(\n"
        "                                self.android_server_generation,\n"
        "                                self.inner.id(),",
        "key input exact connection-ID JNI handoff",
    )
    for diagnostic, label in (
        (
            "Closing Android connection after input owner or queue refusal",
            "mouse refusal connection closure",
        ),
        (
            "Closing Android connection after pointer owner or queue refusal",
            "touch refusal connection closure",
        ),
        (
            "Closing Android connection after key owner or queue refusal",
            "key refusal connection closure",
        ),
        (
            "Closing Android connection after input JNI failure",
            "mouse JNI-failure connection closure",
        ),
        (
            "Closing Android connection after pointer JNI failure",
            "touch JNI-failure connection closure",
        ),
        (
            "Closing Android connection after key JNI failure",
            "key JNI-failure connection closure",
        ),
    ):
        require(server_connection, diagnostic, label)

    input_test = sources["input_owner_test"]
    for behavior, label in (
        ("queue capacity was not enforced", "queue-capacity behavior proof"),
        (
            "exact owner retirement did not remove all owned work",
            "exact owner retirement behavior proof",
        ),
        (
            "one owner retirement removed or reordered another owner's work",
            "other-owner preservation behavior proof",
        ),
        (
            "old generation retirement selected the replacement owner",
            "generation-ABA behavior proof",
        ),
        ("invalid owner reached the bounded queue", "invalid-owner behavior proof"),
    ):
        require(input_test, behavior, label)
    require(
        sources["requirements"],
        '<span class="id">R-S11ei</span>',
        "Android controlled-input ownership normative requirement",
    )
    require(
        sources["requirements"],
        "<tr><td>288</td>",
        "Android controlled-input ownership Appendix C disposition",
    )
    require(
        sources["hardening"],
        "R-S11ei/R-S11e-153",
        "Android controlled-input ownership hardening ledger",
    )
    require(
        sources["verify"],
        'echo "== Android MediaProjection/input lifecycle finality (R-S14/R-S11ei/R-S11ek/R-S11em/R-S11en/R-S11eu/R-S11e-153/R-S11e-169/R-S11e-174/R-S11e-175/R-S11e-182/R-T4) =="',
        "shared Android controlled-input/audio/status generation ownership gate label",
    )
    require(
        sources["verify"],
        "android-controlled-input-owner-test.kt",
        "shared Android controlled-input behavior fixture gate",
    )


Mutation = Tuple[str, str, str, str]

MUTATIONS: Tuple[Mutation, ...] = (
    ("owners", "generation > 0 && sessionId.isNotEmpty()", "generation >= 0", "outgoing owner validity"),
    ("owners", "activeControlledConnections.isNotEmpty() || outgoingVoiceCallActive", "outgoingVoiceCallActive", "controlled aggregation"),
    ("owners", "generation < greatestControlledServiceGeneration", "false", "controlled generation monotonicity"),
    ("owners", "activeControlledServiceGeneration != generation", "false", "retired generation refusal"),
    ("owners", "if (activeControlledServiceGeneration == generation)", "if (false)", "current generation idempotence"),
    ("owners", "activeControlledServiceGeneration = generation", "activeControlledServiceGeneration = null", "controlled generation publication"),
    ("owners", "activeControlledServiceGeneration = generation\n        controlledConnections.clear()\n        activeControlledConnections.clear()", "activeControlledServiceGeneration = generation\n        controlledConnections.clear()\n        activeControlledConnections.clear()\n        outgoingOwner = null", "controlled replacement preserves outgoing ownership"),
    ("owners", "if (!isControlledServiceGeneration(generation) || connectionId <= 0)", "if (connectionId <= 0)", "generation-bound controlled registration"),
    ("owners", "!controlledConnections.contains(connectionId)", "false", "registered controlled update"),
    ("owners", "if (!isControlledServiceGeneration(generation) ||\n            !controlledConnections.contains(connectionId)", "if (!controlledConnections.contains(connectionId)", "generation-bound controlled update"),
    ("owners", "fun unregisterControlledConnection(generation: Long, connectionId: Int): Boolean {\n        if (!isControlledServiceGeneration(generation) || connectionId <= 0)", "fun unregisterControlledConnection(generation: Long, connectionId: Int): Boolean {\n        if (connectionId <= 0)", "generation-bound controlled retirement"),
    ("owners", "activeControlledConnections.remove(connectionId)", "// active owner retained", "exact controlled retirement"),
    ("owners", "if (!isControlledServiceGeneration(generation)) {\n            return false\n        }\n        controlledConnections.clear()", "if (false) {\n            return false\n        }\n        controlledConnections.clear()", "exact-generation controlled service teardown"),
    ("owners", "activeControlledConnections.clear()\n        activeControlledServiceGeneration = null", "// active owners and generation retained", "controlled service teardown"),
    ("owners", "if (current != null && current != owner)", "if (false)", "single outgoing owner"),
    ("owners", "if (current != previous)", "if (false)", "resume previous-owner identity"),
    ("owners", "if (current == replacement)", "if (false)", "lost-response resume retry idempotence"),
    ("owners", "replacement.sessionId != previous.sessionId", "false", "resume session identity"),
    ("owners", "replacement.generation < previous.generation", "replacement.generation <= previous.generation", "idempotent same-generation resume"),
    ("owners", "if (outgoingOwner != owner)", "if (false)", "exact outgoing update"),
    ("coordinator", "@Synchronized\n    fun beginControlledServiceGeneration", "    fun beginControlledServiceGeneration", "controlled generation serialization"),
    ("coordinator", "@Synchronized\n    fun setControlledVoiceCallActive", "    fun setControlledVoiceCallActive", "controlled serialization"),
    ("coordinator", "@Synchronized\n    fun setOutgoingVoiceCallActive", "    fun setOutgoingVoiceCallActive", "outgoing serialization"),
    ("coordinator", "val alreadyCurrent = owners.isControlledServiceGeneration(generation)", "val alreadyCurrent = false", "idempotent generation playback preservation"),
    ("coordinator", "if (!owners.beginControlledServiceGeneration(generation))", "if (false)", "controlled generation admission"),
    ("coordinator", "owners.registerControlledConnection(generation, connectionId)", "owners.registerControlledConnection(1, connectionId)", "controlled registration generation"),
    ("coordinator", "owners.setControlledVoiceCallActive(generation, connectionId, active)", "owners.setControlledVoiceCallActive(1, connectionId, active)", "controlled update generation"),
    ("coordinator", "owners.unregisterControlledConnection(generation, connectionId)", "owners.unregisterControlledConnection(1, connectionId)", "controlled retirement generation"),
    ("coordinator", "if (!owners.clearControlledConnections(generation))", "if (false)", "controlled teardown generation"),
    ("coordinator", "if (playbackProjection?.first == generation)", "if (playbackProjection != null)", "playback teardown generation"),
    ("coordinator", "if (!owners.isControlledServiceGeneration(generation))", "if (false)", "playback update generation"),
    ("coordinator", "projection?.let { generation to it }", "projection?.let { 1L to it }", "playback generation publication"),
    ("coordinator", "if (owners.requiresVoiceCapture) {", "if (false) {", "voice capture priority"),
    ("coordinator", "return recorder.switchToPlaybackCapture(projection)", "return true", "playback reconciliation"),
    ("audio", "recorder.state != AudioRecord.STATE_INITIALIZED", "false", "recorder initialization proof"),
    ("audio", "if (platformMinBufferSize <= 0)", "if (platformMinBufferSize == 0)", "negative buffer refusal"),
    ("audio", "platformMinBufferSize.toLong() * 2L * 4L", "platformMinBufferSize * 2 * 4", "buffer overflow safety"),
    ("audio", "recorder.recordingState != AudioRecord.RECORDSTATE_RECORDING", "false", "recording-state proof"),
    ("audio", "start = false", "start = true", "worker ownership publication"),
    ("audio", "reader.readSync(recorder) ?: break", "reader.readSync(recorder) ?: continue", "terminal read failure"),
    ("audio", "while (worker.isAlive)", "if (worker.isAlive)", "exact worker join"),
    ("audio", "Thread.currentThread().interrupt()", "// interrupt swallowed", "interrupt restoration"),
    ("audio", "captureProjection === mediaProjection", "captureProjection != null", "exact projection reuse"),
    ("connection_type", '                "PortForward" -> PORT_FORWARD', '                "PortForward" -> REMOTE', "PortForward exact type"),
    ("connection_type", "get() = this == REMOTE || this == VIEW_CAMERA", "get() = this != FILE_TRANSFER", "Remote-or-ViewCamera voice authority"),
    ("connection_type", "else -> null", "else -> REMOTE", "unknown connection-type refusal"),
    ("capture_owners", "get() = owners.isNotEmpty()", "get() = false", "capture-owner aggregation"),
    ("capture_owners", "if (authorized && connectionType.requiresDesktopCapture)", "if (connectionType != ControlledConnectionType.FILE_TRANSFER)", "authorized exact-type capture admission"),
    ("capture_owners", "owners.remove(connectionId)", "// capture owner retained", "exact capture-owner retirement"),
    ("service", "@Keep\n    @Synchronized\n    fun rustSetByName", "@Keep\n    fun rustSetByName", "controlled-resource dispatch serialization"),
    ("service", "controlledCaptureOwners.upsert(id, authorized, connectionType)", "true", "capture-owner admission"),
    ("service", "captureRequested = controlledCaptureOwners.requiresDesktopCapture", "captureRequested = false", "owner-set capture reconciliation"),
    ("service", "controlledCaptureOwners.unregister(id)", "true", "capture-owner retirement"),
    ("service", "private fun releaseControlledConnectionResources() {\n        acceptingControlledConnections = false", "private fun releaseControlledConnectionResources() {\n        acceptingControlledConnections = true", "resource admission closure"),
    ("service", "VoiceCallAudioCoordinator.registerControlledConnection(\n                            nativeServerGeneration,\n                            id,", "VoiceCallAudioCoordinator.registerControlledConnection(\n                            1,\n                            id,", "controlled registration generation"),
    ("service", "if (connectionType.allowsVoiceCall &&", "if (true &&", "typed controlled voice-call admission"),
    ("service", '"remove_connection" ->', '"remove_connection_disabled" ->', "controlled removal dispatch"),
    ("service", "VoiceCallAudioCoordinator.unregisterControlledConnection(\n                            nativeServerGeneration,\n                            id,", "VoiceCallAudioCoordinator.unregisterControlledConnection(\n                            1,\n                            id,", "controlled retirement generation"),
    ("service", "VoiceCallAudioCoordinator.setControlledVoiceCallActive(\n                            nativeServerGeneration,\n                            id,", "VoiceCallAudioCoordinator.setControlledVoiceCallActive(\n                            1,\n                            id,", "controlled update generation"),
    ("service", "VoiceCallAudioCoordinator.clearControlledConnections(nativeServerGeneration)", "true", "service generation owner teardown"),
    ("service", "nativeServerGeneration = FFI.startServer(this, configPath, \"\")", "FFI.startServer(configPath, \"\")", "exact-object service generation ownership"),
    ("service", "VoiceCallAudioCoordinator.beginControlledServiceGeneration(\n                nativeServerGeneration", "VoiceCallAudioCoordinator.beginControlledServiceGeneration(\n                1", "audio coordinator generation binding"),
    ("service", "private var acceptingControlledConnections = false", "private var acceptingControlledConnections = true", "closed-by-default controlled admission"),
    ("service", "acceptingControlledConnections = true", "// controlled admission retained closed", "post-generation controlled admission"),
    ("service", "VoiceCallAudioCoordinator.setPlaybackCaptureProjection(\n                        nativeServerGeneration,\n                        projection,", "VoiceCallAudioCoordinator.setPlaybackCaptureProjection(\n                        1,\n                        projection,", "playback-start generation"),
    ("service", "VoiceCallAudioCoordinator.setPlaybackCaptureProjection(\n                nativeServerGeneration,\n                null,", "VoiceCallAudioCoordinator.setPlaybackCaptureProjection(\n                1,\n                null,", "playback-stop generation"),
    ("test", "controlled-service replacement cleared the outgoing owner", "controlled-service replacement passed", "controlled replacement preserves outgoing ownership"),
    ("test", "superseded controlled generation was reactivated", "superseded controlled generation passed", "superseded controlled generation behavior proof"),
    ("service", "FFI.stopServer(nativeServerGeneration)", "FFI.stopServer(0)", "exact service generation stop"),
    ("service", "FFI.releaseService(this)", "true", "exact service callback-owner release"),
    ("service", "VoiceCallAudioCoordinator.unregisterOutgoingOwner(owner.toVoiceCallOwner())", "true", "task-removal owner teardown"),
    ("activity", "VoiceCallAudioCoordinator.invalidateOutgoingOwner()", "true", "new-isolate invalidation"),
    ("activity", "internal data class ClientSessionOwner", "data class ClientSessionOwner", "Activity owner visibility"),
    ("activity", "internal fun takeStoppedClientSessionOwners", "fun takeStoppedClientSessionOwners", "stopped-owner transfer visibility"),
    ("activity", "VoiceCallAudioCoordinator.registerOutgoingOwner(owner.toVoiceCallOwner())", "true", "outgoing owner registration"),
    ("activity", "result.success(setOutgoingVoiceCallActive(true))", "setOutgoingVoiceCallActive(true)", "voice-start completion"),
    ("activity", "VoiceCallAudioCoordinator.unregisterOutgoingOwner(owner.toVoiceCallOwner())", "true", "Activity owner teardown"),
    ("activity", "VoiceCallAudioCoordinator.resumeOutgoingOwner(", "VoiceCallAudioCoordinator.registerOutgoingOwner(", "resume exact transfer"),
    ("activity", "val retiredRejectedOwner =\n                VoiceCallAudioCoordinator.unregisterOutgoingOwner(owner.toVoiceCallOwner())", "val retiredRejectedOwner = true", "Rust-rejected resume exact recorder cleanup"),
    ("activity", "val retiredUnreconciledOwner =\n                VoiceCallAudioCoordinator.unregisterOutgoingOwner(owner.toVoiceCallOwner())", "val retiredUnreconciledOwner = true", "unreconciled resume exact recorder cleanup"),
    ("activity", "val retiredUnreconciledSessions =\n                FFI.retireClientSessions(owner.generation, owner.sessionId)", "val retiredUnreconciledSessions =\n                FFI.retireClientSessions(resumedOwner.generation, resumedOwner.sessionId)", "unreconciled resume cannot retire replacement Rust owner"),
    ("flutter", 'call_main_service_set_by_name_for_generation(\n                    self.service_generation,\n                    "remove_connection"', 'call_main_service_set_by_name(\n                    "remove_connection"', "generation-bound controlled callback"),
    ("flutter", "service_generation: u64", "service_generation: i64", "connection-manager callback generation"),
    ("ui_cm", "        self.ui_handler.remove_connection(id, close);", '        let _ = scrap::android::call_main_service_set_by_name("stop_capture", None, None);\n        self.ui_handler.remove_connection(id, close);', "detached global capture-stop edge"),
    ("ffi_kt", "external fun init(service: Context, applicationContext: Context)", "external fun init(service: Context)", "separate service/application JNI initialization"),
    ("ffi_kt", "external fun releaseService(service: Context): Boolean", "external fun releaseService(service: Context)", "service callback-owner release result"),
    ("ffi_kt", "external fun startServer(service: Context, app_dir: String, custom_client_config: String): Long", "external fun startServer(app_dir: String, custom_client_config: String): Long", "native server exact-object generation return"),
    ("ffi_kt", "external fun stopServer(generation: Long): Boolean", "external fun stopServer(): Unit", "exact native server generation stop"),
    ("android_ffi", "env.is_same_object(owner.owner.as_obj(), &service)", "true", "exact service callback-owner identity"),
    ("android_ffi", "env.new_global_ref(application_context)", "env.new_global_ref(service)", "application-context global retention"),
    ("android_ffi", "init_ndk_context(java_vm, context_jobject)", "init_ndk_context(java_vm, service.as_obj().as_raw() as *mut c_void)", "application-context native lifetime"),
    ("android_ffi", "env.is_same_object(current.owner.as_obj(), service)", "true", "exact service generation-owner identity"),
    ("android_ffi", "if current.generation.is_some()", "if false", "single service generation binding"),
    ("android_ffi", "if generation == 0 || context.generation != Some(generation)", "if false", "controlled callback generation comparison"),
    ("server_connection", "android_server_generation: u64", "android_server_generation: i64", "connection service-generation ownership"),
    ("server_connection", "call_main_service_pointer_input_for_generation", "call_main_service_pointer_input", "generation-bound controlled pointer dispatch"),
    ("server_connection", "call_main_service_key_event_for_generation", "call_main_service_key_event", "generation-bound controlled key dispatch"),
    ("direct_service", "lifecycle.stop_generation(expected_generation)", "lifecycle.stop_generation(lifecycle.generation)", "exact serialized server-generation stop"),
    ("flutter_ffi", "bind_main_service_generation(&env, &service, generation)", "true", "exact-object listener/callback generation binding"),
    ("flutter", "|| self.session_id.as_ref() != Some(&session_id)", "|| false", "Rust cross-isolate Activity resume refusal"),
    ("flutter", "client_owner_id: Option<SessionID>", "client_owner_id: Option<()>", "stored mobile client-owner association"),
    ("flutter", "acquire_android_client_owner(&client_owner_id)?", "acquire_android_client_owner(&session_id)?", "existing-session owner admission"),
    ("flutter", "take_previous_android_mobile_client_sessions(client_owner_id, session_id)?", "sessions::ClientOwnerDrain::default()", "replacement pre-insertion drain"),
    ("flutter", "sessions::session_has_client_owner(session_id, client_owner_id)", "true", "start-time owner association"),
    ("flutter", "handler_session_id != session_id\n                        || handler.client_owner_id.as_ref() != Some(client_owner_id)", "handler_session_id != session_id\n                        && handler.client_owner_id.as_ref() != Some(client_owner_id)", "exact owner-and-session preservation"),
    ("flutter", "if handlers.is_empty() {\n                removed_keys.push(key.clone());\n            } else {\n                check_remove_unused_displays(None, session, &handlers);", "if handlers.is_empty() {\n                removed_keys.push(key.clone());\n            } else {\n                check_remove_unused_displays(Some(session_id), session, &handlers);", "replacement display reconciliation includes preserved exact session"),
    ("flutter", "if owned_handler_ids.is_empty() {\n                continue;\n            }\n            if handlers.is_empty() {\n                removed_keys.push(key.clone());\n            } else {\n                check_remove_unused_displays(None, session, &handlers);", "if owned_handler_ids.is_empty() {\n                continue;\n            }\n            if handlers.is_empty() {\n                removed_keys.push(key.clone());\n            } else {\n                check_remove_unused_displays(Some(client_owner_id), session, &handlers);", "Activity-owner display reconciliation includes all remaining sessions"),
    ("flutter", "excluded_session_id: Option<&SessionID>", "excluded_session_id: &SessionID", "optional display-reconciliation exclusion"),
    ("flutter", "fn stale_mobile_session_close_cannot_select_replacement_from_same_owner()", "fn stale_mobile_session_close_can_select_replacement_from_same_owner()", "same-owner stale-close behavior proof"),
    ("flutter", "const ANDROID_CLIENT_DRAIN_QUEUE_CAPACITY: usize = 1;", "const ANDROID_CLIENT_DRAIN_QUEUE_CAPACITY: usize = 2;", "one-slot Android client lifecycle drain"),
    ("flutter", "_worker: std::thread::JoinHandle<()>", "_worker: std::thread::Thread", "retained Android client lifecycle drain worker"),
    ("flutter", "fn android_lifecycle_retirement_is_nonblocking_and_replacement_waits_for_exact_drain()", "fn android_lifecycle_retirement_may_block_and_replacement_skips_exact_drain()", "nonblocking lifecycle exact-barrier behavior proof"),
    ("flutter", "drop(owner_admission);\n    Ok(drain)", "Ok(drain)", "owner guard release before prior-mobile finality"),
    ("flutter", "let owner_admission = acquire_android_client_owner(client_owner_id)?;\n\n    // to-do: check the same id session.", "// post-drain owner revalidation omitted\n\n    // to-do: check the same id session.", "post-drain exact-owner revalidation"),
    ("flutter", "fn android_lifecycle_transition_does_not_wait_for_mobile_replacement_drain()", "fn android_lifecycle_transition_waits_for_mobile_replacement_drain()", "nonblocking lifecycle during mobile replacement-drain behavior proof"),
    ("flutter_ffi", "client_owner_id: SessionID,", "client_owner_id: String,", "authored dual-identity bridge"),
    ("dart_main", "'register_client_session_owner', gFFI.clientOwnerId.toString())", "'register_client_session_owner', gFFI.sessionId.toString())", "Activity owner registration identity"),
    ("dart_model", "final _mobileClientOwnerId = Uuid().v4obj();", "final _mobileClientOwnerId = SessionID.nil();", "canonical mobile owner UUID"),
    ("dart_model", "late SessionID sessionId;\n  late final SessionID clientOwnerId;", "late final SessionID sessionId;\n  late final SessionID clientOwnerId;", "rotating connection identity"),
    ("dart_model", "sessionId = Uuid().v4obj();", "sessionId = clientOwnerId;", "fresh per-connection UUID"),
    ("dart_model", "mobileReset(previousSessionId);", "mobileReset(clientOwnerId);", "pre-rotation exact-session model reset"),
    ("dart_model", "qualityMonitorModel.reset();", "// quality monitor retained", "quality-monitor state retirement"),
    ("dart_model", "recordingModel.reset();", "// recording state retained", "recording state retirement"),
    ("dart_model", "void reconnect(OverlayDialogManager dialogManager, SessionID sessionId) {\n    if (!_isCurrentSession(sessionId)) return;", "void reconnect(OverlayDialogManager dialogManager, SessionID sessionId) {", "delayed reconnect session refusal"),
    ("dart_model", "tryShowAndroidActionsOverlay(SessionID expectedSessionId,", "tryShowAndroidActionsOverlay(SessionID ignoredSessionId,", "delayed Android overlay session identity"),
    ("dart_model", "void mobileFocusCanvasCursor() {\n    final expectedSessionId = parent.target?.sessionId;", "void mobileFocusCanvasCursor() {\n    final expectedSessionId = SessionID.nil();", "delayed mobile canvas-focus session identity"),
    ("dart_model", "void restoreMobileOffsetAfterSoftKeyboard() {\n    final expectedSessionId = parent.target?.sessionId;", "void restoreMobileOffsetAfterSoftKeyboard() {\n    final expectedSessionId = SessionID.nil();", "delayed mobile canvas-restore session identity"),
    ("dart_model", "final remoteWindowCoords = <RemoteWindowCoords>[];\n      final windowRect =\n          await InputModel.fillRemoteCoordsAndGetCurFrame(remoteWindowCoords);", "final windowRect =\n          await InputModel.fillRemoteCoordsAndGetCurFrame(_remoteWindowCoords);", "cursor coordinate staging"),
    ("dart_model", "_x = -10000;\n    _y = -10000;\n    _id = \"-1\";", "_x = -10000;\n    _x = -10000;\n    _id = \"-1\";", "cursor y-state retirement"),
    ("dart_model", "_edgeScrollFallbackState = null;", "// edge-scroll fallback retained", "canvas fallback retirement"),
    ("dart_model", "if (closed || sessionId != activeSessionId) return;", "if (closed) return;", "stale event-stream refusal"),
    ("dart_model", "SessionID get sessionId => parent.target!.sessionId;", "late final SessionID sessionId;", "borrowed long-lived model identity"),
    ("dart_model", "await bind.sessionClose(sessionId: closingSessionId);", "await bind.sessionClose(sessionId: sessionId);", "exact captured native close"),
    ("mobile_files", "await model.close(sessionId);", "await Future<void>.delayed(Duration.zero);", "file-page state persistence before native close"),
    ("dart_input_model", "SessionID get sessionId => parent.target!.sessionId;", "late final SessionID sessionId;", "borrowed input identity"),
    ("dart_input_model", "_relativeMouse.resetForSession(expectedSessionId);", "_relativeMouse.dispose();", "reusable input-model session reset"),
    ("dart_input_model", "_lastScale = 1.0;\n    _pointerMovedAfterEnter = false;\n    _pointerInsideImage = false;\n    _lastButtons = 0;\n    lastMousePos = Offset.zero;", "_pointerMovedAfterEnter = false;\n    _pointerInsideImage = false;\n    _lastButtons = 0;", "reusable input gesture-coordinate reset"),
    ("dart_input_model", "Future<void> _sendMousePair(MouseButtons button, Duration hold) async {\n    if (!keyboardPerm || isViewCamera) return;\n    final expectedSessionId = sessionId;", "Future<void> _sendMousePair(MouseButtons button, Duration hold) async {\n    if (!keyboardPerm || isViewCamera) return;\n    final expectedSessionId = SessionID.nil();", "paired mobile mouse session identity"),
    ("dart_input_model", "Future<void> tapHidKey(int usbHidUsage) async {\n    final expectedSessionId = sessionId;", "Future<void> tapHidKey(int usbHidUsage) async {\n    final expectedSessionId = SessionID.nil();", "paired mobile HID session identity"),
    ("dart_input_model", "final expectedSessionId = sessionId;\n      Future.delayed(Duration.zero, () async {\n        final remoteWindowCoords = <RemoteWindowCoords>[];", "Future.delayed(Duration.zero, () async {\n        final remoteWindowCoords = <RemoteWindowCoords>[];", "input coordinate session identity"),
    ("dart_chat_model", "SessionID get sessionId => parent.target!.sessionId;", "late final SessionID sessionId;", "borrowed chat identity"),
    ("dart_relative_mouse", "sessionId: expectedSessionId ?? getSessionId(),", "sessionId: SessionID.nil(),", "borrowed relative-mouse identity"),
    ("dart_relative_mouse", "_performCleanupCore(expectedSessionId: expectedSessionId);", "_performCleanupCore();", "relative-mouse exact retired-session cleanup"),
    ("dart_file_model", "unawaited(evtLoop.close());", "// prior file dialog retained", "file-dialog prior-session retirement"),
    ("dart_file_model", "fileFetcher.cancelPending();", "// stale file tasks retained", "file-transfer pending-resource retirement"),
    ("dart_file_model", "localController.resetForSession();", "// local controller retained", "file-controller prior-peer state retirement"),
    ("dart_file_model", "void onEventsRetired() {\n    _overrideConfirm = null;\n    _skip = false;", "void onEventsRetired() {\n    _overrideConfirm = null;\n    _skip = true;", "file-dialog remembered-policy retirement"),
    ("dart_file_model", "if (model == null || !model._isCurrentSession(expectedSessionId))", "if (model == null)", "file-dialog stale-session callback refusal"),
    ("dart_file_model", "if (!identical(tasks[key], pending)) return;", "if (false) return;", "file-fetch timeout exact-completer retirement"),
    ("dart_file_model", "Future<bool> _openDirectoryPath(String path,\n      {bool isBack = false, SessionID? expectedSessionId}) async {\n    final selectedSessionId = expectedSessionId ?? sessionId;", "Future<bool> _openDirectoryPath(String path,\n      {bool isBack = false, SessionID? expectedSessionId}) async {\n    final selectedSessionId = sessionId;", "file-controller captured directory session"),
    ("dart_file_model", "Future<FileDirectory> fetchDirectory(\n      String path, bool isLocal, bool showHidden,\n      {SessionID? expectedSessionId}) async {\n    final selectedSessionId = expectedSessionId ?? sessionId;", "Future<FileDirectory> fetchDirectory(\n      String path, bool isLocal, bool showHidden,\n      {SessionID? expectedSessionId}) async {\n    final selectedSessionId = sessionId;", "file-fetcher captured native session"),
    ("dart_file_model", "final home = await bind.mainGetHomeDir();\n      if (!_isCurrentSession(expectedSessionId)) return;\n      options.value.home = home;", "options.value.home = await bind.mainGetHomeDir();", "file-controller local-home post-await refusal"),
    ("dart_event_loop", "generation == _generation", "generation <= _generation", "event-loop exact generation"),
    ("mobile_remote", "gFFI.close(expectedSessionId: sessionId)", "gFFI.close(expectedSessionId: gFFI.sessionId)", "remote-page exact cleanup"),
    ("mobile_camera", "gFFI.close(expectedSessionId: sessionId)", "gFFI.close(expectedSessionId: gFFI.sessionId)", "camera-page exact cleanup"),
    ("mobile_files", "gFFI.close(expectedSessionId: sessionId)", "gFFI.close(expectedSessionId: gFFI.sessionId)", "file-page exact cleanup"),
    ("mobile_remote", ".tryShowAndroidActionsOverlay(sessionId);", ".tryShowAndroidActionsOverlay(gFFI.sessionId);", "remote-page delayed overlay identity"),
    ("mobile_camera", ".tryShowAndroidActionsOverlay(sessionId);", ".tryShowAndroidActionsOverlay(gFFI.sessionId);", "camera-page delayed overlay identity"),
    ("mobile_remote", "Timer(const Duration(milliseconds: 200), () {\n                                  if (!mounted ||\n                                      !gFFI.isCurrentSession(sessionId)) {", "Timer(const Duration(milliseconds: 200), () {\n                                  if (!mounted) {", "remote-page delayed orientation refusal"),
    ("mobile_camera", "Timer(const Duration(milliseconds: 200), () {\n                            if (!mounted || !gFFI.isCurrentSession(sessionId)) {", "Timer(const Duration(milliseconds: 200), () {\n                            if (!mounted) {", "camera-page delayed orientation refusal"),
    ("mobile_remote", "void onSoftKeyboardChanged(bool visible) {\n    if (!mounted || !gFFI.isCurrentSession(sessionId)) return;", "void onSoftKeyboardChanged(bool visible) {", "remote-page delayed keyboard session refusal"),
    ("mobile_remote", "if (!mounted || !gFFI.isCurrentSession(widget.sessionId)) return;", "if (!mounted) return;", "remote-page delayed key-help session refusal"),
    ("mobile_camera", "void didChangeMetrics() {\n    if (!mounted || !gFFI.isCurrentSession(sessionId)) return;", "void didChangeMetrics() {", "camera-page delayed metrics session refusal"),
    ("mobile_files", "unawaited(_directorySubscription.cancel());", "// directory subscription retained", "mobile file-view subscription retirement"),
    ("client", "let next = self.next.checked_add(1)?;", "let next = self.next.wrapping_add(1);", "clipboard monotonic lease identity"),
    ("client", "if !self.active.remove(&lease)", "if !self.active.contains(&lease)", "clipboard exact lease retirement"),
    ("client", "worker: Option<ClientClipboardWorker>,", "worker: Option<()>,", "clipboard retained worker owner"),
    ("client", "worker.stop_requested.store(true, Ordering::Release);", "worker.stop_requested.store(true, Ordering::Relaxed);", "clipboard stop publication"),
    ("client", "worker.subscription.close();", "// clipboard listener admission left open", "clipboard exact subscription retirement"),
    ("client", "state.worker_transition = true;", "state.worker_transition = false;", "clipboard join transition ownership"),
    ("client", "state.pending_start = None;\n            if state.worker_transition", "if state.worker_transition", "clipboard retired-start cancellation"),
    ("client", "on_complete: Some(MediaWorkerCompletion::ClientClipboard)", "on_complete: None", "clipboard completion callback authority"),
    ("client", "if state.leases.is_empty() {\n            state.pending_start = None;", "if true {\n            state.pending_start = None;", "clipboard replacement-preserving finality"),
    ("client", "clipboard_leases_track_exact_network_rounds_without_stale_stop", "clipboard_leases_ignore_stale_network_round_stop", "clipboard exact-lease behavior proof"),
    ("io_loop", ".then(Client::acquire_clipboard_session);", ".then(|| ClientClipboardSession { lease: None });", "clipboard network-round acquisition"),
    ("io_loop", "clipboard_session.as_ref(),", "None,", "clipboard peer-handler exact-lease handoff"),
    ("io_loop", "#[cfg(not(target_os = \"ios\"))] clipboard_session: Option<&ClientClipboardSession>", "#[cfg(not(target_os = \"ios\"))] _clipboard_session: Option<&ClientClipboardSession>", "clipboard peer-handler lease parameter"),
    ("io_loop", "drop(clipboard_session.take());", "let _ = clipboard_session.take();", "clipboard network-round release"),
    ("flutter", "\n}\n\nfn close_client_owner_drain(", "\n    pub fn has_sessions_running() -> bool { true }\n}\n\nfn close_client_owner_drain(", "clipboard UI-registry liveness facade absence"),
    ("requirements", '<span class="id">R-S11eb</span>', '<span class="id">R-S11eb-disabled</span>', "mobile owner/connection requirement"),
    ("requirements", "<tr><td>281</td>", "<tr><td>281-disabled</td>", "mobile owner/connection disposition"),
    ("hardening", "R-S11eb/R-S11e-146", "R-S11eb-disabled/R-S11e-146", "mobile owner/connection hardening ledger"),
    ("requirements", '<span class="id">R-S11ec</span>', '<span class="id">R-S11ec-disabled</span>', "clipboard network-round requirement"),
    ("requirements", "<tr><td>282</td>", "<tr><td>282-disabled</td>", "clipboard network-round disposition"),
    ("hardening", "R-S11ec/R-S11e-147", "R-S11ec-disabled/R-S11e-147", "clipboard network-round hardening ledger"),
    ("verify", "client::tests::clipboard_leases_track_exact_network_rounds_without_stale_stop", "client::tests::clipboard_lifecycle_gate_disabled", "shared clipboard lifecycle behavior gate"),
    ("dart_verify", "client::tests::clipboard_leases_track_exact_network_rounds_without_stale_stop", "client::tests::clipboard_lifecycle_gate_disabled", "generated-bridge clipboard lifecycle behavior gate"),
    ("ui_session", "self.send(Data::InputOsPassword {\n            password: pass,\n            activate,\n        });", "let session = self.clone();\n        std::thread::spawn(move || {\n            session.send(Data::InputOsPassword {\n                password: pass,\n                activate,\n            });\n        });", "OS-password current-round typed admission"),
    ("client", "InputOsPassword {\n        password: String,\n        activate: bool,\n    },", "InputOsPasswordDisabled {\n        password: String,\n        activate: bool,\n    },", "OS-password typed in-process command"),
    ("client", "hbb_common::tokio::time::sleep(Duration::from_millis(50)).await;", "std::thread::sleep(Duration::from_millis(50));", "OS-password asynchronous activation delay"),
    ("client", "sender: ViewerCommandSender,", "sender: hbb_common::tokio::sync::mpsc::UnboundedSender<Data>,", "OS-password bounded captured exact-round sender"),
    ("client", "sequence: InputOsPasswordSequence,\n    sender: ViewerCommandSender,", "sequence: InputOsPasswordSequence,\n    interface: impl Interface,\n    sender: ViewerCommandSender,", "OS-password delayed task excludes mutable Session capability"),
    ("client", "if !send_os_password_input(&sender, password)", "if !send_os_password_input(&replacement_sender, password)", "OS-password exact event sender"),
    ("client", "pub(crate) async fn run_input_os_password_sequence(", "fn _input_os_password(", "detached-helper absence"),
    ("io_loop", "task: Option<tokio::task::JoinHandle<()>>,", "task: Option<()>,", "OS-password sole JoinHandle owner"),
    ("io_loop", "self.stop_and_join().await;\n        self.task = Some(tokio::spawn(future));", "self.task = Some(tokio::spawn(future));", "OS-password replacement cancellation-before-spawn"),
    ("io_loop", "        task.abort();\n        match task.await {", "        match task.await {", "OS-password exact task abort"),
    ("io_loop", "match task.await {", "match task {", "OS-password task cancellation join"),
    ("io_loop", 'log::error!("OS-password input task failed: {err}");', "std::process::abort();", "OS-password joined helper failure does not abort process"),
    ("io_loop", "if let Some(task) = self.task.take() {\n            task.abort();", "if let Some(_task) = self.task.take() {", "OS-password hard-drop abort"),
    ("io_loop", "input_os_password_task: OwnedInputOsPasswordTask,", "input_os_password_task: (),", "Remote-retained OS-password task owner"),
    ("io_loop", "self.input_os_password_task.stop_and_join().await;", "// stale OS-password task retained", "OS-password final round teardown"),
    ("io_loop", "let sender = self.sender.clone();\n                self.input_os_password_task", "let sender = self.handler.clone();\n                self.input_os_password_task", "OS-password exact Remote sender capture"),
    ("io_loop", "r_s11e148_os_password_input_is_cancelled_and_joined_before_round_replacement", "os_password_input_replacement_gate_disabled", "OS-password replacement behavior proof"),
    ("requirements", '<span class="id">R-S11ed</span>', '<span class="id">R-S11ed-disabled</span>', "OS-password exact-round requirement"),
    ("requirements", "<tr><td>283</td>", "<tr><td>283-disabled</td>", "OS-password exact-round disposition"),
    ("hardening", "R-S11ed/R-S11e-148", "R-S11ed-disabled/R-S11e-148", "OS-password exact-round hardening ledger"),
    ("verify", "client::io_loop::tests::r_s11e148_os_password_input_is_cancelled_and_joined_before_round_replacement", "client::io_loop::tests::os_password_gate_disabled", "shared OS-password exact-round behavior gate"),
    ("dart_verify", "client::io_loop::tests::r_s11e148_os_password_input_is_cancelled_and_joined_before_round_replacement", "client::io_loop::tests::os_password_gate_disabled", "generated-bridge OS-password exact-round behavior gate"),
    ("screenshot", "pub fn handle_screenshot(data: bytes::Bytes, action: String) -> String", "pub fn handle_screenshot(action: String) -> String", "value-owned screenshot action"),
    ("io_loop", "let data = (!data.is_empty()).then_some(data);", "crate::client::screenshot::set_screenshot(data.clone());\n                            let data = (!data.is_empty()).then_some(data);", "process-global screenshot setter call"),
    ("io_loop", ".retain(|_, existing_owner_sid| existing_owner_sid != &owner_sid);", ".retain(|_, _| true);", "prior exact-session screenshot request retirement"),
    ("io_loop", "if self.owners.len() >= MAX_PENDING_SCREENSHOT_RESPONSES", "if false", "screenshot request capacity"),
    ("io_loop", ".next_sequence\n            .checked_add(1)", ".next_sequence\n            .wrapping_add(1)", "monotonic screenshot request identity"),
    ("io_loop", "self.owners.insert(request_id.clone(), owner_sid);", "self.owners.insert(request_id.clone(), String::new());", "screenshot request owner association"),
    ("io_loop", "self.owners.remove(request_id)", "self.owners.get(request_id).cloned()", "one-time screenshot request completion"),
    ("io_loop", "pending_screenshot_requests: PendingScreenshotRequests,", "pending_screenshot_requests: HashMap<String, String>,", "Remote-owned screenshot request map"),
    ("io_loop", "self.pending_screenshot_requests.replace(sid.clone())", "Ok(sid.clone())", "fresh screenshot request admission"),
    ("io_loop", "sid: request_id.clone(),", "sid: sid.clone(),", "exact screenshot wire request ID"),
    ("io_loop", "self.pending_screenshot_requests.complete(&request_id)", "None", "exact screenshot response retirement"),
    ("io_loop", "r_s11e149_screenshot_responses_require_the_current_exact_request", "screenshot_request_replacement_gate_disabled", "exact screenshot request behavior proof"),
    ("flutter", "screenshot: Option<OwnedScreenshot>,", "screenshot: Option<bytes::Bytes>,", "exact-handler screenshot owner"),
    ("flutter", "request_id: String,\n    data: bytes::Bytes,", "data: bytes::Bytes,", "request-bound screenshot value"),
    ("flutter", "handler.screenshot = None;", "// prior screenshot retained", "new screenshot request clears exact handler"),
    ("flutter", "!= Some(request_id)", "== Some(request_id)", "screenshot request-ID match"),
    ("flutter", "handler.screenshot.take().map(|screenshot| screenshot.data)", "handler.screenshot.as_ref().map(|screenshot| screenshot.data.clone())", "one-time screenshot consumption"),
    ("flutter", "let Some(handler) = handlers.get_mut(&sid)", "let Some(handler) = handlers.values_mut().next()", "screenshot response exact-session selection"),
    ("flutter", "request_id: request_id.clone(),", "request_id: String::new(),", "screenshot response exact-request storage"),
    ("flutter", '("screenshot_id", json!(request_id))', '("screenshot_id", json!(""))', "screenshot response request-ID event"),
    ("flutter", "r_s11e149_screenshot_data_is_owned_by_the_exact_ui_session", "screenshot_session_owner_gate_disabled", "exact screenshot handler behavior proof"),
    ("flutter_ffi", "if s.ui_handler.begin_screenshot_request(&session_id) {", "if true {", "exact handler clear before screenshot request"),
    ("flutter_ffi", "screenshot_id: String,", "screenshot_id: (),", "screenshot action request-ID input"),
    ("flutter_ffi", ".take_screenshot(&session_id, &screenshot_id)", ".take_screenshot(&session_id, \"\")", "screenshot action session-and-request match"),
    ("dart_model", "final screenshotId = evt['screenshot_id'] ?? '';", "final screenshotId = '';", "Dart screenshot request-ID capture"),
    ("dart_model", "screenshotId: screenshotId,", "screenshotId: '',", "Dart screenshot action request binding"),
    ("web_bridge", "required String screenshotId,", "String screenshotId = '',", "web screenshot action signature parity"),
    ("requirements", '<span class="id">R-S11ee</span>', '<span class="id">R-S11ee-disabled</span>', "exact-session screenshot requirement"),
    ("requirements", "<tr><td>284</td>", "<tr><td>284-disabled</td>", "exact-session screenshot disposition"),
    ("hardening", "R-S11ee/R-S11e-149", "R-S11ee-disabled/R-S11e-149", "exact-session screenshot hardening ledger"),
    ("verify", "client::io_loop::tests::r_s11e149_screenshot_responses_require_the_current_exact_request", "client::io_loop::tests::screenshot_gate_disabled", "shared exact screenshot request behavior gate"),
    ("dart_verify", "client::io_loop::tests::r_s11e149_screenshot_responses_require_the_current_exact_request", "client::io_loop::tests::screenshot_gate_disabled", "generated-bridge exact screenshot request behavior gate"),
    ("video_service", "const MAX_SCREENSHOT_REQUEST_OWNERS: usize = 64;", "const MAX_SCREENSHOT_REQUEST_OWNERS: usize = usize::MAX;", "controlled screenshot owner capacity"),
    ("video_service", "const SCREENSHOT_ENCODE_QUEUE_CAPACITY: usize = 2;", "const SCREENSHOT_ENCODE_QUEUE_CAPACITY: usize = 1024;", "controlled screenshot encoder queue capacity"),
    ("video_service", "static ref SCREENSHOTS: Mutex<PendingScreenshots> = Default::default();", "static ref SCREENSHOTS: Mutex<HashMap<(VideoSource, usize), PendingScreenshotRequest>> = Default::default();", "exact controlled screenshot owner registry"),
    ("video_service", "static ref SCREENSHOT_ENCODER: Result<ScreenshotEncoder, String> = ScreenshotEncoder::new();", "static ref SCREENSHOT_ENCODER: Option<ScreenshotEncoder> = None;", "retained controlled screenshot encoder"),
    ("video_service", "if owner.tx.same_channel(&tx) {\n                owner.pending = Some(request);", "if true {\n                owner.pending = Some(request);", "same-channel screenshot pending replacement"),
    ("video_service", "let matches_frame = !owner.in_flight", "let matches_frame = true", "one controlled screenshot in-flight request"),
    ("video_service", "request.source == source && request.display_idx == display_idx", "request.display_idx == display_idx", "controlled screenshot source separation"),
    ("video_service", "if owner.tx.same_channel(tx) && owner.in_flight {", "if owner.in_flight {", "exact-channel screenshot completion"),
    ("video_service", "if owner.pending.is_none() {\n            screenshot.request.restore_vram = true;", "if true {\n            screenshot.request.restore_vram = true;", "successor-preserving screenshot fallback"),
    ("video_service", ".map(|owner| owner.tx.same_channel(tx))\n            .unwrap_or(false);", ".map(|_| true)\n            .unwrap_or(false);", "exact-channel screenshot cancellation"),
    ("video_service", "_worker: std::thread::JoinHandle<()>,", "_worker: (),", "retained screenshot worker handle"),
    ("video_service", "std::sync::mpsc::sync_channel::<ScreenshotEncodeJob>(SCREENSHOT_ENCODE_QUEUE_CAPACITY)", "std::sync::mpsc::channel::<ScreenshotEncodeJob>()", "bounded screenshot encoder channel"),
    ("video_service", "while let Ok(job) = receiver.recv() {\n                    handle_screenshot_job(job);", "while let Ok(_job) = receiver.recv() {", "retained screenshot worker execution"),
    ("video_service", "match sender.try_send(job)", "match sender.send(job)", "nonblocking screenshot encoder admission"),
    ("video_service", ".retain(|screenshot| pending.is_in_flight(screenshot));", ".retain(|_| true);", "cancelled screenshot work suppression"),
    ("video_service", "if !screenshot_dimensions_are_bounded(job.width, job.height) {", "if false {", "screenshot encode dimension bound"),
    ("video_service", "if job.rgba.len() != expected_len {", "if false {", "screenshot exact RGBA length"),
    ("video_service", "if png.len() > crate::peer_text::MAX_PEER_SCREENSHOT_RESPONSE_BYTES {", "if false {", "screenshot encoded-byte bound"),
    ("video_service", "if next_len > self.max_bytes {", "if false {", "screenshot PNG writer allocation bound"),
    ("video_service", "r_s11ef_stale_channel_cannot_cancel_reused_connection_id", "controlled_screenshot_aba_gate_disabled", "controlled screenshot ABA behavior proof"),
    ("video_service", "r_s11ef_png_writer_stops_at_encoded_byte_limit", "controlled_screenshot_png_bound_gate_disabled", "controlled screenshot bounded-writer behavior proof"),
    ("peer_text", "!request_id.is_empty()\n        && request_id.len() <= MAX_PEER_SCREENSHOT_SID_BYTES", "request_id.len() <= MAX_PEER_SCREENSHOT_SID_BYTES", "nonempty controlled screenshot request ID"),
    ("peer_text", "&& !request_id.chars().any(char::is_control)", "&& true", "control-free controlled screenshot request ID"),
    ("server_connection", "if !crate::peer_text::is_bounded_peer_screenshot_request_id(&request.sid) {", "if false {", "controlled screenshot request-ID admission"),
    ("server_connection", "video_service::cancel_take_screenshot(id, tx);", "// stale screenshot authority retained", "controlled screenshot disconnect cancellation"),
    ("requirements", '<span class="id">R-S11ef</span>', '<span class="id">R-S11ef-disabled</span>', "controlled screenshot ownership requirement"),
    ("requirements", "<tr><td>285</td>", "<tr><td>285-disabled</td>", "controlled screenshot ownership disposition"),
    ("hardening", "R-S11ef/R-S11e-150", "R-S11ef-disabled/R-S11e-150", "controlled screenshot ownership hardening ledger"),
    ("verify", "\"${RUN[@]}\" cargo test --lib --features linux-pkg-config \\\n  server::video_service::screenshot_ownership_tests::r_s11ef_ -- --test-threads=1", "true # shared controlled screenshot behavior gate disabled", "shared controlled screenshot behavior gate"),
    ("dart_verify", "server::video_service::screenshot_ownership_tests::r_s11ef_", "server::video_service::screenshot_ownership_tests::disabled_", "generated-bridge controlled screenshot behavior gate"),
    ("video_service", "const MAX_VIDEO_FRAME_ACK_CONTROLLERS: usize = 64;", "const MAX_VIDEO_FRAME_ACK_CONTROLLERS: usize = usize::MAX;", "video acknowledgement controller capacity"),
    ("video_service", "static ref VIDEO_FRAME_ACK_CONTROLLERS: Mutex<HashMap<VideoFrameStreamKey, Weak<VideoFrameAckState>>> = Default::default();", "static ref VIDEO_FRAME_ACK_CONTROLLERS: Mutex<HashMap<usize, Arc<VideoFrameAckState>>> = Default::default();", "exact source/display video acknowledgement registry"),
    ("video_service", "targets: HashMap<i32, VideoFrameTargetState>,", "targets: HashMap<i32, bool>,", "per-target shared video capture state"),
    ("video_service", "self.targets.is_empty() || self.progressed", "self.targets.is_empty() && self.progressed", "one-peer-or-disconnected shared capture progress"),
    ("video_service", "round.targets.extend(", "round.targets.extend_disabled(", "exact shared video capture round targets"),
    ("video_service", "generation == 0 || generation <= round.generation", "generation < round.generation", "nonzero strictly monotonic video acknowledgement generation"),
    ("video_service", "if round.generation != generation {\n            return false;\n        }\n        let Some(state) = round.targets.get_mut(&connection_id)", "let Some(state) = round.targets.get_mut(&connection_id)", "generation-exact video acknowledgement"),
    ("video_service", "*state = VideoFrameTargetState::Acknowledged;\n        round.progressed = true;", "*state = VideoFrameTargetState::Acknowledged;\n        round.progressed = false;", "monotonic exact peer progress publication"),
    ("video_service", "let removed = round.targets.remove(&connection_id).is_some();", "let removed = false;", "all-disconnected shared capture release"),
    ("video_service", "*state = VideoFrameTargetState::Retired;", "round.targets.remove(&connection_id);", "supersession is not peer progress"),
    ("video_service", ".wait_timeout_while(round, timeout, |round| !round.capture_may_advance())", ".wait_timeout_while(round, timeout, |_| false)", "condition-driven video progress wait"),
    ("video_service", "sp.is_option_true(OPTION_REFRESH) || frame_controller.wait_for_progress(timeout)", "frame_controller.wait_for_progress(timeout)", "refresh-interruptible shared video wait"),
    ("video_service", "controllers.retain(|_, state| state.strong_count() != 0);", "controllers.clear();", "live weak video controller retention"),
    ("video_service", "controllers.len() >= MAX_VIDEO_FRAME_ACK_CONTROLLERS", "false", "bounded video controller admission"),
    ("video_service", "controllers.insert(key, Arc::downgrade(&state));", "controllers.clear();", "weak video controller registration"),
    ("video_service", "Arc::ptr_eq(&state, &self.state)", "true", "exact-generation video controller retirement"),
    ("video_service", ".filter_map(|(_, state)| state.upgrade())", ".filter_map(|(key, state)| (key.source == VideoSource::Monitor).then(|| state.upgrade()).flatten())", "trusted disconnect retires all exact sources"),
    ("video_service", "let frame_controller = VideoFrameController::new(source, display_idx)?;", "let frame_controller = VideoFrameController::new(VideoSource::Monitor, display_idx)?;", "capture-source-bound video controller"),
    ("server_service", "lock.video_frame_generation.checked_add(1)", "lock.video_frame_generation.wrapping_add(1)", "checked service-lifetime video generation"),
    ("server_service", "prepare(&conn_ids, generation)?;\n        frame.generation = generation;", "frame.generation = generation;\n        prepare(&conn_ids, generation)?;", "prepare-before-wire video generation ownership"),
    ("server_service", "subscriber.send_video_frame(Arc::clone(&msg), source, display, generation);", "subscriber.send(Arc::clone(&msg));", "source/display/generation exact video mailbox enqueue"),
    ("server_connection", "const VIDEO_EGRESS_WAKE_CAPACITY: usize = 1;", "const VIDEO_EGRESS_WAKE_CAPACITY: usize = 1024;", "video egress wake capacity"),
    ("server_connection", "const VIDEO_EGRESS_MAX_DISPLAYS: usize = 32;", "const VIDEO_EGRESS_MAX_DISPLAYS: usize = usize::MAX;", "video egress display capacity"),
    ("server_connection", "switch_display: Option<(Instant, Arc<Message>)>,", "switch_display: Vec<(Instant, Arc<Message>)>,", "one pending display switch"),
    ("server_connection", "displays: HashMap<usize, VideoDisplayEgress>,", "displays: Vec<VideoDisplayEgress>,", "display-keyed video mailbox"),
    ("server_connection", "awaiting_independent: true,", "awaiting_independent: false,", "fresh display awaits an independent video sequence"),
    (
        "server_connection",
        "match self.wake.try_send(()) {\n"
        "            Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => true,",
        "match self.wake.send(()) {\n"
        "            Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => true,",
        "nonblocking video mailbox wake",
    ),
    ("server_connection", "let independent = crate::client::io_loop::starts_video_sequence(frame);", "let independent = true;", "GOP-aware video classification"),
    ("server_connection", "slot.awaiting_independent = true;", "slot.awaiting_independent = false;", "dependent replacement closes GOP"),
    ("server_connection", "slot.pending = Some(PendingVideoEgress::RefreshRequired);", "slot.pending = Some(PendingVideoEgress::Frame(queued));", "dependent replacement requests independent sequence"),
    ("server_connection", "if !self.wake_receiver() && !retired.contains(&identity) {", "if false {", "closed video receiver retires stale-subscriber enqueue"),
    ("server_connection", "state.switch_display.take()", "state.ready_displays.pop_front().map(|_| unreachable!())", "display switch precedes video"),
    (
        "server_connection",
        "pub(crate) async fn recv(&mut self) -> Option<VideoEgressItem> {\n"
        "        loop {\n"
        "            if let Some(item) = self.take_next() {\n"
        "                return Some(item);\n"
        "            }\n"
        "            self.wake.recv().await?;",
        "pub(crate) async fn recv(&mut self) -> Option<VideoEgressItem> {\n"
        "        loop {\n"
        "            if let Some(item) = self.take_next() {\n"
        "                return Some(item);\n"
        "            }\n"
        "            self.wake.try_recv().ok()?;",
        "event-driven video mailbox receive",
    ),
    ("server_connection", "fn with_connection_owner(mut self, connection_id: i32) -> Self", "fn with_connection_owner(mut self, _connection_id: i32) -> Self", "exact video receiver connection owner"),
    ("server_connection", "video_service::retire_video_frame_connection(connection_id);", "video_service::retire_video_frame_connection(connection_id + 1);", "video receiver exact-owner retirement"),
    ("server_connection", "let mut rx_video = rx_video.with_connection_owner(id);", "let mut rx_video = rx_video;", "video receiver connection-owner installation"),
    ("server_connection", "completion = wait_for_video_write(&mut pending_video_delivery)", "completion = std::future::ready(Ok(Ok(())))", "writer completion ownership"),
    ("server_connection", "conn.stream.send_with_receipt(frame.message.as_ref()).await", "conn.stream.send(frame.message.as_ref()).await.map(|_| unreachable!())", "tracked exact video send"),
    ("server_connection", "authenticated_source != Some(self.identity.source)", "authenticated_source.is_none()", "authenticated-session video source ownership"),
    ("server_connection", "receipt.generation != self.identity.generation", "receipt.generation < self.identity.generation", "exact peer video generation ownership"),
    ("server_connection", "self.writer_complete && self.peer_received", "self.writer_complete || self.peer_received", "writer and peer receipt conjunction"),
    ("server_connection", "pending.mark_writer_complete();\n                            complete_video_delivery(&mut pending_video_delivery, id);", "pending.mark_writer_complete();\n                            video_service::notify_video_frame_fetched(pending.identity.source, pending.identity.display, pending.identity.generation, id, None);", "local writer cannot directly complete capture progress"),
    ("server_connection", "item = rx_video.recv(), if pending_video_delivery.is_none()", "item = rx_video.recv()", "one unreceipted transmitted video frame"),
    ("server_connection", "login.video_frame_receipt_version == VIDEO_FRAME_RECEIPT_VERSION", "true", "video login exact receipt compatibility"),
    ("server_connection", "Some(message::Union::VideoFrameReceipt(receipt))", "Some(message::Union::VideoFrame(_))", "typed peer video receipt dispatch"),
    ("io_loop", "generation == 0", "generation == u64::MAX", "viewer rejects zero video generation"),
    ("io_loop", "generation <= *last", "generation < *last", "viewer rejects duplicate video generation"),
    ("io_loop", "receipt_message.set_video_frame_receipt(receipt);", "receipt_message.set_misc(Misc::new());", "viewer emits typed exact video receipt"),
    ("io_loop", "peer.send(&receipt_message).await", "peer.send(&receipt_message);", "viewer receipt exact send result"),
    ("io_loop", "if !self.video_threads.contains_key(&display) && !self.new_video_thread(display)", "if !self.video_threads.contains_key(&display) && { self.new_video_thread(display); false }", "viewer propagates decoder-owner construction failure"),
    ("io_loop", '"video decoder ownership missing after admission for display {display}"', '"continuing without video decoder ownership for display {display}"', "viewer fails closed on missing decoder ownership"),
    ("io_loop", "pi.video_frame_receipt_version != VIDEO_FRAME_RECEIPT_VERSION", "false", "viewer requires controlled receipt capability echo"),
    ("client", "ConnType::DEFAULT_CONN | ConnType::VIEW_CAMERA", "ConnType::FILE_TRANSFER | ConnType::TERMINAL", "video-only receipt capability advertisement"),
    ("server_connection", "video_service::retire_video_frame_connection(id);", "video_service::retire_video_frame_connection(id + 1);", "exact local disconnect retirement"),
    ("transport_tcp", "completion: Option<oneshot::Sender<io::Result<()>>>,", "completion: Option<oneshot::Sender<()>>,", "writer command exact result receipt"),
    ("transport_tcp", "let result = sink.send(bytes).await;", "let result = Ok(());", "writer receipt follows exact sink send"),
    ("transport_tcp", "let _ = completion.send(result);", "drop(completion);", "writer reports exact completion"),
    ("transport_stream", "pub async fn send_with_receipt(", "pub async fn tracked_send_disabled(", "stream exact writer receipt wrapper"),
    ("message_proto", "reserved 2, 9, 12, 14;", "reserved 2, 12, 14;\n  bool video_ack_required = 9;", "retired video acknowledgement negotiation tag"),
    ("message_proto", "reserved 12; // retired displayless acknowledgement; versioned top-level exact receipts own peer progress", "VideoReceived video_received = 12;", "retired displayless peer acknowledgement tag"),
    ("message_proto", "uint64 generation = 15;", "uint64 generation = 12;", "video wire generation tag"),
    ("message_proto", "VideoFrameReceipt video_frame_receipt = 33;", "VideoFrameReceipt video_frame_receipt = 12;", "top-level exact video receipt tag"),
    ("hbb_common_lib", "pub const VIDEO_FRAME_RECEIPT_VERSION: u32 = 1;", "pub const VIDEO_FRAME_RECEIPT_VERSION: u32 = 0;", "exact video receipt protocol version"),
    ("hbb_common_lib", "r_s11fk_wire_round_trips_exact_video_identity_and_capability", "video_wire_round_trip_test_disabled", "exact video protocol wire behavior proof"),
    ("video_service", "r_s11eg_monitor_and_camera_acknowledgements_are_source_exact", "video_ack_source_test_disabled", "video acknowledgement source behavior proof"),
    ("video_service", "r_s11eg_acknowledgement_round_is_installed_before_frame_enqueue", "video_ack_prepare_order_test_disabled", "video acknowledgement prepare-order behavior proof"),
    ("video_service", "r_s11fb_late_completion_cannot_satisfy_a_new_round", "video_ack_stale_round_test_disabled", "video acknowledgement stale-round behavior proof"),
    ("video_service", "r_s11fk_controller_rejects_zero_and_reused_wire_generations", "video_wire_generation_test_disabled", "video wire generation behavior proof"),
    ("video_service", "r_s11fl_one_exact_peer_receipt_paces_shared_capture_without_the_slow_peer", "video_shared_progress_test_disabled", "one-peer shared capture progress behavior proof"),
    ("video_service", "r_s11fl_blocked_capture_wait_wakes_on_one_exact_peer_receipt", "video_shared_wait_wake_test_disabled", "blocked shared capture wait wake behavior proof"),
    ("video_service", "test_waiter_blocked: std::sync::atomic::AtomicBool", "test_waiter_blocked_disabled: std::sync::atomic::AtomicBool", "test-only blocked-wait state proof"),
    ("video_service", ".store(true, std::sync::atomic::Ordering::SeqCst)", ".store(false, std::sync::atomic::Ordering::SeqCst)", "blocked-wait entry behavior proof"),
    ("video_service", "while !wait_state", "while false && !wait_state", "blocked-wait observation behavior proof"),
    ("video_service", "r_s11fl_superseded_frame_is_not_peer_progress_for_its_exact_round", "video_supersession_progress_test_disabled", "supersession non-progress behavior proof"),
    ("video_service", "r_s11fl_empty_or_fully_disconnected_round_does_not_delay_capture", "video_disconnected_release_test_disabled", "disconnected shared capture release behavior proof"),
    ("video_service", "r_s11fl_refresh_interrupts_an_obsolete_capture_wait", "video_refresh_wait_test_disabled", "refresh-interruptible capture wait behavior proof"),
    ("server_connection", "r_s11fb_dependent_replacement_requests_an_independent_sequence", "video_egress_gop_test_disabled", "video egress GOP behavior proof"),
    ("server_connection", "r_s11fb_fresh_display_rejects_dependent_until_independent", "video_egress_fresh_gop_test_disabled", "fresh-display GOP behavior proof"),
    ("server_connection", "r_s11fb_closed_receiver_retires_a_stale_subscriber_enqueue", "video_egress_closed_receiver_test_disabled", "closed-receiver video retirement behavior proof"),
    ("server_connection", "r_s11fk_local_write_then_exact_peer_receipt_completes_once", "video_peer_receipt_order_test_disabled", "writer-first peer receipt behavior proof"),
    ("server_connection", "r_s11fk_exact_peer_receipt_then_local_write_completes", "video_writer_receipt_order_test_disabled", "peer-first writer receipt behavior proof"),
    ("io_loop", "r_s11fk_viewer_receipts_are_nonzero_display_exact_and_monotonic", "viewer_video_receipt_test_disabled", "viewer exact video receipt behavior proof"),
    ("client", "r_s11fk_login_negotiates_exact_receipts_only_for_video_sessions", "video_receipt_login_test_disabled", "video capability behavior proof"),
    ("transport_tcp", "r_s11fb_receipt_waits_for_the_exact_sink_send", "writer_receipt_backpressure_test_disabled", "writer receipt backpressure behavior proof"),
    ("transport_tcp", "r_s11fb_tracked_keyed_send_round_trips_the_exact_frame", "writer_receipt_keyed_round_trip_test_disabled", "writer receipt keyed round-trip behavior proof"),
    ("transport_tcp", "r_s11fk_real_tcp_receipt_can_precede_peer_read", "writer_receipt_real_tcp_boundary_test_disabled", "real TCP local-receipt boundary behavior proof"),
    ("requirements", '<span class="id">R-S11eg</span>', '<span class="id">R-S11eg-disabled</span>', "controlled video acknowledgement requirement"),
    ("requirements", "<tr><td>286</td>", "<tr><td>286-disabled</td>", "controlled video acknowledgement disposition"),
    ("hardening", "R-S11eg/R-S11e-151", "R-S11eg-disabled/R-S11e-151", "controlled video acknowledgement hardening ledger"),
    ("requirements", '<span class="id">R-S11fb</span>', '<span class="id">R-S11fb-disabled</span>', "controlled video egress requirement"),
    ("requirements", "<tr><td>310</td>", "<tr><td>310-disabled</td>", "controlled video egress disposition"),
    ("hardening", "**R-S11fb/R-S11e-189 controlled video exact-writer egress", "**R-S11fb-disabled/R-S11e-189 controlled video exact-writer egress", "controlled video egress hardening ledger"),
    ("requirements", '<span class="id">R-S11fk</span>', '<span class="id">R-S11fk-disabled</span>', "controlled video exact peer receipt requirement"),
    ("requirements", "<tr><td>319</td>", "<tr><td>319-disabled</td>", "controlled video exact peer receipt disposition"),
    ("hardening", "R-S11fk/R-S11e-198 controlled-video exact peer receipt", "R-S11fk-disabled/R-S11e-198 controlled-video exact peer receipt", "controlled video exact peer receipt hardening ledger"),
    ("requirements", '<span class="id">R-S11fl</span>', '<span class="id">R-S11fl-disabled</span>', "controlled video shared capture pacing requirement"),
    ("requirements", "<tr><td>320</td>", "<tr><td>320-disabled</td>", "controlled video shared capture pacing disposition"),
    ("hardening", "R-S11fl/R-S11e-199 controlled-video shared capture pacing", "R-S11fl-disabled/R-S11e-199 controlled-video shared capture pacing", "controlled video shared capture pacing hardening ledger"),
    ("verify", "\"${RUN[@]}\" cargo test --lib --features linux-pkg-config \\\n  server::video_service::video_frame_ack_tests::r_s11eg_ -- --test-threads=1", "true # shared video acknowledgement behavior gate disabled", "shared controlled video acknowledgement behavior gate"),
    ("verify", "\"${RUN[@]}\" cargo test --lib --features linux-pkg-config \\\n  server::video_service::video_frame_ack_tests::r_s11fl_ -- --test-threads=1", "true # shared video pacing behavior gate disabled", "shared controlled video pacing behavior gate"),
    ("verify", "\"${RUN[@]}\" cargo test --lib --features linux-pkg-config \\\n  server::connection::video_egress_tests::r_s11fb_ -- --test-threads=1", "true # shared video egress behavior gate disabled", "shared controlled video egress behavior gate"),
    ("verify", "\"${RUN[@]}\" cargo test -p hbb_common writer_receipt_tests::r_s11fb_ -- --test-threads=1", "true # shared writer receipt behavior gate disabled", "shared writer receipt behavior gate"),
    ("verify", "\"${RUN[@]}\" cargo test -p hbb_common writer_receipt_tests::r_s11fk_real_tcp_receipt_can_precede_peer_read -- --test-threads=1", "true # shared real TCP boundary behavior gate disabled", "shared real TCP local-receipt boundary behavior gate"),
    ("verify", "\"${RUN[@]}\" cargo test --lib --features linux-pkg-config r_s11fk_ -- --test-threads=1", "true # shared exact peer receipt behavior gate disabled", "shared exact peer video receipt behavior gate"),
    ("verify", "\"${RUN[@]}\" cargo test -p hbb_common exact_video_receipt_wire_tests::r_s11fk_ -- --test-threads=1", "true # shared exact video wire behavior gate disabled", "shared exact video protocol wire behavior gate"),
    ("dart_verify", "server::video_service::video_frame_ack_tests::r_s11eg_", "server::video_service::video_frame_ack_tests::disabled_", "generated-bridge controlled video acknowledgement behavior gate"),
    ("dart_verify", "server::video_service::video_frame_ack_tests::r_s11fl_", "server::video_service::video_frame_ack_tests::disabled_fl_", "generated-bridge controlled video pacing behavior gate"),
    ("dart_verify", "server::connection::video_egress_tests::r_s11fb_", "server::connection::video_egress_tests::disabled_", "generated-bridge controlled video egress behavior gate"),
    ("dart_verify", "writer_receipt_tests::r_s11fb_", "writer_receipt_tests::disabled_", "generated-bridge writer receipt behavior gate"),
    ("dart_verify", "writer_receipt_tests::r_s11fk_real_tcp_receipt_can_precede_peer_read", "writer_receipt_tests::disabled_real_tcp_receipt_can_precede_peer_read", "generated-bridge real TCP local-receipt boundary behavior gate"),
    ("dart_verify", "      r_s11fk_ -- --test-threads=1", "      peer_receipt_gate_disabled", "generated-bridge exact peer video receipt behavior gate"),
    ("dart_verify", "exact_video_receipt_wire_tests::r_s11fk_", "video_wire_gate_disabled", "generated-bridge exact video protocol wire behavior gate"),
    ("server_connection", "const AUDIO_EGRESS_WAKE_CAPACITY: usize = 1;", "const AUDIO_EGRESS_WAKE_CAPACITY: usize = 1024;", "audio wake capacity"),
    ("server_connection", "format: Option<(Instant, Arc<Message>)>,", "format: Vec<(Instant, Arc<Message>)>,", "one pending audio format"),
    ("server_connection", "frame: Option<(Instant, Arc<Message>)>,", "frame: Vec<(Instant, Arc<Message>)>,", "one pending audio frame"),
    ("server_connection", "mpsc::channel(AUDIO_EGRESS_WAKE_CAPACITY)", "mpsc::unbounded_channel()", "bounded audio wake channel"),
    ("server_connection", "state.frame = Some(queued);", "drop(queued);", "latest audio frame replacement"),
    ("server_connection", "state.format = Some(queued);", "drop(queued);", "latest audio format replacement"),
    ("server_connection", "state.frame = None;", "// old-generation frame retained", "audio format generation retirement"),
    (
        "server_connection",
        "match self.wake.try_send(()) {\n"
        "            Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => {}",
        "match self.wake.send(()) {\n"
        "            Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => {}",
        "nonblocking audio wake",
    ),
    (
        "server_connection",
        "match self.wake.try_send(()) {\n"
        "            Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => {}",
        "match self.wake.try_send(()) {\n"
        "            Ok(()) | Err(mpsc::error::TrySendError::Closed(_)) => {}",
        "coalesced full audio wake",
    ),
    ("server_connection", "state.format.take().or_else(|| state.frame.take())", "state.frame.take().or_else(|| state.format.take())", "format-before-frame dequeue"),
    (
        "server_connection",
        "pub(crate) async fn recv(&mut self) -> Option<(Instant, Arc<Message>)> {\n"
        "        loop {\n"
        "            if let Some(queued) = self.take_next() {\n"
        "                return Some(queued);\n"
        "            }\n"
        "            self.wake.recv().await?;",
        "pub(crate) async fn recv(&mut self) -> Option<(Instant, Arc<Message>)> {\n"
        "        loop {\n"
        "            if let Some(queued) = self.take_next() {\n"
        "                return Some(queued);\n"
        "            }\n"
        "            self.wake.try_recv().ok()?;",
        "event-driven async audio receive",
    ),
    ("server_connection", "self.wake.blocking_recv()?", "self.wake.try_recv().ok()?", "event-driven blocking audio receive"),
    ("server_connection", "impl Drop for AudioEgressReceiver", "impl AudioEgressReceiver", "receiver retained-state retirement"),
    ("server_connection", 'log::error!("audio egress state was poisoned")', 'log::debug!("audio egress state was poisoned")', "audio poison diagnostic"),
    ("client", "let (audio_sender, thread) = new_audio_thread();\n    OwnedMediaThread::new(\"audio decoder\", audio_sender, thread)", "let (audio_sender, _thread) = new_audio_thread();\n    audio_sender", "sole owning audio constructor"),
    ("server_connection", "decoder: OwnedMediaThread,", "decoder: MediaSender,", "controlled audio decoder owner"),
    ("server_connection", "controlled_audio: Option<ControlledAudioThread>,", "controlled_audio: Option<ControlledAudioThread>,\n    audio_sender: Option<MediaSender>,", "retired controlled audio sender field"),
    ("server_connection", "controlled_audio: Option<ControlledAudioThread>,", "controlled_audio: Option<ControlledAudioThread>,\n    audio_format: Option<(u32, u32)>,", "retired controlled audio format field"),
    ("server_connection", "controlled_audio: Option<ControlledAudioThread>,", "controlled_audio: Option<ControlledAudioThread>,\n    voice_calling: bool,", "retired controlled voice-call boolean field"),
    ("server_connection", "tx_audio: Option<AudioEgressSender>", "tx_audio_removed: Option<AudioEgressSender>", "exact connection audio sender"),
    ("server_connection", "let tx_by_audio = match &msg.union", "let tx_by_audio = match &None", "audio route classification"),
    ("server_connection", "Some(misc::Union::AudioFormat(_))", "Some(misc::Union::StopService(_))", "audio format route classification"),
    ("server_connection", "if tx_by_audio {", "if false {", "audio route admission"),
    ("server_connection", "let (tx_audio, mut rx_audio) = audio_egress_channel();", "let (tx_audio, mut rx_audio) = mpsc::unbounded_channel();", "controlled bounded audio channel"),
    ("server_connection", "ConnInner::with_audio(id, Some(tx), Some(tx_video), Some(tx_audio))", "ConnInner::new(id, Some(tx), Some(tx_video))", "controlled audio sender installation"),
    ("server_connection", "Some((instant, value)) = rx_audio.recv()", "Some((instant, value)) = rx.recv()", "controlled separate audio receive"),
    ("server_connection", "instant.elapsed() > Duration::from_secs(1)", "false", "stale controlled audio refusal"),
    ("io_loop", "receiver: AudioEgressReceiver", "receiver_removed: AudioEgressReceiver", "outgoing bounded receiver owner"),
    ("io_loop", "if let Some(subscription) = self.subscription.take()", "if false", "outgoing exact unsubscribe"),
    ("io_loop", ".subscribe(audio_service::NAME, subscription, false)", ".subscribe(audio_service::NAME, subscription, true)", "outgoing unsubscribe action"),
    ("io_loop", "voice_call.receiver.recv().await", "std::future::pending().await", "outgoing event-driven receive"),
    ("io_loop", "let (tx_audio_data, rx_audio_data) = audio_egress_channel();", "let (tx_audio_data, rx_audio_data) = mpsc::unbounded_channel();", "outgoing bounded audio channel"),
    ("io_loop", "ConnInner::with_audio(conn_id, None, None, Some(tx_audio_data))", "ConnInner::new(conn_id, Some(tx_audio_data), None)", "outgoing audio-only subscription"),
    ("io_loop", "peer.send(&message as &Message).await", "self.sender.send(Data::Message((*message).clone()))", "outgoing sole peer writer"),
    ("server_connection", "r_s11eh_audio_egress_retains_only_the_latest_frame", "audio_latest_frame_test_disabled", "latest-frame audio behavior proof"),
    ("server_connection", "r_s11eh_new_audio_format_retires_an_old_pending_frame", "audio_generation_test_disabled", "audio generation behavior proof"),
    ("server_connection", "r_s11eh_async_audio_egress_waits_without_polling_and_closes", "audio_async_test_disabled", "async audio behavior proof"),
    ("server_connection", "receiver retirement must release retained audio without another producer send", "receiver retirement retained audio", "receiver-retirement behavior proof"),
    ("requirements", '<span class="id">R-S11eh</span>', '<span class="id">R-S11eh-disabled</span>', "bounded audio egress requirement"),
    ("requirements", "<tr><td>287</td>", "<tr><td>287-disabled</td>", "bounded audio egress disposition"),
    ("hardening", "R-S11eh/R-S11e-152", "R-S11eh-disabled/R-S11e-152", "bounded audio egress hardening ledger"),
    ("verify", "\"${RUN[@]}\" cargo test --lib --features linux-pkg-config \\\n  server::connection::audio_egress_tests::r_s11eh_ -- --test-threads=1", "true # shared bounded audio behavior gate disabled", "shared bounded audio behavior gate"),
    ("dart_verify", "server::connection::audio_egress_tests::r_s11eh_", "server::connection::audio_egress_tests::disabled_", "generated-bridge bounded audio behavior gate"),
    ("input_owner", "serviceGeneration > 0 && connectionId > 0", "serviceGeneration >= 0 && connectionId > 0", "controlled-input owner validity"),
    ("input_queue", "if (!owner.isValid || entries.size >= capacity)", "if (!owner.isValid)", "controlled-input queue capacity"),
    ("input_queue", "if (iterator.next().owner == owner)", "if (iterator.next().owner.connectionId == owner.connectionId)", "controlled-input exact generation retirement"),
    ("capture_owners", "fun ownsRemoteInput(connectionId: Int): Boolean = owners.contains(connectionId)", "fun ownsRemoteInput(connectionId: Int): Boolean = true", "controlled-input Remote authority lookup"),
    ("service", "!controlledCaptureOwners.ownsRemoteInput(connectionId)", "false", "controlled-input service authority"),
    ("service", "InputService.ctx?.retireServiceGeneration(nativeServerGeneration)", "// input generation retained", "controlled-input service-generation teardown"),
    ("input_service", "private const val MAX_PENDING_WHEEL_ACTIONS = 32", "private const val MAX_PENDING_WHEEL_ACTIONS = Int.MAX_VALUE", "controlled-input wheel capacity"),
    ("input_service", "if (destroyed || owner !in activeInputOwners)", "if (destroyed)", "controlled-input active-owner admission"),
    ("input_service", "private val mainHandler = Handler(Looper.getMainLooper())", "private val timer = Timer()", "retired controlled-input Timer thread"),
    ("input_service", "activePointerOwner != owner", "false", "controlled-input pointer owner"),
    ("input_service", "while (next != null && next.owner !in activeInputOwners)", "while (false)", "controlled-input stale queued-owner filtering"),
    ("input_service", "override fun onCancelled(gestureDescription: GestureDescription)", "fun onCancelledDisabled(gestureDescription: GestureDescription)", "controlled-input gesture cancellation drain"),
    ("input_service", "if (!keyActions.offer(owner, keyEvent))", "if (false)", "controlled-input key capacity"),
    ("android_ffi", "\"(IIIII)Z\"", "\"(IIII)Z\"", "controlled-input pointer JNI identity"),
    ("android_ffi", "\"(I[B)Z\"", "\"([B)Z\"", "controlled-input key JNI identity"),
    ("server_connection", "call_main_service_key_event_for_generation(\n                                self.android_server_generation,\n                                self.inner.id(),", "call_main_service_key_event_for_generation(\n                                self.android_server_generation,\n                                0,", "controlled-input Rust connection identity"),
    ("input_owner_test", "old generation retirement selected the replacement owner", "old generation retirement passed", "controlled-input generation-ABA behavior proof"),
    ("requirements", '<span class="id">R-S11ei</span>', '<span class="id">R-S11ei-disabled</span>', "controlled-input ownership requirement"),
    ("requirements", "<tr><td>288</td>", "<tr><td>288-disabled</td>", "controlled-input ownership disposition"),
    ("hardening", "R-S11ei/R-S11e-153", "R-S11ei-disabled/R-S11e-153", "controlled-input ownership hardening ledger"),
    ("verify", 'echo "== Android MediaProjection/input lifecycle finality (R-S14/R-S11ei/R-S11ek/R-S11em/R-S11en/R-S11eu/R-S11e-153/R-S11e-169/R-S11e-174/R-S11e-175/R-S11e-182/R-T4) =="', 'echo "== Android MediaProjection/input lifecycle finality (R-S14/R-S11ei-disabled/R-S11ek/R-S11em/R-S11en/R-S11eu/R-S11e-153/R-S11e-169/R-S11e-174/R-S11e-175/R-S11e-182/R-T4) =="', "shared controlled-input/audio/status generation ownership gate"),
    ("verify", "android-controlled-input-owner-test.kt", "android-controlled-input-owner-test-disabled.kt", "shared controlled-input behavior fixture gate"),
    ("verify", "grep -qF 'take_previous_android_mobile_client_sessions(client_owner_id, session_id)?' src/flutter.rs", "true # replacement-drain shared gate disabled", "shared mobile replacement-drain gate"),
    ("verify", "if [ \"$(grep -cF 'check_remove_unused_displays(None, session, &handlers);' src/flutter.rs)\" -ne 2 ]; then", "if false; then # post-drain display gate disabled", "shared post-drain display-reconciliation gate"),
    ("dart_verify", "cargo test --offline --locked --lib --features flutter,unix-file-copy-paste \\\n      flutter::mobile_session_lifecycle_tests:: -- --test-threads=1", "true # generated-bridge mobile lifecycle tests disabled", "generated-bridge mobile lifecycle behavior gate"),
    ("dart_verify", "flutter test --no-pub test/mobile_file_session_lifecycle_test.dart", "true # mobile file-session lifecycle test disabled", "mobile file-session lifecycle behavior gate"),
    ("mobile_file_lifecycle_test", "expect((await replacement).path, '/same-path');", "expect((await replacement).path, isEmpty);", "reserve-before-dispatch retirement versus replacement behavior proof"),
    ("io_loop", "self.voice_call_audio = self.start_voice_call();\n                                if self.voice_call_audio.is_some() {\n                                    self.handler.on_voice_call_started();", "self.handler.on_voice_call_started();\n                                self.voice_call_audio = self.start_voice_call();\n                                if self.voice_call_audio.is_some() {", "audio-owner-before-native voice activation"),
    ("io_loop", '.on_voice_call_closed("Failed to start voice call audio")', '.on_voice_call_started()', "outgoing voice start-failure retirement"),
    ("test", "one controlled teardown cleared another owner", "controlled teardown passed", "controlled behavior proof"),
    ("connection_type_test", '"PortForward" to ControlledConnectionType.PORT_FORWARD', '"PortForward" to ControlledConnectionType.REMOTE', "PortForward behavior proof"),
    ("connection_type_test", "one Remote teardown cleared another live owner", "concurrent Remote aggregation disabled", "capture-owner aggregation behavior"),
    ("connection_type_test", "remove-then-add ordering lost new Remote demand", "remove-before-add convergence disabled", "capture remove-before-add behavior"),
    ("connection_type_test", "add-then-remove ordering lost new Remote demand", "add-before-remove convergence disabled", "capture add-before-remove behavior"),
    ("requirements", '<span class="id">R-S11br</span>', '<span class="id">R-S11br-disabled</span>', "normative requirement"),
    ("requirements", "generation that is equal (idempotent ordinary resume) or newer (lost-response recovery)", "a strictly newer generation", "idempotent same-generation resume requirement"),
    ("requirements", "only then publish native/UI started state", "publish native/UI started state before construction", "audio-owner-before-native start requirement"),
    ("requirements", "service-owned set of exact positive connection IDs", "one global Boolean reconstructed in Rust", "service-owned capture-demand requirement"),
    ("requirements", "detached global stop edge", "best-effort global stop edge", "stale capture-stop prohibition"),
    ("requirements", "gate its controlled-state and input JNI callbacks against the exact live Service generation", "route callbacks through the latest Service object", "stale-generation callback prohibition"),
    ("requirements", "bind that generation only after JNI proves that its caller is the exact currently retained <code>MainService</code> object", "bind that generation to whichever Service object is currently reachable", "exact-object listener-generation requirement"),
    ("requirements", "a retained global <code>applicationContext</code> reference", "a JNI local <code>applicationContext</code> reference", "application-context global-reference requirement"),
    ("requirements", "<tr><td>211</td>", "<tr><td>211-disabled</td>", "Appendix disposition"),
    ("requirements", '<span class="id">R-S11ek</span>', '<span class="id">R-S11ek-disabled</span>', "controlled-service audio generation requirement"),
    ("requirements", "<tr><td>290</td>", "<tr><td>290-disabled</td>", "controlled-service audio generation disposition"),
    ("hardening", "R-S11br/R-S11e-84 — Android native voice-call capture has exact process-wide owners", "R-S11br/R-S11e-84 — Android native voice-call capture is best effort", "hardening ledger"),
    ("hardening", "R-S11ek/R-S11e-169", "R-S11ek-disabled/R-S11e-169", "controlled-service audio generation hardening ledger"),
    ("hardening", "same-or-newer resume with active-state retention plus older/cross-isolate refusal", "strictly newer resume with active-state retention", "idempotent same-generation resume ledger"),
    ("hardening", "it never mints a generation, replaces an owner, or drains sessions", "allocating a fresh generation and draining a different superseded owner", "read-only Activity-resume summary"),
    ("hardening", "publishes `on_voice_call_started` only after that complete owner exists", "publishes `on_voice_call_started` before that complete owner exists", "audio-owner-before-native start ledger"),
    ("hardening", "service-owned exact Remote connection-ID set", "Rust-owned Boolean capture snapshot", "exact capture-owner hardening ledger"),
    ("hardening", "exact-object JNI release", "process-lifetime stale JNI retention", "service callback-owner release ledger"),
    ("hardening", "refuses a zero, stopped, or replaced generation before entering Java", "accepts callbacks from any native generation", "callback-generation hardening ledger"),
    ("hardening", "`startServer(this, ...)` returns that exact generation only after JNI proves", "`startServer()` attaches the generation to the latest Service without comparison", "exact-object listener-generation hardening ledger"),
    ("verify", "grep -qF 'stale_android_activity_cannot_reclaim_the_replacement_owner' src/flutter.rs", "grep -qF 'resumed_android_activity_reclaims_owner_without_reusing_a_stale_generation' src/flutter.rs", "shared stale-Activity takeover-refusal regression gate"),
    ("verify", 'and owner_resume.index("ANDROID_CLIENT_OWNER")\n        < owner_resume.index(".read()")\n        < owner_resume.index(".resume(generation, session_id)")', 'and owner_resume.index("ANDROID_CLIENT_OWNER.write()")\n        < owner_resume.index(".resume(generation, session_id)")', "shared read-only Rust Activity-resume gate"),
    ("verify", 'and "close_sessions_owned_by" not in owner_resume', 'and "close_sessions_owned_by" in owner_resume', "shared resume-without-takeover gate"),
    ("flutter", "match s.start_io_thread_with_lock(&mut thread_lock)", "match s.start_io_thread()", "failed-start transactional match"),
    ("flutter", "let mut thread_lock = s.thread.lock().unwrap();\n        let mut handlers = s.session_handlers.write().unwrap();", "let mut handlers = s.session_handlers.write().unwrap();\n        let mut thread_lock = s.thread.lock().unwrap();", "worker-slot before handler-owner lock order"),
    ("flutter", "rollback_failed_session_start(session_id, client_owner_id);", "// failed-start rollback omitted", "false failed-start rollback"),
    ("flutter", "fn rollback_failed_session_start(session_id: &SessionID, client_owner_id: &SessionID) {\n    if let Some(session) =\n        sessions::remove_failed_start_by_exact_ui_owner(session_id, client_owner_id)", "fn rollback_failed_session_start(session_id: &SessionID, client_owner_id: &SessionID) {\n    if let Some(session) = sessions::get_session_by_session_id(session_id) {\n        session.close_event_stream(*session_id);\n    }\n    if let Some(session) =\n        sessions::remove_failed_start_by_exact_ui_owner(session_id, client_owner_id)", "failed-start normal-close marker refusal"),
    ("flutter", "handler.client_owner_id.as_ref() != Some(client_owner_id) {\n                return None;\n            }\n            if handlers.remove(id).is_none()", "false {\n                return None;\n            }\n            if handlers.remove(id).is_none()", "failed-start replacement-owner preservation"),
    ("flutter", "fn failed_session_start_rolls_back_and_joins_only_the_exact_session()", "fn failed_session_start_rollback_is_unchecked()", "failed-start exact rollback behavior proof"),
    ("flutter", "let result = sessions::replace_peer_session_display_owner(", "sessions::insert_peer_session_id(", "atomic existing-session display-owner replacement"),
    ("flutter_ffi", "static ref MOBILE_SESSION_ADD_TRANSACTION: Mutex<()> = Mutex::new(());", "static ref MOBILE_SESSION_ADD_TRANSACTION_DISABLED: Mutex<()> = Mutex::new(());", "serialized mobile-add transaction owner"),
    ("flutter_ffi", "pub fn session_add_mobile(", "pub fn session_add_mobile_sync(", "asynchronous mobile-add entry"),
    ("flutter_ffi", "    conn_token: Option<String>,\n) -> Result<()> {\n    if !cfg!(any(target_os = \"android\", target_os = \"ios\"))", "    conn_token: Option<String>,\n) -> ResultType<()> {\n    if !cfg!(any(target_os = \"android\", target_os = \"ios\"))", "concrete codegen-compatible mobile-add result"),
    ("flutter_ffi", "let _transaction = MOBILE_SESSION_ADD_TRANSACTION\n        .lock()", "let _transaction = MOBILE_SESSION_ADD_TRANSACTION\n        .try_lock()", "complete mobile add transaction serialization"),
    ("flutter_ffi", "flutter::wait_for_android_client_owner_drain(&client_owner_id)?;", "// Android predecessor drain barrier omitted", "Android lifecycle predecessor drain barrier"),
    ("flutter_ffi", "Synchronous session preparation is unavailable on mobile", "Synchronous session preparation is available on mobile", "synchronous mobile-add refusal"),
    ("flutter_ffi", "Existing-session attachment is unavailable on mobile", "Existing-session attachment is available on mobile", "synchronous mobile-attachment refusal"),
    ("dart_mobile_start_queue", "_pending?.complete(MobileSessionStartDisposition.superseded);", "// superseded pending request retained", "latest-pending replacement"),
    ("dart_mobile_start_queue", "if (pending != null && matches(pending.request))", "if (pending != null)", "exact pending cancellation"),
    ("dart_mobile_start_queue", "return running.done.future;", "return null;", "running exact-finality lookup"),
    ("dart_mobile_start_queue", "if (entry == null) {\n        return;", "if (entry == null) {\n        continue;", "failure-safe bounded successor drain"),
    ("dart_mobile_start_queue", "_running = _pending;", "_running = null;", "bounded successor continuation"),
    ("dart_mobile_start_queue", "_MobileSessionStartEntry<T>? _pending;", "_MobileSessionStartEntry<T>? _pending;\n  final List<T> backlog = [];", "unbounded mobile-start backlog refusal"),
    ("mobile_start_queue_test", "closing the running request waits while a newer request is pending", "closing the running request returns while a newer request is pending", "running-preparation finality behavior proof"),
    ("mobile_start_queue_test", "a failed running request does not wedge the bounded successor", "a failed running request may wedge the bounded successor", "failed-preparation successor behavior proof"),
    ("dart_stream_finality", "if (_expectedCloseReceived || _unexpectedTerminationReported)", "if (_unexpectedTerminationReported)", "expected-close stream termination suppression"),
    ("stream_finality_test", "an exact normal-close event suppresses later stream termination", "an exact normal-close event permits later stream termination", "expected-close stream behavior proof"),
    ("dart_model", "await bind.sessionAddMobile(", "bind.sessionAddSync(", "off-UI mobile session add"),
    ("dart_model", "await _closeNativeSession(request.sessionId);", "await _closeNativeSession(sessionId);", "stale preparation exact close"),
    ("dart_model", "_mobileSessionStarts.cancelPendingOrGetRunning(", "_mobileSessionStarts.cancelPending(", "exact pending-or-running close finality"),
    ("dart_model", "await _awaitMobileSessionStart(closingSessionId);", "// preparation finality omitted", "stale-entry mobile close preparation finality"),
    ("dart_model", "if (!isCurrentSession(expectedSessionId)) {\n      return;\n    }\n    closed = true;\n    _retireSessionOwner(expectedSessionId);\n    dialogManager.dismissAll();", "if (true) {\n      // stale stream failure accepted\n    }\n    closed = true;\n    _retireSessionOwner(expectedSessionId);\n    dialogManager.dismissAll();", "stale stream-failure refusal"),
    ("dart_model", "closed = true;\n    _retireSessionOwner(expectedSessionId);", "closed = true;", "stream-failure session-owner retirement"),
    ("dart_model", "closed = true;\n            _retireSessionOwner(activeSessionId);", "closed = true;", "expected-close session-owner retirement"),
    ("dart_model", "streamFinality.acceptExpectedClose();", "// expected close identity erased", "expected exact-close stream marker"),
    ("dart_model", "}, onError: (Object error, StackTrace stackTrace) {\n      sessionEvents.retire(streamOwner);\n      if (!streamFinality.acceptUnexpectedTermination())", "}, onErrorDisabled: (Object error, StackTrace stackTrace) {\n      sessionEvents.retire(streamOwner);\n      if (!streamFinality.acceptUnexpectedTermination())", "session stream error handler"),
    ("dart_model", "onDone: () {\n      sessionEvents.retire(streamOwner);\n      if (!streamFinality.acceptUnexpectedTermination())", "onDone: () {\n      sessionEvents.retire(streamOwner);\n      if (true)", "session stream end handler"),
    ("dart_model", "qualityMonitorModel.checkShowQualityMonitor(request.sessionId)", "qualityMonitorModel.checkShowQualityMonitor(sessionId)", "post-add quality-option ordering"),
    ("dart_model", "if (isMobile && isNewPeer)", "if (false && isNewPeer)", "mobile asynchronous start admission"),
    ("mobile_remote", "gFFI.inputModel.listenToMouse(true);", "gFFI.inputModel.listenToMouse(true);\n    gFFI.qualityMonitorModel.checkShowQualityMonitor(sessionId);", "remote pre-add quality-option refusal"),
    ("mobile_camera", "gFFI.inputModel.listenToMouse(true);", "gFFI.inputModel.listenToMouse(true);\n    gFFI.qualityMonitorModel.checkShowQualityMonitor(sessionId);", "camera pre-add quality-option refusal"),
    ("web_bridge", "Future<void> sessionAddMobile(", "void sessionAddMobile(", "web mobile-add interface parity"),
    ("dart_verify", "test/mobile_session_start_queue_test.dart", "test/mobile_session_start_queue_test_disabled.dart", "mobile-start queue behavior gate"),
    ("dart_verify", "test/session_stream_finality_test.dart", "test/session_stream_finality_test_disabled.dart", "stream-finality behavior gate"),
    ("dart_verify", 'printf "%s\\n" "$mobile_add_impl" | grep -qF "_platform.executeNormal(FlutterRustBridgeTask("', 'printf "%s\\n" "$mobile_add_impl" | grep -qF "_platform.executeSync(FlutterRustBridgeSyncTask("', "generated asynchronous mobile-add gate"),
    ("requirements", '<span class="id">R-S11eo</span>', '<span class="id">R-S11eo-disabled</span>', "mobile preparation requirement"),
    ("requirements", "<tr><td>297</td>", "<tr><td>297-disabled</td>", "mobile preparation disposition"),
    ("hardening", "R-S11eo/R-S11e-176", "R-S11eo-disabled/R-S11e-176", "mobile preparation hardening ledger"),
    ("requirements", '<span class="id">R-S11eq</span>', '<span class="id">R-S11eq-disabled</span>', "Android lifecycle-drain requirement"),
    ("requirements", "<tr><td>299</td>", "<tr><td>299-disabled</td>", "Android lifecycle-drain disposition"),
    ("hardening", "R-S11eq/R-S11e-178 Android component-thread outgoing-owner retirement", "R-S11eq-disabled/R-S11e-178 Android component-thread outgoing-owner retirement", "Android lifecycle-drain hardening ledger"),
    ("verify", "python3 scripts/verify-android-client-lifecycle-drain.py --repo . --self-test", "true # Android lifecycle-drain focused gate disabled", "shared Android lifecycle-drain focused gate"),
    ("verify", "grep -qF 'test/mobile_session_start_queue_test.dart' scripts/dart-verify.sh", "true # mobile preparation shared queue gate disabled", "shared mobile preparation queue gate"),
    ("verify", "and session_start.count(\"rollback_failed_session_start(session_id, client_owner_id);\") == 2", "and session_start.count(\"rollback_failed_session_start(session_id, client_owner_id);\") >= 0", "shared session-start rollback-count gate"),
    ("verify", "and dart_close.count(\"await _awaitMobileSessionStart(closingSessionId);\") == 2", "and dart_close.count(\"await _awaitMobileSessionStart(closingSessionId);\") >= 0", "shared dual close-preparation finality gate"),
    ("verify", "python3 scripts/verify-android-voice-call-ownership.py --repo . --self-test", "true # Android voice-call ownership gate removed", "shared gate wiring"),
)


def run_self_test(sources: Dict[str, str]) -> None:
    for source_name, old, new, label in MUTATIONS:
        source = sources[source_name]
        if old not in source:
            raise VerificationError(f"mutation fixture missing {label}: {old!r}")
        mutated = dict(sources)
        mutated[source_name] = source.replace(old, new, 1)
        try:
            validate(mutated)
        except VerificationError:
            continue
        raise VerificationError(f"mutation survived: {label}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=".", help="repository root")
    parser.add_argument("--self-test", action="store_true", help="reject deliberate regressions")
    args = parser.parse_args()
    sources = load_sources(Path(args.repo).resolve())
    validate(sources)
    if args.self_test:
        run_self_test(sources)
        print(f"android voice-call ownership verifier: {len(MUTATIONS)} mutations rejected")
    else:
        print("android voice-call ownership verifier: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
