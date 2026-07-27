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
        "flutter_ffi": (repo / "src/flutter_ffi.rs").read_text(encoding="utf-8"),
        "ui_cm": (repo / "src/ui_cm_interface.rs").read_text(encoding="utf-8"),
        "flutter": (repo / "src/flutter.rs").read_text(encoding="utf-8"),
        "dart_main": (repo / "flutter/lib/main.dart").read_text(encoding="utf-8"),
        "dart_model": (repo / "flutter/lib/models/model.dart").read_text(
            encoding="utf-8"
        ),
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
        "client": (repo / "src/client.rs").read_text(encoding="utf-8"),
        "io_loop": (repo / "src/client/io_loop.rs").read_text(encoding="utf-8"),
        "test": (repo / "scripts/android-voice-call-owner-state-test.kt").read_text(
            encoding="utf-8"
        ),
        "connection_type_test": (
            repo / "scripts/android-controlled-connection-type-test.kt"
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
        ("private var outgoingOwner: OutgoingVoiceCallOwner? = null", "outgoing exact owner"),
        ("private var outgoingVoiceCallActive = false", "outgoing activity state"),
        (
            "get() = activeControlledConnections.isNotEmpty() || outgoingVoiceCallActive",
            "aggregate voice-capture demand",
        ),
    ):
        require(state, needle, label)

    register_controlled = extract_item(
        state, "fun registerControlledConnection", "controlled-owner registration"
    )
    require_order(
        register_controlled,
        ("if (connectionId <= 0)", "return false", "controlledConnections.add(connectionId)"),
        "positive exact controlled-owner registration",
    )
    set_controlled = extract_item(
        state, "fun setControlledVoiceCallActive", "controlled-owner state update"
    )
    require_order(
        set_controlled,
        (
            "if (!controlledConnections.contains(connectionId))",
            "return false",
            "if (active)",
            "activeControlledConnections.add(connectionId)",
            "activeControlledConnections.remove(connectionId)",
        ),
        "registered-only exact controlled-owner update",
    )
    unregister_controlled = extract_item(
        state, "fun unregisterControlledConnection", "controlled-owner retirement"
    )
    require_order(
        unregister_controlled,
        (
            "if (connectionId <= 0)",
            "return false",
            "controlledConnections.remove(connectionId)",
            "activeControlledConnections.remove(connectionId)",
        ),
        "exact controlled-owner registration-and-activity retirement",
    )
    clear_controlled = extract_item(
        state, "fun clearControlledConnections", "controlled-owner service teardown"
    )
    require_order(
        clear_controlled,
        ("controlledConnections.clear()", "activeControlledConnections.clear()"),
        "complete controlled-owner teardown",
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
    require(coordinator, "private var playbackProjection: MediaProjection? = null", "playback owner")
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
    reconcile = extract_item(coordinator, "private fun reconcileRecorder", "recorder reconciliation")
    require_order(
        reconcile,
        (
            "if (owners.requiresVoiceCapture)",
            "return recorder.switchToVoiceCall()",
            "val projection = playbackProjection",
            "if (projection != null)",
            "return recorder.switchToPlaybackCapture(projection)",
            "recorder.stopCapture()",
        ),
        "voice-over-playback-over-stopped recorder priority",
    )
    for function in (
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
            "FFI.setFrameRawEnable(\"audio\", true)",
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
            "FFI.setFrameRawEnable(\"audio\", false)",
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
            "FFI.setFrameRawEnable(\"audio\", false)",
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
            "VoiceCallAudioCoordinator.registerControlledConnection(id)",
            "reconcileControlledCaptureDemand()",
        ),
        "serialized exact-AuthConnType controlled-resource admission",
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
            "VoiceCallAudioCoordinator.unregisterControlledConnection(id)",
            "reconcileControlledCaptureDemand()",
            "cancelNotification(id)",
        ),
        "serialized exact controlled-resource removal",
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
            "VoiceCallAudioCoordinator.setControlledVoiceCallActive(id, inVoiceCall)",
        ),
        "connection-ID-bound controlled voice update",
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
        ),
        "exact MainService native generation ownership",
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
            "VoiceCallAudioCoordinator.clearControlledConnections()",
        ),
        "closed-admission controlled resource teardown",
    )
    forbid(service, '"stop_capture"', "detached global capture-stop dispatch")
    task_removed = extract_item(service, "override fun onTaskRemoved", "task-removal teardown")
    require_order(
        task_removed,
        (
            "MainActivity.takeStoppedClientSessionOwners()",
            "VoiceCallAudioCoordinator.unregisterOutgoingOwner(owner.toVoiceCallOwner())",
            "FFI.closeClientSessions(owner.generation, owner.sessionId)",
        ),
        "task-removal native-before-Rust exact-owner retirement",
    )
    require(
        service,
        "VoiceCallAudioCoordinator.setPlaybackCaptureProjection(projection)",
        "screen-start playback demand",
    )
    require(
        service,
        "VoiceCallAudioCoordinator.setPlaybackCaptureProjection(null)",
        "screen-stop playback retirement",
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
            "FFI.closeClientSessions(owner.generation, owner.sessionId)",
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
            "FFI.closeClientSessions(owner.generation, owner.sessionId)",
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
            "val closedUnreconciledSessions =",
            "FFI.closeClientSessions(owner.generation, owner.sessionId)",
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
            "sessions::insert_peer_session_id(",
            "client_owner_id,",
            "drop(owner_admission)",
        ),
        "owner-bound existing-session attachment",
    )
    session_add = extract_item(
        flutter, "pub fn session_add(", "Rust outgoing-session insertion"
    )
    require_order(
        session_add,
        (
            "client_owner_id: &SessionID",
            "acquire_android_client_owner(client_owner_id)?",
            "close_previous_mobile_client_sessions(client_owner_id, session_id)",
            "sessions::insert_session(",
            "*client_owner_id,",
            "drop(owner_admission)",
        ),
        "owner-admitted replacement drain and insertion",
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
            "session.start_io_thread()?",
            "drop(owner_admission)",
        ),
        "owner-associated outgoing worker start",
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
        "check_remove_unused_displays(None, None, session, &handlers);",
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
        "check_remove_unused_displays(None, None, session, &handlers);",
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
        "if excluded_session_id == Some(k)",
        "optional live-handler exclusion predicate",
    )
    require(
        flutter,
        "fn stale_mobile_session_close_cannot_select_replacement_from_same_owner()",
        "stale-close versus same-owner replacement regression",
    )
    require(
        sources["flutter_ffi"],
        "session_id: SessionID,\n    client_owner_id: SessionID,",
        "authored Rust bridge dual-identity parameters",
    )
    require_count(
        sources["flutter_ffi"],
        "client_owner_id: SessionID,",
        4,
        "all authored Rust add/attach/start dual-identity entries",
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
        "clientOwnerId = isMobile ? _mobileClientOwnerId : sessionId;",
        "mobile owner versus desktop connection identity selection",
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
    dart_start_begin = dart_model.find("  SessionID start(")
    dart_start_end = dart_model.find("\n  void onEvent2UIRgba(", dart_start_begin)
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
            "sessionId: activeSessionId,\n        clientOwnerId: clientOwnerId,",
            "stream.listen((message)",
            "if (closed || sessionId != activeSessionId) return;",
            "return activeSessionId;",
        ),
        "fresh mobile connection and captured event-stream identity",
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
            "_x = -10000;",
            "_y = -10000;",
            '_id = "-1";',
            "_windowRect = null;",
            "_remoteWindowCoords.clear();",
            "_blockedRects.clear();",
            "_cacheKeys.clear();",
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
    require_order(
        dart_file_model,
        (
            "void beginSession(SessionID expectedSessionId)",
            "evtLoop.clear();",
            "parent.target?.dialogManager.dismissAll();",
            "fileFetcher.cancelPending();",
            "jobController.clear();",
            "localController.resetForSession();",
            "remoteController.resetForSession();",
            "fileConfirmCheckboxRemember = false;",
        ),
        "file-transfer pending-resource retirement at connection start",
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
        "if (identical(tasks[",
        3,
        "file-fetch timeout exact-completer retirement",
    )
    file_fetcher = extract_item(
        dart_file_model,
        "class FileFetcher",
        "connection-aware file fetcher",
    )
    require_order(
        file_fetcher,
        (
            "Future<FileDirectory> fetchDirectory(",
            "{SessionID? expectedSessionId}) async {",
            "final selectedSessionId = expectedSessionId ?? sessionId;",
            "sessionId: selectedSessionId, path: path, showHidden: showHidden",
            "sessionId: selectedSessionId,",
        ),
        "file-fetcher captured-session native operations",
    )
    file_dialog_loop = extract_item(
        dart_file_model,
        "class FileDialogEventLoop",
        "file-dialog event loop",
    )
    file_dialog_clear = extract_item(
        file_dialog_loop,
        "  void clear()",
        "file-dialog synchronous reset",
    )
    require_order(
        file_dialog_clear,
        (
            "void clear()",
            "super.clear();",
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
        "evtLoop.pushEvent(_FileDialogEvent(\n"
        "        WeakReference(this), expectedSessionId, FileDialogType.overwrite, evt));",
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
            "final generation = _generation;",
            "(timer) => _handleTimer(timer, generation)",
            "bool _isCurrent(int generation)",
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
            "_timer?.cancel();",
            "_timer = null;",
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
            "if generation == 0",
            "call_main_service_set_by_name_inner(Some(generation)",
        ),
        "positive generation-bound controlled callback entry",
    )
    generation_dispatch_inner = extract_item(
        android_ffi,
        "fn call_main_service_set_by_name_inner",
        "controlled callback generation comparison",
    )
    require_order(
        generation_dispatch_inner,
        (
            "let context = MAIN_SERVICE_CTX.read().unwrap()",
            "if generation.is_some() && context.generation != generation",
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
            "start_listen(cm, rx, tx)",
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
        "start_channel(rx_to_cm, tx_from_cm, conn.android_server_generation)",
        "generation-bound connection-manager channel start",
    )
    direct_service = sources["direct_service"]
    exact_stop = extract_item(
        direct_service, "pub fn android_request_stop", "exact Android server stop"
    )
    require_order(
        exact_stop,
        (
            "expected_generation.checked_add(1)",
            "ANDROID_SERVER_GENERATION.compare_exchange(",
            "expected_generation",
            "next_generation",
            "Ok(_) =>",
            "true",
            "Err(current) =>",
            "false",
        ),
        "exact generation compare-and-exchange stop",
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
            "self.voice_call_thread = self.start_voice_call()",
            "if self.voice_call_thread.is_some()",
            "self.handler.on_voice_call_started()",
            ".on_voice_call_closed(\"Failed to start voice call audio\")",
            "let msg = new_voice_call_request(false)",
            "peer.send(&msg).await",
        ),
        "worker-before-native outgoing voice-call activation",
    )

    behavior = sources["test"]
    for needle, label in (
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
        "generation that is equal (idempotent ordinary resume) or newer (lost-response recovery)",
        "Android idempotent same-generation resume requirement",
    )
    require(
        sources["requirements"],
        "only then publish native/UI started state",
        "Android worker-before-native start requirement",
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
        "publishes `on_voice_call_started` only after that worker exists",
        "Android worker-before-native start ledger",
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
        "grep -qF 'close_previous_mobile_client_sessions(client_owner_id, session_id)' src/flutter.rs",
        "shared mobile replacement-drain gate",
    )
    require(
        sources["verify"],
        "if [ \"$(grep -cF 'check_remove_unused_displays(None, None, session, &handlers);' src/flutter.rs)\" -ne 2 ]; then",
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
            "final retired = fetcher.registerReadTask(false, path);",
            "fetcher.cancelPending();",
            "final replacement = fetcher.registerReadTask(false, path);",
            "fetcher.tryCompleteTask(",
            "await replacement.timeout(",
            "expect(directory.path, path);",
        ),
        "retired file timeout versus replacement behavior proof",
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
        "    thread: std::thread::JoinHandle<()>,\n"
        "}",
        "clipboard stop-and-join authority pair",
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
            "clipboard_listener::unsubscribe(Self::CLIENT_CLIPBOARD_NAME);",
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


Mutation = Tuple[str, str, str, str]

MUTATIONS: Tuple[Mutation, ...] = (
    ("owners", "generation > 0 && sessionId.isNotEmpty()", "generation >= 0", "outgoing owner validity"),
    ("owners", "activeControlledConnections.isNotEmpty() || outgoingVoiceCallActive", "outgoingVoiceCallActive", "controlled aggregation"),
    ("owners", "if (!controlledConnections.contains(connectionId))", "if (false)", "registered controlled update"),
    ("owners", "activeControlledConnections.remove(connectionId)", "// active owner retained", "exact controlled retirement"),
    ("owners", "activeControlledConnections.clear()", "// active owners retained", "controlled service teardown"),
    ("owners", "if (current != null && current != owner)", "if (false)", "single outgoing owner"),
    ("owners", "if (current != previous)", "if (false)", "resume previous-owner identity"),
    ("owners", "if (current == replacement)", "if (false)", "lost-response resume retry idempotence"),
    ("owners", "replacement.sessionId != previous.sessionId", "false", "resume session identity"),
    ("owners", "replacement.generation < previous.generation", "replacement.generation <= previous.generation", "idempotent same-generation resume"),
    ("owners", "if (outgoingOwner != owner)", "if (false)", "exact outgoing update"),
    ("coordinator", "@Synchronized\n    fun setControlledVoiceCallActive", "    fun setControlledVoiceCallActive", "controlled serialization"),
    ("coordinator", "@Synchronized\n    fun setOutgoingVoiceCallActive", "    fun setOutgoingVoiceCallActive", "outgoing serialization"),
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
    ("service", "acceptingControlledConnections = false", "acceptingControlledConnections = true", "resource admission closure"),
    ("service", "VoiceCallAudioCoordinator.registerControlledConnection(id)", "true", "controlled registration"),
    ("service", "if (connectionType.allowsVoiceCall &&", "if (true &&", "typed controlled voice-call admission"),
    ("service", '"remove_connection" ->', '"remove_connection_disabled" ->', "controlled removal dispatch"),
    ("service", "VoiceCallAudioCoordinator.setControlledVoiceCallActive(id, inVoiceCall)", "VoiceCallAudioCoordinator.setControlledVoiceCallActive(1, inVoiceCall)", "controlled update identity"),
    ("service", "VoiceCallAudioCoordinator.clearControlledConnections()", "true", "service owner teardown"),
    ("service", "nativeServerGeneration = FFI.startServer(this, configPath, \"\")", "FFI.startServer(configPath, \"\")", "exact-object service generation ownership"),
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
    ("activity", "val closedUnreconciledSessions =\n                FFI.closeClientSessions(owner.generation, owner.sessionId)", "val closedUnreconciledSessions =\n                FFI.closeClientSessions(resumedOwner.generation, resumedOwner.sessionId)", "unreconciled resume cannot close replacement Rust owner"),
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
    ("android_ffi", "if generation.is_some() && context.generation != generation", "if false", "controlled callback generation comparison"),
    ("server_connection", "android_server_generation: u64", "android_server_generation: i64", "connection service-generation ownership"),
    ("server_connection", "call_main_service_pointer_input_for_generation", "call_main_service_pointer_input", "generation-bound controlled pointer dispatch"),
    ("server_connection", "call_main_service_key_event_for_generation", "call_main_service_key_event", "generation-bound controlled key dispatch"),
    ("direct_service", "expected_generation.checked_add(1)", "expected_generation.wrapping_add(1)", "exact server-generation stop"),
    ("flutter_ffi", "bind_main_service_generation(&env, &service, generation)", "true", "exact-object listener/callback generation binding"),
    ("flutter", "|| self.session_id.as_ref() != Some(&session_id)", "|| false", "Rust cross-isolate Activity resume refusal"),
    ("flutter", "client_owner_id: Option<SessionID>", "client_owner_id: Option<()>", "stored mobile client-owner association"),
    ("flutter", "acquire_android_client_owner(&client_owner_id)?", "acquire_android_client_owner(&session_id)?", "existing-session owner admission"),
    ("flutter", "close_previous_mobile_client_sessions(client_owner_id, session_id)", "(0, 0)", "replacement pre-insertion drain"),
    ("flutter", "sessions::session_has_client_owner(session_id, client_owner_id)", "true", "start-time owner association"),
    ("flutter", "handler_session_id != session_id\n                        || handler.client_owner_id.as_ref() != Some(client_owner_id)", "handler_session_id != session_id\n                        && handler.client_owner_id.as_ref() != Some(client_owner_id)", "exact owner-and-session preservation"),
    ("flutter", "check_remove_unused_displays(None, None, session, &handlers);", "check_remove_unused_displays(None, Some(session_id), session, &handlers);", "replacement display reconciliation includes preserved exact session"),
    ("flutter", "if owned_handler_ids.is_empty() {\n                continue;\n            }\n            if handlers.is_empty() {\n                removed_keys.push(key.clone());\n            } else {\n                check_remove_unused_displays(None, None, session, &handlers);", "if owned_handler_ids.is_empty() {\n                continue;\n            }\n            if handlers.is_empty() {\n                removed_keys.push(key.clone());\n            } else {\n                check_remove_unused_displays(None, Some(client_owner_id), session, &handlers);", "Activity-owner display reconciliation includes all remaining sessions"),
    ("flutter", "excluded_session_id: Option<&SessionID>", "excluded_session_id: &SessionID", "optional display-reconciliation exclusion"),
    ("flutter", "fn stale_mobile_session_close_cannot_select_replacement_from_same_owner()", "fn stale_mobile_session_close_can_select_replacement_from_same_owner()", "same-owner stale-close behavior proof"),
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
    ("dart_file_model", "fileFetcher.cancelPending();", "// stale file tasks retained", "file-transfer pending-resource retirement"),
    ("dart_file_model", "localController.resetForSession();", "// local controller retained", "file-controller prior-peer state retirement"),
    ("dart_file_model", "void clear() {\n    super.clear();\n    _overrideConfirm = null;\n    _skip = false;", "void clear() {\n    super.clear();", "file-dialog remembered-policy retirement"),
    ("dart_file_model", "if (model == null || !model._isCurrentSession(expectedSessionId))", "if (model == null)", "file-dialog stale-session callback refusal"),
    ("dart_file_model", "if (identical(tasks[", "if (false && identical(tasks[", "file-fetch timeout exact-completer retirement"),
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
    ("verify", "grep -qF 'close_previous_mobile_client_sessions(client_owner_id, session_id)' src/flutter.rs", "true # replacement-drain shared gate disabled", "shared mobile replacement-drain gate"),
    ("verify", "if [ \"$(grep -cF 'check_remove_unused_displays(None, None, session, &handlers);' src/flutter.rs)\" -ne 2 ]; then", "if false; then # post-drain display gate disabled", "shared post-drain display-reconciliation gate"),
    ("dart_verify", "cargo test --offline --locked --lib --features flutter,unix-file-copy-paste \\\n      flutter::mobile_session_lifecycle_tests:: -- --test-threads=1", "true # generated-bridge mobile lifecycle tests disabled", "generated-bridge mobile lifecycle behavior gate"),
    ("dart_verify", "flutter test --no-pub test/mobile_file_session_lifecycle_test.dart", "true # mobile file-session lifecycle test disabled", "mobile file-session lifecycle behavior gate"),
    ("mobile_file_lifecycle_test", "expect(directory.path, path);", "expect(directory.path, isEmpty);", "retired file timeout replacement behavior proof"),
    ("io_loop", "self.voice_call_thread = self.start_voice_call();\n                                if self.voice_call_thread.is_some() {\n                                    self.handler.on_voice_call_started();", "self.handler.on_voice_call_started();\n                                self.voice_call_thread = self.start_voice_call();\n                                if self.voice_call_thread.is_some() {", "worker-before-native voice activation"),
    ("io_loop", '.on_voice_call_closed("Failed to start voice call audio")', '.on_voice_call_started()', "outgoing voice start-failure retirement"),
    ("test", "one controlled teardown cleared another owner", "controlled teardown passed", "controlled behavior proof"),
    ("connection_type_test", '"PortForward" to ControlledConnectionType.PORT_FORWARD', '"PortForward" to ControlledConnectionType.REMOTE', "PortForward behavior proof"),
    ("connection_type_test", "one Remote teardown cleared another live owner", "concurrent Remote aggregation disabled", "capture-owner aggregation behavior"),
    ("connection_type_test", "remove-then-add ordering lost new Remote demand", "remove-before-add convergence disabled", "capture remove-before-add behavior"),
    ("connection_type_test", "add-then-remove ordering lost new Remote demand", "add-before-remove convergence disabled", "capture add-before-remove behavior"),
    ("requirements", '<span class="id">R-S11br</span>', '<span class="id">R-S11br-disabled</span>', "normative requirement"),
    ("requirements", "generation that is equal (idempotent ordinary resume) or newer (lost-response recovery)", "a strictly newer generation", "idempotent same-generation resume requirement"),
    ("requirements", "only then publish native/UI started state", "publish native/UI started state before construction", "worker-before-native start requirement"),
    ("requirements", "service-owned set of exact positive connection IDs", "one global Boolean reconstructed in Rust", "service-owned capture-demand requirement"),
    ("requirements", "detached global stop edge", "best-effort global stop edge", "stale capture-stop prohibition"),
    ("requirements", "gate its controlled-state and input JNI callbacks against the exact live Service generation", "route callbacks through the latest Service object", "stale-generation callback prohibition"),
    ("requirements", "bind that generation only after JNI proves that its caller is the exact currently retained <code>MainService</code> object", "bind that generation to whichever Service object is currently reachable", "exact-object listener-generation requirement"),
    ("requirements", "a retained global <code>applicationContext</code> reference", "a JNI local <code>applicationContext</code> reference", "application-context global-reference requirement"),
    ("requirements", "<tr><td>211</td>", "<tr><td>211-disabled</td>", "Appendix disposition"),
    ("hardening", "R-S11br/R-S11e-84 — Android native voice-call capture has exact process-wide owners", "R-S11br/R-S11e-84 — Android native voice-call capture is best effort", "hardening ledger"),
    ("hardening", "same-or-newer resume with active-state retention plus older/cross-isolate refusal", "strictly newer resume with active-state retention", "idempotent same-generation resume ledger"),
    ("hardening", "it never mints a generation, replaces an owner, or drains sessions", "allocating a fresh generation and draining a different superseded owner", "read-only Activity-resume summary"),
    ("hardening", "publishes `on_voice_call_started` only after that worker exists", "publishes `on_voice_call_started` before that worker exists", "worker-before-native start ledger"),
    ("hardening", "service-owned exact Remote connection-ID set", "Rust-owned Boolean capture snapshot", "exact capture-owner hardening ledger"),
    ("hardening", "exact-object JNI release", "process-lifetime stale JNI retention", "service callback-owner release ledger"),
    ("hardening", "refuses a zero, stopped, or replaced generation before entering Java", "accepts callbacks from any native generation", "callback-generation hardening ledger"),
    ("hardening", "`startServer(this, ...)` returns that exact generation only after JNI proves", "`startServer()` attaches the generation to the latest Service without comparison", "exact-object listener-generation hardening ledger"),
    ("verify", "grep -qF 'stale_android_activity_cannot_reclaim_the_replacement_owner' src/flutter.rs", "grep -qF 'resumed_android_activity_reclaims_owner_without_reusing_a_stale_generation' src/flutter.rs", "shared stale-Activity takeover-refusal regression gate"),
    ("verify", 'and owner_resume.index("ANDROID_CLIENT_OWNER")\n        < owner_resume.index(".read()")\n        < owner_resume.index(".resume(generation, session_id)")', 'and owner_resume.index("ANDROID_CLIENT_OWNER.write()")\n        < owner_resume.index(".resume(generation, session_id)")', "shared read-only Rust Activity-resume gate"),
    ("verify", 'and "close_sessions_owned_by" not in owner_resume', 'and "close_sessions_owned_by" in owner_resume', "shared resume-without-takeover gate"),
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
