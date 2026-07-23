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
