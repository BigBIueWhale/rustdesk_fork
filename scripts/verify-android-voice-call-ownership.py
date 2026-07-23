#!/usr/bin/env python3
"""Verify Android's process-wide exact-owner voice-call recorder state machine."""

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
        "flutter": (repo / "src/flutter.rs").read_text(encoding="utf-8"),
        "io_loop": (repo / "src/client/io_loop.rs").read_text(encoding="utf-8"),
        "test": (repo / "scripts/android-voice-call-owner-state-test.kt").read_text(
            encoding="utf-8"
        ),
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

    service = sources["service"]
    add_connection = extract_item(service, '"add_connection" ->', "controlled connection admission")
    require_order(
        add_connection,
        (
            'val isFileTransfer = jsonObject["is_file_transfer"] as Boolean',
            'val isViewCamera = jsonObject["is_view_camera"] as Boolean',
            'val isTerminal = jsonObject["is_terminal"] as Boolean',
            'val portForward = jsonObject["port_forward"] as String',
            "val canUseVoiceCall = isViewCamera ||",
            "(!isFileTransfer && !isTerminal && portForward.isEmpty())",
            "VoiceCallAudioCoordinator.registerControlledConnection(id)",
        ),
        "Remote-or-ViewCamera controlled-owner admission",
    )
    remove_connection = extract_item(service, '"remove_connection" ->', "controlled connection removal")
    require_order(
        remove_connection,
        (
            "val id = arg1.toIntOrNull()",
            "VoiceCallAudioCoordinator.unregisterControlledConnection(id)",
            "cancelNotification(id)",
        ),
        "exact controlled-owner removal",
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
            "releaseCaptureResources()",
            "VoiceCallAudioCoordinator.clearControlledConnections()",
            "FFI.stopServer()",
            "super.onDestroy()",
        ),
        "service capture-and-owner teardown",
    )
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
            'call_main_service_set_by_name("remove_connection", Some(&id), None)',
            'self.push_event(\n                "on_client_remove"',
        ),
        "native owner retirement before UI connection removal",
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
    ("service", "VoiceCallAudioCoordinator.registerControlledConnection(id)", "true", "controlled registration"),
    ("service", '"remove_connection" ->', '"remove_connection_disabled" ->', "controlled removal dispatch"),
    ("service", "VoiceCallAudioCoordinator.setControlledVoiceCallActive(id, inVoiceCall)", "VoiceCallAudioCoordinator.setControlledVoiceCallActive(1, inVoiceCall)", "controlled update identity"),
    ("service", "VoiceCallAudioCoordinator.clearControlledConnections()", "true", "service owner teardown"),
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
    ("flutter", 'call_main_service_set_by_name("remove_connection", Some(&id), None)', 'call_main_service_set_by_name("stop_capture", Some(&id), None)', "Rust exact removal bridge"),
    ("flutter", "|| self.session_id.as_ref() != Some(&session_id)", "|| false", "Rust cross-isolate Activity resume refusal"),
    ("io_loop", "self.voice_call_thread = self.start_voice_call();\n                                if self.voice_call_thread.is_some() {\n                                    self.handler.on_voice_call_started();", "self.handler.on_voice_call_started();\n                                self.voice_call_thread = self.start_voice_call();\n                                if self.voice_call_thread.is_some() {", "worker-before-native voice activation"),
    ("io_loop", '.on_voice_call_closed("Failed to start voice call audio")', '.on_voice_call_started()', "outgoing voice start-failure retirement"),
    ("test", "one controlled teardown cleared another owner", "controlled teardown passed", "controlled behavior proof"),
    ("requirements", '<span class="id">R-S11br</span>', '<span class="id">R-S11br-disabled</span>', "normative requirement"),
    ("requirements", "generation that is equal (idempotent ordinary resume) or newer (lost-response recovery)", "a strictly newer generation", "idempotent same-generation resume requirement"),
    ("requirements", "only then publish native/UI started state", "publish native/UI started state before construction", "worker-before-native start requirement"),
    ("requirements", "<tr><td>211</td>", "<tr><td>211-disabled</td>", "Appendix disposition"),
    ("hardening", "R-S11br/R-S11e-84 — Android native voice-call capture has exact process-wide owners", "R-S11br/R-S11e-84 — Android native voice-call capture is best effort", "hardening ledger"),
    ("hardening", "same-or-newer resume with active-state retention plus older/cross-isolate refusal", "strictly newer resume with active-state retention", "idempotent same-generation resume ledger"),
    ("hardening", "it never mints a generation, replaces an owner, or drains sessions", "allocating a fresh generation and draining a different superseded owner", "read-only Activity-resume summary"),
    ("hardening", "publishes `on_voice_call_started` only after that worker exists", "publishes `on_voice_call_started` before that worker exists", "worker-before-native start ledger"),
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
