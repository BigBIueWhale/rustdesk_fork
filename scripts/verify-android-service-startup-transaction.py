#!/usr/bin/env python3
"""Validate Android MainService exact-generation startup and rollback."""

from __future__ import annotations

import argparse
import pathlib
from dataclasses import dataclass
from typing import Dict, Tuple


class VerificationError(RuntimeError):
    pass


@dataclass(frozen=True)
class Mutation:
    source: str
    old: str
    new: str
    label: str


def require(source: str, token: str, label: str) -> None:
    if token not in source:
        raise VerificationError("missing {}: {!r}".format(label, token))


def forbid(source: str, token: str, label: str) -> None:
    if token in source:
        raise VerificationError("forbidden {} remains: {!r}".format(label, token))


def require_count(source: str, token: str, count: int, label: str) -> None:
    actual = source.count(token)
    if actual != count:
        raise VerificationError(
            "{} count differs: expected {}, got {}".format(label, count, actual)
        )


def require_order(source: str, tokens: Tuple[str, ...], label: str) -> None:
    position = -1
    for token in tokens:
        position = source.find(token, position + 1)
        if position < 0:
            raise VerificationError(
                "{} is missing ordered token {!r}".format(label, token)
            )


def extract(source: str, start: str, end: str, label: str) -> str:
    if source.count(start) != 1:
        raise VerificationError("{} start cardinality differs".format(label))
    begin = source.index(start)
    finish = source.find(end, begin + len(start))
    if finish < 0:
        raise VerificationError("{} end is absent".format(label))
    return source[begin:finish]


def validate(sources: Dict[str, str]) -> None:
    owner = sources["owner"]
    behavior = sources["behavior"]
    service = sources["service"]
    ffi_kt = sources["ffi_kt"]
    rust_ffi = sources["rust_ffi"]
    scrap_ffi = sources["scrap_ffi"]
    direct_service = sources["direct_service"]
    verify = sources["verify"]
    dart_verify = sources["dart_verify"]
    requirements = sources["requirements"]
    hardening = sources["hardening"]
    workspace = sources["workspace"]

    require_order(
        owner,
        (
            "internal data class MainServiceGenerationRetirement(",
            "val generation: Long",
            "val retireStatus: Boolean",
            "val retireVoice: Boolean",
            "internal class MainServiceGenerationOwner",
            "private enum class Phase",
            "RESERVED",
            "STATUS_ATTEMPTED",
            "VOICE_ATTEMPTED",
            "ACTIVATION_ATTEMPTED",
            "COMMITTED",
            "private var greatestGeneration = 0L",
            "private var activeGeneration: Long? = null",
            "private var phase: Phase? = null",
        ),
        "closed startup phase owner",
    )
    for signature in (
        "beginReservation(generation: Long): Boolean",
        "noteStatusAttempt(generation: Long): Boolean",
        "noteVoiceAttempt(generation: Long): Boolean",
        "noteActivationAttempt(generation: Long): Boolean",
        "commit(generation: Long): Boolean",
        "isCommitted(generation: Long): Boolean",
        "retire(generation: Long): MainServiceGenerationRetirement?",
    ):
        require(
            owner,
            "@Synchronized\n    fun {}".format(signature),
            "serialized startup operation {}".format(signature),
        )

    begin = extract(
        owner,
        "    fun beginReservation(generation: Long): Boolean {",
        "\n    @Synchronized\n    fun noteStatusAttempt",
        "listener-stage begin",
    )
    require_order(
        begin,
        (
            "generation <= 0L",
            "activeGeneration != null",
            "generation <= greatestGeneration",
            "return false",
            "greatestGeneration = generation",
            "activeGeneration = generation",
            "phase = Phase.RESERVED",
            "return true",
        ),
        "fresh positive monotonic generation reservation",
    )
    status = extract(
        owner,
        "    fun noteStatusAttempt(generation: Long): Boolean {",
        "\n    @Synchronized\n    fun noteVoiceAttempt",
        "status-attempt transition",
    )
    require_order(
        status,
        (
            "activeGeneration != generation || phase != Phase.RESERVED",
            "return false",
            "phase = Phase.STATUS_ATTEMPTED",
            "return true",
        ),
        "exact listener-to-status transition",
    )
    voice = extract(
        owner,
        "    fun noteVoiceAttempt(generation: Long): Boolean {",
        "\n    @Synchronized\n    fun noteActivationAttempt",
        "voice-attempt transition",
    )
    require_order(
        voice,
        (
            "activeGeneration != generation || phase != Phase.STATUS_ATTEMPTED",
            "return false",
            "phase = Phase.VOICE_ATTEMPTED",
            "return true",
        ),
        "exact status-to-voice transition",
    )
    activation = extract(
        owner,
        "    fun noteActivationAttempt(generation: Long): Boolean {",
        "\n    @Synchronized\n    fun commit",
        "listener-activation-attempt transition",
    )
    require_order(
        activation,
        (
            "activeGeneration != generation || phase != Phase.VOICE_ATTEMPTED",
            "return false",
            "phase = Phase.ACTIVATION_ATTEMPTED",
            "return true",
        ),
        "exact voice-to-listener-activation transition",
    )
    commit = extract(
        owner,
        "    fun commit(generation: Long): Boolean {",
        "\n    @Synchronized\n    fun isCommitted",
        "generation commit transition",
    )
    require_order(
        commit,
        (
            "activeGeneration != generation || phase != Phase.ACTIVATION_ATTEMPTED",
            "return false",
            "phase = Phase.COMMITTED",
            "return true",
        ),
        "complete-only exact generation commit",
    )
    retire = extract(
        owner,
        "    fun retire(generation: Long): MainServiceGenerationRetirement? {",
        "\n    }\n}",
        "generation retirement plan",
    )
    require_order(
        retire,
        (
            "generation <= 0L || activeGeneration != generation",
            "return null",
            "val currentPhase = phase ?: return null",
            "generation = generation",
            "retireStatus = currentPhase != Phase.RESERVED",
            "retireVoice = currentPhase == Phase.VOICE_ATTEMPTED",
            "currentPhase == Phase.ACTIVATION_ATTEMPTED",
            "currentPhase == Phase.COMMITTED",
            "activeGeneration = null",
            "phase = null",
            "return retirement",
        ),
        "attempt-aware exact retirement plan",
    )

    for token, label in (
        (
            "a replacement generation was reserved while one transaction was active",
            "single active transaction",
        ),
        ("reservation-only rollback selected unrelated authority", "reservation-only rollback"),
        (
            "status-failure rollback did not select exactly the attempted status owner",
            "status-attempt rollback",
        ),
        (
            "voice-failure rollback did not select every attempted exact owner",
            "voice-attempt rollback",
        ),
        (
            "activation-failure rollback did not select every attempted exact owner",
            "activation-attempt rollback",
        ),
        ("generation committed before status and voice", "early commit refusal"),
        ("generation committed before listener activation", "pre-activation commit refusal"),
        ("stale committed retirement selected its replacement", "stale retirement refusal"),
        ("new generation after rollback was rejected", "explicit retry generation"),
    ):
        require(behavior, token, label)

    require(
        service,
        "private val serviceGenerationOwner = MainServiceGenerationOwner()",
        "private startup transaction owner",
    )
    require_order(
        service,
        (
            "@Volatile\n    private var acceptingControlledConnections = false",
            "@Volatile\n    private var nativeCallbackContextReady = false",
            "private val controlledServiceGenerationLock = Any()",
            "private val serviceGenerationOwner = MainServiceGenerationOwner()",
            "private fun initializeControlledServiceGeneration(): Boolean =",
            "synchronized(controlledServiceGenerationLock)",
            "initializeControlledServiceGenerationLocked()",
            "private fun initializeControlledServiceGenerationLocked(): Boolean {",
        ),
        "visible admission and dedicated non-callback transaction lock",
    )
    initialize = extract(
        service,
        "    private fun initializeControlledServiceGenerationLocked(): Boolean {",
        "\n    private fun retireControlledServiceGeneration(generation: Long, reason: String): Boolean =",
        "MainService startup transaction",
    )
    require_order(
        initialize,
        (
            "if (!nativeCallbackContextReady)",
            "return false",
            "val currentGeneration = nativeServerGeneration",
            "serviceGenerationOwner.isCommitted(currentGeneration)",
            "FFI.isServerGenerationActive(this, currentGeneration)",
            "return true",
            "retireControlledServiceGeneration(",
            '"incomplete generation before retry"',
            "acceptingControlledConnections = false",
            'val generation = FFI.startServer(this, configPath, "")',
            "if (generation <= 0L)",
            "return false",
            "nativeServerGeneration = generation",
            "serviceGenerationOwner.beginReservation(generation)",
            "FFI.stopServer(this, generation)",
            "nativeServerGeneration = 0L",
            "publishScreenInfo()",
            'retireControlledServiceGeneration(generation, "screen publication failure")',
            "serviceGenerationOwner.noteStatusAttempt(generation)",
            "statusOwner.begin(generation)",
            'retireControlledServiceGeneration(generation, "status publication failure")',
            "serviceGenerationOwner.noteVoiceAttempt(generation)",
            "VoiceCallAudioCoordinator.beginControlledServiceGeneration(generation)",
            'retireControlledServiceGeneration(generation, "audio publication failure")',
            "serviceGenerationOwner.noteActivationAttempt(generation)",
            "serviceGenerationOwner.commit(generation)",
            'retireControlledServiceGeneration(generation, "generation commit failure")',
            "acceptingControlledConnections = true",
            "FFI.activateServer(this, generation)",
            "acceptingControlledConnections = false",
            'retireControlledServiceGeneration(generation, "listener activation failure")',
            "return true",
        ),
        "closed-until-complete startup and rollback",
    )
    require_count(
        service,
        "acceptingControlledConnections = true",
        1,
        "single controlled callback admission commit",
    )
    require_count(
        initialize,
        "statusOwner.begin(generation)",
        1,
        "single status publication attempt",
    )
    require_count(
        initialize,
        "VoiceCallAudioCoordinator.beginControlledServiceGeneration(generation)",
        1,
        "single voice publication attempt",
    )
    require(
        service,
        "private fun retireControlledServiceGeneration(generation: Long, reason: String): Boolean =\n"
        "        synchronized(controlledServiceGenerationLock) {\n"
        "            retireControlledServiceGenerationLocked(generation, reason)\n"
        "        }",
        "dedicated-lock generation retirement",
    )
    forbid(
        service,
        "@Synchronized\n    private fun initializeControlledServiceGeneration",
        "callback-monitor startup transaction",
    )
    forbid(
        service,
        "@Synchronized\n    private fun retireControlledServiceGeneration",
        "callback-monitor retirement transaction",
    )

    retirement = extract(
        service,
        "    private fun retireControlledServiceGenerationLocked(\n",
        "\n    override fun onCreate()",
        "MainService generation retirement",
    )
    require_order(
        retirement,
        (
            "acceptingControlledConnections = false",
            "val retirement = serviceGenerationOwner.retire(generation)",
            "if (retirement == null)",
            "FFI.stopServer(this, generation)",
            "nativeServerGeneration = 0L",
            "return retiredNative",
            "FFI.stopServer(this, retirement.generation)",
            "retirement.retireVoice",
            "VoiceCallAudioCoordinator.clearControlledConnections(retirement.generation)",
            "retirement.retireStatus",
            "statusOwner.retire(retirement.generation)",
            "nativeServerGeneration = 0L",
            "return retired",
        ),
        "listener-first attempt-aware exact rollback",
    )

    on_create = extract(
        service,
        "    override fun onCreate() {",
        "\n    override fun onDestroy()",
        "MainService creation",
    )
    require_order(
        on_create,
        (
            "nativeCallbackContextReady = FFI.init(this, applicationContext)",
            "initNotification()",
        ),
        "inert bound-service creation",
    )
    forbid(on_create, "initializeControlledServiceGeneration()", "pre-deadline creation transaction")
    forbid(on_create, "createForegroundNotification()", "bound-only foreground publication")
    forbid(on_create, "acquireNetworkKeepaliveWakeLock()", "bound-only keepalive acquisition")
    forbid(on_create, "registerNetworkCallback()", "bound-only network callback")
    on_start = extract(
        service,
        "    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {",
        "\n    override fun onConfigurationChanged",
        "MainService explicit start",
    )
    require_order(
        on_start,
        (
            "super.onStartCommand(intent, flags, startId)",
            "createForegroundNotification()",
            "if (!initializeControlledServiceGeneration())",
            "stopForeground(STOP_FOREGROUND_REMOVE)",
            "stopSelfResult(startId)",
            "return START_NOT_STICKY",
            "acquireNetworkKeepaliveWakeLock()",
            "registerNetworkCallback()",
            "if (intent?.action == ACT_INIT_MEDIA_PROJECTION_AND_SERVICE)",
            "return START_NOT_STICKY",
        ),
        "foreground deadline and exact explicit-start retry/failure retirement",
    )
    require_count(
        on_start,
        "initializeControlledServiceGeneration()",
        1,
        "one transaction attempt per explicit start callback",
    )
    forbid(on_start, "postDelayed", "startup retry timer")
    forbid(on_start, "START_STICKY", "automatic sticky service restart")
    forbid(on_start, "START_REDELIVER_INTENT", "automatic intent redelivery")

    on_destroy = extract(
        service,
        "    override fun onDestroy() {",
        "\n    override fun onTaskRemoved",
        "MainService destruction",
    )
    require_order(
        on_destroy,
        (
            "val generation = nativeServerGeneration",
            "releaseControlledConnectionResources()",
            'retireControlledServiceGeneration(generation, "MainService destruction")',
            "serviceLooper?.quitSafely()",
            "unregisterNetworkCallback()",
            "releaseNetworkKeepaliveWakeLock()",
            "FFI.releaseService(this)",
            "super.onDestroy()",
        ),
        "capture-before-generation and callback-owner destruction",
    )
    capture_release = extract(
        service,
        "    private fun releaseControlledConnectionResources() {",
        "\n    fun checkMediaPermission()",
        "controlled capture release",
    )
    forbid(
        capture_release,
        "VoiceCallAudioCoordinator.clearControlledConnections",
        "voice retirement outside generation transaction",
    )

    require(
        ffi_kt,
        "external fun init(service: Context, applicationContext: Context): Boolean",
        "exact callback-context admission result",
    )
    require(
        ffi_kt,
        "external fun activateServer(service: Context, generation: Long): Boolean",
        "exact Service-object-and-generation Kotlin activation",
    )
    require(
        ffi_kt,
        "external fun isServerGenerationActive(service: Context, generation: Long): Boolean",
        "exact Service-object-and-generation Kotlin health",
    )
    require(
        ffi_kt,
        "external fun stopServer(service: Context, generation: Long): Boolean",
        "exact Service-object-and-generation Kotlin retirement",
    )
    start_jni = extract(
        rust_ffi,
        '    pub unsafe extern "system" fn Java_ffi_FFI_startServer(',
        '\n    #[no_mangle]\n    pub unsafe extern "system" fn Java_ffi_FFI_activateServer(',
        "exact generation reservation JNI",
    )
    forbid(start_jni, "start_server(true, generation)", "pre-commit listener spawn")
    require_order(
        start_jni,
        (
            "scrap::android::bind_main_service_generation(",
            "&env",
            "&service",
            "crate::direct_service::android_begin_generation",
            "|generation|",
            "android_request_stop(generation)",
            "generation as jlong",
        ),
        "object-authorized listener reservation and exact rollback",
    )
    activate_jni = extract(
        rust_ffi,
        '    pub unsafe extern "system" fn Java_ffi_FFI_activateServer(',
        '\n    #[no_mangle]\n    pub unsafe extern "system" fn Java_ffi_FFI_stopServer(',
        "exact generation activation JNI",
    )
    require_order(
        activate_jni,
        (
            "env: JNIEnv",
            "service: JObject",
            "generation: jlong",
            "claim_main_service_listener_start(&env, &service, generation)",
            "android_activate_generation(generation)",
            "retire_main_service_generation(",
            "android_request_stop(generation)",
            "std::thread::Builder::new()",
            '.name("android-direct-service".to_owned())',
            ".spawn(move || {",
            "AndroidDirectServerWorkerGuard(generation)",
            "start_server(true, generation)",
            "Ok(_) => jboolean::from(true)",
            "retire_main_service_generation(",
            "android_request_stop(generation)",
        ),
        "post-admission reserved-to-active listener activation and rollback",
    )
    stop_jni = extract(
        rust_ffi,
        '    pub unsafe extern "system" fn Java_ffi_FFI_stopServer(',
        "\n    fn parse_client_session_owner",
        "exact generation retirement JNI",
    )
    require_order(
        stop_jni,
        (
            "env: JNIEnv",
            "service: JObject",
            "generation: jlong",
            "generation <= 0 || service.is_null()",
            "let generation = generation as u64",
            "let Some(retirement) = scrap::android::retire_main_service_generation(",
            "&env",
            "&service",
            "generation",
            "android_request_stop_or_confirm_inactive(generation)",
            "retirement.raw_video_retired",
            "retirement.screen_size_retired",
        ),
        "object proof before listener plus callback-generation retirement",
    )
    native_bind = extract(
        scrap_ffi,
        "pub fn bind_main_service_generation<Begin, Rollback>(",
        "\npub fn claim_main_service_listener_start(",
        "native exact Service generation reservation",
    )
    require_order(
        native_bind,
        (
            "service.is_null()",
            "MAIN_SERVICE_CTX.write().unwrap()",
            "env.is_same_object(current.owner.as_obj(), service)",
            "current.generation.is_some()",
            "let generation = begin_generation()",
            "VIDEO_RAW.lock().unwrap().begin_generation(generation)",
            "rollback_generation(generation)",
            "SCREEN_SIZE.lock().unwrap().begin_generation(generation)",
            "rollback_generation(generation)",
            "current.generation = Some(generation)",
            "current.listener_started = false",
            "Some(generation)",
        ),
        "object-authorized inactive native reservation",
    )
    native_init = extract(
        scrap_ffi,
        'pub extern "system" fn Java_ffi_FFI_init(',
        "\npub fn bind_main_service_generation<Begin, Rollback>(",
        "native callback-context admission",
    )
    require_order(
        native_init,
        (
            ") -> jboolean",
            "env.new_global_ref(&service)",
            "let mut current = MAIN_SERVICE_CTX.write().unwrap()",
            "env.is_same_object(context.owner.as_obj(), &service)",
            "Ok(true) => return jboolean::from(true)",
            "Ok(false) if context.generation.is_some()",
            "return jboolean::from(false)",
            "owner: retained_service",
            "jboolean::from(true)",
        ),
        "idempotent exact callback owner and active foreign-replacement refusal",
    )
    forbid(native_init, "retire_generation(generation)", "ambient callback-owner replacement cleanup")
    native_retire = extract(
        scrap_ffi,
        "pub fn retire_main_service_generation(",
        "\n#[no_mangle]\npub extern \"system\" fn Java_ffi_FFI_releaseService",
        "native exact Service generation retirement",
    )
    require_order(
        native_retire,
        (
            "env: &JNIEnv",
            "service: &JObject",
            "generation: u64",
            "generation == 0 || service.is_null()",
            "current.generation != Some(generation)",
            "env.is_same_object(current.owner.as_obj(), service)",
            "VIDEO_RAW.lock().unwrap().retire_generation(generation)",
            "SCREEN_SIZE.lock().unwrap().retire_generation(generation)",
            "current.generation = None",
            "Some(MainServiceGenerationRetirement",
            "raw_video_retired: video_retired",
            "screen_size_retired: screen_retired",
        ),
        "exact object-and-generation raw/screen retirement",
    )
    native_claim = extract(
        scrap_ffi,
        "pub fn claim_main_service_listener_start(",
        "\npub fn retire_main_service_generation(",
        "native exact listener-start claim",
    )
    require_order(
        native_claim,
        (
            "current.generation != Some(generation) || current.listener_started",
            "env.is_same_object(current.owner.as_obj(), service)",
            "current.listener_started = true",
            "true",
        ),
        "single exact Service-and-generation listener-start claim",
    )
    native_health = extract(
        scrap_ffi,
        "pub fn owns_main_service_generation(",
        "\npub fn retire_main_service_generation(",
        "native exact generation health owner",
    )
    require_order(
        native_health,
        (
            "generation == 0 || service.is_null()",
            "MAIN_SERVICE_CTX.read().unwrap()",
            "current.generation != Some(generation)",
            "if !current.listener_started",
            "env.is_same_object(current.owner.as_obj(), service)",
        ),
        "exact object-and-generation health proof",
    )
    require_order(
        direct_service,
        (
            "struct AndroidListenerLifecycle",
            "reserved: bool",
            "active: bool",
            "fn begin_generation(&mut self) -> Option<u64>",
            "if self.reserved || self.active",
            "if next > i64::MAX as u64",
            "self.reserved = true",
            "self.active = false",
            "fn activate_generation(&mut self, expected_generation: u64) -> bool",
            "!self.reserved || self.active",
            "self.reserved = false",
            "self.active = true",
            "fn stop_generation(&mut self, expected_generation: u64) -> bool",
            "(!self.reserved && !self.active)",
            "self.reserved = false",
            "self.active = false",
            "fn snapshot(&self, expected_generation: u64) -> Option<u64>",
            "self.active && expected_generation != 0",
            "fn is_exact_inactive(&self, expected_generation: u64) -> bool",
            "pub fn android_activate_generation(expected_generation: u64) -> bool",
            "pub fn android_request_stop_or_confirm_inactive(expected_generation: u64) -> bool",
            "lifecycle.is_exact_inactive(expected_generation)",
            "pub fn android_generation_is_active(expected_generation: u64) -> bool",
            "pub fn android_note_worker_exit(expected_generation: u64) -> bool",
        ),
        "inactive reservation and exact one-way listener activation",
    )
    require_order(
        direct_service,
        (
            "let mut direct_listener = direct_listener",
            "tokio::select!",
            "outcome = &mut direct_listener",
            "if android_listener_lifecycle_snapshot(my_generation.get()).is_none()",
            "Android direct-listener task returned after exact generation deactivation",
            "Android direct-listener task failed after exact generation deactivation",
            "Android direct-listener task returned while its service worker was active",
            "Android direct-listener task failed while its service worker was active",
            "_ = sleep(1.)",
            "android_listener_lifecycle_snapshot(my_generation.get()).is_none()",
        ),
        "worker completion drives terminal generation health",
    )
    require_order(
        rust_ffi,
        (
            "struct AndroidDirectServerWorkerGuard(u64)",
            "impl Drop for AndroidDirectServerWorkerGuard",
            "android_note_worker_exit(self.0)",
            'pub unsafe extern "system" fn Java_ffi_FFI_isServerGenerationActive(',
            "owns_main_service_generation(&env, &service, generation)",
            "android_generation_is_active(generation)",
        ),
        "RAII worker-exit retirement and exact health JNI",
    )

    for source, token, label in (
        (
            verify,
            "/usr/bin/python3 -I -S scripts/verify-android-service-startup-transaction.py --repo . --self-test",
            "shared focused mutation gate",
        ),
        (
            verify,
            "R-S11hq/R-S11e-254 Android exact-generation MainService startup transaction",
            "shared gate verdict",
        ),
        (
            dart_verify,
            "python3 scripts/verify-android-service-startup-transaction.py --repo . --self-test",
            "Dart/Android focused mutation gate",
        ),
        (requirements, '<span class="id">R-S11hq</span>', "R-S11hq requirement"),
        (requirements, "<tr><td>377</td>", "Appendix C #377"),
        (
            hardening,
            "### R-S11hq/R-S11e-254 — exact-generation Android MainService startup transaction",
            "hardening disposition",
        ),
        (
            workspace,
            "    validate_android_service_startup_transaction_contract(sources)\n"
            "    validate_tray_session_count_mailbox_contract(sources)",
            "independent validator dispatch",
        ),
        (
            workspace,
            '"android_service_startup_transaction_verifier": (',
            "independent focused-verifier source",
        ),
        (
            workspace,
            '"android_main_service_generation_owner": (',
            "independent generation-owner source",
        ),
        (
            workspace,
            '"android_main_service_generation_owner_test": (',
            "independent generation-owner behavior source",
        ),
    ):
        require(source, token, label)


MUTATIONS = (
    Mutation("owner", "activeGeneration != null", "activeGeneration == null", "single active transaction"),
    Mutation("owner", "generation <= greatestGeneration", "generation < greatestGeneration", "retired generation refusal"),
    Mutation("owner", "phase = Phase.STATUS_ATTEMPTED", "phase = Phase.RESERVED", "status-attempt recording"),
    Mutation("owner", "phase = Phase.VOICE_ATTEMPTED", "phase = Phase.STATUS_ATTEMPTED", "voice-attempt recording"),
    Mutation("owner", "phase = Phase.ACTIVATION_ATTEMPTED", "phase = Phase.VOICE_ATTEMPTED", "listener activation attempt"),
    Mutation("owner", "phase = Phase.COMMITTED", "phase = Phase.ACTIVATION_ATTEMPTED", "generation commit"),
    Mutation("owner", "retireStatus = currentPhase != Phase.RESERVED", "retireStatus = false", "attempted status retirement"),
    Mutation("owner", "currentPhase == Phase.COMMITTED", "false", "committed voice retirement"),
    Mutation("owner", "activeGeneration = null\n        phase = null", "phase = null", "retirement deactivation"),
    Mutation("behavior", "reservation-only rollback selected unrelated authority", "reservation rollback passed", "reservation-only rollback behavior"),
    Mutation("behavior", "voice-failure rollback did not select every attempted exact owner", "voice rollback passed", "voice rollback behavior"),
    Mutation("behavior", "activation-failure rollback did not select every attempted exact owner", "activation rollback passed", "activation rollback behavior"),
    Mutation("service", "private val serviceGenerationOwner = MainServiceGenerationOwner()", "internal val serviceGenerationOwner = MainServiceGenerationOwner()", "private transaction authority"),
    Mutation("service", "private var nativeCallbackContextReady = false", "private var nativeCallbackContextReady = true", "closed native callback-context admission"),
    Mutation("service", "nativeCallbackContextReady = FFI.init(this, applicationContext)", "FFI.init(this, applicationContext)", "native callback-context admission publication"),
    Mutation("service", "if (!nativeCallbackContextReady) {\n            Log.e(logTag, \"Cannot start MainService", "if (false) {\n            Log.e(logTag, \"Cannot start MainService", "exact native callback-context startup gate"),
    Mutation("service", "@Volatile\n    private var acceptingControlledConnections = false", "private var acceptingControlledConnections = false", "cross-thread admission visibility"),
    Mutation("service", "private val controlledServiceGenerationLock = Any()", "private val controlledServiceGenerationLock = this", "non-callback transaction lock"),
    Mutation("service", "synchronized(controlledServiceGenerationLock) {\n            initializeControlledServiceGenerationLocked()", "synchronized(this) {\n            initializeControlledServiceGenerationLocked()", "startup lock-order isolation"),
    Mutation("service", "synchronized(controlledServiceGenerationLock) {\n            retireControlledServiceGenerationLocked(generation, reason)", "synchronized(this) {\n            retireControlledServiceGenerationLocked(generation, reason)", "retirement lock-order isolation"),
    Mutation("service", "serviceGenerationOwner.isCommitted(currentGeneration) &&\n                FFI.isServerGenerationActive(this, currentGeneration)", "serviceGenerationOwner.isCommitted(currentGeneration)", "committed-and-active idempotency"),
    Mutation("service", 'val generation = FFI.startServer(this, configPath, "")', 'val generation = FFI.startServer(configPath, "")', "exact Service listener begin"),
    Mutation("service", "serviceGenerationOwner.beginReservation(generation)", "true", "generation-reservation ownership"),
    Mutation("service", "if (!publishScreenInfo())", "if (false)", "screen publication commit gate"),
    Mutation("service", "serviceGenerationOwner.noteStatusAttempt(generation)", "true", "status attempt ownership"),
    Mutation("service", "if (!statusOwner.begin(generation))", "if (!statusOwner.begin(1L))", "exact status publication"),
    Mutation("service", "serviceGenerationOwner.noteVoiceAttempt(generation)", "true", "voice attempt ownership"),
    Mutation("service", "serviceGenerationOwner.noteActivationAttempt(generation)", "true", "listener activation ownership"),
    Mutation("service", "if (!VoiceCallAudioCoordinator.beginControlledServiceGeneration(generation))", "if (false)", "exact voice publication"),
    Mutation("service", "if (!serviceGenerationOwner.commit(generation))", "if (false)", "complete generation commit"),
    Mutation("service", "acceptingControlledConnections = true", "// controlled admission remained closed", "post-commit callback admission"),
    Mutation("service", "if (!FFI.activateServer(this, generation))", "if (false)", "post-admission exact listener activation"),
    Mutation("service", "val retirement = serviceGenerationOwner.retire(generation)", "val retirement = serviceGenerationOwner.retire(1L)", "exact retirement plan"),
    Mutation("service", "FFI.stopServer(this, retirement.generation)", "FFI.stopServer(this, 0L)", "exact native rollback"),
    Mutation("service", "VoiceCallAudioCoordinator.clearControlledConnections(retirement.generation)", "true", "attempted voice rollback"),
    Mutation("service", "statusOwner.retire(retirement.generation)", "true", "attempted status rollback"),
    Mutation("service", "initNotification()\n    }", "initNotification()\n        initializeControlledServiceGeneration()\n    }", "bound-only inert creation"),
    Mutation("service", "if (!initializeControlledServiceGeneration()) {", "if (false) {", "explicit-start transaction failure gate"),
    Mutation("service", "stopSelfResult(startId)", "stopSelfResult(1)", "exact start-request retirement"),
    Mutation("service", "stopForeground(STOP_FOREGROUND_REMOVE)", "// foreground retained after failed startup", "failed-start foreground retirement"),
    Mutation("ffi_kt", "external fun activateServer(service: Context, generation: Long): Boolean", "external fun activateServer(generation: Long): Boolean", "Kotlin exact Service activation"),
    Mutation("ffi_kt", "external fun isServerGenerationActive(service: Context, generation: Long): Boolean", "external fun isServerGenerationActive(generation: Long): Boolean", "Kotlin exact Service health"),
    Mutation("ffi_kt", "external fun stopServer(service: Context, generation: Long): Boolean", "external fun stopServer(generation: Long): Boolean", "Kotlin exact Service retirement"),
    Mutation("ffi_kt", "external fun init(service: Context, applicationContext: Context): Boolean", "external fun init(service: Context, applicationContext: Context)", "Kotlin callback-context admission result"),
    Mutation("rust_ffi", "std::thread::Builder::new()\n            .name(\"android-direct-service\".to_owned())", "std::thread::Builder::new()", "named fallible listener spawn"),
    Mutation("rust_ffi", "let _worker_guard = AndroidDirectServerWorkerGuard(generation);", "// worker exit retained active generation", "worker-exit retirement guard"),
    Mutation("rust_ffi", "claim_main_service_listener_start(&env, &service, generation)", "true", "native exact listener-start claim"),
    Mutation("rust_ffi", "if !crate::direct_service::android_activate_generation(generation)", "if false", "reserved listener activation"),
    Mutation("rust_ffi", "let Some(retirement) = scrap::android::retire_main_service_generation(", "let retirement = scrap::android::retire_main_service_generation(", "object proof before direct stop"),
    Mutation("rust_ffi", 'pub unsafe extern "system" fn Java_ffi_FFI_activateServer(\n        env: JNIEnv,\n        _class: JClass,\n        service: JObject,\n        generation: jlong,', 'pub unsafe extern "system" fn Java_ffi_FFI_activateServer(\n        env: JNIEnv,\n        _class: JClass,\n        owner: JObject,\n        generation: jlong,', "JNI exact Service activation input"),
    Mutation("rust_ffi", "crate::direct_service::android_begin_generation,", "|| 1,", "object-authorized native generation allocation"),
    Mutation("scrap_ffi", "let generation = begin_generation();", "let generation = 1;", "generation allocation after object proof"),
    Mutation("scrap_ffi", "Ok(false) if context.generation.is_some()", "Ok(false)", "active foreign callback-owner replacement refusal"),
    Mutation("scrap_ffi", "if current.generation != Some(generation) {\n        return None;\n    }\n    match env.is_same_object", "if current.generation.is_none() {\n        return None;\n    }\n    match env.is_same_object", "native exact generation comparison"),
    Mutation("scrap_ffi", "current.generation != Some(generation) || current.listener_started", "current.generation != Some(generation)", "single native listener start"),
    Mutation("scrap_ffi", "pub fn owns_main_service_generation(", "pub fn owns_main_service_generation_disabled(", "exact native generation health owner"),
    Mutation("scrap_ffi", "if !current.listener_started {\n        return false;\n    }\n    match env.is_same_object(current.owner.as_obj(), service)", "if false {\n        return false;\n    }\n    match env.is_same_object(current.owner.as_obj(), service)", "started-listener native health claim"),
    Mutation("scrap_ffi", "if current.generation != Some(generation) {\n        return None;\n    }\n    match env.is_same_object(current.owner.as_obj(), service)", "if current.generation != Some(generation) {\n        return None;\n    }\n    match Ok(true)", "native exact Service comparison"),
    Mutation("scrap_ffi", "current.generation = None", "// native generation retained", "native retry release"),
    Mutation("direct_service", "self.reserved = true;\n        self.active = false;", "self.reserved = false;\n        self.active = true;", "inactive listener reservation"),
    Mutation("direct_service", "if self.reserved || self.active", "if false", "single native listener reservation"),
    Mutation("direct_service", "fn activate_generation(&mut self, expected_generation: u64) -> bool", "fn activate_generation_disabled(&mut self, expected_generation: u64) -> bool", "explicit reserved listener activation"),
    Mutation("direct_service", "pub fn android_request_stop_or_confirm_inactive(expected_generation: u64) -> bool", "pub fn android_request_stop_or_confirm_inactive_disabled(expected_generation: u64) -> bool", "already-inactive exact retirement convergence"),
    Mutation("direct_service", "outcome = &mut direct_listener", "_outcome = std::future::pending::<()>()", "terminal listener-task observation"),
    Mutation("direct_service", "outcome = &mut direct_listener => {\n                        if android_listener_lifecycle_snapshot(my_generation.get()).is_none()", "outcome = &mut direct_listener => {\n                        if false", "normal-stop versus active-worker terminal classification"),
    Mutation("direct_service", "if next > i64::MAX as u64", "if next > u64::MAX", "positive Kotlin Long generation range"),
    Mutation("verify", "/usr/bin/python3 -I -S scripts/verify-android-service-startup-transaction.py --repo . --self-test", "true # Android startup transaction gate removed", "shared focused gate"),
    Mutation("dart_verify", "python3 scripts/verify-android-service-startup-transaction.py --repo . --self-test", "true # Android startup transaction gate removed", "Dart focused gate"),
    Mutation("requirements", '<span class="id">R-S11hq</span>', '<span class="id">R-S11hq-disabled</span>', "R-S11hq requirement"),
    Mutation("requirements", "<tr><td>377</td>", "<tr><td>377-disabled</td>", "Appendix C #377"),
    Mutation("hardening", "### R-S11hq/R-S11e-254 — exact-generation Android MainService startup transaction", "### R-S11hq-disabled/R-S11e-254 — exact-generation Android MainService startup transaction", "hardening disposition"),
    Mutation("workspace", "    validate_android_service_startup_transaction_contract(sources)\n    validate_tray_session_count_mailbox_contract(sources)", "    validate_android_service_startup_transaction_contract_disabled(sources)\n    validate_tray_session_count_mailbox_contract(sources)", "independent validator dispatch"),
)


def load_sources(repo: pathlib.Path) -> Dict[str, str]:
    package = repo / "flutter/android/app/src/main/kotlin/com/carriez/flutter_hbb"
    return {
        "owner": (package / "MainServiceGenerationOwner.kt").read_text(encoding="utf-8"),
        "behavior": (repo / "scripts/android-main-service-generation-owner-test.kt").read_text(encoding="utf-8"),
        "service": (package / "MainService.kt").read_text(encoding="utf-8"),
        "ffi_kt": (repo / "flutter/android/app/src/main/kotlin/ffi.kt").read_text(encoding="utf-8"),
        "rust_ffi": (repo / "src/flutter_ffi.rs").read_text(encoding="utf-8"),
        "scrap_ffi": (repo / "libs/scrap/src/android/ffi.rs").read_text(encoding="utf-8"),
        "direct_service": (repo / "src/direct_service.rs").read_text(encoding="utf-8"),
        "verify": (repo / "scripts/verify.sh").read_text(encoding="utf-8"),
        "dart_verify": (repo / "scripts/dart-verify.sh").read_text(encoding="utf-8"),
        "requirements": (repo / "requirements.html").read_text(encoding="utf-8"),
        "hardening": (repo / "HARDENING_STATUS.md").read_text(encoding="utf-8"),
        "workspace": (repo / "scripts/verify-verifier-workspace.py").read_text(encoding="utf-8"),
    }


def run_mutations(sources: Dict[str, str]) -> None:
    for mutation in MUTATIONS:
        original = sources[mutation.source]
        count = original.count(mutation.old)
        if count != 1:
            raise VerificationError(
                "mutation target for {} occurs {} times".format(mutation.label, count)
            )
        changed = dict(sources)
        changed[mutation.source] = original.replace(mutation.old, mutation.new, 1)
        try:
            validate(changed)
        except VerificationError:
            continue
        raise VerificationError("mutation was accepted: {}".format(mutation.label))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=pathlib.Path, default=pathlib.Path("."))
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    sources = load_sources(args.repo.resolve())
    validate(sources)
    if args.self_test:
        run_mutations(sources)
    suffix = " ({} mutations rejected)".format(len(MUTATIONS)) if args.self_test else ""
    print("verify-android-service-startup-transaction: ok{}".format(suffix))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
