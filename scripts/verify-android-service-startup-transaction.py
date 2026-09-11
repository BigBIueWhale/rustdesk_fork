#!/usr/bin/env python3
"""Check the load-bearing Android MainService generation-retirement ordering.

This is deliberately a small source invariant, not Android runtime evidence. The production
Kotlin state tests and native device/emulator scenarios are the behavioral evidence.
"""

from __future__ import annotations

import argparse
import pathlib
from typing import Iterable


class VerificationError(RuntimeError):
    pass


def require(source: str, token: str, label: str) -> None:
    if token not in source:
        raise VerificationError(f"missing {label}: {token!r}")


def forbid(source: str, token: str, label: str) -> None:
    if token in source:
        raise VerificationError(f"forbidden {label} remains: {token!r}")


def require_order(source: str, tokens: Iterable[str], label: str) -> None:
    position = -1
    for token in tokens:
        position = source.find(token, position + 1)
        if position < 0:
            raise VerificationError(f"{label} is missing ordered token {token!r}")


def extract(source: str, start: str, end: str, label: str) -> str:
    if source.count(start) != 1:
        raise VerificationError(f"{label} start cardinality differs")
    begin = source.index(start)
    finish = source.find(end, begin + len(start))
    if finish < 0:
        raise VerificationError(f"{label} end is absent")
    return source[begin:finish]


def read(repo: pathlib.Path, relative: str) -> str:
    return (repo / relative).read_text(encoding="utf-8")


def validate(repo: pathlib.Path) -> None:
    package = "flutter/android/app/src/main/kotlin/com/carriez/flutter_hbb"
    owner = read(repo, f"{package}/MainServiceGenerationOwner.kt")
    service = read(repo, f"{package}/MainService.kt")
    ffi_kt = read(repo, "flutter/android/app/src/main/kotlin/ffi.kt")
    rust_ffi = read(repo, "src/flutter_ffi.rs")
    scrap_ffi = read(repo, "libs/scrap/src/android/ffi.rs")
    native_state = read(repo, "libs/scrap/src/android/main_service_generation.rs")
    direct = read(repo, "src/direct_service.rs")

    require_order(
        owner,
        (
            "COMMITTED,",
            "RETIRING,",
            "private var activeGeneration: Long? = null",
            "private var retirement: MainServiceGenerationRetirement? = null",
            "fun beginRetirement(generation: Long): MainServiceGenerationRetirement?",
            "fun completeRetirement(generation: Long): Boolean",
        ),
        "two-phase Kotlin generation owner",
    )
    begin_retirement = extract(
        owner,
        "    fun beginRetirement(generation: Long): MainServiceGenerationRetirement? {",
        "\n    @Synchronized\n    fun completeRetirement",
        "Kotlin retirement reservation",
    )
    require_order(
        begin_retirement,
        (
            "activeGeneration != generation",
            "retirement?.let { current ->",
            "val plan = MainServiceGenerationRetirement(",
            "phase = Phase.RETIRING",
            "retirement = plan",
            "return plan",
        ),
        "Kotlin retirement plan retention",
    )
    forbid(begin_retirement, "activeGeneration = null", "early Kotlin owner release")
    complete_retirement = extract(
        owner,
        "    fun completeRetirement(generation: Long): Boolean {",
        "\n    @Synchronized\n    fun hasActiveGeneration",
        "Kotlin retirement completion",
    )
    require_order(
        complete_retirement,
        (
            "phase != Phase.RETIRING",
            "retirement?.generation != generation",
            "return false",
            "activeGeneration = null",
            "phase = null",
            "retirement = null",
            "return true",
        ),
        "exact Kotlin retirement completion",
    )
    forbid(owner, "fun retire(generation: Long)", "destructive one-phase Kotlin retirement")

    on_start = extract(
        service,
        "    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {",
        "\n    private fun publishControlledServiceStatus",
        "MainService explicit start",
    )
    require_order(
        on_start,
        (
            "val generationReady = initializeControlledServiceGeneration()",
            "publishControlledServiceStatus(generationReady)",
            "if (!generationReady)",
            "if (nativeServerGeneration > 0L)",
            "Retaining foreground MainService for explicit retry",
            "return START_NOT_STICKY",
            "stopForeground(STOP_FOREGROUND_REMOVE)",
            "stopSelfResult(startId)",
        ),
        "incomplete cleanup retains the exact Service for a later explicit retry",
    )

    retirement = extract(
        service,
        "    private fun retireControlledServiceGenerationLocked(",
        "\n    private fun retireUnownedNativeGenerationLocked(",
        "MainService retirement transaction",
    )
    require_order(
        retirement,
        (
            "acceptingControlledConnections = false",
            "serviceGenerationOwner.beginRetirement(generation)",
            "FFI.deactivateServer(this, retirement.generation)",
            "VoiceCallAudioCoordinator.clearControlledConnections(retirement.generation)",
            "statusOwner.retireOrConfirmInactive(retirement.generation)",
            "if (!retired)",
            "FFI.retireServerGeneration(this, retirement.generation)",
            "serviceGenerationOwner.completeRetirement(retirement.generation)",
            "nativeServerGeneration = 0L",
            "return true",
        ),
        "deactivate-clean-finalize-complete order",
    )
    on_destroy = extract(
        service,
        "    override fun onDestroy() {",
        "\n    override fun onTaskRemoved",
        "MainService destruction",
    )
    require_order(
        on_destroy,
        (
            "val generationRetired = generation <= 0L ||",
            "if (!generationRetired)",
            "if (generationRetired && nativeServerGeneration == 0L)",
            "FFI.releaseService(this)",
            "Retaining MainService callback authority for exact cleanup retry",
        ),
        "callback release after exact retirement only",
    )
    forbid(service, "FFI.stopServer(", "one-phase native stop API")

    for signature in (
        "external fun deactivateServer(service: Context, generation: Long): Boolean",
        "external fun retireServerGeneration(service: Context, generation: Long): Boolean",
    ):
        require(ffi_kt, signature, "exact Service-and-generation JNI surface")
    forbid(ffi_kt, "external fun stopServer(", "ambiguous one-phase Kotlin JNI surface")

    activate = extract(
        rust_ffi,
        '    pub unsafe extern "system" fn Java_ffi_FFI_activateServer(',
        '\n    #[no_mangle]\n    pub unsafe extern "system" fn Java_ffi_FFI_isServerGenerationActive(',
        "native listener activation",
    )
    require(
        activate,
        "claim_main_service_listener_start(&env, &service, generation)",
        "exact activation claim",
    )
    if activate.count("scrap::android::deactivate_main_service_generation(") != 2:
        raise VerificationError("both native activation failures must retain cleanup authority")
    forbid(activate, "retire_main_service_generation(", "resource retirement inside activation failure")

    require_order(
        rust_ffi,
        (
            'fn Java_ffi_FFI_deactivateServer(',
            "scrap::android::deactivate_main_service_generation(",
            "android_request_stop_or_confirm_inactive",
            'fn Java_ffi_FFI_retireServerGeneration(',
            "scrap::android::retire_main_service_generation(",
            "android_generation_is_inactive",
        ),
        "separate native deactivation and finalization JNI",
    )

    require_order(
        native_state,
        (
            "enum ListenerState",
            "Inactive,",
            "Reserved,",
            "ActivationClaimed,",
            "generation: Option<u64>",
            "last_retired_generation: Option<u64>",
            "listener_state: ListenerState",
            "fn confirm_deactivated(&mut self, generation: u64) -> bool",
            "fn can_finalize(&self, generation: u64) -> bool",
            "fn complete_retirement(&mut self, generation: u64) -> bool",
            "fn may_release_callback_owner(&self) -> bool",
        ),
        "native listener transaction state",
    )
    deactivate = extract(
        scrap_ffi,
        "pub fn deactivate_main_service_generation<Stop>(",
        "\npub fn retire_main_service_generation<ConfirmInactive>(",
        "native exact listener deactivation",
    )
    require_order(
        deactivate,
        (
            "env.is_same_object(current.owner.as_obj(), service)",
            "!current.generation.is_current(generation) || !stop_listener(generation)",
            "current.generation.confirm_deactivated(generation)",
        ),
        "native owner proof before listener deactivation",
    )
    forbid(deactivate, "current.generation = None", "native authority release during listener stop")

    native_retirement = extract(
        scrap_ffi,
        "pub fn retire_main_service_generation<ConfirmInactive>(",
        "\n#[no_mangle]\npub extern \"system\" fn Java_ffi_FFI_releaseService(",
        "native generation finalization",
    )
    require_order(
        native_retirement,
        (
            "env.is_same_object(current.owner.as_obj(), service)",
            "!current.generation.can_finalize(generation)",
            "!confirm_listener_inactive(generation)",
            "VIDEO_RAW.lock().unwrap().retire_generation(generation)",
            "SCREEN_SIZE.lock().unwrap().retire_generation(generation)",
            "if video_retired && screen_retired",
            "current.generation.complete_retirement(generation)",
        ),
        "native cleanup acknowledgement before authority release",
    )
    release = extract(
        scrap_ffi,
        'pub extern "system" fn Java_ffi_FFI_releaseService(',
        '\n#[no_mangle]\npub extern "system" fn Java_ffi_FFI_setClipboardManager(',
        "native callback-owner release",
    )
    require_order(
        release,
        (
            "env.is_same_object(owner.owner.as_obj(), &service)",
            "if !owner.generation.may_release_callback_owner()",
            "return jboolean::from(false)",
            "current.take()",
        ),
        "fail-closed callback-owner release",
    )
    forbid(release, "retire_generation(generation)", "best-effort release fallback")

    require(
        direct,
        "pub fn android_generation_is_inactive(expected_generation: u64) -> bool",
        "exact inactive listener confirmation",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=pathlib.Path, default=pathlib.Path("."))
    args = parser.parse_args()
    validate(args.repo.resolve())
    print("verify-android-service-startup-transaction: ok (source invariant only)")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, VerificationError) as error:
        raise SystemExit(f"verify-android-service-startup-transaction: {error}")
