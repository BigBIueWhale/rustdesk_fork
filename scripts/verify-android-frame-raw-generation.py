#!/usr/bin/env python3
"""Validate exact MainService-generation ownership of Android raw video."""

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
    frame_raw = sources["frame_raw"]
    rust_ffi = sources["rust_ffi"]
    kotlin_ffi = sources["kotlin_ffi"]
    main_service = sources["main_service"]
    clipboard = sources["clipboard"]
    audio = sources["audio"]
    scrap_mod = sources["scrap_mod"]
    scrap_lib = sources["scrap_lib"]
    voice_verifier = sources["voice_verifier"]
    verify = sources["verify"]
    requirements = sources["requirements"]
    hardening = sources["hardening"]
    workspace = sources["workspace"]

    state = extract(
        owner,
        "pub(crate) struct FrameRawGenerationOwner {",
        "\n}\n\nimpl FrameRawGenerationOwner {",
        "raw-video generation state",
    )
    require_order(
        state,
        (
            "greatest_generation: u64",
            "active_generation: Option<u64>",
        ),
        "monotonic exact raw-video owner state",
    )
    begin = extract(
        owner,
        "    pub(crate) fn begin(&mut self, generation: u64) -> BeginGeneration {",
        "\n    pub(crate) fn retire(",
        "raw-video generation begin",
    )
    require_order(
        begin,
        (
            "if generation == 0",
            "BeginGeneration::Rejected",
            "if self.active_generation == Some(generation)",
            "BeginGeneration::Current",
            "if generation <= self.greatest_generation",
            "BeginGeneration::Rejected",
            "self.greatest_generation = generation",
            "self.active_generation = Some(generation)",
            "BeginGeneration::New",
        ),
        "checked monotonic raw-video begin",
    )
    retire = extract(
        owner,
        "    pub(crate) fn retire(&mut self, generation: u64) -> bool {",
        "\n    pub(crate) fn admits(",
        "raw-video generation retirement",
    )
    require_order(
        retire,
        (
            "generation == 0",
            "self.active_generation != Some(generation)",
            "return false",
            "self.active_generation = None",
            "true",
        ),
        "exact raw-video generation retirement",
    )
    admits = extract(
        owner,
        "    pub(crate) fn admits(&self, generation: u64) -> bool {",
        "\n}\n\n#[cfg(test)]",
        "raw-video generation admission",
    )
    require(
        admits,
        "generation != 0 && self.active_generation == Some(generation)",
        "exact active-generation admission",
    )
    for token, label in (
        (
            "stale_generation_cannot_mutate_replacement",
            "stale-generation behavior regression",
        ),
        (
            "exact_retirement_prevents_same_generation_reactivation",
            "retired-generation behavior regression",
        ),
        (
            "retired_or_superseded_generations_never_regress",
            "monotonic behavior regression",
        ),
        (
            "assert!(!owner.retire(7));\n        assert!(owner.admits(8));",
            "stale retirement preserves replacement assertion",
        ),
        (
            "assert_eq!(owner.begin(12), BeginGeneration::Rejected);",
            "retired generation cannot reactivate assertion",
        ),
    ):
        require(owner, token, label)

    require(
        frame_raw,
        "use super::frame_raw_generation::{BeginGeneration, FrameRawGenerationOwner};",
        "generation owner integration",
    )
    wrapper = extract(
        frame_raw,
        "pub(crate) struct GenerationOwnedFrameRaw {",
        "\n}\n\nimpl GenerationOwnedFrameRaw {",
        "generation-owned raw frame",
    )
    require_order(
        wrapper,
        ("owner: FrameRawGenerationOwner", "frame: FrameRaw"),
        "generation and frame composition",
    )
    begin_wrapper = extract(
        frame_raw,
        "    pub(crate) fn begin_generation(&mut self, generation: u64) -> bool {",
        "\n    pub(crate) fn retire_generation(",
        "generation-owned frame begin",
    )
    require_order(
        begin_wrapper,
        (
            "self.owner.begin(generation)",
            "BeginGeneration::New",
            "self.frame.set_enable(false)",
            "BeginGeneration::Current => true",
            "BeginGeneration::Rejected => false",
        ),
        "new-generation reset and current-generation preservation",
    )
    retire_wrapper = extract(
        frame_raw,
        "    pub(crate) fn retire_generation(&mut self, generation: u64) -> bool {",
        "\n    pub(crate) fn set_enable(",
        "generation-owned frame retirement",
    )
    require_order(
        retire_wrapper,
        (
            "if !self.owner.retire(generation)",
            "return false",
            "self.frame.set_enable(false)",
            "true",
        ),
        "exact retirement disables and clears raw video",
    )
    set_wrapper = extract(
        frame_raw,
        "    pub(crate) fn set_enable(&mut self, generation: u64, value: bool) -> bool {",
        "\n    pub(crate) fn update_from_jni_buffer(",
        "generation-owned enable",
    )
    require_order(
        set_wrapper,
        (
            "if !self.owner.admits(generation)",
            "return false",
            "self.frame.set_enable(value)",
            "true",
        ),
        "exact-generation raw enable",
    )
    update_wrapper = extract(
        frame_raw,
        "    pub(crate) fn update_from_jni_buffer(\n        &mut self,",
        "\n    pub(crate) fn take(",
        "generation-owned frame update",
    )
    require_order(
        update_wrapper,
        (
            "generation: u64",
            "if !self.owner.admits(generation)",
            "return",
            "self.frame.update_from_jni_buffer(data, len, max_len)",
        ),
        "exact-generation raw frame publication",
    )
    forbid(
        frame_raw,
        "greatest_generation:",
        "duplicated raw-video generation authority",
    )

    require(scrap_mod, "mod frame_raw_generation;", "Android production state module")
    require(
        scrap_lib,
        '#[path = "android/frame_raw_generation.rs"]\n'
        "mod android_frame_raw_generation_tests;",
        "host behavior-test inclusion of production state",
    )

    require_order(
        rust_ffi,
        (
            "static ref VIDEO_RAW: Mutex<GenerationOwnedFrameRaw>",
            'GenerationOwnedFrameRaw::new("video", MAX_VIDEO_FRAME_TIMEOUT)',
            "static ref AUDIO_RAW: Mutex<FrameRaw>",
        ),
        "typed video/audio raw state separation",
    )
    video_update = extract(
        rust_ffi,
        'pub extern "system" fn Java_ffi_FFI_onVideoFrameUpdate(',
        '\n#[no_mangle]\npub extern "system" fn Java_ffi_FFI_onAudioFrameUpdate(',
        "raw-video frame JNI",
    )
    require_order(
        video_update,
        (
            "\n    generation: jni::sys::jlong,\n",
            "let Ok(generation) = u64::try_from(generation)",
            "VIDEO_RAW.lock().unwrap().update_from_jni_buffer(",
            "generation",
            "data",
            "len",
            "MAX_ANDROID_VIDEO_RAW_BYTES",
        ),
        "generation-bound raw-video frame JNI",
    )
    video_enable = extract(
        rust_ffi,
        'pub extern "system" fn Java_ffi_FFI_setVideoFrameRawEnable(',
        '\n#[no_mangle]\npub extern "system" fn Java_ffi_FFI_setAudioFrameRawEnable(',
        "raw-video enable JNI",
    )
    require_order(
        video_enable,
        (
            "\n    generation: jni::sys::jlong,\n",
            ") -> jboolean",
            "let Ok(generation) = u64::try_from(generation)",
            "return jboolean::from(false)",
            ".set_enable(generation, value.eq(&1))",
        ),
        "checked exact-generation raw-video enable JNI",
    )
    require(
        rust_ffi,
        'pub extern "system" fn Java_ffi_FFI_setAudioFrameRawEnable(',
        "typed raw-audio enable JNI",
    )
    forbid(
        rust_ffi,
        "Java_ffi_FFI_setFrameRawEnable",
        "ambient video/audio raw selector JNI",
    )

    init = extract(
        rust_ffi,
        'pub extern "system" fn Java_ffi_FFI_init(',
        "\npub fn bind_main_service_generation(",
        "MainService callback-context installation",
    )
    require_order(
        init,
        (
            "let mut current = MAIN_SERVICE_CTX.write().unwrap()",
            "current.as_ref().and_then(|context| context.generation)",
            "VIDEO_RAW.lock().unwrap().retire_generation(generation)",
            "*current = Some(MainServiceContext {",
            "generation: None",
            "owner: service",
        ),
        "replacement retires predecessor raw-video generation",
    )
    bind = extract(
        rust_ffi,
        "pub fn bind_main_service_generation(",
        "\n#[no_mangle]\npub extern \"system\" fn Java_ffi_FFI_releaseService(",
        "exact-object service-generation binding",
    )
    require_order(
        bind,
        (
            "generation == 0 || service.is_null()",
            "MAIN_SERVICE_CTX.write().unwrap()",
            "env.is_same_object(current.owner.as_obj(), service)",
            "if current.generation.is_some()",
            "VIDEO_RAW.lock().unwrap().begin_generation(generation)",
            "current.generation = Some(generation)",
            "true",
        ),
        "raw-video begin before callback generation publication",
    )
    release = extract(
        rust_ffi,
        'pub extern "system" fn Java_ffi_FFI_releaseService(',
        '\n#[no_mangle]\npub extern "system" fn Java_ffi_FFI_setClipboardManager(',
        "exact-object service release",
    )
    require_order(
        release,
        (
            "let generation = owner.generation",
            "env.is_same_object(owner.owner.as_obj(), &service)",
            "if is_current",
            "VIDEO_RAW.lock().unwrap().retire_generation(generation)",
            "current.take()",
            "jboolean::from(is_current)",
        ),
        "exact-object release retires only its raw-video generation",
    )

    for token, label in (
        (
            "external fun onVideoFrameUpdate(generation: Long, buf: ByteBuffer)",
            "generation-bound Kotlin frame declaration",
        ),
        (
            "external fun setVideoFrameRawEnable(generation: Long, value: Boolean): Boolean",
            "generation-bound Kotlin enable declaration",
        ),
        (
            "external fun setAudioFrameRawEnable(value: Boolean)",
            "typed Kotlin audio declaration",
        ),
    ):
        require(kotlin_ffi, token, label)
    for token, label in (
        (
            "external fun onVideoFrameUpdate(buf: ByteBuffer)",
            "generationless Kotlin video frame declaration",
        ),
        ("setFrameRawEnable", "ambient Kotlin video/audio selector"),
    ):
        forbid(kotlin_ffi, token, label)

    require(
        main_service,
        "@Volatile\n    private var captureActive = false",
        "instance-local cross-thread capture authority",
    )
    require(
        main_service,
        '"is_start" -> {\n                captureActive.toString()',
        "exact-service capture status reply",
    )
    require(
        main_service,
        "if (image == null || !captureActive) return@setOnImageAvailableListener",
        "instance-local frame callback gate",
    )
    require(
        main_service,
        "FFI.onVideoFrameUpdate(nativeServerGeneration, buffer)",
        "exact-generation frame publication",
    )
    require(
        main_service,
        "if (captureActive) {\n                    stopCapturePipeline()",
        "instance-local display reconfiguration",
    )
    forbid(main_service, "if (isStart)", "companion capture resource authority")
    forbid(main_service, "!isStart", "companion frame resource authority")

    start_capture = extract(
        main_service,
        "    fun startCapture(): Boolean {",
        "\n    @Synchronized\n    private fun reconcileControlledCaptureDemand()",
        "MainService capture start",
    )
    require_order(
        start_capture,
        (
            "if (captureActive)",
            "val projection = mediaProjection",
            "surface = createSurface()",
            "if (!startRawVideoRecorder(projection))",
            "releaseCaptureResources(clearCaptureRequest = false)",
            "requestMediaProjection()",
            "return false",
            "if (!FFI.setVideoFrameRawEnable(nativeServerGeneration, true))",
            "Rejected raw-video start from stale MainService generation",
            "stopCapturePipeline(keepReusableDisplay = false)",
            "return false",
            "VoiceCallAudioCoordinator.setPlaybackCaptureProjection(",
            "captureActive = true",
            "return true",
        ),
        "display and raw admission before active-state commit",
    )
    stop_capture = extract(
        main_service,
        "    private fun stopCapturePipeline(",
        "\n    @Synchronized\n    private fun releaseCaptureResources(",
        "MainService capture stop",
    )
    require_order(
        stop_capture,
        (
            "if (!FFI.setVideoFrameRawEnable(nativeServerGeneration, false))",
            "Ignored raw-video stop from stale MainService generation",
            "captureActive = false",
            "virtualDisplay?.release()",
            "imageReader?.close()",
            "surface?.release()",
            "VoiceCallAudioCoordinator.setPlaybackCaptureProjection(",
            "nativeServerGeneration",
            "null",
        ),
        "exact raw disable before local pipeline retirement",
    )
    forbid(main_service, "_isStart", "process-global capture-start publication")
    forbid(main_service, "setCaptureStarted", "dead clipboard capture publication")
    forbid(clipboard, "isCaptureStarted", "dead clipboard capture status")
    forbid(clipboard, "setCaptureStarted", "dead clipboard capture status writer")

    for token, label in (
        ("FFI.setAudioFrameRawEnable(true)", "typed audio enable"),
        ("FFI.setAudioFrameRawEnable(false)", "typed audio disable"),
    ):
        require(audio, token, label)
        require(voice_verifier, token, "voice verifier {}".format(label))
    forbid(audio, "setFrameRawEnable", "ambient audio selector")

    for token, label in (
        (
            "android_frame_raw_generation_tests::tests:: -- --test-threads=1",
            "shared pure behavior gate",
        ),
        (
            "/usr/bin/python3 -I -S scripts/verify-android-frame-raw-generation.py --repo . --self-test",
            "shared focused mutation gate",
        ),
        (
            "R-S11em/R-S11e-174 Android exact-generation raw-video authority",
            "shared raw-video verdict",
        ),
        (
            "R-S14/R-S11ei/R-S11ek/R-S11em/R-S11en/R-S11e-153/R-S11e-169/R-S11e-174/R-S11e-175/R-T4",
            "shared capture lifecycle integration label",
        ),
    ):
        require(verify, token, label)
    for token, label in (
        ('<span class="id">R-S11em</span>', "R-S11em requirement"),
        ("<tr><td>295</td>", "Appendix C #295"),
        (
            "R-S11en separately owns the Activity-visible service/MediaProjection status",
            "explicit adjacent status boundary",
        ),
    ):
        require(requirements, token, label)
    require(
        hardening,
        "R-S11em/R-S11e-174 exact MainService-generation Android raw-video ownership",
        "hardening disposition",
    )
    for token, label in (
        (
            "validate_android_frame_raw_generation_contract(sources)",
            "independent contract dispatch",
        ),
        (
            '"android_frame_raw_generation_verifier": (\n'
            '                repo / "scripts/verify-android-frame-raw-generation.py"',
            "independent focused-verifier source",
        ),
        (
            "stale raw-video generation retirement",
            "independent stale-retirement mutation",
        ),
    ):
        require(workspace, token, label)


MUTATIONS = (
    Mutation(
        "owner",
        "        if generation == 0 {\n            return BeginGeneration::Rejected;",
        "        if false {\n            return BeginGeneration::Rejected;",
        "zero generation refusal",
    ),
    Mutation(
        "owner",
        "        if self.active_generation == Some(generation) {\n"
        "            return BeginGeneration::Current;",
        "        if false {\n            return BeginGeneration::Current;",
        "idempotent current generation",
    ),
    Mutation(
        "owner",
        "        if generation <= self.greatest_generation {",
        "        if generation < self.greatest_generation {",
        "retired generation refusal",
    ),
    Mutation(
        "owner",
        "        self.greatest_generation = generation;\n"
        "        self.active_generation = Some(generation);",
        "        self.active_generation = Some(generation);",
        "monotonic generation record",
    ),
    Mutation(
        "owner",
        "generation == 0 || self.active_generation != Some(generation)",
        "generation == 0",
        "exact retirement generation",
    ),
    Mutation(
        "owner",
        "        self.active_generation = None;\n        true",
        "        true",
        "retirement deactivation",
    ),
    Mutation(
        "owner",
        "generation != 0 && self.active_generation == Some(generation)",
        "generation != 0",
        "exact active generation admission",
    ),
    Mutation(
        "owner",
        "assert!(!owner.retire(7));\n        assert!(owner.admits(8));",
        "assert!(owner.retire(7));\n        assert!(owner.admits(8));",
        "stale retirement preserves replacement",
    ),
    Mutation(
        "owner",
        "assert_eq!(owner.begin(12), BeginGeneration::Rejected);",
        "assert_eq!(owner.begin(12), BeginGeneration::New);",
        "retired generation behavior",
    ),
    Mutation(
        "frame_raw",
        "            BeginGeneration::New => {\n"
        "                self.frame.set_enable(false);\n"
        "                true",
        "            BeginGeneration::New => {\n                true",
        "new generation raw reset",
    ),
    Mutation(
        "frame_raw",
        "        if !self.owner.retire(generation) {",
        "        if false {",
        "wrapper exact retirement",
    ),
    Mutation(
        "frame_raw",
        "        if !self.owner.admits(generation) {\n"
        "            return false;\n"
        "        }\n"
        "        self.frame.set_enable(value);",
        "        self.frame.set_enable(value);",
        "wrapper enable admission",
    ),
    Mutation(
        "frame_raw",
        "        if !self.owner.admits(generation) {\n"
        "            return;\n"
        "        }\n"
        "        self.frame.update_from_jni_buffer(data, len, max_len);",
        "        self.frame.update_from_jni_buffer(data, len, max_len);",
        "wrapper frame admission",
    ),
    Mutation(
        "rust_ffi",
        "static ref VIDEO_RAW: Mutex<GenerationOwnedFrameRaw>",
        "static ref VIDEO_RAW: Mutex<FrameRaw>",
        "generation-owned native video buffer",
    ),
    Mutation(
        "rust_ffi",
        "    generation: jni::sys::jlong,\n    buffer: JObject,",
        "    _generation: jni::sys::jlong,\n    buffer: JObject,",
        "frame JNI generation input",
    ),
    Mutation(
        "rust_ffi",
        "VIDEO_RAW.lock().unwrap().update_from_jni_buffer(\n"
        "                generation,\n",
        "VIDEO_RAW.lock().unwrap().update_from_jni_buffer(\n                1,\n",
        "frame JNI exact generation forwarding",
    ),
    Mutation(
        "rust_ffi",
        'pub extern "system" fn Java_ffi_FFI_setVideoFrameRawEnable(',
        'pub extern "system" fn Java_ffi_FFI_setFrameRawEnable(',
        "typed video enable JNI",
    ),
    Mutation(
        "rust_ffi",
        ".set_enable(generation, value.eq(&1))",
        ".set_enable(1, value.eq(&1))",
        "enable JNI exact generation forwarding",
    ),
    Mutation(
        "rust_ffi",
        'pub extern "system" fn Java_ffi_FFI_setAudioFrameRawEnable(',
        'pub extern "system" fn Java_ffi_FFI_setFrameRawEnable(',
        "typed audio enable JNI",
    ),
    Mutation(
        "rust_ffi",
        "if let Some(generation) = current.as_ref().and_then(|context| context.generation) {\n"
        "        if !VIDEO_RAW.lock().unwrap().retire_generation(generation)",
        "if let Some(generation) = current.as_ref().and_then(|context| context.generation) {\n"
        "        if !VIDEO_RAW.lock().unwrap().set_enable(generation, false)",
        "replacement raw-video retirement",
    ),
    Mutation(
        "rust_ffi",
        "    if !VIDEO_RAW.lock().unwrap().begin_generation(generation) {",
        "    if false {",
        "raw-video begin during exact-object binding",
    ),
    Mutation(
        "rust_ffi",
        "if !VIDEO_RAW.lock().unwrap().retire_generation(generation) {\n"
        "                log::warn!(\n"
        '                    "failed to retire Android raw-video generation {generation} during MainService release"',
        "if false {\n"
        "                log::warn!(\n"
        '                    "failed to retire Android raw-video generation {generation} during MainService release"',
        "exact-object release raw retirement",
    ),
    Mutation(
        "kotlin_ffi",
        "external fun onVideoFrameUpdate(generation: Long, buf: ByteBuffer)",
        "external fun onVideoFrameUpdate(buf: ByteBuffer)",
        "Kotlin frame generation contract",
    ),
    Mutation(
        "kotlin_ffi",
        "external fun setVideoFrameRawEnable(generation: Long, value: Boolean): Boolean",
        "external fun setVideoFrameRawEnable(value: Boolean): Boolean",
        "Kotlin enable generation contract",
    ),
    Mutation(
        "kotlin_ffi",
        "external fun setAudioFrameRawEnable(value: Boolean)",
        "external fun setFrameRawEnable(name: String, value: Boolean)",
        "Kotlin typed audio contract",
    ),
    Mutation(
        "main_service",
        "@Volatile\n    private var captureActive = false",
        "private var captureActive = false",
        "cross-thread local capture authority",
    ),
    Mutation(
        "main_service",
        '"is_start" -> {\n                captureActive.toString()',
        '"is_start" -> {\n                isStart.toString()',
        "exact-service capture status",
    ),
    Mutation(
        "main_service",
        "if (image == null || !captureActive) return@setOnImageAvailableListener",
        "if (image == null || !isStart) return@setOnImageAvailableListener",
        "instance-local frame callback admission",
    ),
    Mutation(
        "main_service",
        "FFI.onVideoFrameUpdate(nativeServerGeneration, buffer)",
        "FFI.onVideoFrameUpdate(0L, buffer)",
        "Kotlin exact-generation frame publication",
    ),
    Mutation(
        "main_service",
        "if (!FFI.setVideoFrameRawEnable(nativeServerGeneration, true))",
        "if (!FFI.setVideoFrameRawEnable(0L, true))",
        "Kotlin exact-generation raw start",
    ),
    Mutation(
        "main_service",
        "            stopCapturePipeline(keepReusableDisplay = false)\n"
        "            return false\n"
        "        }\n\n"
        "        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R)",
        "            return false\n"
        "        }\n\n"
        "        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R)",
        "rejected raw start local cleanup",
    ),
    Mutation(
        "main_service",
        "if (!FFI.setVideoFrameRawEnable(nativeServerGeneration, false))",
        "if (!FFI.setVideoFrameRawEnable(0L, false))",
        "Kotlin exact-generation raw stop",
    ),
    Mutation(
        "audio",
        "FFI.setAudioFrameRawEnable(true)",
        'FFI.setFrameRawEnable("audio", true)',
        "typed raw-audio enable",
    ),
    Mutation(
        "scrap_lib",
        '#[path = "android/frame_raw_generation.rs"]\n'
        "mod android_frame_raw_generation_tests;",
        'mod android_frame_raw_generation_tests_disabled;',
        "production-state host behavior inclusion",
    ),
    Mutation(
        "verify",
        "android_frame_raw_generation_tests::tests:: -- --test-threads=1",
        "android_frame_raw_generation_tests_disabled::tests:: -- --test-threads=1",
        "shared pure behavior gate",
    ),
    Mutation(
        "verify",
        "/usr/bin/python3 -I -S scripts/verify-android-frame-raw-generation.py --repo . --self-test",
        "true # Android raw-video generation gate removed",
        "shared focused mutation gate",
    ),
    Mutation(
        "requirements",
        '<span class="id">R-S11em</span>',
        '<span class="id">R-S11em-disabled</span>',
        "R-S11em requirement",
    ),
    Mutation(
        "requirements",
        "<tr><td>295</td>",
        "<tr><td>295-disabled</td>",
        "Appendix C #295",
    ),
    Mutation(
        "hardening",
        "R-S11em/R-S11e-174 exact MainService-generation Android raw-video ownership",
        "R-S11em/R-S11e-174 ambient Android raw-video ownership",
        "hardening disposition",
    ),
    Mutation(
        "workspace",
        '"android_frame_raw_generation_verifier": (\n'
        '                repo / "scripts/verify-android-frame-raw-generation.py"',
        '"android_frame_raw_generation_verifier_disabled": (\n'
        '                repo / "scripts/verify-android-frame-raw-generation.py"',
        "independent focused-verifier source",
    ),
)


def load_sources(repo: pathlib.Path) -> Dict[str, str]:
    return {
        "owner": (
            repo / "libs/scrap/src/android/frame_raw_generation.rs"
        ).read_text(encoding="utf-8"),
        "frame_raw": (repo / "libs/scrap/src/android/frame_raw.rs").read_text(
            encoding="utf-8"
        ),
        "rust_ffi": (repo / "libs/scrap/src/android/ffi.rs").read_text(
            encoding="utf-8"
        ),
        "kotlin_ffi": (
            repo / "flutter/android/app/src/main/kotlin/ffi.kt"
        ).read_text(encoding="utf-8"),
        "main_service": (
            repo
            / "flutter/android/app/src/main/kotlin/com/carriez/flutter_hbb/MainService.kt"
        ).read_text(encoding="utf-8"),
        "clipboard": (
            repo
            / "flutter/android/app/src/main/kotlin/com/carriez/flutter_hbb/RdClipboardManager.kt"
        ).read_text(encoding="utf-8"),
        "audio": (
            repo
            / "flutter/android/app/src/main/kotlin/com/carriez/flutter_hbb/AudioRecordHandle.kt"
        ).read_text(encoding="utf-8"),
        "scrap_mod": (repo / "libs/scrap/src/android/mod.rs").read_text(
            encoding="utf-8"
        ),
        "scrap_lib": (repo / "libs/scrap/src/lib.rs").read_text(encoding="utf-8"),
        "voice_verifier": (
            repo / "scripts/verify-android-voice-call-ownership.py"
        ).read_text(encoding="utf-8"),
        "verify": (repo / "scripts/verify.sh").read_text(encoding="utf-8"),
        "requirements": (repo / "requirements.html").read_text(encoding="utf-8"),
        "hardening": (repo / "HARDENING_STATUS.md").read_text(encoding="utf-8"),
        "workspace": (
            repo / "scripts/verify-verifier-workspace.py"
        ).read_text(encoding="utf-8"),
    }


def run_mutations(sources: Dict[str, str]) -> None:
    for mutation in MUTATIONS:
        original = sources[mutation.source]
        count = original.count(mutation.old)
        if count != 1:
            raise VerificationError(
                "mutation target for {} occurs {} times".format(
                    mutation.label,
                    count,
                )
            )
        changed = dict(sources)
        changed[mutation.source] = original.replace(
            mutation.old,
            mutation.new,
            1,
        )
        try:
            validate(changed)
        except VerificationError:
            continue
        raise VerificationError("mutation was accepted: {}".format(mutation.label))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=pathlib.Path, default=pathlib.Path("."))
    parser.add_argument("--self-test", action="store_true")
    arguments = parser.parse_args()
    sources = load_sources(arguments.repo.resolve())
    validate(sources)
    if arguments.self_test:
        run_mutations(sources)
    print(
        "verify-android-frame-raw-generation: PASS"
        + (
            " ({} mutations rejected)".format(len(MUTATIONS))
            if arguments.self_test
            else ""
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, VerificationError) as error:
        raise SystemExit("verify-android-frame-raw-generation: {}".format(error))
