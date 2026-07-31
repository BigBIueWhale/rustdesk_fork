#!/usr/bin/env python3
"""Validate exact-generation Android MainService status and explicit Stop."""

from __future__ import annotations

import argparse
import ast
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


def require_exact_count(source: str, token: str, count: int, label: str) -> None:
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
    behavior_test = sources["behavior_test"]
    service = sources["service"]
    activity = sources["activity"]
    clipboard = sources["clipboard"]
    verify = sources["verify"]
    requirements = sources["requirements"]
    hardening = sources["hardening"]
    workspace = sources["workspace"]

    require_order(
        owner,
        (
            "internal data class MainServiceStatus(",
            "val generation: Long",
            "val mediaProjectionReady: Boolean",
            "internal class MainServiceStatusOwner",
            "private var greatestGeneration = 0L",
            "private var activeGeneration: Long? = null",
            "private var mediaProjectionReady = false",
        ),
        "immutable status snapshot and serialized owner state",
    )
    for function in (
        "begin(generation: Long)",
        "setMediaProjectionReady(generation: Long, ready: Boolean)",
        "retire(generation: Long)",
        "snapshot(): MainServiceStatus?",
    ):
        require(
            owner,
            "@Synchronized\n    fun {}".format(function),
            "serialized status {}".format(function),
        )

    begin = extract(
        owner,
        "    fun begin(generation: Long): Boolean {",
        "\n    @Synchronized\n    fun setMediaProjectionReady",
        "status generation begin",
    )
    require_order(
        begin,
        (
            "generation <= 0L",
            "generation < greatestGeneration",
            "generation == greatestGeneration && activeGeneration != generation",
            "return false",
            "if (activeGeneration == generation)",
            "return true",
            "greatestGeneration = generation",
            "activeGeneration = generation",
            "mediaProjectionReady = false",
            "return true",
        ),
        "positive monotonic status generation begin",
    )
    readiness = extract(
        owner,
        "    fun setMediaProjectionReady(generation: Long, ready: Boolean): Boolean {",
        "\n    @Synchronized\n    fun retire",
        "status MediaProjection readiness",
    )
    require_order(
        readiness,
        (
            "generation <= 0L || activeGeneration != generation",
            "return false",
            "mediaProjectionReady = ready",
            "return true",
        ),
        "exact-generation status readiness update",
    )
    retire = extract(
        owner,
        "    fun retire(generation: Long): Boolean {",
        "\n    @Synchronized\n    fun snapshot",
        "status generation retirement",
    )
    require_order(
        retire,
        (
            "generation <= 0L || activeGeneration != generation",
            "return false",
            "activeGeneration = null",
            "mediaProjectionReady = false",
            "return true",
        ),
        "exact-generation status retirement",
    )
    snapshot = extract(
        owner,
        "    fun snapshot(): MainServiceStatus? {",
        "\n    }\n}",
        "status snapshot",
    )
    require_order(
        snapshot,
        (
            "val generation = activeGeneration ?: return null",
            "return MainServiceStatus(generation, mediaProjectionReady)",
        ),
        "active-generation immutable status snapshot",
    )

    for token, label in (
        ("fresh status owner published a service", "fresh-empty behavior"),
        ("unbound generation published MediaProjection readiness", "unbound refusal"),
        ("idempotent begin cleared current readiness", "idempotent preservation"),
        ("replacement generation inherited predecessor readiness", "replacement reset"),
        ("stale generation retired its replacement", "stale retirement refusal"),
        ("retired generation was reactivated", "retired reactivation refusal"),
    ):
        require(behavior_test, token, "status owner {}".format(label))
    require(
        behavior_test,
        "owner.snapshot() == MainServiceStatus(8, false)",
        "replacement status behavior assertion",
    )

    companion = extract(
        service,
        "    companion object {",
        "\n    private val logTag",
        "MainService status publication surface",
    )
    require_order(
        companion,
        (
            "private val statusOwner = MainServiceStatusOwner()",
            "internal fun currentStatus(): MainServiceStatus? = statusOwner.snapshot()",
        ),
        "read-only private MainService status publication",
    )
    for token, label in (
        ("_isReady", "generationless readiness companion"),
        ("_isStart", "generationless capture-start companion"),
        ("val isReady:", "generationless public readiness getter"),
        ("val isStart:", "generationless public capture getter"),
        ("fun destroy()", "duplicate Service teardown method"),
        ("stopSelf(", "bound-service self-stop path"),
    ):
        forbid(service, token, label)

    on_create = extract(
        service,
        "    override fun onCreate() {",
        "\n    override fun onDestroy()",
        "MainService creation",
    )
    require_order(
        on_create,
        (
            'nativeServerGeneration = FFI.startServer(this, configPath, "")',
            "if (nativeServerGeneration <= 0L)",
            "else if (!statusOwner.begin(nativeServerGeneration))",
            "VoiceCallAudioCoordinator.beginControlledServiceGeneration(",
            "acceptingControlledConnections = true",
        ),
        "native generation before status and controlled admission",
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
            "releaseControlledConnectionResources()",
            "statusOwner.retire(nativeServerGeneration)",
            "FFI.stopServer(nativeServerGeneration)",
            "FFI.releaseService(this)",
            "super.onDestroy()",
        ),
        "resource and status retirement before exact native release",
    )
    release_projection = extract(
        service,
        "    private fun releaseMediaProjection() {",
        "\n    @Synchronized\n    private fun installMediaProjection",
        "MediaProjection release",
    )
    require_order(
        release_projection,
        (
            "mediaProjection = null",
            "mediaProjectionCallback = null",
            "statusOwner.setMediaProjectionReady(nativeServerGeneration, false)",
            "projection.unregisterCallback(callback)",
            "it.stop()",
        ),
        "exact-generation readiness clear before projection release",
    )
    install_projection = extract(
        service,
        "    private fun installMediaProjection(projection: MediaProjection) {",
        "\n    @Synchronized\n    private fun onMediaProjectionStopped",
        "MediaProjection installation",
    )
    require_order(
        install_projection,
        (
            "projection.registerCallback(",
            "if (!statusOwner.setMediaProjectionReady(nativeServerGeneration, true))",
            "Rejected MediaProjection readiness from stale MainService generation",
            "releaseMediaProjection()",
            "return",
            "checkMediaPermission()",
            "if (captureRequested)",
            "startCapture()",
        ),
        "exact-generation readiness admission before capture resume",
    )
    stopped_projection = extract(
        service,
        "    private fun onMediaProjectionStopped(",
        "\n    @Synchronized\n    private fun releaseControlledConnectionResources",
        "MediaProjection stop callback",
    )
    require_order(
        stopped_projection,
        (
            "mediaProjection !== projection || mediaProjectionCallback !== callback",
            "return",
            "mediaProjection = null",
            "mediaProjectionCallback = null",
            "statusOwner.setMediaProjectionReady(nativeServerGeneration, false)",
            "stopCapturePipeline(keepReusableDisplay = false)",
            "checkMediaPermission()",
        ),
        "exact local projection and service-generation status invalidation",
    )
    permission = extract(
        service,
        "    fun checkMediaPermission(): Boolean {",
        "\n    private fun startRawVideoRecorder",
        "MainService MediaProjection status query",
    )
    require_order(
        permission,
        (
            "val ready = currentStatus()?.let {",
            "it.generation == nativeServerGeneration && it.mediaProjectionReady",
            "} == true",
            '"value" to ready.toString()',
            "return ready",
        ),
        "exact-service readiness observation",
    )
    forbid(service, "setCaptureStarted", "dead clipboard capture publication")
    forbid(clipboard, "isCaptureStarted", "dead clipboard capture status")
    forbid(clipboard, "setCaptureStarted", "dead clipboard capture status writer")

    configure = extract(
        activity,
        "    override fun configureFlutterEngine",
        "\n    override fun onResume",
        "MainActivity service observation",
    )
    require_order(
        configure,
        (
            "if (MainService.currentStatus() != null)",
            "bindMainService(createIfNeeded = false)",
        ),
        "passive bind cannot create MainService",
    )
    bind = extract(
        activity,
        "    private fun bindMainService(createIfNeeded: Boolean): Boolean {",
        "\n    private fun unbindMainService",
        "MainActivity service bind",
    )
    require_order(
        bind,
        (
            "val flags = if (createIfNeeded) Context.BIND_AUTO_CREATE else 0",
            "bindService(",
            "Intent(this, MainService::class.java)",
            "serviceConnection",
            "flags",
        ),
        "explicit-only auto-create binding",
    )
    require_exact_count(
        activity,
        "Context.BIND_AUTO_CREATE",
        1,
        "MainActivity auto-create binding authority",
    )
    unbind = extract(
        activity,
        "    private fun unbindMainService(): Boolean {",
        "\n    private val serviceConnection",
        "MainActivity service unbind",
    )
    require_order(
        unbind,
        (
            "if (!isServiceBound)",
            "return false",
            "unbindService(serviceConnection)",
            "isServiceBound = false",
            "mainService = null",
        ),
        "exact Activity binding retirement",
    )
    activity_destroy = extract(
        activity,
        "    override fun onDestroy() {",
        "\n    private fun bindMainService",
        "MainActivity destruction",
    )
    require_order(
        activity_destroy,
        (
            "activityFlutterMethodChannel = null",
            "unbindMainService()",
            "super.onDestroy()",
        ),
        "Activity teardown drops its service binding",
    )
    init_service = extract(
        activity,
        '                "init_service" -> {',
        '                "stop_service" -> {',
        "explicit MainService initialization",
    )
    require_order(
        init_service,
        (
            "val status = MainService.currentStatus()",
            "bindMainService(createIfNeeded = status == null)",
            "if (status?.mediaProjectionReady == true)",
            "result.success(false)",
            "requestMediaProjection()",
            "result.success(true)",
        ),
        "status-aware explicit initialization",
    )
    stop_service = extract(
        activity,
        '                "stop_service" -> {',
        '                "check_permission" -> {',
        "explicit MainService Stop",
    )
    require_order(
        stop_service,
        (
            "val stopped = stopService(Intent(this, MainService::class.java))",
            "val unbound = unbindMainService()",
            "result.success(stopped || unbound)",
        ),
        "platform stop before Activity binding retirement",
    )
    forbid(activity, ".destroy()", "Activity call to duplicate Service teardown")
    require_exact_count(
        activity,
        "stopService(Intent(this, MainService::class.java))",
        1,
        "single explicit platform service stop",
    )
    for token, label in (
        (
            "MainService.currentStatus()?.mediaProjectionReady == true",
            "unbound exact readiness query",
        ),
        (
            "MainService.currentStatus()?.mediaProjectionReady == true\n"
            "                            ).toString()",
            "UI status publication",
        ),
    ):
        require(activity, token, label)

    for token, label in (
        (
            "/usr/bin/python3 -I -S scripts/verify-android-main-service-status.py --repo . --self-test",
            "shared focused mutation gate",
        ),
        (
            "R-S11en/R-S11e-175 Android exact-generation service status and explicit-stop authority",
            "shared focused verdict",
        ),
        (
            "R-S14/R-S11ei/R-S11ek/R-S11em/R-S11en/R-S11eu/R-S11e-153/R-S11e-169/R-S11e-174/R-S11e-175/R-S11e-182/R-T4",
            "shared lifecycle integration label",
        ),
    ):
        require(verify, token, label)
    for token, label in (
        ('<span class="id">R-S11en</span>', "R-S11en requirement"),
        ("<tr><td>296</td>", "Appendix C #296"),
        (
            "stopping the started service does not actually stop it until all clients unbind",
            "Android platform lifecycle contract",
        ),
    ):
        require(requirements, token, label)
    require(
        hardening,
        "R-S11en/R-S11e-175 exact MainService status and explicit-stop lifecycle ownership",
        "hardening disposition",
    )
    for token, label in (
        (
            "validate_android_main_service_status_contract(sources)",
            "independent contract dispatch",
        ),
        (
            '"android_main_service_status_verifier": (\n'
            '                repo / "scripts/verify-android-main-service-status.py"',
            "independent focused-verifier source",
        ),
        (
            '"android_main_service_status_owner": (',
            "independent status-owner source",
        ),
        (
            "stale status generation retirement",
            "independent stale-retirement mutation",
        ),
    ):
        require(workspace, token, label)


MUTATIONS = (
    Mutation(
        "owner",
        "@Synchronized\n    fun begin(generation: Long)",
        "fun begin(generation: Long)",
        "serialized generation begin",
    ),
    Mutation(
        "owner",
        "@Synchronized\n    fun setMediaProjectionReady(generation: Long, ready: Boolean)",
        "fun setMediaProjectionReady(generation: Long, ready: Boolean)",
        "serialized readiness update",
    ),
    Mutation(
        "owner",
        "@Synchronized\n    fun retire(generation: Long)",
        "fun retire(generation: Long)",
        "serialized generation retirement",
    ),
    Mutation(
        "owner",
        "@Synchronized\n    fun snapshot(): MainServiceStatus?",
        "fun snapshot(): MainServiceStatus?",
        "serialized status snapshot",
    ),
    Mutation(
        "owner",
        "generation <= 0L ||\n            generation < greatestGeneration",
        "generation < greatestGeneration",
        "positive generation refusal",
    ),
    Mutation(
        "owner",
        "(generation == greatestGeneration && activeGeneration != generation)",
        "false",
        "retired generation refusal",
    ),
    Mutation(
        "owner",
        "        if (activeGeneration == generation) {\n            return true",
        "        if (false) {\n            return true",
        "idempotent active generation",
    ),
    Mutation(
        "owner",
        "        greatestGeneration = generation\n        activeGeneration = generation",
        "        activeGeneration = generation",
        "monotonic greatest generation",
    ),
    Mutation(
        "owner",
        "        activeGeneration = generation\n        mediaProjectionReady = false",
        "        activeGeneration = generation",
        "replacement readiness reset",
    ),
    Mutation(
        "owner",
        "fun setMediaProjectionReady(generation: Long, ready: Boolean): Boolean {\n"
        "        if (generation <= 0L || activeGeneration != generation)",
        "fun setMediaProjectionReady(generation: Long, ready: Boolean): Boolean {\n"
        "        if (generation <= 0L)",
        "exact readiness generation",
    ),
    Mutation(
        "owner",
        "        mediaProjectionReady = ready\n        return true",
        "        return true",
        "readiness state commit",
    ),
    Mutation(
        "owner",
        "fun retire(generation: Long): Boolean {\n"
        "        if (generation <= 0L || activeGeneration != generation)",
        "fun retire(generation: Long): Boolean {\n"
        "        if (generation <= 0L)",
        "exact retirement generation",
    ),
    Mutation(
        "owner",
        "        activeGeneration = null\n        mediaProjectionReady = false",
        "        mediaProjectionReady = false",
        "retirement deactivation",
    ),
    Mutation(
        "owner",
        "        activeGeneration = null\n        mediaProjectionReady = false",
        "        activeGeneration = null",
        "retirement readiness clear",
    ),
    Mutation(
        "owner",
        "val generation = activeGeneration ?: return null",
        "val generation = greatestGeneration",
        "active-only status snapshot",
    ),
    Mutation(
        "behavior_test",
        "stale generation retired its replacement",
        "stale retirement accepted",
        "stale retirement behavior regression",
    ),
    Mutation(
        "service",
        "private val statusOwner = MainServiceStatusOwner()",
        "internal val statusOwner = MainServiceStatusOwner()",
        "private status mutation authority",
    ),
    Mutation(
        "service",
        "else if (!statusOwner.begin(nativeServerGeneration))",
        "else if (!statusOwner.begin(1L))",
        "exact status generation begin",
    ),
    Mutation(
        "service",
        "statusOwner.retire(nativeServerGeneration)",
        "statusOwner.retire(1L)",
        "exact status generation retirement",
    ),
    Mutation(
        "service",
        "statusOwner.setMediaProjectionReady(nativeServerGeneration, true)",
        "statusOwner.setMediaProjectionReady(1L, true)",
        "exact MediaProjection readiness admission",
    ),
    Mutation(
        "service",
        "it.generation == nativeServerGeneration && it.mediaProjectionReady",
        "it.mediaProjectionReady",
        "exact-service readiness observation",
    ),
    Mutation(
        "service",
        "        captureActive = true\n        return true",
        "        captureActive = true\n        _isStart = true\n        return true",
        "generationless capture-start publication removal",
    ),
    Mutation(
        "clipboard",
        "class RdClipboardManager(private val clipboardManager: ClipboardManager) {",
        "class RdClipboardManager(private val clipboardManager: ClipboardManager) {\n"
        "    val isCaptureStarted = false",
        "dead clipboard capture status removal",
    ),
    Mutation(
        "activity",
        "bindMainService(createIfNeeded = false)",
        "bindMainService(createIfNeeded = true)",
        "passive bind cannot auto-create",
    ),
    Mutation(
        "activity",
        "val flags = if (createIfNeeded) Context.BIND_AUTO_CREATE else 0",
        "val flags = Context.BIND_AUTO_CREATE",
        "explicit-only auto-create binding",
    ),
    Mutation(
        "activity",
        "bindMainService(createIfNeeded = status == null)",
        "bindMainService(createIfNeeded = true)",
        "status-aware explicit bind",
    ),
    Mutation(
        "activity",
        "if (status?.mediaProjectionReady == true)",
        "if (status != null)",
        "readiness-specific consent skip",
    ),
    Mutation(
        "activity",
        "val stopped = stopService(Intent(this, MainService::class.java))",
        "val stopped = false",
        "platform service stop",
    ),
    Mutation(
        "activity",
        "val unbound = unbindMainService()\n                    result.success(stopped || unbound)",
        "val unbound = false\n                    result.success(stopped || unbound)",
        "explicit Stop binding retirement",
    ),
    Mutation(
        "activity",
        "activityFlutterMethodChannel = null\n\n        unbindMainService()",
        "activityFlutterMethodChannel = null",
        "Activity destruction binding retirement",
    ),
    Mutation(
        "verify",
        "/usr/bin/python3 -I -S scripts/verify-android-main-service-status.py --repo . --self-test",
        "true # Android MainService status gate removed",
        "shared focused mutation gate",
    ),
    Mutation(
        "requirements",
        '<span class="id">R-S11en</span>',
        '<span class="id">R-S11en-disabled</span>',
        "R-S11en requirement",
    ),
    Mutation(
        "requirements",
        "<tr><td>296</td>",
        "<tr><td>296-disabled</td>",
        "Appendix C #296",
    ),
    Mutation(
        "hardening",
        "R-S11en/R-S11e-175 exact MainService status and explicit-stop lifecycle ownership",
        "R-S11en/R-S11e-175 ambient MainService status ownership",
        "hardening disposition",
    ),
    Mutation(
        "workspace",
        '"android_main_service_status_verifier": (\n'
        '                repo / "scripts/verify-android-main-service-status.py"',
        '"android_main_service_status_verifier_disabled": (\n'
        '                repo / "scripts/verify-android-main-service-status.py"',
        "independent focused-verifier source",
    ),
)


def load_sources(repo: pathlib.Path) -> Dict[str, str]:
    package = (
        repo
        / "flutter/android/app/src/main/kotlin/com/carriez/flutter_hbb"
    )
    return {
        "owner": (package / "MainServiceStatusOwner.kt").read_text(encoding="utf-8"),
        "behavior_test": (
            repo / "scripts/android-main-service-status-test.kt"
        ).read_text(encoding="utf-8"),
        "service": (package / "MainService.kt").read_text(encoding="utf-8"),
        "activity": (package / "MainActivity.kt").read_text(encoding="utf-8"),
        "clipboard": (package / "RdClipboardManager.kt").read_text(encoding="utf-8"),
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
        "verify-android-main-service-status: PASS"
        + (
            " ({} mutations rejected)".format(len(MUTATIONS))
            if arguments.self_test
            else ""
        )
    )
    return 0


if __name__ == "__main__":
    try:
        ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"))
        raise SystemExit(main())
    except (OSError, SyntaxError, VerificationError) as error:
        raise SystemExit("verify-android-main-service-status: {}".format(error))
