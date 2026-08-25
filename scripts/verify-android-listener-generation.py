#!/usr/bin/env python3
"""Validate exact-generation ownership of Android listener rebuilds."""

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


def require_count(source: str, token: str, expected: int, label: str) -> None:
    observed = source.count(token)
    if observed != expected:
        raise VerificationError(
            "{} count is {}, expected {}: {!r}".format(
                label,
                observed,
                expected,
                token,
            )
        )


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
    main_service = sources["main_service"]
    kotlin_ffi = sources["kotlin_ffi"]
    rust_ffi = sources["rust_ffi"]
    direct = sources["direct"]
    verify = sources["verify"]
    desktop_ipc = sources["desktop_ipc"]
    requirements = sources["requirements"]
    hardening = sources["hardening"]
    workspace = sources["workspace"]

    lifecycle = extract(
        direct,
        "struct AndroidListenerLifecycle {",
        "\n}\n\n#[cfg(any(target_os = \"android\", test))]\nimpl AndroidListenerLifecycle {",
        "Android listener lifecycle state",
    )
    require_order(
        lifecycle,
        (
            "generation: u64",
            "rebuild_epoch: u64",
            "reserved: bool",
            "active: bool",
        ),
        "single listener lifecycle state",
    )
    require(
        direct,
        "static ANDROID_LISTENER_LIFECYCLE: Mutex<AndroidListenerLifecycle>",
        "serialized Android listener lifecycle",
    )
    forbid(direct, "LISTENER_REBUILD_EPOCH", "generationless rebuild epoch")
    forbid(direct, "ANDROID_SERVER_GENERATION", "separate server generation")
    forbid(
        direct,
        "request_direct_listener_rebuild(",
        "generationless listener rebuild API",
    )

    begin = extract(
        direct,
        "    fn begin_generation(&mut self) -> Option<u64> {",
        "\n    fn activate_generation(",
        "generation begin transition",
    )
    require_order(
        begin,
        (
            "if self.reserved || self.active",
            "return None",
            "let Some(next) = self.generation.checked_add(1) else",
            "self.reserved = false",
            "self.active = false",
            "return None",
            "if next > i64::MAX as u64",
            "self.reserved = false",
            "self.active = false",
            "return None",
            "self.generation = next",
            "self.rebuild_epoch = 0",
            "self.reserved = true",
            "self.active = false",
            "Some(next)",
        ),
        "checked inactive generation reservation",
    )

    activate = extract(
        direct,
        "    fn activate_generation(&mut self, expected_generation: u64) -> bool {",
        "\n    fn stop_generation(",
        "generation activation transition",
    )
    require_order(
        activate,
        (
            "!self.reserved",
            "self.active",
            "self.generation != expected_generation",
            "return false",
            "self.reserved = false",
            "self.active = true",
            "true",
        ),
        "exact reserved-to-active generation transition",
    )

    stop = extract(
        direct,
        "    fn stop_generation(&mut self, expected_generation: u64) -> bool {",
        "\n    fn request_rebuild(",
        "generation stop transition",
    )
    require_order(
        stop,
        (
            "(!self.reserved && !self.active)",
            "expected_generation == 0",
            "self.generation != expected_generation",
            "return false",
            "self.reserved = false",
            "self.active = false",
            "true",
        ),
        "exact generation deactivation",
    )

    rebuild = extract(
        direct,
        "    fn request_rebuild(&mut self, expected_generation: u64) -> Option<u64> {",
        "\n    fn snapshot(",
        "generation rebuild transition",
    )
    require_order(
        rebuild,
        (
            "!self.active",
            "expected_generation == 0",
            "self.generation != expected_generation",
            "return None",
            "let Some(next) = self.rebuild_epoch.checked_add(1) else",
            "self.active = false",
            "return None",
            "self.rebuild_epoch = next",
            "Some(next)",
        ),
        "exact checked fail-closed rebuild admission",
    )

    snapshot = extract(
        direct,
        "    fn snapshot(&self, expected_generation: u64) -> Option<u64> {",
        "\n    fn is_exact_inactive(",
        "generation and epoch snapshot",
    )
    require_order(
        snapshot,
        (
            "self.active",
            "expected_generation != 0",
            "self.generation == expected_generation",
            ".then_some(self.rebuild_epoch)",
        ),
        "atomic lifecycle snapshot",
    )
    exact_inactive = extract(
        direct,
        "    fn is_exact_inactive(&self, expected_generation: u64) -> bool {",
        "\n}\n\n#[cfg(target_os = \"android\")]",
        "exact inactive generation state",
    )
    require_order(
        exact_inactive,
        (
            "expected_generation != 0",
            "self.generation == expected_generation",
            "!self.reserved",
            "!self.active",
        ),
        "exact stopped-generation convergence state",
    )

    begin_api = extract(
        direct,
        "pub fn android_begin_generation() -> u64 {",
        "\n}\n\n/// R-S11hq: activate",
        "generation begin API",
    )
    activate_api = extract(
        direct,
        "pub fn android_activate_generation(expected_generation: u64) -> bool {",
        "\n}\n\n/// R-D7a: deactivate",
        "generation activation API",
    )
    stop_api = extract(
        direct,
        "pub fn android_request_stop(expected_generation: u64) -> bool {",
        "\n}\n\n/// Exact retirement used",
        "generation stop API",
    )
    converged_stop_api = extract(
        direct,
        "pub fn android_request_stop_or_confirm_inactive(expected_generation: u64) -> bool {",
        "\n}\n\n/// Read-only exact-generation health",
        "converged generation stop API",
    )
    health_api = extract(
        direct,
        "pub fn android_generation_is_active(expected_generation: u64) -> bool {",
        "\n}\n\n/// RAII worker-exit convergence",
        "generation health API",
    )
    worker_exit_api = extract(
        direct,
        "pub fn android_note_worker_exit(expected_generation: u64) -> bool {",
        "\n}\n\n/// R-T13/R-D7a:",
        "worker-exit convergence API",
    )
    rebuild_api = extract(
        direct,
        "pub fn android_request_listener_rebuild(expected_generation: u64, reason: &str) -> bool {",
        "\n}\n\n/// Return the rebuild epoch",
        "generation rebuild API",
    )
    lifecycle_snapshot = extract(
        direct,
        "fn android_listener_lifecycle_snapshot(expected_generation: u64) -> Option<u64> {",
        "\n}\n\n/// R-A4",
        "lifecycle snapshot API",
    )
    for body, transition, label in (
        (begin_api, "lifecycle.begin_generation()", "serialized begin"),
        (
            activate_api,
            "lifecycle.activate_generation(expected_generation)",
            "serialized activation",
        ),
        (
            stop_api,
            "lifecycle.stop_generation(expected_generation)",
            "serialized stop",
        ),
        (
            worker_exit_api,
            "lifecycle.stop_generation(expected_generation)",
            "serialized worker-exit convergence",
        ),
        (
            rebuild_api,
            "lifecycle.request_rebuild(expected_generation)",
            "serialized rebuild",
        ),
    ):
        require_order(
            body,
            (
                "ANDROID_LISTENER_LIFECYCLE.lock().unwrap()",
                transition,
            ),
            label,
        )
    require_order(
        converged_stop_api,
        (
            "ANDROID_LISTENER_LIFECYCLE.lock().unwrap()",
            "lifecycle.stop_generation(expected_generation)",
            "lifecycle.is_exact_inactive(expected_generation)",
            "true",
            "false",
        ),
        "serialized exact stop or already-inactive convergence",
    )
    require_order(
        health_api,
        (
            "ANDROID_LISTENER_LIFECYCLE",
            ".lock()",
            ".unwrap()",
            ".snapshot(expected_generation)",
            ".is_some()",
        ),
        "serialized active-generation health",
    )
    require_order(
        lifecycle_snapshot,
        (
            "ANDROID_LISTENER_LIFECYCLE",
            ".lock()",
            ".unwrap()",
            ".snapshot(expected_generation)",
        ),
        "serialized generation and epoch snapshot",
    )

    start_direct = extract(
        direct,
        "pub async fn start_direct_only(",
        "\n#[cfg_attr(not(target_os = \"android\"), allow(unused_variables))]",
        "Android direct listener worker",
    )
    require_order(
        start_direct,
        (
            "let direct_listener = tokio::spawn(async move",
            "let mut direct_listener = direct_listener",
            "tokio::select!",
            "outcome = &mut direct_listener",
            "if android_listener_lifecycle_snapshot(my_generation.get()).is_none()",
            "Android direct-listener task returned after exact generation deactivation",
            "Android direct-listener task failed after exact generation deactivation",
            "Android direct-listener task returned while its service worker was active",
            "Android direct-listener task failed while its service worker was active",
            "return",
            "_ = sleep(1.)",
            "android_listener_lifecycle_snapshot(my_generation.get()).is_none()",
        ),
        "terminal listener task observation and exact lifecycle poll",
    )

    server_loop = extract(
        direct,
        "async fn direct_server(server: ServerPtr, android_generation: Option<u64>) {",
        "\n// R-D4:",
        "direct listener loop",
    )
    listener_rebind = "                    listener = None;\n                    continue;"
    require_order(
        server_loop,
        (
            "let mut seen_rebuild_epoch = match android_listener_lifecycle_snapshot(my_generation)",
            "let rebuild_epoch = match android_listener_lifecycle_snapshot(my_generation)",
            "if rebuild_epoch != seen_rebuild_epoch",
            "seen_rebuild_epoch = rebuild_epoch",
            listener_rebind,
        ),
        "exact-generation listener rebuild",
    )
    require(
        verify,
        'rebind = "                    listener = None;\\n                    continue;"',
        "shared exact listener rebind selection",
    )
    forbid(
        verify,
        '< server_loop.index("listener = None;")',
        "shared generic first-occurrence listener rebind selection",
    )
    require(
        desktop_ipc,
        '    require(\n'
        '        start,\n'
        '        "if android_listener_lifecycle_snapshot(my_generation.get()).is_none() {",\n'
        '        "Android exact active-generation teardown",\n'
        '    )',
        "exact active-generation desktop lifecycle assertion",
    )
    require_count(
        desktop_ipc,
        "android_generation_current(my_generation)",
        1,
        "single stale desktop lifecycle generation token",
    )
    require(
        desktop_ipc,
        '    absent(\n'
        '        start,\n'
        '        "android_generation_current(my_generation)",\n'
        '        "obsolete Android generation teardown",\n'
        '    )',
        "stale desktop lifecycle generation refusal",
    )

    request = extract(
        main_service,
        "    private fun requestDirectListenerRebuild(reason: String) {",
        "\n    @Synchronized\n    private fun registerNetworkCallback()",
        "MainService rebuild callback",
    )
    require_order(
        request,
        (
            "val generation = nativeServerGeneration",
            "generation <= 0L",
            "FFI.rebuildDirectServerListener(generation)",
            "ignored network change from stale MainService generation",
            "Android network change admitted for MainService generation",
        ),
        "generation-bound Kotlin rebuild callback",
    )
    require(
        main_service,
        "@Volatile\n    private var nativeServerGeneration = 0L",
        "cross-thread visible native server generation",
    )
    destroy = extract(
        main_service,
        "    override fun onDestroy() {",
        "\n    override fun onTaskRemoved(",
        "MainService teardown",
    )
    require_order(
        destroy,
        (
            "releaseControlledConnectionResources()",
            'retireControlledServiceGeneration(generation, "MainService destruction")',
            "serviceLooper?.quitSafely()",
            "unregisterNetworkCallback()",
            "FFI.releaseService(this)",
            "super.onDestroy()",
        ),
        "stop-before-callback-drain teardown",
    )
    retirement = extract(
        main_service,
        "    private fun retireControlledServiceGenerationLocked(\n",
        "\n    override fun onCreate()",
        "MainService generation retirement",
    )
    require_order(
        retirement,
        (
            "acceptingControlledConnections = false",
            "serviceGenerationOwner.retire(generation)",
            "FFI.stopServer(this, retirement.generation)",
            "nativeServerGeneration = 0L",
        ),
        "exact listener retirement before local generation release",
    )
    require_count(
        retirement,
        "FFI.stopServer(this, retirement.generation)",
        1,
        "single exact listener stop",
    )

    require(
        kotlin_ffi,
        "external fun rebuildDirectServerListener(generation: Long): Boolean",
        "generation-bound Kotlin JNI declaration",
    )
    forbid(
        kotlin_ffi,
        "external fun rebuildDirectServerListener()",
        "generationless Kotlin JNI declaration",
    )
    jni = extract(
        rust_ffi,
        '    pub unsafe extern "system" fn Java_ffi_FFI_rebuildDirectServerListener(',
        '\n    #[no_mangle]\n    pub unsafe extern "system" fn Java_ffi_FFI_translateLocale(',
        "listener rebuild JNI",
    )
    require_order(
        jni,
        (
            "\n        generation: jlong,\n",
            ") -> jboolean",
            "u64::try_from(generation)",
            "jboolean::from(crate::direct_service::android_request_listener_rebuild(",
            "generation",
            '"android-network-change"',
        ),
        "generation-bound JNI admission",
    )

    for token, label in (
        (
            "stale_network_callback_cannot_advance_replacement_generation_epoch",
            "stale-callback behavior regression",
        ),
        (
            "invalid_or_exhausted_listener_lifecycle_transitions_fail_closed",
            "invalid/exhausted behavior regression",
        ),
        (
            "assert_eq!(lifecycle.request_rebuild(first), None);\n"
            "        assert_eq!(lifecycle.snapshot(replacement), Some(1));",
            "stale rebuild refusal and replacement preservation assertion",
        ),
        (
            "assert!(lifecycle.stop_generation(i64::MAX as u64));\n"
            "        assert_eq!(lifecycle.snapshot(i64::MAX as u64), None);\n\n"
            "        assert_eq!(lifecycle.begin_generation(), None);",
            "maximum-generation exact-stop assertion",
        ),
        (
            "assert_eq!(lifecycle.begin_generation(), None);\n"
            "        assert_eq!(lifecycle.snapshot(first), Some(1));",
            "active generation reservation refusal assertion",
        ),
        (
            "assert_eq!(lifecycle.begin_generation(), None);\n"
            "        assert!(!lifecycle.stop_generation(i64::MAX as u64));\n"
            "        assert_eq!(lifecycle.generation, i64::MAX as u64);\n"
            "        assert!(!lifecycle.reserved);\n"
            "        assert!(!lifecycle.active);\n"
            "        assert_eq!(lifecycle.snapshot(i64::MAX as u64), None);",
            "generation exhaustion deactivation assertion",
        ),
        (
            "assert_eq!(lifecycle.snapshot(reserved), None);\n"
            "        assert!(!lifecycle.activate_generation(reserved + 1));\n"
            "        assert!(lifecycle.stop_generation(reserved));\n"
            "        assert!(!lifecycle.activate_generation(reserved));",
            "reserved generation exact stop assertion",
        ),
        (
            "assert_eq!(lifecycle.request_rebuild(7), None);\n"
            "        assert_eq!(lifecycle.rebuild_epoch, u64::MAX);\n"
            "        assert!(!lifecycle.active);\n"
            "        assert_eq!(lifecycle.snapshot(7), None);",
            "rebuild exhaustion deactivation assertion",
        ),
    ):
        require(direct, token, label)

    for token, label in (
        (
            "direct_service::android_listener_lifecycle_tests:: -- --test-threads=1",
            "canonical lifecycle behavior gate",
        ),
        (
            "/usr/bin/python3 -I -S scripts/verify-android-listener-generation.py --repo . --self-test",
            "canonical focused gate",
        ),
        (
            "R-S11el/R-S11e-172 Android exact-generation listener rebuild authority",
            "shared gate verdict",
        ),
    ):
        require(verify, token, label)
    for token, label in (
        ('<span class="id">R-S11el</span>', "R-S11el requirement"),
        ("<tr><td>293</td>", "Appendix C #293"),
        ("<tr><td>294</td>", "Appendix C #294"),
    ):
        require(requirements, token, label)
    require(
        hardening,
        "R-S11el/R-S11e-172 exact MainService-generation Android listener rebuild ownership",
        "hardening disposition",
    )
    require(
        hardening,
        "R-S11el/R-S11e-173 Android listener lifecycle verifier integration",
        "verifier-integration hardening disposition",
    )
    for token, label in (
        (
            '"scripts/verify-android-listener-generation.py"',
            "independent focused-verifier source",
        ),
        (
            "R-S11el/R-S11e-172 exact MainService-generation Android listener rebuild ownership",
            "independent ledger binding",
        ),
        (
            "stale network callback generation",
            "independent stale-callback mutation",
        ),
    ):
        require(workspace, token, label)


MUTATIONS = (
    Mutation(
        "main_service",
        "@Volatile\n    private var nativeServerGeneration = 0L",
        "private var nativeServerGeneration = 0L",
        "cross-thread generation visibility",
    ),
    Mutation(
        "main_service",
        "FFI.rebuildDirectServerListener(generation)",
        "FFI.rebuildDirectServerListener(0L)",
        "Kotlin exact generation",
    ),
    Mutation(
        "main_service",
        "generation <= 0L || !FFI.rebuildDirectServerListener(generation)",
        "!FFI.rebuildDirectServerListener(generation)",
        "Kotlin invalid-generation refusal",
    ),
    Mutation(
        "main_service",
        "FFI.stopServer(this, retirement.generation)",
        "FFI.stopServer(this, 0L)",
        "exact teardown generation",
    ),
    Mutation(
        "main_service",
        "        releaseControlledConnectionResources()\n",
        "        // Controlled resources retained through callback drain.\n",
        "capture-before-listener teardown",
    ),
    Mutation(
        "main_service",
        "serviceLooper?.quitSafely()",
        "serviceLooper?.quit()",
        "stop-before-callback-drain order",
    ),
    Mutation(
        "kotlin_ffi",
        "external fun rebuildDirectServerListener(generation: Long): Boolean",
        "external fun rebuildDirectServerListener(): Unit",
        "Kotlin JNI generation contract",
    ),
    Mutation(
        "rust_ffi",
        '    pub unsafe extern "system" fn Java_ffi_FFI_rebuildDirectServerListener(\n'
        "        _env: JNIEnv,\n"
        "        _class: JClass,\n"
        "        generation: jlong,\n"
        "    ) -> jboolean {",
        '    pub unsafe extern "system" fn Java_ffi_FFI_rebuildDirectServerListener(\n'
        "        _env: JNIEnv,\n"
        "        _class: JClass,\n"
        "        _generation: jlong,\n"
        "    ) -> jboolean {",
        "JNI generation input",
    ),
    Mutation(
        "rust_ffi",
        '        log::debug!("R-T13 rebuildDirectServerListener from jvm");\n'
        "        let Ok(generation) = u64::try_from(generation)",
        '        log::debug!("R-T13 rebuildDirectServerListener from jvm");\n'
        "        let Ok(generation) = u64::try_from(1)",
        "JNI checked generation conversion",
    ),
    Mutation(
        "rust_ffi",
        "android_request_listener_rebuild(\n            generation,",
        "android_request_listener_rebuild(\n            1,",
        "JNI exact generation forwarding",
    ),
    Mutation(
        "direct",
        "static ANDROID_LISTENER_LIFECYCLE: Mutex<AndroidListenerLifecycle>",
        "static ANDROID_LISTENER_LIFECYCLE: AndroidListenerLifecycle",
        "serialized lifecycle",
    ),
    Mutation(
        "direct",
        "    fn request_rebuild(&mut self, expected_generation: u64) -> Option<u64> {\n"
        "        if !self.active || expected_generation == 0 || self.generation != expected_generation",
        "    fn request_rebuild(&mut self, expected_generation: u64) -> Option<u64> {\n"
        "        if !self.active || expected_generation == 0",
        "stale network callback generation",
    ),
    Mutation(
        "direct",
        "let Some(next) = self.rebuild_epoch.checked_add(1) else {",
        "let Some(next) = Some(self.rebuild_epoch.wrapping_add(1)) else {",
        "checked rebuild epoch",
    ),
    Mutation(
        "direct",
        "    fn begin_generation(&mut self) -> Option<u64> {\n"
        "        if self.reserved || self.active {\n"
        "            return None;\n"
        "        }\n"
        "        let Some(next) = self.generation.checked_add(1) else {",
        "    fn begin_generation(&mut self) -> Option<u64> {\n"
        "        if self.reserved || self.active {\n"
        "            return None;\n"
        "        }\n"
        "        let Some(next) = Some(self.generation.wrapping_add(1)) else {",
        "checked service-generation begin",
    ),
    Mutation(
        "direct",
        "if self.reserved || self.active",
        "if false",
        "single reserved or active listener generation",
    ),
    Mutation(
        "direct",
        "        self.reserved = false;\n"
        "        self.active = false;\n"
        "        true\n"
        "    }\n\n"
        "    fn request_rebuild",
        "        true\n"
        "    }\n\n"
        "    fn request_rebuild",
        "exact service-generation deactivation",
    ),
    Mutation(
        "direct",
        "(self.active && expected_generation != 0 && self.generation == expected_generation)",
        "(expected_generation != 0 && self.generation == expected_generation)",
        "snapshot active ownership",
    ),
    Mutation(
        "direct",
        "        self.rebuild_epoch = 0;\n"
        "        self.reserved = true;",
        "        self.reserved = true;",
        "per-generation rebuild epoch reset",
    ),
    Mutation(
        "direct",
        "let Some(next) = self.rebuild_epoch.checked_add(1) else {\n"
        "            self.active = false;",
        "let Some(next) = self.rebuild_epoch.checked_add(1) else {\n"
        "            return None;",
        "rebuild exhaustion deactivation",
    ),
    Mutation(
        "direct",
        "let Some(next) = self.generation.checked_add(1) else {\n"
        "            self.reserved = false;\n"
        "            self.active = false;",
        "let Some(next) = self.generation.checked_add(1) else {\n"
        "            self.reserved = false;\n"
        "            return None;",
        "generation exhaustion deactivation",
    ),
    Mutation(
        "direct",
        "        self.reserved = true;\n        self.active = false;",
        "        self.reserved = false;\n        self.active = true;",
        "inactive listener reservation",
    ),
    Mutation(
        "direct",
        "    fn activate_generation(&mut self, expected_generation: u64) -> bool {",
        "    fn activate_generation_disabled(&mut self, expected_generation: u64) -> bool {",
        "exact reserved listener activation",
    ),
    Mutation(
        "direct",
        "if next > i64::MAX as u64",
        "if next > u64::MAX",
        "Kotlin Long generation range",
    ),
    Mutation(
        "direct",
        "(self.active && expected_generation != 0 && self.generation == expected_generation)",
        "(self.active && expected_generation != 0)",
        "snapshot generation equality",
    ),
    Mutation(
        "direct",
        "lifecycle.request_rebuild(expected_generation)",
        "lifecycle.request_rebuild(lifecycle.generation)",
        "rebuild API forwarding",
    ),
    Mutation(
        "direct",
        "fn android_listener_lifecycle_snapshot(expected_generation: u64) -> Option<u64> {\n"
        "    ANDROID_LISTENER_LIFECYCLE\n"
        "        .lock()\n"
        "        .unwrap()\n"
        "        .snapshot(expected_generation)",
        "fn android_listener_lifecycle_snapshot(expected_generation: u64) -> Option<u64> {\n"
        "    ANDROID_LISTENER_LIFECYCLE\n"
        "        .lock()\n"
        "        .unwrap()\n"
        "        .snapshot(1)",
        "snapshot API forwarding",
    ),
    Mutation(
        "direct",
        "    fn is_exact_inactive(&self, expected_generation: u64) -> bool {",
        "    fn is_exact_inactive_disabled(&self, expected_generation: u64) -> bool {",
        "exact inactive-generation convergence",
    ),
    Mutation(
        "direct",
        "pub fn android_request_stop_or_confirm_inactive(expected_generation: u64) -> bool {",
        "pub fn android_request_stop_or_confirm_inactive_disabled(expected_generation: u64) -> bool {",
        "stop-after-worker-exit convergence API",
    ),
    Mutation(
        "direct",
        "pub fn android_generation_is_active(expected_generation: u64) -> bool {",
        "pub fn android_generation_is_active_disabled(expected_generation: u64) -> bool {",
        "active generation health API",
    ),
    Mutation(
        "direct",
        "pub fn android_note_worker_exit(expected_generation: u64) -> bool {",
        "pub fn android_note_worker_exit_disabled(expected_generation: u64) -> bool {",
        "terminal worker-exit convergence API",
    ),
    Mutation(
        "direct",
        "outcome = &mut direct_listener",
        "_outcome = std::future::pending::<()>()",
        "terminal listener task observation",
    ),
    Mutation(
        "direct",
        "outcome = &mut direct_listener => {\n"
        "                        if android_listener_lifecycle_snapshot(my_generation.get()).is_none()",
        "outcome = &mut direct_listener => {\n"
        "                        if false",
        "normal-stop versus active-worker terminal classification",
    ),
    Mutation(
        "direct",
        "let rebuild_epoch = match android_listener_lifecycle_snapshot(my_generation)",
        "let rebuild_epoch = seen_rebuild_epoch",
        "loop lifecycle snapshot",
    ),
    Mutation(
        "direct",
        "if rebuild_epoch != seen_rebuild_epoch",
        "if false",
        "rebuild epoch observation",
    ),
    Mutation(
        "direct",
        "                    listener = None;\n"
        "                    continue;",
        "                    // listener retained\n"
        "                    continue;",
        "listener rebind transition",
    ),
    Mutation(
        "verify",
        'rebind = "                    listener = None;\\n                    continue;"',
        'rebind = "listener = None;"',
        "shared exact listener rebind selection",
    ),
    Mutation(
        "desktop_ipc",
        '    require(\n'
        '        start,\n'
        '        "if android_listener_lifecycle_snapshot(my_generation.get()).is_none() {",\n'
        '        "Android exact active-generation teardown",\n'
        '    )',
        '    require(\n'
        '        start,\n'
        '        "if android_listener_lifecycle_snapshot(0).is_none() {",\n'
        '        "Android exact active-generation teardown",\n'
        '    )',
        "desktop exact active-generation assertion",
    ),
    Mutation(
        "desktop_ipc",
        '    absent(\n'
        '        start,\n'
        '        "android_generation_current(my_generation)",\n'
        '        "obsolete Android generation teardown",\n'
        '    )',
        '    require(\n'
        '        start,\n'
        '        "android_generation_current(my_generation)",\n'
        '        "obsolete Android generation teardown",\n'
        '    )',
        "desktop stale generation refusal",
    ),
    Mutation(
        "direct",
        "assert_eq!(lifecycle.request_rebuild(first), None);",
        "assert_eq!(lifecycle.request_rebuild(first), Some(3));",
        "stale callback regression",
    ),
    Mutation(
        "direct",
        "assert_eq!(lifecycle.request_rebuild(first), None);\n"
        "        assert_eq!(lifecycle.snapshot(replacement), Some(1));",
        "assert_eq!(lifecycle.request_rebuild(first), None);\n"
        "        assert_eq!(lifecycle.snapshot(replacement), None);",
        "replacement preservation regression",
    ),
    Mutation(
        "direct",
        "assert!(lifecycle.stop_generation(i64::MAX as u64));\n"
        "        assert_eq!(lifecycle.snapshot(i64::MAX as u64), None);",
        "assert!(!lifecycle.stop_generation(i64::MAX as u64));\n"
        "        assert_eq!(lifecycle.snapshot(i64::MAX as u64), None);",
        "maximum-generation exact-stop regression",
    ),
    Mutation(
        "verify",
        "direct_service::android_listener_lifecycle_tests:: -- --test-threads=1",
        "direct_service::disabled_android_listener_lifecycle_tests:: -- --test-threads=1",
        "canonical lifecycle behavior gate",
    ),
    Mutation(
        "verify",
        "/usr/bin/python3 -I -S scripts/verify-android-listener-generation.py --repo . --self-test",
        "true # exact Android listener-generation gate removed",
        "canonical focused gate",
    ),
    Mutation(
        "requirements",
        '<span class="id">R-S11el</span>',
        '<span class="id">R-S11el-disabled</span>',
        "R-S11el requirement",
    ),
    Mutation(
        "requirements",
        "<tr><td>293</td>",
        "<tr><td>293-disabled</td>",
        "Appendix C #293",
    ),
    Mutation(
        "requirements",
        "<tr><td>294</td>",
        "<tr><td>294-disabled</td>",
        "Appendix C #294",
    ),
    Mutation(
        "hardening",
        "R-S11el/R-S11e-172 exact MainService-generation Android listener rebuild ownership",
        "R-S11el/R-S11e-172 ambient Android listener rebuild ownership",
        "hardening disposition",
    ),
    Mutation(
        "hardening",
        "R-S11el/R-S11e-173 Android listener lifecycle verifier integration",
        "R-S11el/R-S11e-173 ambient Android listener lifecycle verification",
        "verifier-integration hardening disposition",
    ),
    Mutation(
        "workspace",
        '"scripts/verify-android-listener-generation.py"',
        '"scripts/verify-android-listener-generation-disabled.py"',
        "independent verifier source",
    ),
)


def load_sources(repo: pathlib.Path) -> Dict[str, str]:
    return {
        "main_service": (
            repo
            / "flutter/android/app/src/main/kotlin/com/carriez/flutter_hbb/MainService.kt"
        ).read_text(encoding="utf-8"),
        "kotlin_ffi": (
            repo / "flutter/android/app/src/main/kotlin/ffi.kt"
        ).read_text(encoding="utf-8"),
        "rust_ffi": (repo / "src/flutter_ffi.rs").read_text(encoding="utf-8"),
        "direct": (repo / "src/direct_service.rs").read_text(encoding="utf-8"),
        "verify": (repo / "scripts/verify.sh").read_text(encoding="utf-8"),
        "desktop_ipc": (
            repo / "scripts/verify-desktop-ipc-lifecycle.py"
        ).read_text(encoding="utf-8"),
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
        "verify-android-listener-generation: PASS"
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
        raise SystemExit("verify-android-listener-generation: {}".format(error))
