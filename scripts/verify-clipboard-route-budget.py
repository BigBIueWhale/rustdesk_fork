#!/usr/bin/env python3
"""Verify exact, bounded, connection-round-owned file-clipboard routing."""

from __future__ import annotations

import argparse
import ast
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
        raise VerificationError(f"missing start for {label}")
    finish = source.find(end, begin + len(start))
    if finish < 0:
        raise VerificationError(f"missing end for {label}")
    return source[begin:finish]


def load_sources(repo: Path) -> Dict[str, str]:
    paths = {
        "clipboard": "libs/clipboard/src/lib.rs",
        "windows": "libs/clipboard/src/platform/windows.rs",
        "fuse": "libs/clipboard/src/platform/unix/fuse/cs.rs",
        "client": "src/client/io_loop.rs",
        "connection": "src/server/connection.rs",
        "ui_cm": "src/ui_cm_interface.rs",
        "flutter_bridge": "src/flutter.rs",
        "windows_probe": "src/windows_cm_lifecycle_probe.rs",
        "server_model": "flutter/lib/models/server_model.dart",
        "model": "flutter/lib/models/model.dart",
        "server_model_test": "flutter/test/server_model_test.dart",
        "android_service": "flutter/android/app/src/main/kotlin/com/carriez/flutter_hbb/MainService.kt",
        "android_capture_owners": "flutter/android/app/src/main/kotlin/com/carriez/flutter_hbb/ControlledCaptureOwnerState.kt",
        "android_capture_test": "scripts/android-controlled-connection-type-test.kt",
        "requirements": "requirements.html",
        "hardening": "HARDENING_STATUS.md",
        "native_watch": "docs/NATIVE-CODEC-WATCH.md",
        "verify": "scripts/verify.sh",
        "apple": "scripts/apple-conform-check.sh",
        "workspace": "scripts/verify-verifier-workspace.py",
    }
    return {
        key: (repo / relative).read_text(encoding="utf-8")
        for key, relative in paths.items()
    }


def validate(sources: Dict[str, str]) -> None:
    clipboard = sources["clipboard"]
    client = sources["client"]
    connection = sources["connection"]
    ui_cm = sources["ui_cm"]
    flutter_bridge = sources["flutter_bridge"]
    server_model = sources["server_model"]
    model = sources["model"]
    android_service = sources["android_service"]
    android_capture_owners = sources["android_capture_owners"]

    for source, needle, label in (
        (clipboard, "UnboundedSender<ClipboardFile>", "unbounded file-clipboard sender"),
        (clipboard, "UnboundedReceiver<ClipboardFile>", "unbounded file-clipboard receiver"),
        (clipboard, "Arc<TokioMutex<UnboundedReceiver", "shared process-global receiver"),
        (clipboard, "struct MsgChannel", "legacy shared channel abstraction"),
        (clipboard, "VEC_MSG_CHANNEL", "legacy channel registry"),
        (clipboard, "get_rx_cliprdr_client", "reused viewer receiver API"),
        (clipboard, "get_rx_cliprdr_server", "reused controlled receiver API"),
        (clipboard, "remove_channel_by_conn_id", "identity-only stale cleanup API"),
        (clipboard, "get_client_conn_id", "legacy ambiguous viewer lookup"),
    ):
        forbid(source, needle, label)

    for needle, label in (
        ("const CLIPBOARD_FILE_EGRESS_WAKE_CAPACITY: usize = 1;", "one-slot wake"),
        ("const CLIPBOARD_FILE_EGRESS_MAX_MESSAGES: usize = 256;", "message-count ceiling"),
        (
            "const CLIPBOARD_FILE_EGRESS_MAX_MESSAGE_HEAP_BYTES: usize = hbb_common::cpace::MAX_SESSION_PACKET;",
            "individual retained-heap ceiling",
        ),
        ("hbb_common::cpace::MAX_SESSION_PACKET * 2", "two-message retained-heap ceiling"),
        (
            "std::mem::size_of::<QueuedClipboardFile>() * CLIPBOARD_FILE_EGRESS_MAX_MESSAGES",
            "fixed entry accounting",
        ),
        ("queue: VecDeque<QueuedClipboardFile>", "finite FIFO state"),
        ("queued_bytes: usize", "retained-byte state"),
        ("terminal: Option<ClipboardFileEgressFailure>", "typed terminal state"),
        ("receiver_open: bool", "receiver lifetime state"),
        ("mpsc::channel(CLIPBOARD_FILE_EGRESS_WAKE_CAPACITY)", "bounded wake constructor"),
    ):
        require(clipboard, needle, label)

    sizing = extract_braced_item(
        clipboard,
        "fn clipboard_file_heap_bytes(",
        "file-clipboard retained-heap sizing",
    )
    for needle, label in (
        ("r#type.capacity()", "notification type capacity"),
        ("title.capacity()", "notification title capacity"),
        ("text.capacity()", "notification text capacity"),
        (
            "checked_allocation_bytes::<(i32, String)>(format_list.capacity())",
            "format-list allocation capacity",
        ),
        ("format.capacity()", "nested format-name capacity"),
        ("format_data.capacity()", "format-data capacity"),
        ("requested_data.capacity()", "file-content capacity"),
        (
            "checked_allocation_bytes::<(String, u64)>(files.capacity())",
            "file-list allocation capacity",
        ),
        ("path.capacity()", "nested file-path capacity"),
    ):
        require(sizing, needle, label)
    for needle, label in (
        (".len()", "length-only heap accounting"),
        ("saturating_", "lossy heap accounting"),
    ):
        forbid(sizing, needle, label)

    sender = extract_between(
        clipboard,
        "impl ClipboardFileEgressSender {",
        "impl ClipboardFileEgressReceiver {",
        "file-clipboard producer",
    )
    wake = extract_braced_item(sender, "fn wake_receiver(", "nonblocking wake")
    require(wake, "self.wake.try_send(())", "nonblocking one-slot wake")
    require(wake, "TrySendError::Full(_)", "coalesced wake token")
    failure = extract_braced_item(sender, "fn fail_with_state(", "atomic terminal failure")
    require_order(
        failure,
        (
            "state.queue.clear();",
            "state.queued_bytes = 0;",
            "state.terminal = Some(failure);",
            "drop(state);",
            "self.wake_receiver()?;",
            "Err(ClipboardFileEgressAdmissionError::Failed(failure))",
        ),
        "terminal clear-before-wake finality",
    )
    send = extract_braced_item(sender, "fn send(", "checked file-clipboard admission")
    require_order(
        send,
        (
            "clipboard_file_heap_bytes(&data)",
            "heap_bytes > self.limits.max_message_heap_bytes",
            "heap_bytes.checked_add(std::mem::size_of::<QueuedClipboardFile>())",
            "state.queue.len().checked_add(1)",
            "next_count > self.limits.max_messages",
            "state.queued_bytes.checked_add(retained_bytes)",
            "next_bytes > self.limits.max_queued_bytes",
            "state.queue.push_back(QueuedClipboardFile {",
            "state.queued_bytes = next_bytes;",
            "self.wake_receiver()",
        ),
        "checked FIFO nonwaiting admission",
    )
    if send.count("return self.fail_with_state(") != 4:
        raise VerificationError("every guarded admission refusal must share one atomic terminal transition")
    for needle, label in (
        (".await", "awaiting synchronous producer"),
        ("blocking_send", "blocking synchronous producer"),
        ("saturating_", "lossy producer accounting"),
        ("tokio::spawn", "detached producer task"),
        ("Runtime::new", "nested producer runtime"),
        ("std::fs::", "filesystem I/O under producer ownership"),
    ):
        forbid(send, needle, label)

    receiver = extract_between(
        clipboard,
        "impl ClipboardFileEgressReceiver {",
        "impl Drop for ClipboardFileEgressReceiver {",
        "file-clipboard receiver",
    )
    require_order(
        receiver,
        (
            "if let Some(failure) = state.terminal.take()",
            "state.receiver_open = false;",
            "state.queue.pop_front()",
            "state.queued_bytes.checked_sub(queued.retained_bytes)",
            "ClipboardFileEgressItem::Message(queued.data)",
            "self.wake.recv().await",
        ),
        "terminal-first checked FIFO drain",
    )
    receiver_drop = extract_braced_item(
        clipboard,
        "impl Drop for ClipboardFileEgressReceiver",
        "receiver retirement",
    )
    require_order(
        receiver_drop,
        (
            "self.wake.close();",
            "state.receiver_open = false;",
            "state.queue.clear();",
            "state.queued_bytes = 0;",
            "state.terminal = None;",
        ),
        "receiver retirement releases retained state",
    )

    route = extract_between(
        clipboard,
        "enum ClipboardFileRouteOwner",
        "impl ClipboardFile {",
        "sender-only exact route registry",
    )
    for needle, label in (
        ("Viewer { peer_id: String }", "viewer route class"),
        ("Controlled", "controlled route class"),
        ("struct ClipboardFileRoute", "route record"),
        ("route_generation: u64", "route generation"),
        ("sender: ClipboardFileEgressSender", "sender-only route"),
        ("RwLock<Vec<ClipboardFileRoute>>", "route registry"),
        ("struct ClipboardFileRouteLease", "route lease"),
    ):
        require(route, needle, label)
    forbid(route, "ClipboardFileEgressReceiver", "receiver in global route registry")
    route_drop = extract_braced_item(
        clipboard,
        "impl Drop for ClipboardFileRouteLease",
        "generation-bound route cleanup",
    )
    require_order(
        route_drop,
        (
            "route.conn_id == self.conn_id",
            "route.route_generation == self.route_generation",
            "routes.remove(index);",
        ),
        "exact generation-bound route cleanup",
    )

    next_viewer = extract_braced_item(
        clipboard, "fn next_viewer_conn_id(", "viewer route identity allocation"
    )
    require(next_viewer, "lock.checked_sub(1)", "checked negative viewer IDs")
    require(next_viewer, "std::process::abort();", "viewer ID exhaustion finality")
    viewer_registration = extract_braced_item(
        clipboard, "pub fn register_cliprdr_viewer(", "fresh viewer route"
    )
    require_order(
        viewer_registration,
        (
            "next_viewer_conn_id()",
            "next_route_generation()",
            "clipboard_file_egress_channel()",
            "ClipboardFileRouteOwner::Viewer",
            "ClipboardFileRouteLease",
        ),
        "fresh viewer route and exact lease",
    )
    controlled_registration = extract_braced_item(
        clipboard, "pub fn register_cliprdr_controlled(", "exclusive controlled route"
    )
    require_order(
        controlled_registration,
        (
            "if conn_id <= 0",
            "let mut routes = CLIPBOARD_FILE_ROUTES.write().unwrap();",
            "routes.iter().any(|route| route.conn_id == conn_id)",
            "next_route_generation()",
            "clipboard_file_egress_channel()",
            "routes.push(ClipboardFileRoute {",
            "ClipboardFileRouteOwner::Controlled",
            "drop(routes);",
            "Ok((",
            "ClipboardFileRouteLease",
        ),
        "locked vacancy-before-resource controlled route admission",
    )

    runner_state = extract_braced_item(
        ui_cm, "struct IpcTaskRunner", "desktop CM IPC runner state"
    )
    forbid(runner_state, "running: bool", "ambiguous CM run/retry Boolean")
    require(ui_cm, "async fn run(&mut self) {", "single CM stream lifecycle signature")
    runner = extract_braced_item(
        ui_cm,
        "async fn run(&mut self)",
        "desktop CM IPC stream lifecycle",
    )
    require(
        runner,
        '"failed to register exact CM file-clipboard route for {}: {}",\n'
        "                                                    id,\n"
        "                                                    error\n"
        "                                                );\n"
        "                                                break;",
        "route-setup terminal finality",
    )
    require(
        runner,
        '"failed to publish CM file-clipboard readiness: {error}"\n'
        "                                            );\n"
        "                                            break;",
        "readiness-send terminal finality",
    )
    require(
        runner,
        'Ok(None) => {\n'
        '                            log::warn!("Rejected malformed data on CM IPC stream");\n'
        "                            break;\n"
        "                        }",
        "malformed CM frame terminal finality",
    )
    require_order(
        runner,
        (
            "let (mut _idle_clip_sender, mut rx_clip)",
            "let mut _cliprdr_route = None;",
            "loop {",
            "Data::Login",
            "if self.conn_id != 0",
            '"Rejected repeated CM login on connection {}: requested conn_id={}"',
            "validate_cm_connection_authority(",
            "if !authorized || !connection_authority.valid",
            "match clipboard::register_cliprdr_controlled(id)",
            '"failed to register exact CM file-clipboard route for {}: {}"',
            "break;",
            "if ContextSend::is_enabled()",
            "send(&Data::ClipboardFile(clipboard::ClipboardFile::MonitorReady))",
            '"failed to publish CM file-clipboard readiness: {error}"',
            "break;",
            "let client_owner = match self.cm.add_connection(",
            "Ok(owner) => owner,",
            '"Rejected CM client-registry admission for connection {}: {}"',
            "break;",
            "self.conn_id = id;",
            "self.client_owner = Some(client_owner);",
            "_cliprdr_route = Some(controlled_clip_route);",
            "continue;",
            "if let Some(owner) = self.client_owner.take()",
            "self.cm.remove_connection(owner, self.close);",
            "drop(_cliprdr_route);",
        ),
        "single-stream CM admission, active ownership, and terminal cleanup",
    )
    if runner.count("clipboard::register_cliprdr_controlled(id)") != 1:
        raise VerificationError("CM stream must have one controlled-route admission")
    require(runner, "if self.conn_id != 0", "repeated CM login refusal")
    if runner.count("self.cm.add_connection(") != 1:
        raise VerificationError("CM stream must have one client-registry commit")
    require(
        runner,
        "Ok(owner) => owner,",
        "checked client-registry admission",
    )
    forbid(runner, "self.running", "mutable CM run/retry state")
    forbid(runner, "CmIpcRunDisposition", "restartable CM run disposition")
    ipc_task = extract_braced_item(ui_cm, "async fn ipc_task(", "desktop CM IPC owner")
    require_order(
        ipc_task,
        (
            "let mut task_runner = Self {",
            "task_runner.run().await;",
            'log::debug!("ipc task end");',
        ),
        "single CM stream lifecycle owner",
    )
    forbid(ipc_task, "while task_runner.running", "implicit CM retry loop")
    forbid(ipc_task, "match task_runner.run().await", "restartable CM disposition loop")
    forbid(ipc_task, "loop {", "CM stream lifecycle restart loop")

    for needle, label in (
        ("pub registry_generation: i64,", "serialized CM client registry generation"),
        ("struct CmClientOwner {", "task-owned CM client lease"),
        ("struct CmClientRegistry {", "generation-owning CM client registry"),
        ("static ref CLIENTS: RwLock<CmClientRegistry>", "typed CM client registry"),
        ("#[serde(skip)]\n    source_generation: u64,", "nonserialized source generation"),
    ):
        require(ui_cm, needle, label)
    forbid(
        ui_cm,
        "static ref CLIENTS: RwLock<HashMap<i32, Client>>",
        "bare-ID process-global CM client registry",
    )
    registry = extract_braced_item(
        ui_cm, "impl CmClientRegistry", "CM client registry authority"
    )
    admission = extract_braced_item(
        registry, "fn admit(", "checked CM client registry admission"
    )
    require_order(
        admission,
        (
            "if client.id <= 0",
            "source_generation < current.source_generation",
            "CmClientAdmissionError::StaleSourceGeneration",
            "source_generation == current.source_generation && !current.disconnected",
            "CmClientAdmissionError::ActiveIdCollision",
            ".checked_add(1)",
            "CmClientAdmissionError::GenerationExhausted",
            "self.generation = generation;",
            "client.registry_generation = generation;",
            "client.source_generation = source_generation;",
            ".retain(|_, current| !(current.disconnected && current.peer_id == client.peer_id))",
            "self.clients.insert(client.id, client.clone())",
            "CmClientOwner {",
        ),
        "source-qualified checked CM client admission before exact-owner commit",
    )
    if admission.count("self.clients.insert(client.id, client.clone())") != 1:
        raise VerificationError("CM client admission must have one registry commit")
    retirement = extract_braced_item(
        registry, "fn retire(", "exact CM client retirement"
    )
    require_order(
        retirement,
        (
            "if !self.is_current(owner)",
            "return false;",
            "if close",
            "self.clients.remove(&owner.id);",
            "client.disconnected = true;",
        ),
        "stale-owner refusal before CM client retirement",
    )

    manager = extract_braced_item(
        ui_cm,
        "impl<T: InvokeUiCM> ConnectionManager<T>",
        "CM client lifecycle manager",
    )
    manager_add = extract_braced_item(
        manager, "fn add_connection(", "CM client lifecycle admission"
    )
    require_order(
        manager_add,
        (
            ".admit(&mut client, self.source_generation)?",
            "replaced.filter(|client| !client.disconnected)",
            "replaced.tx.send(Data::Close)",
            "self.ui_handler.add_connection(&client);",
            "Ok(owner)",
        ),
        "exact admission and displaced-owner close before UI publication",
    )
    manager_remove = extract_braced_item(
        manager, "fn remove_connection(", "exact CM client lifecycle cleanup"
    )
    require_order(
        manager_remove,
        (
            "if !CLIENTS.write().unwrap().retire(owner, close)",
            "return;",
            "try_empty_clipboard_files(ClipboardSide::Host, owner.id)",
            ".remove_connection(owner.id, owner.generation, close)",
        ),
        "stale cleanup refusal before client-scoped side effects",
    )
    manager_message = extract_braced_item(
        manager, "fn new_message(", "exact CM chat publication"
    )
    require_order(
        manager_message,
        (
            "is_current(owner)",
            ".new_message(owner.id, owner.generation, text)",
        ),
        "generation-bound CM chat publication",
    )
    manager_voice = extract_braced_item(
        manager, "fn update_voice_call(", "exact CM voice-state mutation"
    )
    require_order(
        manager_voice,
        (
            "current_mut(owner)",
            "client.incoming_voice_call = incoming;",
            "client.in_voice_call = active;",
            "client.clone()",
            "self.ui_handler.update_voice_call_state(&client);",
        ),
        "generation-bound CM voice-state mutation and unlocked publication",
    )
    disconnected_remove = extract_braced_item(
        ui_cm, "pub fn remove(id: i32)", "UI disconnected-client removal"
    )
    require_order(
        disconnected_remove,
        (
            ".map(|client| client.disconnected)",
            "clients.clients.remove(&id);",
        ),
        "bare-ID UI removal limited to disconnected entries",
    )

    require(runner_state, "client_owner: Option<CmClientOwner>", "desktop exact client owner")
    for needle, label in (
        ("self.cm.new_message(owner, text);", "desktop owner-bound chat"),
        ("self.cm.voice_call_started(owner);", "desktop owner-bound voice start"),
        ("self.cm.voice_call_incoming(owner);", "desktop owner-bound incoming voice"),
        ("self.cm.voice_call_closed(owner, reason.as_str());", "desktop owner-bound voice close"),
    ):
        require(runner, needle, label)
    android_listener = extract_braced_item(
        ui_cm,
        "pub async fn start_listen<T: InvokeUiCM>(",
        "Android CM client lifecycle owner",
    )
    require_order(
        android_listener,
        (
            "let mut current_owner = None;",
            "if current_owner.is_some()",
            '"Rejected repeated Android CM login',
            "if !authorized || !connection_authority.valid",
            '"Rejected Android CM login without matching authorized connection',
            "let owner = match cm.add_connection(",
            "Ok(owner) => owner,",
            "current_owner = Some(owner);",
            "cm.new_message(owner, text);",
            "cm.voice_call_started(owner);",
            "cm.voice_call_incoming(owner);",
            "cm.voice_call_closed(owner, reason.as_str());",
            "if let Some(owner) = current_owner",
            "cm.remove_connection(owner, true);",
        ),
        "Android exact client owner from admission through terminal cleanup",
    )
    forbid(
        android_listener,
        "cm.remove_connection(current_id, true)",
        "Android bare-ID terminal cleanup",
    )

    capture_state = extract_braced_item(
        android_capture_owners,
        "internal class ControlledCaptureOwnerState",
        "Android exact-generation controlled-resource registry",
    )
    for needle, label in (
        ("val registryGeneration: Long", "Android registry-generation owner field"),
        ("private val owners = mutableMapOf<Int, Owner>()", "Android exact owner map"),
        ("owners.values.any { it.requiresDesktopCapture }", "Android derived capture demand"),
        ("owners[connectionId]?.registryGeneration == registryGeneration", "Android exact current owner"),
    ):
        require(capture_state, needle, label)
    capture_admit = extract_braced_item(
        capture_state, "fun upsert(", "Android controlled-resource admission"
    )
    require_order(
        capture_admit,
        (
            "registryGeneration: Long",
            "connectionId <= 0 || registryGeneration <= 0",
            "registryGeneration <= current.registryGeneration",
            "return false",
            "owners[connectionId] = Owner(",
            "authorized && connectionType.requiresDesktopCapture",
        ),
        "Android monotonic exact-generation resource admission",
    )
    capture_retire = extract_braced_item(
        capture_state, "fun unregister(", "Android controlled-resource retirement"
    )
    require_order(
        capture_retire,
        (
            "if (!isCurrent(connectionId, registryGeneration))",
            "return false",
            "owners.remove(connectionId)",
        ),
        "Android exact-generation resource retirement",
    )
    kotlin_add = extract_braced_item(
        android_service, '"add_connection" ->', "Android service client admission"
    )
    require_order(
        kotlin_add,
        (
            'jsonObject.getLong("registry_generation")',
            "controlledCaptureOwners.upsert(",
            "registryGeneration",
            "VoiceCallAudioCoordinator.registerControlledConnection(",
            "onClientAuthorizedNotification",
        ),
        "Android registry generation before controlled-resource publication",
    )
    kotlin_remove = extract_braced_item(
        android_service, '"remove_connection" ->', "Android service client cleanup"
    )
    require_order(
        kotlin_remove,
        (
            "val registryGeneration = arg2.toLongOrNull()",
            "controlledCaptureOwners.unregister(id, registryGeneration)",
            '"Rejected stale controlled connection removal',
            "InputService.ctx?.retireInputOwner(",
            "VoiceCallAudioCoordinator.unregisterControlledConnection(",
            "reconcileControlledCaptureDemand()",
            "cancelNotification(id)",
        ),
        "Android stale cleanup refusal before all controlled-resource side effects",
    )
    kotlin_voice = extract_braced_item(
        android_service, '"update_voice_call_state" ->', "Android service voice update"
    )
    require_order(
        kotlin_voice,
        (
            'jsonObject.getLong("registry_generation")',
            "if (!controlledCaptureOwners.isCurrent(id, registryGeneration))",
            "return",
            "VoiceCallAudioCoordinator.setControlledVoiceCallActive(",
        ),
        "Android stale voice refusal before audio and notification side effects",
    )

    bridge_remove = extract_braced_item(
        flutter_bridge, "fn remove_connection(", "generation-bearing CM removal event"
    )
    require_order(
        bridge_remove,
        (
            "registry_generation: i64",
            "let registry_generation = registry_generation.to_string();",
            "Some(&registry_generation)",
            '"registry_generation"',
            "registry_generation.to_string()",
        ),
        "CM removal generation publication",
    )
    bridge_message = extract_braced_item(
        flutter_bridge,
        "fn new_message(&self, id: i32,",
        "generation-bearing CM chat event",
    )
    require_order(
        bridge_message,
        (
            "registry_generation: i64",
            '"registry_generation"',
            "registry_generation.to_string()",
        ),
        "CM chat generation publication",
    )
    android_channel = extract_braced_item(
        flutter_bridge, "pub fn start_channel(", "Android generation-bound CM channel"
    )
    require_order(
        android_channel,
        (
            "if service_generation == 0",
            "return;",
            "ConnectionManager::new(",
            "FlutterHandler { service_generation }",
            "service_generation,",
        ),
        "Android MainService generation becomes CM source authority",
    )
    require(
        sources["windows_probe"],
        "ConnectionManager::new(NoopConnectionManager, 0)",
        "desktop Windows probe source-generation isolation",
    )
    desktop_cm = extract_braced_item(
        flutter_bridge, "fn start_listen_ipc(new_thread: bool)", "desktop CM startup"
    )
    require_order(
        desktop_cm,
        (
            "let cm = ConnectionManager::new(",
            "FlutterHandler {",
            "},\n            0,\n        );",
        ),
        "desktop process-local CM source generation",
    )

    dart_add = extract_braced_item(
        server_model, "void addConnection(", "Dart CM client admission reconciliation"
    )
    require_order(
        dart_add,
        (
            "client.registryGeneration < _clients[index].registryGeneration",
            "return;",
            "dismissByTag(getLoginDialogTag(client.id))",
            "client.registryGeneration == current.registryGeneration",
            "_clients.removeAt(index);",
            "tabController.remove(index);",
            "_clients.add(client);",
            "_addTab(client);",
        ),
        "stale-event refusal and aligned newer-generation client/tab replacement",
    )
    dart_remove = extract_braced_item(
        server_model, "void onClientRemove(", "Dart exact-generation CM removal"
    )
    require_order(
        dart_remove,
        (
            "client.id == id &&",
            "client.registryGeneration == registryGeneration",
            "if (index < 0)",
            "return;",
            "_clients.removeAt(index);",
            "dismissByTag(getLoginDialogTag(id))",
        ),
        "Dart stale removal refusal before client and UI side effects",
    )
    dart_voice = extract_braced_item(
        server_model, "void updateVoiceCallState(", "Dart exact-generation CM voice update"
    )
    require(
        dart_voice,
        "element.registryGeneration == client.registryGeneration",
        "Dart exact-generation voice filter",
    )
    require(
        server_model,
        "bool ownsClientGeneration(int id, int registryGeneration)",
        "Dart current-generation query",
    )
    require(
        model,
        ".ownsClientGeneration(id, registryGeneration)",
        "Dart exact-generation chat filter",
    )
    for needle, label in (
        ("int registryGeneration = 0;", "Dart CM client generation field"),
        ("registryGeneration = json['registry_generation'];", "Dart CM generation decode"),
        ("data['registry_generation'] = registryGeneration;", "Dart CM generation encode"),
    ):
        require(server_model, needle, label)
    for test in (
        "r_s11iu_stale_owner_cannot_mutate_or_retire_a_reused_client_id",
        "r_s11iu_registry_rejects_stale_and_same_source_active_collisions",
        "r_s11iu_disconnected_owner_can_be_replaced_but_cannot_retire_replacement",
        "r_s11iu_generation_exhaustion_does_not_commit_a_client",
    ):
        require(ui_cm, test, f"{test} regression")
    require(
        sources["server_model_test"],
        "expect(serialized['registry_generation'], 19);",
        "Dart CM generation serialization regression",
    )
    for needle, label in (
        ("!owners.unregister(41, 10)", "Android stale same-ID cleanup regression"),
        (
            "!owners.upsert(41, 11, true, ControlledConnectionType.VIEW_CAMERA)",
            "Android duplicate same-ID replacement regression",
        ),
        (
            "!owners.upsert(41, 9, true, ControlledConnectionType.VIEW_CAMERA)",
            "Android stale same-ID replacement regression",
        ),
        ("owners.isCurrent(41, 11)", "Android exact current-owner regression"),
    ):
        require(sources["android_capture_test"], needle, label)

    sender_lookup = extract_braced_item(
        clipboard, "fn send_data_to_channel(", "sender snapshot before admission"
    )
    require_order(
        sender_lookup,
        (
            "CLIPBOARD_FILE_ROUTES",
            ".read()",
            ".map(|route| route.sender.clone())",
            ".ok_or_else(",
            "sender\n        .send(data)",
        ),
        "registry lock ends at sender snapshot",
    )
    for function in ("pub fn send_data_exclude(", "fn send_data_to_all("):
        broadcast = extract_braced_item(clipboard, function, "bounded sender broadcast")
        require_order(
            broadcast,
            (".map(|route| route.sender.clone())", ".collect::<Vec<_>>()", "sender.send(data.clone())"),
            "broadcast snapshots routes before admission",
        )
        require(broadcast, 'log::error!("file-clipboard broadcast route retired: {error}")', "visible broadcast refusal")

    for needle, label in (
        ("conn_id as UINT32", "Windows outbound opaque ID bit preservation"),
        ("conn_id = (*clip_format_list).connID as i32;", "Windows inbound viewer ID bit restoration"),
        ("conn_id = (*file_contents_response).connID as i32;", "Windows inbound file-response ID bit restoration"),
    ):
        require(sources["windows"], needle, label)

    for source, needles, label in (
        (
            client,
            (
                "clipboard::register_cliprdr_viewer(&self.handler.get_id())",
                "rx_clip_client = receiver;",
                "ClipboardFileEgressItem::Failed(failure)",
                "break;",
            ),
            "viewer round owns and retires its exact route",
        ),
        (
            connection,
            (
                '#[cfg(all(feature = "unix-file-copy-paste", not(target_os = "windows")))]',
                "clipboard::register_cliprdr_controlled(id)",
                "ClipboardFileEgressItem::Failed(failure)",
                "conn.on_close(",
                "break;",
            ),
            "Unix controlled round exact route and terminal finality",
        ),
        (
            ui_cm,
            (
                '#[cfg(target_os = "windows")]',
                "clipboard::register_cliprdr_controlled(id)",
                "ClipboardFileEgressItem::Failed(failure)",
                "break;",
            ),
            "Windows CM exact route and terminal finality",
        ),
    ):
        require_order(source, needles, label)
    forbid(
        connection,
        '#[cfg(feature = "unix-file-copy-paste")]\n        let (mut rx_clip',
        "Windows direct controlled route competing with CM",
    )

    for test in (
        "r_s11gz_file_clipboard_egress_is_fifo_and_releases_capacity",
        "r_s11gz_file_clipboard_egress_capacity_failure_is_terminal_and_clears_payloads",
        "r_s11gz_file_clipboard_egress_counts_retained_capacity_and_total_bytes",
        "r_s11gz_file_clipboard_egress_wakes_and_receiver_retirement_is_final",
        "r_s11gz_viewer_routes_are_fresh_negative_and_controlled_routes_are_disjoint",
    ):
        require(clipboard, test, f"{test} regression")
    for needle, label in (
        ("drop(sender);\n        assert!(receiver.recv().await.is_none());", "producer retirement regression"),
        ("assert!(!Arc::ptr_eq(&first_receiver.state, &second_receiver.state));", "fresh receiver regression"),
        ("assert!(register_cliprdr_controlled(controlled_id).is_err());", "duplicate controlled route regression"),
        ("crate::register_cliprdr_controlled(conn_id).unwrap();", "FUSE exact-route regression wiring"),
    ):
        require(clipboard if "FUSE" not in label else sources["fuse"], needle, label)

    gate_command = "python3 scripts/verify-clipboard-route-budget.py --repo . --self-test"
    for key, needle, label in (
        ("verify", gate_command, "shared focused gate"),
        (
            "verify",
            "cargo test -p clipboard --features unix-file-copy-paste --lib r_s11gz_ --color never",
            "shared Rust behavior gate",
        ),
        ("apple", gate_command, "Apple/shared focused gate"),
        ("requirements", '<div class="req"><span class="id">R-S11gz</span>', "normative requirement"),
        ("requirements", "<tr><td>361</td>", "Appendix C row"),
        ("hardening", "### R-S11gz/R-S11e-238 — exact bounded file-clipboard route ownership", "hardening ledger"),
        ("requirements", '<div class="req"><span class="id">R-S11it</span>', "CM route-setup finality requirement"),
        ("requirements", "<tr><td>405</td>", "CM route-setup Appendix C row"),
        ("hardening", "### R-S11it/R-S11e-283 — terminal CM stream and route-setup ownership", "CM route-setup hardening ledger"),
        (
            "verify",
            "cargo test --lib --features linux-pkg-config,flutter r_s11iu_ --color never",
            "shared CM registry Rust behavior gate",
        ),
        ("requirements", '<div class="req"><span class="id">R-S11iu</span>', "CM registry-generation requirement"),
        ("requirements", "<tr><td>406</td>", "CM registry-generation Appendix C row"),
        ("hardening", "### R-S11iu/R-S11e-284 — exact-generation CM client-registry ownership", "CM registry-generation hardening ledger"),
        ("workspace", "def validate_clipboard_route_budget_contract(sources):", "independent contract"),
        ("workspace", "validate_clipboard_route_budget_contract(sources)", "independent dispatch"),
    ):
        require(sources[key], needle, label)

    workspace_module = ast.parse(sources["workspace"])
    validate_sources_function = next(
        (
            node
            for node in workspace_module.body
            if isinstance(node, ast.FunctionDef) and node.name == "validate_sources"
        ),
        None,
    )
    if validate_sources_function is None:
        raise VerificationError("independent file-clipboard dispatch owner is absent")
    dispatches = [
        node
        for node in validate_sources_function.body
        if isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Name)
        and node.value.func.id == "validate_clipboard_route_budget_contract"
    ]
    if len(dispatches) != 1:
        raise VerificationError("independent file-clipboard dispatch must occur exactly once")

    requirements_digest = hashlib.sha256(sources["requirements"].encode("utf-8")).hexdigest()
    require(
        sources["hardening"],
        f"{requirements_digest}  requirements.html",
        "exact hardening requirements digest",
    )
    require(
        sources["native_watch"],
        f"Requirements hash: {requirements_digest}",
        "exact native-watch requirements digest",
    )


Mutation = Tuple[str, str, str, str]

MUTATIONS: Tuple[Mutation, ...] = (
    ("clipboard", "const CLIPBOARD_FILE_EGRESS_WAKE_CAPACITY: usize = 1;", "const CLIPBOARD_FILE_EGRESS_WAKE_CAPACITY: usize = 64;", "one-slot wake"),
    ("clipboard", "const CLIPBOARD_FILE_EGRESS_MAX_MESSAGES: usize = 256;", "const CLIPBOARD_FILE_EGRESS_MAX_MESSAGES: usize = usize::MAX;", "message ceiling"),
    ("clipboard", "hbb_common::cpace::MAX_SESSION_PACKET * 2", "hbb_common::cpace::MAX_SESSION_PACKET * 8", "retained-byte ceiling"),
    ("clipboard", "mpsc::channel(CLIPBOARD_FILE_EGRESS_WAKE_CAPACITY)", "mpsc::unbounded_channel()", "bounded wake"),
    ("clipboard", "r#type.capacity()", "r#type.len()", "notification capacity accounting"),
    ("clipboard", "checked_allocation_bytes::<(i32, String)>(format_list.capacity())", "format_list.len()", "format-list allocation accounting"),
    ("clipboard", "format_data.capacity()", "format_data.len()", "format-data capacity accounting"),
    ("clipboard", "requested_data.capacity()", "requested_data.len()", "file-content capacity accounting"),
    ("clipboard", "checked_allocation_bytes::<(String, u64)>(files.capacity())", "files.len()", "file-list allocation accounting"),
    ("clipboard", "self.wake.try_send(())", "self.wake.blocking_send(())", "nonblocking wake"),
    ("clipboard", "state.queue.clear();\n        state.queued_bytes = 0;\n        state.terminal = Some(failure);", "state.terminal = Some(failure);", "terminal payload release"),
    ("clipboard", "heap_bytes.checked_add(std::mem::size_of::<QueuedClipboardFile>())", "Some(heap_bytes)", "fixed entry accounting"),
    ("clipboard", "state.queue.len().checked_add(1)", "Some(state.queue.len() + 1)", "checked count"),
    ("clipboard", "next_count > self.limits.max_messages", "false", "count admission"),
    ("clipboard", "state.queued_bytes.checked_add(retained_bytes)", "Some(state.queued_bytes + retained_bytes)", "checked retained bytes"),
    ("clipboard", "next_bytes > self.limits.max_queued_bytes", "false", "byte admission"),
    ("clipboard", "state.queue.push_back(QueuedClipboardFile {", "state.queue.push_front(QueuedClipboardFile {", "FIFO admission"),
    ("clipboard", "state.queued_bytes.checked_sub(queued.retained_bytes)", "Some(state.queued_bytes)", "checked drain"),
    ("clipboard", "self.wake.close();", "// wake left open", "receiver retirement"),
    ("clipboard", "struct ClipboardFileRoute {", "struct MsgChannel {", "legacy abstraction exclusion"),
    ("clipboard", "sender: ClipboardFileEgressSender,", "receiver: ClipboardFileEgressReceiver,", "sender-only registry"),
    ("clipboard", "route.route_generation == self.route_generation", "true", "generation-bound cleanup"),
    ("clipboard", "lock.checked_sub(1)", "lock.checked_add(1)", "negative viewer identity"),
    ("clipboard", "if conn_id <= 0", "if false", "positive controlled identity"),
    ("clipboard", "routes.iter().any(|route| route.conn_id == conn_id)", "false", "exclusive controlled route"),
    (
        "clipboard",
        "    let mut routes = CLIPBOARD_FILE_ROUTES.write().unwrap();\n"
        "    if routes.iter().any(|route| route.conn_id == conn_id) {\n"
        "        return Err(CliprdrError::InvalidRequest {\n"
        "            description: format!(\n"
        "                \"controlled file-clipboard route already exists for connection {conn_id}\"\n"
        "            ),\n"
        "        });\n"
        "    }\n"
        "    let route_generation = next_route_generation();\n"
        "    let (sender, receiver) = clipboard_file_egress_channel();",
        "    let route_generation = next_route_generation();\n"
        "    let (sender, receiver) = clipboard_file_egress_channel();\n"
        "    let mut routes = CLIPBOARD_FILE_ROUTES.write().unwrap();\n"
        "    if routes.iter().any(|route| route.conn_id == conn_id) {\n"
        "        return Err(CliprdrError::InvalidRequest {\n"
        "            description: format!(\n"
        "                \"controlled file-clipboard route already exists for connection {conn_id}\"\n"
        "            ),\n"
        "        });\n"
        "    }",
        "controlled route resource allocation before vacancy",
    ),
    ("clipboard", ".map(|route| route.sender.clone())", ".map(|route| { route.sender.send(data.clone()).ok(); route.sender.clone() })", "sender snapshot"),
    ("windows", "conn_id = (*clip_format_list).connID as i32;", "conn_id = (*clip_format_list).connID as i16 as i32;", "Windows ID restoration"),
    ("client", "clipboard::register_cliprdr_viewer(&self.handler.get_id())", "clipboard::current_cliprdr_viewer_id(&self.handler.get_id())", "fresh viewer route"),
    ("client", "ClipboardFileEgressItem::Failed(failure)", "ClipboardFileEgressItem::Failed(_failure)", "viewer terminal finality"),
    ("connection", '#[cfg(all(feature = "unix-file-copy-paste", not(target_os = "windows")))]', '#[cfg(feature = "unix-file-copy-paste")]', "single Windows controlled owner"),
    ("connection", "clipboard::register_cliprdr_controlled(id)", "clipboard::clipboard_file_egress_channel()", "Unix exact controlled route"),
    ("ui_cm", "clipboard::register_cliprdr_controlled(id)", "clipboard::clipboard_file_egress_channel()", "Windows CM exact route"),
    (
        "ui_cm",
        "    close: bool,\n    conn_id: i32,",
        "    close: bool,\n    running: bool,\n    conn_id: i32,",
        "ambiguous CM run/retry Boolean",
    ),
    (
        "ui_cm",
        "async fn run(&mut self) {",
        "async fn run(&mut self) -> bool {",
        "single CM stream lifecycle",
    ),
    (
        "ui_cm",
        "if self.conn_id != 0",
        "if false",
        "repeated CM login refusal",
    ),
    (
        "ui_cm",
        '"failed to register exact CM file-clipboard route for {}: {}",\n'
        "                                                    id,\n"
        "                                                    error\n"
        "                                                );\n"
        "                                                break;",
        '"failed to register exact CM file-clipboard route for {}: {}",\n'
        "                                                    id,\n"
        "                                                    error\n"
        "                                                );\n"
        "                                                continue;",
        "route-setup terminal finality",
    ),
    (
        "ui_cm",
        '"failed to publish CM file-clipboard readiness: {error}"\n'
        "                                            );\n"
        "                                            break;",
        '"failed to publish CM file-clipboard readiness: {error}"\n'
        "                                            );\n"
        "                                            continue;",
        "readiness-send terminal finality",
    ),
    (
        "ui_cm",
        'Ok(None) => {\n'
        '                            log::warn!("Rejected malformed data on CM IPC stream");\n'
        "                            break;\n"
        "                        }",
        'Ok(None) => {\n'
        '                            log::warn!("Rejected malformed data on CM IPC stream");\n'
        "                            continue;\n"
        "                        }",
        "malformed CM frame terminal finality",
    ),
    (
        "ui_cm",
        "_cliprdr_route = Some(controlled_clip_route);",
        "drop(controlled_clip_route);",
        "route lease through terminal client cleanup",
    ),
    (
        "ui_cm",
        "let client_owner = match self.cm.add_connection(",
        "let client_owner = match self.cm.add_connection_bypassed(",
        "single client-registry commit",
    ),
    (
        "ui_cm",
        "Ok(owner) => owner,",
        "Ok(_owner) => return,",
        "checked client-registry activation",
    ),
    (
        "ui_cm",
        "        if let Some(owner) = self.client_owner.take() {\n"
        "            self.cm.remove_connection(owner, self.close);\n"
        "        }\n"
        "        #[cfg(target_os = \"windows\")]\n"
        "        drop(_cliprdr_route);",
        "        #[cfg(target_os = \"windows\")]\n"
        "        drop(_cliprdr_route);\n"
        "        if let Some(owner) = self.client_owner.take() {\n"
        "            self.cm.remove_connection(owner, self.close);\n"
        "        }",
        "client cleanup before route-lease release",
    ),
    (
        "ui_cm",
        "task_runner.run().await;",
        "loop { task_runner.run().await; }",
        "single CM stream lifecycle owner",
    ),
    (
        "ui_cm",
        "pub registry_generation: i64,",
        "pub registry_generation_disabled: i64,",
        "serialized CM client generation",
    ),
    (
        "ui_cm",
        "#[serde(skip)]\n    source_generation: u64,",
        "source_generation: u64,",
        "nonserialized client source generation",
    ),
    (
        "ui_cm",
        "static ref CLIENTS: RwLock<CmClientRegistry>",
        "static ref CLIENTS: RwLock<HashMap<i32, Client>>",
        "typed CM client registry",
    ),
    (
        "ui_cm",
        "source_generation < current.source_generation",
        "source_generation > current.source_generation",
        "stale Android service-source refusal",
    ),
    (
        "ui_cm",
        "source_generation == current.source_generation && !current.disconnected",
        "source_generation == current.source_generation && false",
        "same-source active ID collision refusal",
    ),
    (
        "ui_cm",
        ".generation\n            .checked_add(1)",
        ".generation\n            .wrapping_add(1)",
        "checked CM client generation",
    ),
    (
        "ui_cm",
        "client.registry_generation = generation;",
        "client.registry_generation = 0;",
        "CM client generation commit",
    ),
    (
        "ui_cm",
        "client.source_generation = source_generation;",
        "client.source_generation = 0;",
        "CM client source-generation commit",
    ),
    (
        "ui_cm",
        "if !self.is_current(owner) {",
        "if false {",
        "exact-owner CM client retirement",
    ),
    (
        "ui_cm",
        ".admit(&mut client, self.source_generation)?",
        ".admit(&mut client, 0)?",
        "source-qualified CM client admission",
    ),
    (
        "ui_cm",
        "replaced.tx.send(Data::Close)",
        "replaced.tx.send(Data::ClickTime(0))",
        "displaced active client closure",
    ),
    (
        "ui_cm",
        "if !CLIENTS.write().unwrap().retire(owner, close) {",
        "if false {",
        "stale terminal cleanup refusal",
    ),
    (
        "ui_cm",
        "if CLIENTS.read().unwrap().is_current(owner) {",
        "if true {",
        "exact-generation CM chat publication",
    ),
    (
        "ui_cm",
        "CLIENTS.write().unwrap().current_mut(owner)",
        "CLIENTS.write().unwrap().clients.get_mut(&owner.id)",
        "exact-generation CM voice mutation",
    ),
    (
        "ui_cm",
        ".map(|client| client.disconnected)",
        ".map(|_client| true)",
        "disconnected-only bare-ID UI removal",
    ),
    (
        "ui_cm",
        "client_owner: Option<CmClientOwner>,",
        "client_owner: Option<i32>,",
        "desktop task-owned CM client lease",
    ),
    (
        "ui_cm",
        "if current_owner.is_some() {",
        "if false {",
        "Android repeated Login refusal",
    ),
    (
        "ui_cm",
        "Rejected Android CM login without matching authorized connection",
        "Accepted Android CM login without matching authorized connection",
        "Android unauthorized Login refusal",
    ),
    (
        "ui_cm",
        "if let Some(owner) = current_owner {\n        cm.remove_connection(owner, true);",
        "if current_id > 0 {\n        cm.remove_connection_by_id(current_id, true);",
        "Android exact-owner terminal cleanup",
    ),
    (
        "android_capture_owners",
        "private val owners = mutableMapOf<Int, Owner>()",
        "private val owners = mutableMapOf<Int, Long>()",
        "Android exact controlled-resource owner map",
    ),
    (
        "android_capture_owners",
        "owners[connectionId]?.registryGeneration == registryGeneration",
        "owners.containsKey(connectionId)",
        "Android exact current controlled-resource owner",
    ),
    (
        "android_capture_owners",
        "connectionId <= 0 || registryGeneration <= 0",
        "connectionId <= 0",
        "Android valid controlled-resource generation",
    ),
    (
        "android_capture_owners",
        "registryGeneration <= current.registryGeneration",
        "registryGeneration < current.registryGeneration",
        "Android stale controlled-resource admission",
    ),
    (
        "android_capture_owners",
        "if (!isCurrent(connectionId, registryGeneration))",
        "if (false)",
        "Android exact controlled-resource retirement",
    ),
    (
        "android_service",
        "val registryGeneration = jsonObject.getLong(\"registry_generation\")",
        "val registryGeneration = 1L",
        "Android serialized client generation",
    ),
    (
        "android_service",
        "controlledCaptureOwners.upsert(",
        "controlledCaptureOwners.upsert_disabled(",
        "Android controlled-resource admission",
    ),
    (
        "android_service",
        "val registryGeneration = arg2.toLongOrNull()",
        "val registryGeneration = arg1.toLongOrNull()",
        "Android exact cleanup generation input",
    ),
    (
        "android_service",
        "controlledCaptureOwners.unregister(id, registryGeneration)",
        "true",
        "Android exact controlled-resource cleanup",
    ),
    (
        "android_service",
        "if (!controlledCaptureOwners.isCurrent(id, registryGeneration))",
        "if (false)",
        "Android exact voice-state update",
    ),
    (
        "flutter_bridge",
        "fn remove_connection(&self, id: i32, registry_generation: i64, close: bool)",
        "fn remove_connection(&self, id: i32, registry_generation: i32, close: bool)",
        "generation-bearing Flutter removal callback",
    ),
    (
        "flutter_bridge",
        "Some(&registry_generation)",
        "None",
        "registry-generation-bearing Android removal callback",
    ),
    (
        "flutter_bridge",
        "fn new_message(&self, id: i32, registry_generation: i64, text: String)",
        "fn new_message(&self, id: i32, registry_generation: i32, text: String)",
        "generation-bearing Flutter chat callback",
    ),
    (
        "flutter_bridge",
        "if service_generation == 0 {",
        "if false {",
        "Android zero service-generation refusal",
    ),
    (
        "flutter_bridge",
        "FlutterHandler { service_generation },\n            service_generation,",
        "FlutterHandler { service_generation },\n            0,",
        "Android CM source-generation binding",
    ),
    (
        "flutter_bridge",
        "},\n            0,\n        );",
        "},\n            1,\n        );",
        "desktop process-local CM generation",
    ),
    (
        "windows_probe",
        "ConnectionManager::new(NoopConnectionManager, 0)",
        "ConnectionManager::new(NoopConnectionManager, 1)",
        "Windows CM probe process-local generation",
    ),
    (
        "server_model",
        "client.registryGeneration < _clients[index].registryGeneration",
        "client.registryGeneration > _clients[index].registryGeneration",
        "Dart stale client-add refusal",
    ),
    (
        "server_model",
        "_clients.removeAt(index);\n          tabController.remove(index);\n          _clients.add(client);",
        "_clients[index] = client;\n          tabController.remove(index);\n          _clients.add(client);",
        "Dart client/tab replacement alignment",
    ),
    (
        "server_model",
        "client.registryGeneration == registryGeneration",
        "client.registryGeneration != registryGeneration",
        "Dart exact-generation client removal",
    ),
    (
        "server_model",
        "element.registryGeneration == client.registryGeneration",
        "true",
        "Dart exact-generation voice update",
    ),
    (
        "model",
        ".ownsClientGeneration(id, registryGeneration)",
        ".ownsClientGeneration(id, 0)",
        "Dart exact-generation chat update",
    ),
    (
        "server_model",
        "registryGeneration = json['registry_generation'];",
        "registryGeneration = 0;",
        "Dart CM generation decode",
    ),
    (
        "server_model_test",
        "expect(serialized['registry_generation'], 19);",
        "expect(serialized['registry_generation'], 0);",
        "Dart CM generation serialization regression",
    ),
    (
        "android_capture_test",
        "!owners.unregister(41, 10)",
        "owners.unregister(41, 10)",
        "Android stale same-ID cleanup regression",
    ),
    (
        "android_capture_test",
        "!owners.upsert(41, 11, true, ControlledConnectionType.VIEW_CAMERA)",
        "owners.upsert(41, 11, true, ControlledConnectionType.VIEW_CAMERA)",
        "Android duplicate same-ID replacement regression",
    ),
    (
        "android_capture_test",
        "!owners.upsert(41, 9, true, ControlledConnectionType.VIEW_CAMERA)",
        "owners.upsert(41, 9, true, ControlledConnectionType.VIEW_CAMERA)",
        "Android stale same-ID replacement regression",
    ),
    (
        "android_capture_test",
        "owners.isCurrent(41, 11)",
        "owners.isCurrent(41, 10)",
        "Android current same-ID owner regression",
    ),
    (
        "ui_cm",
        "r_s11iu_stale_owner_cannot_mutate_or_retire_a_reused_client_id",
        "r_s11iu_disabled_stale_owner_cannot_mutate_or_retire_a_reused_client_id",
        "stale CM owner regression",
    ),
    (
        "ui_cm",
        "r_s11iu_registry_rejects_stale_and_same_source_active_collisions",
        "r_s11iu_disabled_registry_rejects_stale_and_same_source_active_collisions",
        "CM source collision regression",
    ),
    (
        "ui_cm",
        "r_s11iu_disconnected_owner_can_be_replaced_but_cannot_retire_replacement",
        "r_s11iu_disabled_disconnected_owner_can_be_replaced_but_cannot_retire_replacement",
        "disconnected CM owner replacement regression",
    ),
    (
        "ui_cm",
        "r_s11iu_generation_exhaustion_does_not_commit_a_client",
        "r_s11iu_disabled_generation_exhaustion_does_not_commit_a_client",
        "CM registry generation-exhaustion regression",
    ),
    ("verify", "python3 scripts/verify-clipboard-route-budget.py --repo . --self-test", "true # file-clipboard route gate disabled", "shared gate"),
    ("apple", "python3 scripts/verify-clipboard-route-budget.py --repo . --self-test", "true # file-clipboard route gate disabled", "Apple gate"),
    ("requirements", '<div class="req"><span class="id">R-S11gz</span>', '<div class="req"><span class="id">R-S11gz-disabled</span>', "normative requirement"),
    ("requirements", "<tr><td>361</td>", "<tr><td>361-disabled</td>", "Appendix disposition"),
    ("hardening", "### R-S11gz/R-S11e-238 — exact bounded file-clipboard route ownership", "### R-S11gz-disabled/R-S11e-238 — exact bounded file-clipboard route ownership", "hardening ledger"),
    ("requirements", '<div class="req"><span class="id">R-S11it</span>', '<div class="req"><span class="id">R-S11it-disabled</span>', "CM route-setup requirement"),
    ("requirements", "<tr><td>405</td>", "<tr><td>405-disabled</td>", "CM route-setup Appendix disposition"),
    ("hardening", "### R-S11it/R-S11e-283 — terminal CM stream and route-setup ownership", "### R-S11it-disabled/R-S11e-283 — terminal CM stream and route-setup ownership", "CM route-setup ledger"),
    (
        "verify",
        "cargo test --lib --features linux-pkg-config,flutter r_s11iu_ --color never",
        "true # CM registry Rust gate disabled",
        "shared CM registry Rust behavior gate",
    ),
    ("requirements", '<div class="req"><span class="id">R-S11iu</span>', '<div class="req"><span class="id">R-S11iu-disabled</span>', "CM registry-generation requirement"),
    ("requirements", "<tr><td>406</td>", "<tr><td>406-disabled</td>", "CM registry-generation Appendix disposition"),
    ("hardening", "### R-S11iu/R-S11e-284 — exact-generation CM client-registry ownership", "### R-S11iu-disabled/R-S11e-284 — exact-generation CM client-registry ownership", "CM registry-generation ledger"),
    ("workspace", "    validate_cm_egress_budget_contract(sources)\n    validate_clipboard_route_budget_contract(sources)\n    validate_keyed_writer_budget_contract(sources)", "    validate_cm_egress_budget_contract(sources)\n    validate_clipboard_route_budget_contract_disabled(sources)\n    validate_keyed_writer_budget_contract(sources)", "independent dispatch"),
)


def run_self_test(sources: Dict[str, str]) -> None:
    for key, old, new, label in MUTATIONS:
        if old not in sources[key]:
            raise VerificationError(f"self-test fixture missing for {label}")
        mutated = dict(sources)
        mutated[key] = sources[key].replace(old, new, 1)
        try:
            validate(mutated)
        except (VerificationError, SyntaxError):
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
        print(f"File-clipboard route verifier self-test passed ({len(MUTATIONS)} mutations)")
    else:
        print("File-clipboard route verifier passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VerificationError as error:
        print(f"File-clipboard route verifier failed: {error}")
        raise SystemExit(1)
