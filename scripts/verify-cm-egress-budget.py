#!/usr/bin/env python3
"""Verify closed, bounded connection-manager result ownership."""

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
        "ui_cm": "src/ui_cm_interface.rs",
        "connection": "src/server/connection.rs",
        "flutter": "src/flutter.rs",
        "ipc": "src/ipc.rs",
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
    ui_cm = sources["ui_cm"]
    connection = sources["connection"]
    flutter = sources["flutter"]

    for source, needle, label in (
        (ui_cm, "mpsc::unbounded_channel::<Data>()", "unbounded producer-to-CM IPC result queue"),
        (ui_cm, "tx: mpsc::UnboundedSender<Data>", "unbounded CM result sender field"),
        (ui_cm, "rx: mpsc::UnboundedReceiver<Data>", "unbounded CM result receiver field"),
        (connection, "mpsc::unbounded_channel::<ipc::Data>()", "unbounded CM-to-connection result queue"),
        (connection, "tx_from_cm: mpsc::UnboundedSender<ipc::Data>", "unbounded CM bridge result sender"),
        (flutter, "tx: UnboundedSender<crate::ipc::Data>", "unbounded Android CM result sender"),
    ):
        forbid(source, needle, label)
    for needle, label in (
        ("mpsc::unbounded_channel::<String>()", "unbounded CM file-job log queue"),
        ("UnboundedSender<String>", "unbounded CM file-job log sender"),
        ("tx_log", "detached CM file-job log producer"),
        ("rx_log", "detached CM file-job log consumer"),
    ):
        forbid(ui_cm, needle, label)

    for needle, label in (
        ("const CM_EGRESS_WAKE_CAPACITY: usize = 1;", "one-slot wake"),
        ("const CM_EGRESS_MAX_MESSAGES: usize = 256;", "message-count ceiling"),
        ("ipc::CM_IPC_MAX_FRAME_BYTES + ipc::CM_FILE_BLOCK_MAX_FRAME_BYTES", "combined individual-message ceiling"),
        ("CM_EGRESS_MAX_MESSAGE_BYTES * 2", "two-message retained-byte ceiling"),
        ("std::mem::size_of::<QueuedCmEgress>() * CM_EGRESS_MAX_MESSAGES", "fixed entry accounting"),
        ("queue: VecDeque<QueuedCmEgress>", "finite FIFO state"),
        ("queued_bytes: usize", "retained-byte state"),
        ("terminal: Option<CmEgressFailure>", "typed terminal state"),
        ("receiver_open: bool", "receiver lifetime state"),
    ):
        require(ui_cm, needle, label)
    if ui_cm.count("assert!(!waiting.is_finished());") != 2:
        raise VerificationError("both asynchronous CM receiver waits must remain pending before wake")
    require(
        sources["ipc"],
        "pub(crate) const CM_IPC_MAX_FRAME_BYTES: usize = 128 * 1024 * 1024;",
        "128 MiB structured CM frame ceiling",
    )
    require(
        sources["ipc"],
        "pub(crate) const CM_FILE_BLOCK_MAX_FRAME_BYTES: usize = 256 * 1024;",
        "256 KiB raw CM block ceiling",
    )

    channel = extract_braced_item(
        ui_cm,
        "fn cm_egress_channel_with_limits(",
        "CM egress channel constructor",
    )
    require_order(
        channel,
        (
            "StdMutex::new(CmEgressState::default())",
            "mpsc::channel(CM_EGRESS_WAKE_CAPACITY)",
            "state: Arc::clone(&state)",
            "wake,",
            "limits,",
        ),
        "shared bounded state and one-slot wake construction",
    )

    classification = extract_braced_item(
        ui_cm, "fn is_cm_egress_data(", "closed CM result vocabulary"
    )
    for needle, label in (
        ("Data::Close\n        | Data::ClickTime(_)", "close and click-time results"),
        ("Data::ClickTime(_)", "click-time result"),
        ("Data::CmErr(_)", "CM error result"),
        ("Data::ChatMessage { .. }", "chat result"),
        ("Data::CmFileResponse(_)", "typed file result"),
        ("Data::PrivacyModeState(_)", "privacy-state result"),
        ("Data::VoiceCallResponse(_)", "voice response"),
        ("Data::CloseVoiceCall(_)", "voice close"),
        ("Data::ClipboardFile(_)", "Windows file clipboard result"),
        ("_ => false", "closed default refusal"),
    ):
        require(classification, needle, label)
    forbid(classification, "Data::Disconnected", "ambient disconnect result")
    forbid(classification, "Data::FS", "untyped filesystem command in result direction")

    size_counter = extract_braced_item(
        ui_cm, "impl Write for CmEgressSizeCounter", "nonallocating size counter"
    )
    require_order(
        size_counter,
        (
            "self.bytes.checked_add(buf.len())",
            "self.failure = Some(CmEgressFailure::AccountingOverflow);",
            "if next > self.limit",
            "self.failure = Some(CmEgressFailure::MessageTooLarge);",
            "self.bytes = next;",
        ),
        "checked size counting with typed overflow and oversize failures",
    )

    sizing = extract_braced_item(
        ui_cm, "fn cm_egress_encoded_bytes(", "complete CM result sizing"
    )
    require_order(
        sizing,
        (
            "ipc::CmFileResponseKind::ReadBlock { data, .. } => data.len()",
            "raw_bytes > ipc::CM_FILE_BLOCK_MAX_FRAME_BYTES",
            "limit: limit.min(ipc::CM_IPC_MAX_FRAME_BYTES)",
            "serde_json::to_writer(&mut counter, data)",
            "counter.failure.unwrap_or(CmEgressFailure::Encoding)",
            ".checked_add(raw_bytes)",
            ".filter(|bytes| *bytes <= limit)",
        ),
        "structured plus serde-skipped raw-byte ownership",
    )
    for needle, label in (
        ("serde_json::to_vec", "allocated duplicate JSON sizing"),
        ("serde_json::to_string", "allocated duplicate string sizing"),
        ("saturating_add", "lossy size addition"),
    ):
        forbid(sizing, needle, label)

    sender = extract_between(
        ui_cm,
        "impl CmEgressSender {",
        "impl CmEgressReceiver {",
        "CM egress producer",
    )
    wake = extract_braced_item(sender, "fn wake_receiver(", "nonblocking CM wake")
    require(wake, "self.wake.try_send(())", "nonblocking one-slot wake")
    send = extract_braced_item(sender, "pub(crate) fn send(", "CM result admission")
    require_order(
        send,
        (
            "if !is_cm_egress_data(&data)",
            "if !state.receiver_open",
            "if let Some(failure) = state.terminal",
            "cm_egress_encoded_bytes(&data, self.limits.max_message_bytes)",
            "encoded_bytes.checked_add(std::mem::size_of::<QueuedCmEgress>())",
            "let mut state = lock_cm_egress(&self.state);",
            "state.queue.len().checked_add(1)",
            "next_count > self.limits.max_messages",
            "state.queued_bytes.checked_add(retained_bytes)",
            "next_bytes > self.limits.max_queued_bytes",
            "state.queue.push_back(QueuedCmEgress {",
            "state.queued_bytes = next_bytes;",
            "self.wake_receiver()",
        ),
        "precounted, checked, FIFO, nonwaiting admission",
    )
    if send.count("return self.fail_with_state(") != 4:
        raise VerificationError(
            "every in-guard count/byte refusal must use the inspected state guard"
        )
    for needle, label in (
        (".await", "awaiting synchronous admission"),
        ("blocking_send", "blocking synchronous admission"),
        ("std::thread::sleep", "sleeping synchronous admission"),
        ("tokio::spawn", "detached admission task"),
        ("Runtime::new", "nested admission runtime"),
        ("std::fs::", "filesystem I/O in admission"),
        ("saturating_", "lossy admission accounting"),
    ):
        forbid(send, needle, label)

    failure = extract_braced_item(
        sender, "fn fail_with_state(", "atomic CM terminal transition"
    )
    require_order(
        failure,
        (
            "if !state.receiver_open",
            "if let Some(existing) = state.terminal",
            "state.queue.clear();",
            "state.queued_bytes = 0;",
            "state.terminal = Some(failure);",
            "drop(state);",
            "self.wake_receiver()?;",
            "Err(CmEgressAdmissionError::Failed(failure))",
        ),
        "terminal clear-before-wake finality",
    )

    receiver = extract_between(
        ui_cm,
        "impl CmEgressReceiver {",
        "impl Drop for CmEgressReceiver {",
        "CM egress receiver",
    )
    require_order(
        receiver,
        (
            "if let Some(failure) = state.terminal.take()",
            "state.receiver_open = false;",
            "state.queue.clear();",
            "CmEgressItem::Failed(failure)",
            "state.queue.pop_front()",
            "state.queued_bytes.checked_sub(queued.retained_bytes)",
            "CmEgressItem::Data(queued.data)",
            "self.wake.recv().await",
        ),
        "terminal-first FIFO drain and checked byte release",
    )
    receiver_drop = extract_braced_item(
        ui_cm, "impl Drop for CmEgressReceiver", "CM receiver retirement"
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
        "receiver retirement closes and releases all retained state",
    )

    sender_lookup = extract_braced_item(
        ui_cm, "fn cm_egress_sender(", "single-connection sender snapshot"
    )
    require_order(
        sender_lookup,
        ("CLIENTS", ".read()", ".get(&id)", ".map(|client| client.tx.clone())"),
        "short registry lookup returns only a sender clone",
    )
    for signature, needle, label in (
        ("pub fn check_click_time(", "cm_egress_sender(id)", "click-time sender snapshot"),
        ("pub fn close(id:", "cm_egress_sender(id)", "close sender snapshot"),
        ("pub fn send_chat(", "cm_egress_sender(id)", "chat sender snapshot"),
        ("pub fn handle_incoming_voice_call(", "cm_egress_sender(id)", "voice sender snapshot"),
        ("pub fn close_voice_call(", "cm_egress_sender(id)", "voice-close sender snapshot"),
    ):
        body = extract_braced_item(ui_cm, signature, label)
        require(body, needle, label)
        forbid(body, "CLIENTS.read()", f"global registry held during {label}")

    ipc_task = extract_braced_item(ui_cm, "async fn ipc_task(", "desktop CM IPC task")
    require(
        ipc_task,
        "let (tx, rx) = cm_egress_channel();",
        "bounded producer-to-CM IPC mailbox",
    )
    ipc_runner = extract_braced_item(ui_cm, "async fn run(&mut self)", "desktop CM IPC runner")
    require_order(
        ipc_runner,
        (
            "Some(item) = self.rx.recv()",
            "CmEgressItem::Data(data) => data",
            "CmEgressItem::Failed(failure)",
            'log::error!("connection-manager output retired: {failure}");',
            "break;",
            "self.stream.send(&data).await",
        ),
        "first desktop hop terminates before IPC after mailbox failure",
    )
    handle_fs = extract_braced_item(
        ui_cm, "async fn handle_fs(", "exact-command CM file handler"
    )
    if handle_fs.count("\n    return_job_log: bool,\n") != 1:
        raise VerificationError(
            "exact-command CM file handler must expose one explicit direct-log policy"
        )
    require_order(
        handle_fs,
        (
            "return_job_log: bool,",
            ") -> Option<String>",
            "let mut job_log = None;",
            "match fs {",
            "job_log",
        ),
        "direct optional CM file-job log result",
    )
    if handle_fs.count("if return_job_log {") != 4:
        raise VerificationError(
            "every and only four terminal CM file-job paths must construct a direct log"
        )
    for needle, label in (
        (
            'job_log = Some(serialize_transfer_job(&job.job, false, true, ""));',
            "write/read cancellation log",
        ),
        (
            'job_log = Some(serialize_transfer_job(&job.job, true, false, ""));',
            "successful write-finality log",
        ),
        (
            "job_log = Some(serialize_transfer_job(&job.job, false, false, &err));",
            "failed write-finality log",
        ),
    ):
        require(handle_fs, needle, label)
    if handle_fs.count(
        'job_log = Some(serialize_transfer_job(&job.job, false, true, ""));'
    ) != 2:
        raise VerificationError("write and read cancellation must each return one direct log")
    for needle, label in (
        ("mpsc::", "channel use inside exact-command file handler"),
        ("tokio::spawn", "detached exact-command file-log work"),
        ("std::thread", "threaded exact-command file-log work"),
    ):
        forbid(handle_fs, needle, label)
    desktop_file_commands = extract_between(
        ipc_runner,
        "Data::AuthorizedFS { cm_auth_token, mut fs } => {",
        "Data::FS(_) => {",
        "desktop authorized file-command branch",
    )
    require_order(
        desktop_file_commands,
        (
            "let job_log = if let ipc::FS::WriteBlock",
            "handle_fs(",
            "true,",
            ".await",
            "if let Some(job_log) = job_log",
            'self.cm.ui_handler.file_transfer_log("transfer", &job_log);',
            "if !self.read_jobs.is_empty()",
        ),
        "exact desktop command-to-log presentation ordering",
    )
    if desktop_file_commands.count("handle_fs(") != 2:
        raise VerificationError(
            "desktop authorized file-command branch must have exactly two direct handler calls"
        )
    if desktop_file_commands.count("\n                                                true,\n") != 1:
        raise VerificationError("desktop raw-block command must request its direct log")
    if desktop_file_commands.count("\n                                            true,\n") != 1:
        raise VerificationError("desktop ordinary file command must request its direct log")
    forbid(
        desktop_file_commands,
        "\n                                            false,\n",
        "desktop file-command log omission",
    )
    forbid(ipc_runner, "rx_log.recv()", "select-driven CM file-job log drain")

    start = extract_braced_item(connection, "pub async fn start(", "controlled connection loop")
    require(
        start,
        "let (tx_from_cm_holder, mut rx_from_cm) = crate::ui_cm_interface::cm_egress_channel();",
        "bounded CM-to-connection mailbox",
    )
    require_order(
        start,
        (
            "Some(item) = rx_from_cm.recv()",
            "CmEgressItem::Data(data) => data",
            "CmEgressItem::Failed(failure)",
            "conn.on_close(&failure.to_string(), false).await;",
            "break;",
        ),
        "main connection terminates on CM mailbox failure",
    )
    port_forward = extract_braced_item(
        connection,
        "async fn try_port_forward_loop(",
        "sealed port-forward CM result loop",
    )
    require_order(
        port_forward,
        (
            "rx_from_cm: &mut crate::ui_cm_interface::CmEgressReceiver",
            "Some(item) = rx_from_cm.recv()",
            "CmEgressItem::Failed(failure)",
            "bail!(failure.to_string())",
        ),
        "port-forward connection terminates on CM mailbox failure",
    )
    require(
        connection,
        "tx_from_cm: crate::ui_cm_interface::CmEgressSender,",
        "desktop CM bridge sender type",
    )
    bridge = extract_braced_item(connection, "async fn start_ipc(", "desktop CM bridge")
    require_order(
        bridge,
        (
            "tx_from_cm: crate::ui_cm_interface::CmEgressSender",
            "tx_from_cm.send(ipc::Data::CmFileResponse(envelope))?;",
            "tx_from_cm.send(data)?;",
        ),
        "desktop CM bridge propagates result admission failure",
    )

    android_channel = extract_braced_item(
        flutter, "pub fn start_channel(", "Android CM result channel"
    )
    require_order(
        android_channel,
        (
            "tx: crate::ui_cm_interface::CmEgressSender",
            "use crate::ui_cm_interface::start_listen;",
            "std::thread::spawn(move || start_listen(cm, rx, terminal, tx))",
        ),
        "Android uses the shared bounded result mailbox",
    )
    android_listener = extract_braced_item(
        ui_cm, "pub async fn start_listen<", "Android connection manager listener"
    )
    require(
        android_listener,
        "tx: CmEgressSender",
        "Android listener bounded result sender type",
    )
    android_file_commands = extract_between(
        android_listener,
        "Some(Data::FS(fs)) => {",
        "Some(Data::Close) => {",
        "Android authorized file-command branch",
    )
    require_order(
        android_file_commands,
        (
            "Some(Data::FS(fs))",
            "let _ = handle_fs(",
            "CmFileResponder {",
            "false,",
            ".await;",
        ),
        "Android drops the direct optional log without a queue",
    )
    if android_file_commands.count("handle_fs(") != 1:
        raise VerificationError(
            "Android file-command branch must have exactly one direct handler call"
        )
    if android_file_commands.count("\n                    false,\n") != 1:
        raise VerificationError("Android file command must omit its direct log")
    forbid(
        android_file_commands,
        "\n                    true,\n",
        "Android file-command log construction",
    )

    for test in (
        "r_s11gy_cm_egress_is_fifo_and_releases_capacity_on_receive",
        "r_s11gy_cm_egress_capacity_and_wrong_class_are_terminal",
        "r_s11gy_cm_egress_encoded_byte_limits_are_terminal",
        "r_s11gy_cm_egress_accounts_serde_skipped_raw_blocks_and_receiver_retirement",
        "r_s11gy_cm_egress_wakes_without_polling_and_sender_retirement_closes",
        "r_s11ha_cm_file_job_log_is_returned_to_the_exact_command_owner",
        "r_s11ha_cm_file_job_log_can_be_omitted_without_retaining_the_job",
    ):
        require(ui_cm, test, f"deterministic {test} regression")
    for needle, label in (
        ("assert!(state.queue.is_empty());", "terminal payload-clear regression"),
        ("assert_eq!(state.queued_bytes, 0);", "terminal byte-clear regression"),
        ("structured_only + 64", "serde-skipped raw-byte regression"),
        ("CM_FILE_BLOCK_MAX_FRAME_BYTES + 1", "raw-block oversize regression"),
        ("assert!(!waiting.is_finished());", "asynchronous wait regression"),
        ("assert!(waiting.await.unwrap().is_none());", "producer-retirement regression"),
        ("Err(CmEgressAdmissionError::ReceiverGone)", "stale-sender regression"),
        ('terminal_log.get("cancel")', "direct terminal-log regression"),
        ("assert!(write_jobs.is_empty());", "terminal job-retirement regression"),
    ):
        require(ui_cm, needle, label)

    gate_command = "python3 scripts/verify-cm-egress-budget.py --repo . --self-test"
    for key, needle, label in (
        ("verify", gate_command, "shared focused gate"),
        ("verify", "cargo test --lib --features linux-pkg-config,flutter r_s11gy_ --color never", "shared Rust behavior gate"),
        ("verify", "cargo test --lib --features linux-pkg-config,flutter r_s11ha_ --color never", "shared direct-log behavior gate"),
        ("apple", gate_command, "Apple/shared focused gate"),
        ("requirements", '<div class="req"><span class="id">R-S11gy</span>', "normative CM egress requirement"),
        ("requirements", "<tr><td>360</td>", "Appendix C CM egress row"),
        ("requirements", '<div class="req"><span class="id">R-S11ha</span>', "normative direct-log requirement"),
        ("requirements", "<tr><td>362</td>", "Appendix C direct-log row"),
        ("hardening", "### R-S11gy/R-S11e-237 — bounded connection-manager result ownership", "hardening ledger entry"),
        ("hardening", "### R-S11ha/R-S11e-239 — exact-command CM file-job log ownership", "direct-log hardening ledger entry"),
        ("workspace", "def validate_cm_egress_budget_contract(sources):", "independent workspace contract"),
        ("workspace", "validate_cm_egress_budget_contract(sources)", "independent workspace dispatch"),
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
        raise VerificationError("independent CM-egress dispatch owner is absent")
    dispatches = [
        node
        for node in validate_sources_function.body
        if isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Name)
        and node.value.func.id == "validate_cm_egress_budget_contract"
    ]
    if len(dispatches) != 1:
        raise VerificationError("independent CM-egress dispatch must occur exactly once")

    requirements_digest = hashlib.sha256(
        sources["requirements"].encode("utf-8")
    ).hexdigest()
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
    ("ui_cm", "const CM_EGRESS_WAKE_CAPACITY: usize = 1;", "const CM_EGRESS_WAKE_CAPACITY: usize = 64;", "bounded wake"),
    ("ui_cm", "const CM_EGRESS_MAX_MESSAGES: usize = 256;", "const CM_EGRESS_MAX_MESSAGES: usize = usize::MAX;", "count ceiling"),
    ("ui_cm", "CM_EGRESS_MAX_MESSAGE_BYTES * 2", "CM_EGRESS_MAX_MESSAGE_BYTES * 8", "byte ceiling"),
    ("ui_cm", "queue: VecDeque<QueuedCmEgress>,", "queue: Vec<QueuedCmEgress>,", "FIFO state"),
    ("ui_cm", "terminal: Option<CmEgressFailure>,", "terminal: Option<String>,", "typed terminal"),
    ("ui_cm", "mpsc::channel(CM_EGRESS_WAKE_CAPACITY)", "mpsc::unbounded_channel()", "bounded constructor"),
    ("ui_cm", "Data::Close\n        | Data::ClickTime(_)", "Data::ClickTime(_)", "close vocabulary"),
    ("ui_cm", "Data::CmFileResponse(_)", "Data::FS(_)\n        | Data::CmFileResponse(_)", "closed result vocabulary"),
    ("ui_cm", "_ => false,", "_ => true,", "closed default refusal"),
    ("ui_cm", "self.bytes.checked_add(buf.len())", "Some(self.bytes + buf.len())", "checked size counter"),
    ("ui_cm", "self.failure = Some(CmEgressFailure::AccountingOverflow);", "self.failure = Some(CmEgressFailure::Encoding);", "typed size overflow"),
    ("ui_cm", "ipc::CmFileResponseKind::ReadBlock { data, .. } => data.len()", "ipc::CmFileResponseKind::ReadBlock { .. } => 0", "raw-byte accounting"),
    ("ui_cm", "raw_bytes > ipc::CM_FILE_BLOCK_MAX_FRAME_BYTES", "false", "raw-block ceiling"),
    ("ui_cm", "limit: limit.min(ipc::CM_IPC_MAX_FRAME_BYTES)", "limit", "structured ceiling"),
    ("ui_cm", "serde_json::to_writer(&mut counter, data)", "serde_json::to_vec(data)", "nonallocating sizing"),
    ("ui_cm", ".checked_add(raw_bytes)", ".saturating_add(raw_bytes)", "checked raw addition"),
    ("ui_cm", "if !is_cm_egress_data(&data)", "if false && !is_cm_egress_data(&data)", "wrong-class refusal"),
    ("ui_cm", "encoded_bytes.checked_add(std::mem::size_of::<QueuedCmEgress>())", "Some(encoded_bytes)", "fixed entry addition"),
    ("ui_cm", "state.queue.len().checked_add(1)", "Some(state.queue.len() + 1)", "checked count"),
    ("ui_cm", "next_count > self.limits.max_messages", "false", "count admission"),
    ("ui_cm", "state.queued_bytes.checked_add(retained_bytes)", "Some(state.queued_bytes + retained_bytes)", "checked retained bytes"),
    ("ui_cm", "next_bytes > self.limits.max_queued_bytes", "false", "byte admission"),
    ("ui_cm", "state.queue.push_back(QueuedCmEgress {", "state.queue.push_front(QueuedCmEgress {", "FIFO admission"),
    ("ui_cm", "fn fail_with_state(", "fn fail_after_relock(", "atomic terminal owner"),
    ("ui_cm", "state.queue.clear();\n        state.queued_bytes = 0;\n        state.terminal = Some(failure);", "state.terminal = Some(failure);", "terminal clears retained work"),
    ("ui_cm", "state.terminal = Some(failure);\n        drop(state);\n        self.wake_receiver()?;", "state.terminal = Some(failure);\n        self.wake_receiver()?;", "unlock before wake"),
    ("ui_cm", "if let Some(failure) = state.terminal.take()", "if false && state.terminal.is_some()", "terminal-first receiver"),
    ("ui_cm", "state.queue.pop_front()", "state.queue.pop_back()", "FIFO drain"),
    ("ui_cm", "state.queued_bytes.checked_sub(queued.retained_bytes)", "Some(state.queued_bytes)", "checked drain subtraction"),
    ("ui_cm", "self.wake.close();", "// wake left open", "receiver retirement"),
    ("ui_cm", ".map(|client| client.tx.clone())", ".map(|client| { client.tx.send(Data::Close).ok(); client.tx.clone() })", "sender-only registry snapshot"),
    ("ui_cm", "let (tx, rx) = cm_egress_channel();", "let (tx, rx) = mpsc::unbounded_channel::<Data>();", "first desktop hop"),
    ("ui_cm", "CmEgressItem::Failed(failure) => {\n                            log::error!(\"connection-manager output retired: {failure}\");\n                            break;", "CmEgressItem::Failed(failure) => {\n                            log::error!(\"{failure}\");\n                            continue;", "first-hop finality"),
    ("connection", "crate::ui_cm_interface::cm_egress_channel();", "mpsc::unbounded_channel::<ipc::Data>();", "second desktop hop"),
    ("connection", "CmEgressItem::Failed(failure) => {\n                            conn.on_close(&failure.to_string(), false).await;\n                            break;", "CmEgressItem::Failed(_failure) => {\n                            continue;", "main connection finality"),
    ("connection", "CmEgressItem::Failed(failure) => {\n                                bail!(failure.to_string());", "CmEgressItem::Failed(_failure) => {\n                                continue;", "port-forward finality"),
    ("connection", "tx_from_cm.send(ipc::Data::CmFileResponse(envelope))?;", "let _ = tx_from_cm.send(ipc::Data::CmFileResponse(envelope));", "raw result failure propagation"),
    ("connection", "tx_from_cm.send(data)?;", "let _ = tx_from_cm.send(data);", "ordinary result failure propagation"),
    ("flutter", "tx: crate::ui_cm_interface::CmEgressSender,", "tx: UnboundedSender<crate::ipc::Data>,", "Android bounded sender"),
    ("ui_cm", "fn r_s11gy_cm_egress_is_fifo_and_releases_capacity_on_receive", "fn cm_results_may_reorder", "FIFO regression"),
    ("ui_cm", "fn r_s11gy_cm_egress_capacity_and_wrong_class_are_terminal", "fn capacity_is_advisory", "terminal regression"),
    ("ui_cm", "structured_only + 64", "structured_only", "raw-byte regression"),
    ("ui_cm", "CM_FILE_BLOCK_MAX_FRAME_BYTES + 1", "CM_FILE_BLOCK_MAX_FRAME_BYTES", "raw oversize regression"),
    ("ui_cm", "assert!(!waiting.is_finished());", "assert!(waiting.is_finished());", "asynchronous wake regression"),
    ("ui_cm", "        self.running = false;", "        let (_tx_log, mut rx_log) = mpsc::unbounded_channel::<String>();\n        self.running = false;", "unbounded file-job log queue absence"),
    ("ui_cm", "    return_job_log: bool,", "    _return_job_log: bool,", "direct file-job log policy"),
    ("ui_cm", "    let mut job_log = None;", "    let job_log = None;", "owned direct file-job log result"),
    ("ui_cm", 'job_log = Some(serialize_transfer_job(&job.job, false, true, ""));', 'let _ = serialize_transfer_job(&job.job, false, true, "");', "cancellation log ownership"),
    ("ui_cm", 'job_log = Some(serialize_transfer_job(&job.job, true, false, ""));', 'let _ = serialize_transfer_job(&job.job, true, false, "");', "completion log ownership"),
    ("ui_cm", "job_log = Some(serialize_transfer_job(&job.job, false, false, &err));", "let _ = serialize_transfer_job(&job.job, false, false, &err);", "error log ownership"),
    ("ui_cm", "if let Some(job_log) = job_log {\n                                        self.cm.ui_handler.file_transfer_log(\"transfer\", &job_log);", "if false && job_log.is_some() {\n                                        self.cm.ui_handler.file_transfer_log(\"transfer\", job_log.as_deref().unwrap_or_default());", "desktop direct-log consumption"),
    ("ui_cm", "                    false,\n                )\n                .await;", "                    true,\n                )\n                .await;", "Android log omission"),
    ("ui_cm", "fn r_s11ha_cm_file_job_log_is_returned_to_the_exact_command_owner", "fn direct_log_may_detach", "direct-log regression"),
    ("ui_cm", "fn r_s11ha_cm_file_job_log_can_be_omitted_without_retaining_the_job", "fn omitted_log_may_retain_job", "omitted-log regression"),
    ("verify", "python3 scripts/verify-cm-egress-budget.py --repo . --self-test", "true # CM egress gate disabled", "shared gate wiring"),
    ("verify", "cargo test --lib --features linux-pkg-config,flutter r_s11ha_ --color never", "true # direct CM file-log tests disabled", "direct-log behavior gate wiring"),
    ("apple", "python3 scripts/verify-cm-egress-budget.py --repo . --self-test", "true # CM egress gate disabled", "Apple gate wiring"),
    ("requirements", '<div class="req"><span class="id">R-S11gy</span>', '<div class="req"><span class="id">R-S11gy-disabled</span>', "normative requirement"),
    ("requirements", "<tr><td>360</td>", "<tr><td>360-disabled</td>", "Appendix disposition"),
    ("requirements", '<div class="req"><span class="id">R-S11ha</span>', '<div class="req"><span class="id">R-S11ha-disabled</span>', "direct-log normative requirement"),
    ("requirements", "<tr><td>362</td>", "<tr><td>362-disabled</td>", "direct-log Appendix disposition"),
    ("hardening", "### R-S11gy/R-S11e-237 — bounded connection-manager result ownership", "### R-S11gy-disabled/R-S11e-237 — bounded connection-manager result ownership", "hardening ledger"),
    ("hardening", "### R-S11ha/R-S11e-239 — exact-command CM file-job log ownership", "### R-S11ha-disabled/R-S11e-239 — exact-command CM file-job log ownership", "direct-log hardening ledger"),
    ("workspace", "    validate_controlled_control_egress_contract(sources)\n    validate_cm_egress_budget_contract(sources)\n    validate_clipboard_listener_ownership_contract(sources)\n    validate_clipboard_route_budget_contract(sources)\n    validate_keyed_writer_budget_contract(sources)", "    validate_controlled_control_egress_contract(sources)\n    validate_cm_egress_budget_contract_disabled(sources)\n    validate_clipboard_listener_ownership_contract(sources)\n    validate_clipboard_route_budget_contract(sources)\n    validate_keyed_writer_budget_contract(sources)", "independent dispatch"),
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
        print(f"CM egress budget verifier self-test passed ({len(MUTATIONS)} mutations)")
    else:
        print("CM egress budget verifier passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VerificationError as error:
        print(f"CM egress budget verifier failed: {error}")
        raise SystemExit(1)
