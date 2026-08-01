#!/usr/bin/env python3
"""Verify outgoing-viewer file admission and exact writer finality."""

from __future__ import annotations

import argparse
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


def extract_rust_item(source: str, signature: str, label: str) -> str:
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
    paths = {
        "client": "src/client.rs",
        "cli": "src/cli.rs",
        "file_trait": "src/client/file_trait.rs",
        "io_loop": "src/client/io_loop.rs",
        "fs": "libs/hbb_common/src/fs.rs",
        "flutter_ffi": "src/flutter_ffi.rs",
        "session": "src/ui_session_interface.rs",
        "server": "src/server/connection.rs",
        "dart_file": "flutter/lib/models/file_model.dart",
        "dart_model": "flutter/lib/models/model.dart",
        "desktop": "flutter/lib/desktop/pages/file_manager_page.dart",
        "mobile": "flutter/lib/mobile/pages/file_manager_page.dart",
        "requirements": "requirements.html",
        "hardening": "HARDENING_STATUS.md",
        "verify": "scripts/verify.sh",
        "apple": "scripts/apple-conform-check.sh",
        "workspace": "scripts/verify-verifier-workspace.py",
        "dart_verify": "scripts/dart-verify.sh",
    }
    return {
        key: (repo / relative).read_text(encoding="utf-8")
        for key, relative in paths.items()
    }


def validate(sources: Dict[str, str]) -> None:
    client = sources["client"]
    file_trait = sources["file_trait"]
    io_loop = sources["io_loop"]
    fs = sources["fs"]

    interface = extract_rust_item(client, "pub trait Interface", "viewer interface")
    require(
        interface,
        "fn try_send(&self, data: Data) -> ResultType<()>;",
        "fallible viewer command admission",
    )
    data = extract_rust_item(client, "pub enum Data", "viewer command enum")
    require(data, "FileMessage(Message)", "typed file command variant")

    forbid(file_trait, "self.send(", "void file-command admission")
    for method in (
        "cancel_job",
        "read_empty_dirs",
        "read_remote_dir",
        "remove_file",
        "remove_dir_all",
        "remove_dir",
        "create_dir",
        "send_files",
        "add_job",
        "resume_job",
        "set_confirm_override_file",
        "rename_file",
    ):
        item = extract_rust_item(file_trait, f"fn {method}", f"FileManager::{method}")
        require(item, "-> ResultType<()>", f"fallible FileManager::{method}")
    require(
        file_trait,
        "self.try_send(Data::FileMessage(msg_out))",
        "typed directory-command admission",
    )
    require(
        file_trait,
        "fs::remove_all_empty_dir(&fs::get_path(&path))",
        "local remove error propagation",
    )
    forbid(
        extract_rust_item(file_trait, "fn remove_dir(", "FileManager::remove_dir"),
        ".ok()",
        "discarded local remove error",
    )

    session_try_send = extract_rust_item(
        sources["session"], "fn try_send(&self, data: Data)", "session try_send"
    )
    require_order(
        session_try_send,
        (
            ".sender",
            ".read()",
            ".unwrap()",
            ".as_ref()",
            ".cloned()",
            'ok_or_else(|| anyhow!("no active viewer connection round"))?',
            "sender.send(data)",
        ),
        "exact active-round admission",
    )
    require_order(
        extract_rust_item(
            sources["cli"], "fn try_send(&self, data: Data)", "CLI try_send"
        ),
        ("self.sender", ".send(data)", ".map_err("),
        "CLI admission error propagation",
    )

    for method in (
        "session_read_remote_dir",
        "session_send_files",
        "session_set_confirm_override_file",
        "session_remove_file",
        "session_read_dir_to_remove_recursive",
        "session_remove_all_empty_dirs",
        "session_cancel_job",
        "session_create_dir",
        "session_read_remote_empty_dirs_recursive_sync",
        "session_add_job",
        "session_resume_job",
        "session_rename_file",
    ):
        item = extract_rust_item(
            sources["flutter_ffi"], f"pub fn {method}", f"Flutter FFI {method}"
        )
        require(item, "-> Result<()>", f"fallible Flutter FFI {method}")
        require(
            item,
            'ok_or_else(|| hbb_common::anyhow::anyhow!("viewer session is not available"))?',
            f"missing-session failure for {method}",
        )

    dart = sources["dart_file"] + sources["desktop"] + sources["mobile"]
    for call in (
        "sessionReadRemoteDir",
        "sessionSendFiles",
        "sessionSetConfirmOverrideFile",
        "sessionRemoveFile",
        "sessionReadDirToRemoveRecursive",
        "sessionRemoveAllEmptyDirs",
        "sessionCancelJob",
        "sessionCreateDir",
        "sessionReadRemoteEmptyDirsRecursiveSync",
        "sessionAddJob",
        "sessionResumeJob",
        "sessionRenameFile",
    ):
        require(dart, f"await bind.{call}(", f"awaited Dart {call}")
    require_order(
        sources["dart_file"],
        (
            "final jobID = jobController.addTransferJob(from, isRemoteToLocal);",
            "await bind.sessionSendFiles(",
            "jobController.updateJobStatus(jobID,",
            "state: JobState.error);",
            "rethrow;",
        ),
        "new transfer admission failure remains visible",
    )
    resume_job = extract_rust_item(
        sources["dart_file"], "Future<void> resumeJob(", "Dart resumeJob"
    )
    require_order(
        resume_job,
        (
            "await bind.sessionResumeJob(",
            "job.state = JobState.inProgress;",
        ),
        "resume state follows native admission",
    )
    require(
        sources["dart_model"],
        "unawaited(future.catchError((Object error) {",
        "explicit event-path future ownership",
    )

    for needle, label in (
        (
            "const MAX_PENDING_VIEWER_FILE_WRITES: usize = 256;",
            "file receipt count bound",
        ),
        (
            "const MAX_PENDING_VIEWER_FILE_WRITE_BYTES: usize = hbb_common::cpace::MAX_SESSION_PACKET * 2;",
            "file receipt byte bound",
        ),
        (
            "const VIEWER_FILE_WRITE_TIMEOUT: Duration = Duration::from_secs(30);",
            "file receipt deadline",
        ),
    ):
        require(io_loop, needle, label)

    tracker = extract_rust_item(
        io_loop, "impl ViewerFileWriteTracker", "file writer tracker"
    )
    require_order(
        tracker,
        (
            "self.contexts.len() >= self.limits.count",
            ".checked_add(bytes)",
            "pending_bytes > self.limits.bytes",
            ".checked_add(1)",
            "self.contexts.contains_key(&id)",
            "time::timeout(timeout, receipt).await",
            ".checked_sub(bytes)",
        ),
        "bounded checked exact-receipt ownership",
    )
    forbid(tracker, "saturating_", "silent tracker accounting repair")
    retire = extract_rust_item(tracker, "fn retire", "file writer tracker retirement")
    require_order(
        retire,
        (
            "self.completions = FuturesUnordered::new();",
            "self.pending_bytes = 0;",
            "self.contexts",
            ".drain()",
        ),
        "exact pending file-writer retirement",
    )

    context = extract_rust_item(
        io_loop, "fn file_message_context", "file action context decoder"
    )
    for variant in (
        "Send(value)",
        "Receive(value)",
        "RemoveDir(value)",
        "RemoveFile(value)",
        "Create(value)",
        "Cancel(value)",
        "SendConfirm(value)",
        "Rename(value)",
        "AllFiles(value)",
        "ReadDir(_)",
        "ReadEmptyDirs(_)",
    ):
        require(context, f"file_action::Union::{variant}", f"{variant} context")
    require(context, "_ => return None", "unknown file action refusal")

    tracked_send = extract_rust_item(
        io_loop, "async fn send_tracked_file_action", "central tracked file send"
    )
    require_order(
        tracked_send,
        (
            "Self::file_message_context(message)",
            "Self::enqueue_file_message(&mut self.file_writes, peer, message, context.clone())",
            "self.record_file_flow_failure(context, err)",
        ),
        "central context-derived tracked file send",
    )
    enqueue = extract_rust_item(
        io_loop, "async fn enqueue_file_message", "exact file frame enqueue"
    )
    require_order(
        enqueue,
        (
            "message.compute_size()",
            "file_writes.reserve(context, retained_bytes)?",
            "peer.send_with_receipt(message).await",
            "file_writes.cancel(reservation)",
            "file_writes.attach(reservation, receipt)",
        ),
        "reserve-before-exact-frame admission",
    )

    ui_dispatch = extract_rust_item(
        io_loop, "async fn handle_msg_from_ui", "viewer UI dispatch"
    )
    require(
        ui_dispatch,
        "Some(message::Union::FileAction(_))",
        "generic file-action rejection",
    )
    require(
        ui_dispatch,
        "Data::FileMessage(msg)",
        "typed file-action dispatch",
    )
    require(
        ui_dispatch,
        "self.send_tracked_file_action(peer, &msg).await",
        "central typed file-action send",
    )

    transfer_step = extract_rust_item(
        io_loop, "async fn enqueue_file_transfer_step", "file transfer step"
    )
    require_order(
        transfer_step,
        (
            "file_writes.reserve(context, hbb_common::cpace::MAX_SESSION_PACKET)?",
            "fs::handle_read_jobs(read_jobs, peer).await",
            "Ok((_log, Some(receipt)))",
            "file_writes.cancel(reservation)",
            "file_writes.attach(reservation, receipt)",
        ),
        "reserve-before-one-frame producer admission",
    )
    forbid(io_loop, "writer_barrier", "redundant file writer barrier")
    require(
        io_loop,
        "completion = self.file_writes.next(), if !self.file_writes.is_empty()",
        "event-driven file receipt select branch",
    )
    require(
        io_loop,
        "_ = self.timer.tick(), if !self.file_writes.has_transfer_data()",
        "transfer producer pacing by exact receipt",
    )
    require(io_loop, "self.finish_file_flow();", "file flow final retirement")

    init_jobs = extract_rust_item(fs, "async fn init_jobs", "common file job init")
    require(
        init_jobs,
        "jobs.iter_mut().find(|job| !job.is_last_job)",
        "one active initialization job",
    )
    forbid(init_jobs, "for job in jobs.iter_mut()", "multi-job initialization burst")
    read_jobs = extract_rust_item(
        fs, "pub async fn handle_read_jobs", "common file read producer"
    )
    require(
        read_jobs,
        "ResultType<(String, Option<crate::tcp::WriterReceipt>)>",
        "exact common-producer receipt return",
    )
    require(
        read_jobs,
        "if let Some(receipt) = init_jobs(jobs, stream).await?",
        "one initialization message per call",
    )
    require(read_jobs, "// Break to handle jobs one by one.", "one read job per call")
    for producer in ("new_error", "new_block", "new_done"):
        require(
            read_jobs,
            f"send_with_receipt(&{producer}",
            f"exact {producer} writer receipt",
        )
    forbid(read_jobs, ".send(&new_", "ambiguous common file send")
    require(
        sources["server"],
        "Ok((log, _receipt))",
        "explicit controlled-side receipt discard",
    )

    for test in (
        "r_s11fg_read_step_returns_the_exact_file_frame_receipt",
        "r_s11fg_file_writer_success_releases_exact_count_and_bytes",
        "r_s11fg_file_writer_count_byte_and_sequence_limits_fail_closed",
        "r_s11fg_file_writer_failure_and_retirement_are_explicit",
        "r_s11fg_file_writer_timeout_is_terminal_and_bounded",
    ):
        require(fs + io_loop, f"fn {test}()", f"{test} regression")

    for key, needle, label in (
        (
            "requirements",
            '<div class="req"><span class="id">R-S11fg</span>',
            "R-S11fg normative requirement",
        ),
        ("requirements", "<tr><td>315</td>", "Appendix C #315"),
        (
            "hardening",
            "**R-S11fg/R-S11e-194 outgoing viewer file-command admission",
            "R-S11e-194 hardening ledger",
        ),
        (
            "verify",
            "python3 scripts/verify-viewer-file-finality.py --repo . --self-test",
            "shared focused verifier gate",
        ),
        (
            "apple",
            "python3 scripts/verify-viewer-file-finality.py --repo . --self-test",
            "Apple/shared focused verifier gate",
        ),
        (
            "dart_verify",
            "client::io_loop::tests::r_s11fg_",
            "generated-bridge tracker behavior gate",
        ),
        (
            "dart_verify",
            "fs::tests::r_s11fg_read_step_returns_the_exact_file_frame_receipt",
            "generated-bridge exact-frame behavior gate",
        ),
        (
            "workspace",
            '"viewer_file_finality_verifier": (',
            "independent verifier source binding",
        ),
        (
            "workspace",
            "validate_viewer_file_finality_contract(sources)",
            "independent verifier dispatch",
        ),
    ):
        require(sources[key], needle, label)

    requirements_digest = hashlib.sha256(
        sources["requirements"].encode("utf-8")
    ).hexdigest()
    require(
        sources["hardening"],
        f"{requirements_digest}  requirements.html",
        "exact requirements digest binding",
    )


Mutation = Tuple[str, str, str, str]

MUTATIONS: Tuple[Mutation, ...] = (
    ("client", "FileMessage(Message)", "FileMessageDisabled(Message)", "typed file command"),
    ("file_trait", "self.try_send(Data::FileMessage(msg_out))", "self.send(Data::Message(msg_out)); Ok(())", "typed directory admission"),
    ("file_trait", "fn cancel_job(&self, id: i32) -> ResultType<()>", "fn cancel_job(&self, id: i32)", "fallible file manager"),
    ("session", "fn try_send(&self, data: Data)", "fn send_disabled(&self, data: Data)", "exact round try_send"),
    ("flutter_ffi", "pub fn session_cancel_job(session_id: SessionID, act_id: i32) -> Result<()> {", "pub fn session_cancel_job(session_id: SessionID, act_id: i32) {", "fallible Flutter FFI"),
    ("dart_file", "await bind.sessionSendFiles(", "bind.sessionSendFiles(", "awaited send admission"),
    ("dart_file", "await bind.sessionResumeJob(\n          sessionId: sessionId, actId: job.id", "bind.sessionResumeJob(\n          sessionId: sessionId, actId: job.id", "awaited resume admission"),
    ("dart_model", "unawaited(future.catchError((Object error) {", "future.catchError((Object error) {", "owned event future"),
    ("io_loop", "const MAX_PENDING_VIEWER_FILE_WRITES: usize = 256;", "const MAX_PENDING_VIEWER_FILE_WRITES: usize = 4096;", "receipt count bound"),
    ("io_loop", "const MAX_PENDING_VIEWER_FILE_WRITE_BYTES: usize = hbb_common::cpace::MAX_SESSION_PACKET * 2;", "const MAX_PENDING_VIEWER_FILE_WRITE_BYTES: usize = usize::MAX;", "receipt byte bound"),
    ("io_loop", "const VIEWER_FILE_WRITE_TIMEOUT: Duration = Duration::from_secs(30);", "const VIEWER_FILE_WRITE_TIMEOUT: Duration = Duration::from_secs(300);", "receipt deadline"),
    ("io_loop", ".checked_add(bytes)", ".saturating_add(bytes)", "checked byte addition"),
    ("io_loop", ".checked_add(1)", ".saturating_add(1)", "checked receipt identity"),
    ("io_loop", ".checked_sub(bytes)", ".saturating_sub(bytes)", "checked byte release"),
    ("io_loop", "time::timeout(timeout, receipt).await", "receipt.await", "receipt deadline ownership"),
    ("io_loop", "self.contexts\n            .drain()", "std::iter::empty()", "pending context retirement"),
    ("io_loop", "Some(file_action::Union::ReadEmptyDirs(_))", "Some(file_action::Union::ReadEmptyDirsDisabled(_))", "complete action decoder"),
    ("io_loop", "Self::file_message_context(message)", "Some(ViewerFileWriteContext::control(None, -1, \"caller\"))", "central context derivation"),
    ("io_loop", "peer.send_with_receipt(message).await", "peer.send(message).await", "exact control-frame receipt"),
    ("io_loop", "Some(message::Union::FileAction(_))", "Some(message::Union::FileActionDisabled(_))", "generic path refusal"),
    ("io_loop", "completion = self.file_writes.next(), if !self.file_writes.is_empty()", "completion = self.file_writes.next()", "receipt select guard"),
    ("io_loop", "_ = self.timer.tick(), if !self.file_writes.has_transfer_data()", "_ = self.timer.tick()", "transfer pacing"),
    ("fs", "jobs.iter_mut().find(|job| !job.is_last_job)", "jobs.iter_mut().last()", "one active init job"),
    ("fs", "ResultType<(String, Option<crate::tcp::WriterReceipt>)>", "ResultType<String>", "common producer receipt"),
    ("fs", "send_with_receipt(&new_block(block))", "send(&new_block(block))", "exact block receipt"),
    ("fs", "fn r_s11fg_read_step_returns_the_exact_file_frame_receipt()", "fn read_step_returns_the_exact_file_frame_receipt()", "exact frame regression"),
    ("io_loop", "fn r_s11fg_file_writer_timeout_is_terminal_and_bounded()", "fn file_writer_timeout_is_terminal_and_bounded()", "timeout regression"),
    ("requirements", '<div class="req"><span class="id">R-S11fg</span>', '<div class="req"><span class="id">R-S11fg-disabled</span>', "normative requirement"),
    ("requirements", "<tr><td>315</td>", "<tr><td>315-disabled</td>", "Appendix disposition"),
    ("hardening", "**R-S11fg/R-S11e-194 outgoing viewer file-command admission", "**R-S11fg-disabled/R-S11e-194 outgoing viewer file-command admission", "hardening ledger"),
    ("verify", "python3 scripts/verify-viewer-file-finality.py --repo . --self-test", "python3 scripts/verify-viewer-file-finality.py --repo .", "shared mutation gate"),
    ("apple", "python3 scripts/verify-viewer-file-finality.py --repo . --self-test", "python3 scripts/verify-viewer-file-finality.py --repo .", "Apple mutation gate"),
    ("dart_verify", "client::io_loop::tests::r_s11fg_", "client::io_loop::tests::disabled_", "generated-bridge tracker gate"),
    ("workspace", '"viewer_file_finality_verifier": (', '"viewer_file_finality_verifier_disabled": (', "independent source binding"),
)


def run_self_test(sources: Dict[str, str]) -> None:
    for key, old, new, label in MUTATIONS:
        if old not in sources[key]:
            raise VerificationError(f"self-test fixture missing for {label}")
        mutated = dict(sources)
        mutated[key] = sources[key].replace(old, new, 1)
        try:
            validate(mutated)
        except VerificationError:
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
        print(
            "viewer file finality verifier self-test passed "
            f"({len(MUTATIONS)} mutations)"
        )
    else:
        print("viewer file finality verifier passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VerificationError as error:
        print(f"viewer file finality verifier failed: {error}")
        raise SystemExit(1)
