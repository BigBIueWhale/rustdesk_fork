#!/usr/bin/env python3
"""Verify bounded, generation-aware outgoing-viewer video mailbox semantics."""

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


def require_count(source: str, needle: str, expected: int, label: str) -> None:
    actual = source.count(needle)
    if actual != expected:
        raise VerificationError(
            f"{label}: expected {expected} occurrences of {needle!r}, found {actual}"
        )


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
    return {
        "client": (repo / "src/client.rs").read_text(encoding="utf-8"),
        "io_loop": (repo / "src/client/io_loop.rs").read_text(encoding="utf-8"),
        "cargo": (repo / "Cargo.toml").read_text(encoding="utf-8"),
        "lock": (repo / "Cargo.lock").read_text(encoding="utf-8"),
        "requirements": (repo / "requirements.html").read_text(encoding="utf-8"),
        "hardening": (repo / "HARDENING_STATUS.md").read_text(encoding="utf-8"),
        "verify": (repo / "scripts/verify.sh").read_text(encoding="utf-8"),
        "apple": (repo / "scripts/apple-conform-check.sh").read_text(encoding="utf-8"),
        "workspace": (repo / "scripts/verify-verifier-workspace.py").read_text(
            encoding="utf-8"
        ),
    }


def validate(sources: Dict[str, str]) -> None:
    client = sources["client"]
    io_loop = sources["io_loop"]

    for needle, label in (
        (
            "pub const VIDEO_FRAME_QUEUE_CAPACITY: usize = 8;",
            "eight-frame mailbox bound",
        ),
        (
            "pub const MAX_VIDEO_FRAME_QUEUE_AGE: Duration = Duration::from_secs(1);",
            "one-second receive-through-decode freshness budget",
        ),
    ):
        require(client, needle, label)

    forbid(client, "pub enum MediaData", "retired generic decoder-work union")

    state = extract_rust_item(
        client, "struct VideoMailboxState", "viewer video mailbox state"
    )
    require_order(
        state,
        (
            "work: VecDeque<VideoWork>",
            "frame_count: usize",
            "generation: u64",
            "awaiting_keyframe: bool",
            "refresh_requested: bool",
            "closed: bool",
        ),
        "single ordered mailbox state",
    )
    forbid(state, "control_count", "lossy control-count capacity")

    control_admission = extract_rust_item(
        client, "pub(crate) enum VideoControlAdmission", "video control admission result"
    )
    require_order(
        control_admission,
        ("Accepted,", "RefreshRequired,", "Closed,"),
        "explicit control admission outcomes",
    )

    invalidate = extract_rust_item(
        client, "fn invalidate_frames(&mut self)", "GOP invalidation"
    )
    require_order(
        invalidate,
        (
            "if !self.advance_generation()",
            "self.clear_frames();",
            "self.awaiting_keyframe = true;",
            "self.refresh_requested = true;",
        ),
        "generation retirement before fresh-keyframe wait",
    )

    admission = extract_rust_item(
        client, "fn admit_frame_at(", "viewer video frame admission"
    )
    require_order(
        admission,
        (
            "if state.closed",
            "if is_keyframe",
            "if !state.advance_generation()",
            "state.clear_frames();",
            "state.awaiting_keyframe = false;",
            "state.refresh_requested = false;",
            "state.work.push_back(VideoWork::Frame",
            "if state.awaiting_keyframe",
            "VideoFrameAdmission::AwaitingKeyframe",
            "VideoFrameAdmission::RefreshRequired",
            "if state.frame_count >= VIDEO_FRAME_QUEUE_CAPACITY",
            "let open = state.invalidate_frames();",
            "state.work.push_back(VideoWork::Frame",
            "self.shared.ready.notify_one();",
            "VideoFrameAdmission::Queued",
        ),
        "keyframe replacement, overflow retirement, and direct work reachability",
    )
    for forbidden in (
        "force_push",
        "ArrayQueue",
        "try_send",
        "VideoQueue",
        "thread::sleep",
        "Runtime::new",
        "block_on",
    ):
        forbid(admission, forbidden, "split/polling frame admission")

    control = extract_rust_item(
        client, "pub(crate) fn admit_control", "viewer video control admission"
    )
    require_order(
        control,
        (
            "if state.closed",
            "VideoControl::Reset",
            "let refresh_required = !state.refresh_requested;",
            "if !state.invalidate_frames()",
            "VideoControl::RecordScreen(_) => false",
            "state.work.retain",
            "VideoWork::Control(VideoControl::Reset)",
            "VideoWork::Control(VideoControl::RecordScreen(_))",
            "state.work.push_back(VideoWork::Control(control));",
            "VideoControlAdmission::RefreshRequired",
            "VideoControlAdmission::Accepted",
        ),
        "semantic control coalescing, reset barrier, and explicit refresh ownership",
    )
    for forbidden in (
        "VIDEO_CONTROL_QUEUE_CAPACITY",
        "control_count",
        "try_send_control",
    ):
        forbid(client + io_loop, forbidden, "lossy viewer control admission")
    forbid(control, "TrySendError::Full", "generic control-capacity rejection")

    shared_close = extract_rust_item(
        client, "impl VideoMailboxShared", "shared mailbox closure"
    )
    require_order(
        shared_close,
        (
            "state.closed = true;",
            "state.work.clear();",
            "state.frame_count = 0;",
            "self.ready.notify_all();",
        ),
        "terminal close releases retained work before wake",
    )
    require(
        extract_rust_item(
            client, "impl Drop for VideoMailboxSender", "sender Drop closure"
        ),
        "self.shared.close();",
        "sender-drop receiver wake",
    )
    require(
        extract_rust_item(
            client, "impl Drop for VideoMailboxReceiver", "receiver Drop closure"
        ),
        "self.shared.close();",
        "receiver-drop producer rejection",
    )

    pending_frames = extract_rust_item(
        client,
        "pub(crate) fn pending_frames(&self) -> Option<usize>",
        "mailbox liveness-aware frame count",
    )
    require_order(
        pending_frames,
        (
            "let state = self.shared.state.lock().unwrap();",
            "(!state.closed).then_some(state.frame_count)",
        ),
        "closed mailbox cannot look empty and healthy",
    )
    owned_video_thread = extract_rust_item(
        client, "impl OwnedVideoThread", "owned video endpoint"
    )
    require(
        owned_video_thread,
        ".and_then(VideoMailboxSender::pending_frames)",
        "owned endpoint preserves closed queue observation",
    )
    forbid(
        owned_video_thread,
        ".map_or(0, VideoMailboxSender::pending_frames)",
        "closed endpoint collapsed to an empty queue",
    )

    receive = extract_rust_item(
        client, "fn recv(&self) -> Option<VideoMailboxItem>", "mailbox receive"
    )
    require_order(
        receive,
        (
            "while state.work.is_empty() && !state.closed",
            "state = self.shared.ready.wait(state).unwrap();",
            "let Some(work) = state.work.pop_front()",
            "state.frame_count.checked_sub(1)",
            "frame.generation != state.generation",
            "if !video_frame_is_fresh",
            "let open = state.invalidate_frames();",
            "return Some(VideoMailboxItem::RefreshRequired);",
            "return Some(VideoMailboxItem::Frame(frame));",
        ),
        "event-driven direct receive and stale-GOP retirement",
    )
    forbid(receive, "saturating_sub", "silent mailbox-count repair")

    worker = extract_rust_item(
        client, "pub(crate) fn start_video_thread", "viewer video decoder worker"
    )
    require_order(
        worker,
        (
            "let mut decoder_generation = None;",
            "VideoMailboxItem::RefreshRequired",
            "decoder_generation = None;",
            "VideoMailboxItem::Frame(queued)",
            "if queued.is_keyframe",
            "decoder_generation = Some(queued.generation);",
            "decoder_generation != Some(queued.generation)",
            "video_receiver.invalidate_generation(queued.generation)",
            "handler.handle_frame",
            "if !video_frame_is_fresh(queued_at, std::time::Instant::now())",
            "if !video_receiver.generation_is_current(generation)",
            "if rendered",
            "video_callback(",
            "VideoMailboxItem::Control(VideoControl::Reset)",
            "decoder_generation = None;",
        ),
        "decode freshness, generation check, publication, and reset ordering",
    )
    for forbidden in (
        "MediaData::VideoQueue",
        "MediaData::VideoFrame",
        "discard_queue",
        "ArrayQueue",
        "thread::sleep",
    ):
        forbid(worker, forbidden, "retired split/polling decoder path")

    sequence = extract_rust_item(
        io_loop, "fn starts_video_sequence(", "independent-frame classifier"
    )
    require(
        sequence,
        "f.frames.first().map_or(false, |frame| frame.key)",
        "leading-keyframe classification",
    )
    require(sequence, "Rgb(_) | Yuv(_) => true", "raw independent-frame admission")
    require(sequence, "_ => false", "unknown wire variant refusal")
    forbid(sequence, ".iter().any(", "later-keyframe sequence admission")

    peer_admission = io_loop[
        io_loop.index("Some(message::Union::VideoFrame(vf))") :
        io_loop.index("Some(message::Union::LoginResponse", io_loop.index("Some(message::Union::VideoFrame(vf))"))
    ]
    require_order(
        peer_admission,
        (
            "let Some(thread) = self.video_threads.get_mut(&display) else",
            '"video decoder ownership missing after admission for display {display}"',
            'self.handler\n                            .on_error("Video decoder state became inconsistent");',
            "return false;",
            "let is_keyframe = starts_video_sequence(&vf);",
            "thread.media_thread.admit_frame(vf, is_keyframe)",
            "VideoFrameAdmission::AwaitingKeyframe",
            "VideoFrameAdmission::RefreshRequired",
            "self.handler.refresh_video(display as _)",
            "VideoFrameAdmission::Closed",
            '"video decoder mailbox closed while admitting a frame for display {display}"',
            'self.handler.on_error("Video decoder stopped unexpectedly");',
            "return false;",
        ),
        "peer frame admission, recovery, and terminal endpoint-loss propagation",
    )
    forbid(
        peer_admission,
        "dropping peer video frame after decoder mailbox closure",
        "continued peer round after decoder endpoint loss",
    )
    for forbidden in ("force_push", "MediaData::VideoQueue", "try_send(MediaData::VideoFrame"):
        forbid(peer_admission, forbidden, "split frame/token peer admission")

    refresh_admission = extract_rust_item(
        io_loop, "async fn handle_video_refresh(", "viewer refresh admission"
    )
    require_count(
        refresh_admission,
        "if !thread.media_thread.begin_refresh()",
        2,
        "all-display and single-display refresh endpoint liveness",
    )
    require_order(
        refresh_admission,
        (
            "ViewerVideoRefreshRequest::All",
            "if !thread.media_thread.begin_refresh()",
            'self.handler.on_error("Video decoder stopped unexpectedly");',
            "return false;",
            "ViewerVideoRefreshRequest::Display(display)",
            "if !thread.media_thread.begin_refresh()",
            'self.handler.on_error("Video decoder stopped unexpectedly");',
            "return false;",
            "peer.send(&message).await",
        ),
        "refresh may reach the peer only while every existing decoder endpoint is live",
    )

    fps_control = extract_rust_item(io_loop, "fn fps_control(&mut self", "viewer FPS control")
    require_count(
        fps_control,
        ".media_thread.pending_frames() else",
        3,
        "backlog observation, FPS calculation, and recovery liveness",
    )
    require_count(
        fps_control,
        'self.handler.on_error("Video decoder stopped unexpectedly");',
        4,
        "terminal queue observation and refresh-race reporting",
    )
    require_count(
        fps_control,
        "if !thread.media_thread.begin_refresh()",
        1,
        "backlog recovery refresh endpoint liveness",
    )
    require_order(
        fps_control,
        (
            "if pending_frames > tolerable",
            "if !thread.media_thread.begin_refresh()",
            'self.handler.on_error("Video decoder stopped unexpectedly");',
            "return false;",
            "self.handler.refresh_video(*display as _)",
        ),
        "backlog recovery terminates before peer refresh when its decoder is closed",
    )
    forbid(
        fps_control,
        ".map(|v| v.1.media_thread.pending_frames())",
        "closed decoder reduced through numeric maximum",
    )

    reset_admission = extract_rust_item(
        io_loop, "fn admit_decoder_reset(&self", "decoder reset admission"
    )
    require_order(
        reset_admission,
        (
            "thread.media_thread.admit_control(VideoControl::Reset)",
            "VideoControlAdmission::Accepted",
            "VideoControlAdmission::RefreshRequired",
            "self.handler.refresh_video(display as _)",
            "VideoControlAdmission::Closed",
            "false",
        ),
        "reset barrier refresh and terminal closure propagation",
    )
    recording_admission = extract_rust_item(
        io_loop, "fn update_record_state(&mut self) -> bool", "record-state admission"
    )
    require_order(
        recording_admission,
        (
            "admit_control(VideoControl::RecordScreen(start))",
            "== VideoControlAdmission::Closed",
            "return false;",
            "self.handler.update_record_status(start);",
            "self.sender.send(Data::Message(msg))",
            "return false;",
            "true",
        ),
        "record-state convergence and terminal admission failure",
    )
    for forbidden in (
        "dropping reset",
        "dropping record-state update",
        "viewer video decode queue full",
    ):
        forbid(io_loop, forbidden, "silent admitted-control discard")

    for test in (
        "r_s11ev_video_mailbox_requires_a_keyframe_before_deltas",
        "r_s11ev_video_mailbox_overflow_discards_the_gop_and_recovers_in_order",
        "r_s11ev_keyframe_supersession_preserves_control_order",
        "r_s11ev_superseded_generation_is_rejected_before_publication",
        "r_s11ev_equal_rate_recovery_leaves_no_unreachable_frame_backlog",
        "r_s11ev_stale_frame_retires_the_gop_instead_of_displaying_backlog",
        "r_s11ev_video_freshness_budget_includes_decode_time",
        "r_s11ev_explicit_refresh_clears_frames_but_preserves_controls",
        "r_s11fn_repeated_decoder_resets_coalesce_without_dropping_the_barrier",
        "r_s11fn_recording_control_is_latest_wins_at_its_exact_queue_position",
        "r_s11fn_mixed_controls_retain_exactly_two_semantic_items",
        "r_s11fo_closed_decoder_endpoint_is_not_an_empty_live_mailbox",
        "r_s11ev_close_releases_pending_work_and_wakes_the_worker",
        "r_s11ev_sender_drop_wakes_a_waiting_receiver",
        "r_s11ev_receiver_drop_rejects_new_work",
        "r_s11ev_generation_exhaustion_fails_closed",
        "r_s11ev_only_a_leading_keyframe_starts_an_encoded_sequence",
        "r_s11ev_raw_video_frames_are_independent_sequences",
    ):
        require(client + io_loop, f"fn {test}()", f"{test} behavior regression")

    endpoint_finality_regression = extract_rust_item(
        client,
        "fn r_s11fo_closed_decoder_endpoint_is_not_an_empty_live_mailbox()",
        "decoder endpoint finality regression",
    )
    require_order(
        endpoint_finality_regression,
        (
            "let (panic_sender, panic_receiver) = video_mailbox();",
            "let _unwind_signal = WorkerUnwindSignal(unwind_sender);",
            "let _receiver = panic_receiver;",
            'panic!("deliberate decoder-worker unwind");',
            'unwind_receiver.recv().expect("decoder worker unwound");',
            "assert_eq!(panic_owned.pending_frames(), None);",
            "assert!(!panic_owned.begin_refresh());",
            "VideoFrameAdmission::Closed",
            "assert!(panicked_worker.join().is_err());",
        ),
        "decoder worker unwind closes its exact owned endpoint",
    )

    forbid(sources["cargo"], 'crossbeam-queue = "', "direct crossbeam-queue dependency")
    require(sources["lock"], 'name = "crossbeam-queue"', "transitive queue lock record")

    for key, needle, label in (
        (
            "requirements",
            '<div class="req"><span class="id">R-S11ev</span>',
            "R-S11ev requirement",
        ),
        (
            "requirements",
            '<div class="req"><span class="id">R-S11fn</span>',
            "R-S11fn control-finality requirement",
        ),
        (
            "requirements",
            '<div class="req"><span class="id">R-S11fo</span>',
            "R-S11fo decoder-endpoint finality requirement",
        ),
        ("requirements", "<tr><td>304</td>", "Appendix C #304"),
        ("requirements", "<tr><td>322</td>", "Appendix C #322"),
        ("requirements", "<tr><td>323</td>", "Appendix C #323"),
        (
            "hardening",
            "**R-S11ev/R-S11e-183 directly reachable, bounded, fresh outgoing-viewer video mailbox",
            "viewer video mailbox hardening ledger",
        ),
        (
            "hardening",
            "**R-S11fn/R-S11e-201 semantic, non-dropping viewer decoder-control finality",
            "viewer video control-finality hardening ledger",
        ),
        (
            "hardening",
            "**R-S11fo/R-S11e-202 exact viewer decoder-endpoint finality",
            "viewer decoder-endpoint hardening ledger",
        ),
        (
            "verify",
            "cargo test --lib --features linux-pkg-config client::tests::r_s11ev_ --color never",
            "shared behavior-test wiring",
        ),
        (
            "verify",
            "cargo test --lib --features linux-pkg-config client::tests::r_s11fn_ --color never",
            "shared control-finality behavior-test wiring",
        ),
        (
            "verify",
            "cargo test --lib --features linux-pkg-config client::tests::r_s11fo_ --color never",
            "shared decoder-endpoint behavior-test wiring",
        ),
        (
            "verify",
            "python3 scripts/verify-viewer-video-mailbox.py --repo . --self-test",
            "shared focused-verifier wiring",
        ),
        (
            "apple",
            "python3 scripts/verify-viewer-video-mailbox.py --repo . --self-test",
            "Apple/shared focused-verifier wiring",
        ),
        (
            "workspace",
            '"viewer_video_mailbox_verifier": (',
            "independent verifier source binding",
        ),
        (
            "workspace",
            "validate_viewer_video_mailbox_contract(sources)",
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
    ("client", "pub const VIDEO_FRAME_QUEUE_CAPACITY: usize = 8;", "pub const VIDEO_FRAME_QUEUE_CAPACITY: usize = 120;", "frame bound"),
    ("client", "    Accepted,\n    RefreshRequired,\n    Closed,", "    AcceptedDisabled,\n    RefreshRequired,\n    Closed,", "control admission outcomes"),
    (
        "client",
        "pub const MAX_VIDEO_FRAME_QUEUE_AGE: Duration = Duration::from_secs(1);",
        "pub const MAX_VIDEO_FRAME_QUEUE_AGE: Duration = Duration::from_secs(10);",
        "freshness bound",
    ),
    ("client", "work: VecDeque<VideoWork>", "frames: VecDeque<VideoWork>", "unified work queue"),
    ("client", "state.clear_frames();\n            state.awaiting_keyframe = false;", "state.awaiting_keyframe = false;", "keyframe supersession"),
    ("client", "if state.frame_count >= VIDEO_FRAME_QUEUE_CAPACITY", "if false", "overflow recovery"),
    ("client", "self.shared.ready.notify_one();\n        VideoFrameAdmission::Queued", "VideoFrameAdmission::Queued", "direct frame wake"),
    ("client", "impl Drop for VideoMailboxSender", "impl VideoMailboxSender", "sender-drop finality"),
    ("client", "impl Drop for VideoMailboxReceiver", "impl VideoMailboxReceiver", "receiver-drop finality"),
    ("client", "state.frame_count.checked_sub(1)", "state.frame_count.saturating_sub(1)", "frame counter invariant"),
    ("client", "if !video_frame_is_fresh(frame.queued_at", "if false && !video_frame_is_fresh(frame.queued_at", "dequeue freshness"),
    ("client", "if !video_frame_is_fresh(queued_at, std::time::Instant::now())", "if false", "post-decode freshness"),
    ("client", "if !video_receiver.generation_is_current(generation)", "if false", "publication generation check"),
    ("client", "decoder_generation = None;\n                        if let Some(handler)", "if let Some(handler)", "decoder reset generation"),
    ("client", "fn r_s11ev_equal_rate_recovery_leaves_no_unreachable_frame_backlog()", "fn equal_rate_recovery_leaves_no_unreachable_frame_backlog()", "equal-rate regression"),
    ("client", "let refresh_required = !state.refresh_requested;", "let refresh_required = false;", "reset refresh ownership"),
    ("client", "state.work.retain(|work|", "state.work.iter().all(|work|", "semantic control coalescing"),
    ("client", "(!state.closed).then_some(state.frame_count)", "Some(state.frame_count)", "closed mailbox queue observation"),
    ("client", "fn r_s11fn_repeated_decoder_resets_coalesce_without_dropping_the_barrier()", "fn repeated_decoder_resets_coalesce_without_dropping_the_barrier()", "reset coalescing regression"),
    ("client", "fn r_s11fn_recording_control_is_latest_wins_at_its_exact_queue_position()", "fn recording_control_is_latest_wins_at_its_exact_queue_position()", "record-state regression"),
    ("client", "fn r_s11fn_mixed_controls_retain_exactly_two_semantic_items()", "fn mixed_controls_retain_exactly_two_semantic_items()", "mixed-control bound regression"),
    ("client", "fn r_s11fo_closed_decoder_endpoint_is_not_an_empty_live_mailbox()", "fn closed_decoder_endpoint_is_not_an_empty_live_mailbox()", "decoder-endpoint liveness regression"),
    ("client", "let _receiver = panic_receiver;", "std::mem::forget(panic_receiver);", "decoder-worker unwind endpoint closure"),
    ("io_loop", "f.frames.first().map_or(false, |frame| frame.key)", "f.frames.iter().any(|frame| frame.key)", "leading keyframe"),
    ("io_loop", "thread.media_thread.admit_frame(vf, is_keyframe)", "thread.media_thread.try_send(vf)", "direct mailbox admission"),
    ("io_loop", "return false;\n                    };\n                    let is_keyframe", "return true;\n                    };\n                    let is_keyframe", "missing decoder owner finality"),
    ("io_loop", "return false;\n                        }\n                    }\n                }\n                // R-T15c", "return true;\n                        }\n                    }\n                }\n                // R-T15c", "closed frame admission finality"),
    ("io_loop", "if !thread.media_thread.begin_refresh()", "if false && !thread.media_thread.begin_refresh()", "all-display refresh endpoint finality"),
    ("io_loop", "if let Some(thread) = self.video_threads.get(&display) {\n                    if !thread.media_thread.begin_refresh()", "if let Some(thread) = self.video_threads.get(&display) {\n                    if false && !thread.media_thread.begin_refresh()", "single-display refresh endpoint finality"),
    ("io_loop", "let Some(pending_frames) = thread.media_thread.pending_frames() else {", "if let Some(pending_frames) = thread.media_thread.pending_frames() {", "queue observation endpoint finality"),
    ("io_loop", "if pending_frames > tolerable {\n                if !thread.media_thread.begin_refresh()", "if pending_frames > tolerable {\n                if false && !thread.media_thread.begin_refresh()", "backlog refresh endpoint finality"),
    ("io_loop", "fn admit_decoder_reset(&self", "fn ignore_decoder_reset(&self", "reset caller finality"),
    ("io_loop", "fn update_record_state(&mut self) -> bool", "fn update_record_state(&mut self)", "record-state caller finality"),
    ("cargo", 'async-trait = "0.1"', 'async-trait = "0.1"\ncrossbeam-queue = "0.3"', "retired direct dependency"),
    ("requirements", '<div class="req"><span class="id">R-S11ev</span>', '<div class="req"><span class="id">R-S11ev-disabled</span>', "normative requirement"),
    ("requirements", '<div class="req"><span class="id">R-S11fn</span>', '<div class="req"><span class="id">R-S11fn-disabled</span>', "control-finality requirement"),
    ("requirements", '<div class="req"><span class="id">R-S11fo</span>', '<div class="req"><span class="id">R-S11fo-disabled</span>', "decoder-endpoint requirement"),
    ("requirements", "<tr><td>304</td>", "<tr><td>304-disabled</td>", "Appendix disposition"),
    ("requirements", "<tr><td>322</td>", "<tr><td>322-disabled</td>", "control-finality Appendix disposition"),
    ("requirements", "<tr><td>323</td>", "<tr><td>323-disabled</td>", "decoder-endpoint Appendix disposition"),
    ("hardening", "**R-S11ev/R-S11e-183 directly reachable, bounded, fresh outgoing-viewer video mailbox", "**R-S11ev-disabled/R-S11e-183 directly reachable, bounded, fresh outgoing-viewer video mailbox", "hardening ledger"),
    ("hardening", "**R-S11fn/R-S11e-201 semantic, non-dropping viewer decoder-control finality", "**R-S11fn-disabled/R-S11e-201 semantic, non-dropping viewer decoder-control finality", "control-finality hardening ledger"),
    ("hardening", "**R-S11fo/R-S11e-202 exact viewer decoder-endpoint finality", "**R-S11fo-disabled/R-S11e-202 exact viewer decoder-endpoint finality", "decoder-endpoint hardening ledger"),
    ("verify", "cargo test --lib --features linux-pkg-config client::tests::r_s11ev_ --color never", "cargo test --lib --features linux-pkg-config client::tests::disabled_ --color never", "shared behavior gate"),
    ("verify", "cargo test --lib --features linux-pkg-config client::tests::r_s11fn_ --color never", "cargo test --lib --features linux-pkg-config client::tests::disabled_fn_ --color never", "control-finality behavior gate"),
    ("verify", "cargo test --lib --features linux-pkg-config client::tests::r_s11fo_ --color never", "cargo test --lib --features linux-pkg-config client::tests::disabled_fo_ --color never", "decoder-endpoint behavior gate"),
    ("verify", "python3 scripts/verify-viewer-video-mailbox.py --repo . --self-test", "python3 scripts/verify-viewer-video-mailbox.py --repo .", "shared mutation gate"),
    ("apple", "python3 scripts/verify-viewer-video-mailbox.py --repo . --self-test", "python3 scripts/verify-viewer-video-mailbox.py --repo .", "Apple mutation gate"),
    ("workspace", '"viewer_video_mailbox_verifier": (', '"viewer_video_mailbox_verifier_disabled": (', "independent source binding"),
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
        print(f"viewer video mailbox verifier self-test passed ({len(MUTATIONS)} mutations)")
    else:
        print("viewer video mailbox verifier passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VerificationError as error:
        print(f"viewer video mailbox verifier failed: {error}")
        raise SystemExit(1)
