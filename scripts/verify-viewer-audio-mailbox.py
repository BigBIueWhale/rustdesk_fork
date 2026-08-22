#!/usr/bin/env python3
"""Verify bounded, format-first, fresh peer-audio decoder admission."""

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
        "client": "src/client.rs",
        "io_loop": "src/client/io_loop.rs",
        "connection": "src/server/connection.rs",
        "requirements": "requirements.html",
        "hardening": "HARDENING_STATUS.md",
        "verify": "scripts/verify.sh",
        "apple": "scripts/apple-conform-check.sh",
        "workspace": "scripts/verify-verifier-workspace.py",
    }
    return {
        key: (repo / relative).read_text(encoding="utf-8")
        for key, relative in paths.items()
    }


def validate(sources: Dict[str, str]) -> None:
    client = sources["client"]
    io_loop = sources["io_loop"]
    connection = sources["connection"]

    for needle, label in (
        ("pub const AUDIO_FRAME_QUEUE_CAPACITY: usize = 8;", "eight-frame audio bound"),
        (
            "pub const MAX_AUDIO_FRAME_QUEUE_AGE: Duration = Duration::from_secs(1);",
            "one-second queued-audio freshness bound",
        ),
        ("struct QueuedAudioFrame", "timestamped queued audio frame"),
        ("struct AudioMailboxShared", "single shared audio mailbox"),
        ("pub(crate) struct AudioMailboxSender", "sole audio admission endpoint"),
        ("struct AudioMailboxReceiver", "sole audio consumer endpoint"),
    ):
        require(client, needle, label)
    for needle in (
        "pub enum MediaData",
        "pub type MediaSender",
        "mpsc::sync_channel::<MediaData>",
        "try_send(MediaData::AudioFrame",
        "try_send(MediaData::AudioFormat",
    ):
        forbid(client + io_loop + connection, needle, "retired generic audio queue")

    state = extract_rust_item(client, "struct AudioMailboxState", "audio mailbox state")
    require_order(
        state,
        (
            "format: Option<AudioFormat>",
            "format_key: Option<(u32, u32)>",
            "frames: VecDeque<QueuedAudioFrame>",
            "closed: bool",
        ),
        "constant-shape format and frame state",
    )
    for forbidden in ("HashMap", "HashSet", "Vec<AudioFormat>", "Unbounded"):
        forbid(state, forbidden, "unbounded or multi-format audio state")

    format_result = extract_rust_item(
        client, "pub(crate) enum AudioFormatAdmission", "audio format admission result"
    )
    require_order(
        format_result,
        ("Queued,", "Duplicate,", "Changed,", "Closed,"),
        "closed first-format admission outcomes",
    )
    frame_result = extract_rust_item(
        client, "pub(crate) enum AudioFrameAdmission", "audio frame admission result"
    )
    require_order(
        frame_result,
        ("Queued,", "ReplacedOldest,", "AwaitingFormat,", "Closed,"),
        "explicit real-time frame admission outcomes",
    )

    shared_close = extract_rust_item(
        client, "impl AudioMailboxShared", "audio mailbox closure"
    )
    require_order(
        shared_close,
        (
            "state.closed = true;",
            "state.format = None;",
            "state.frames.clear();",
            "drop(state);",
            "self.ready.notify_all();",
        ),
        "terminal close releases every retained payload before wake",
    )
    require(
        extract_rust_item(client, "impl Drop for AudioMailboxSender", "sender Drop"),
        "self.shared.close();",
        "sender-drop consumer wake",
    )
    require(
        extract_rust_item(client, "impl Drop for AudioMailboxReceiver", "receiver Drop"),
        "self.shared.close();",
        "receiver-drop producer rejection",
    )

    sender = extract_rust_item(client, "impl AudioMailboxSender", "audio producer")
    format_admission = extract_rust_item(
        sender, "pub(crate) fn admit_format", "first-format admission"
    )
    require_order(
        format_admission,
        (
            "if state.closed",
            "native_opus_format_admission(",
            "state.format_key,",
            "NativeOpusFormatAdmission::AcceptFirst",
            "state.format_key = Some(native_opus_format_key(",
            "state.format = Some(format);",
            "state.frames.clear();",
            "drop(state);",
            "self.shared.ready.notify_one();",
            "AudioFormatAdmission::Queued",
            "NativeOpusFormatAdmission::Duplicate => AudioFormatAdmission::Duplicate",
            "NativeOpusFormatAdmission::Changed => AudioFormatAdmission::Changed",
        ),
        "one pinned format is installed before frames and duplicate work is coalesced",
    )
    frame_admission = extract_rust_item(
        sender, "fn admit_frame_queued_at(", "timestamped audio frame admission"
    )
    require_order(
        frame_admission,
        (
            "if state.closed",
            "if state.format_key.is_none()",
            "AudioFrameAdmission::AwaitingFormat",
            "if state.frames.len() >= AUDIO_FRAME_QUEUE_CAPACITY",
            "state.frames.pop_front();",
            "AudioFrameAdmission::ReplacedOldest",
            "state.frames.push_back(QueuedAudioFrame { queued_at, frame });",
            "drop(state);",
            "self.shared.ready.notify_one();",
        ),
        "pre-format rejection and exact oldest-frame replacement",
    )
    for forbidden in (
        "try_send",
        "send(",
        ".await",
        "thread::sleep",
        "Runtime::new",
        "block_on",
        "spawn(",
    ):
        forbid(frame_admission, forbidden, "blocking, retrying, or detached audio admission")

    receive = extract_rust_item(
        client, "impl AudioMailboxReceiver", "event-driven audio receive"
    )
    require_order(
        receive,
        (
            "while state.format.is_none() && state.frames.is_empty() && !state.closed",
            "state = self.shared.ready.wait(state).unwrap();",
            "if state.closed",
            "if let Some(format) = state.format.take()",
            "return Some(AudioMailboxItem::Format(format));",
            "let Some(frame) = state.frames.pop_front()",
            "if audio_frame_is_fresh(frame.queued_at, std::time::Instant::now())",
            "return Some(AudioMailboxItem::Frame(frame.frame));",
        ),
        "format-first event-driven receive with stale-frame refusal",
    )
    for forbidden in ("recv_timeout", "try_recv", "thread::sleep", "saturating"):
        forbid(receive, forbidden, "polling or silent audio receive repair")

    owner_state = extract_rust_item(client, "pub struct OwnedMediaThread", "owned audio worker state")
    require(
        owner_state,
        "sender: Option<AudioMailboxSender>",
        "exact audio admission owner",
    )
    owner = extract_rust_item(client, "impl OwnedMediaThread", "owned audio worker")
    require_order(
        owner,
        (
            "Some(sender) => sender.admit_format(format)",
            "None => AudioFormatAdmission::Closed",
            "Some(sender) => sender.admit_frame(frame)",
            "None => AudioFrameAdmission::Closed",
            "drop(self.sender.take());",
            "self.thread.take()",
        ),
        "typed admission and close-before-handle-transfer ownership",
    )
    worker = extract_rust_item(client, "fn new_audio_thread()", "audio decoder worker")
    require_order(
        worker,
        (
            "let (audio_sender, audio_receiver) = audio_mailbox();",
            "while let Some(data) = audio_receiver.recv()",
            "AudioMailboxItem::Frame(frame)",
            "audio_handler.handle_frame(frame);",
            "AudioMailboxItem::Format(format)",
            "audio_handler.handle_format(format);",
            "(audio_sender, thread)",
        ),
        "sole mailbox consumer and decoder handoff",
    )

    viewer_format = extract_between(
        io_loop,
        "Some(misc::Union::AudioFormat(f)) => {",
        "Some(misc::Union::ChatMessage(c))",
        "viewer audio-format caller",
    )
    require_order(
        viewer_format,
        (
            "native_opus_format_within_limit",
            "self.audio_thread.admit_format(f)",
            "AudioFormatAdmission::Queued",
            "AudioFormatAdmission::Duplicate",
            "AudioFormatAdmission::Changed",
            "AudioFormatAdmission::Closed",
        ),
        "viewer validates and handles every format outcome",
    )
    viewer_frame = extract_between(
        io_loop,
        "Some(message::Union::AudioFrame(frame)) => {",
        "Some(message::Union::FileAction(action))",
        "viewer audio-frame caller",
    )
    require_order(
        viewer_frame,
        (
            "native_opus_packet_within_limit",
            "self.audio_thread.admit_frame(frame)",
            "AudioFrameAdmission::Queued",
            "AudioFrameAdmission::ReplacedOldest",
            "AudioFrameAdmission::AwaitingFormat",
            "AudioFrameAdmission::Closed",
        ),
        "viewer handles every bounded frame outcome",
    )

    controlled_format = extract_between(
        connection,
        "// R-S19: peer->host audio playback is voice-call only.",
        "Some(misc::Union::ChangeResolution",
        "controlled audio-format caller",
    )
    require_order(
        controlled_format,
        (
            "self.voice_call_input.is_some()",
            "native_opus_format_within_limit",
            "NativeOpusFormatAdmission::AcceptFirst",
            "let decoder = start_audio_thread();",
            "match decoder.admit_format(format)",
            "AudioFormatAdmission::Queued",
            "self.controlled_audio = Some(ControlledAudioThread",
            "AudioFormatAdmission::Duplicate",
            "| AudioFormatAdmission::Changed",
            "| AudioFormatAdmission::Closed",
            "decoder.close_and_join().await;",
        ),
        "controlled format authorization, first-format install, and failed-start drain",
    )
    controlled_frame = extract_between(
        connection,
        "// R-S19: peer->host audio frames are voice-call only.",
        "Some(message::Union::VoiceCallRequest(request))",
        "controlled audio-frame caller",
    )
    require_order(
        controlled_frame,
        (
            "self.voice_call_input.is_some()",
            "audio.decoder.admit_frame(frame)",
            "AudioFrameAdmission::Queued",
            "AudioFrameAdmission::ReplacedOldest",
            "AudioFrameAdmission::AwaitingFormat",
            "AudioFrameAdmission::Closed",
        ),
        "controlled authorized playback handles every frame outcome",
    )

    for test in (
        "r_s11hi_audio_mailbox_requires_and_prioritizes_the_first_format",
        "r_s11hi_audio_mailbox_pins_one_format_without_replay_work",
        "r_s11hi_audio_mailbox_retires_oldest_frame_at_its_exact_bound",
        "r_s11hi_audio_mailbox_discards_stale_frames_before_delivery",
        "owned_media_thread_closes_admission_before_join",
        "owned_media_thread_hard_drop_never_joins_inline",
    ):
        require(client, f"fn {test}()", f"{test} behavior regression")

    for key, needle, label in (
        (
            "requirements",
            '<div class="req"><span class="id">R-S11hi</span>',
            "R-S11hi requirement",
        ),
        ("requirements", "<tr><td>369</td>", "Appendix C #369"),
        (
            "hardening",
            "### R-S11hi/R-S11e-246 — bounded format-first peer-audio decoder mailbox",
            "peer-audio decoder hardening ledger",
        ),
        (
            "verify",
            "cargo test --lib --features linux-pkg-config,flutter client::tests::r_s11hi_ --color never",
            "shared Rust behavior-test wiring",
        ),
        (
            "verify",
            "python3 scripts/verify-viewer-audio-mailbox.py --repo . --self-test",
            "shared focused-verifier wiring",
        ),
        (
            "apple",
            "python3 scripts/verify-viewer-audio-mailbox.py --repo . --self-test",
            "Apple/shared focused-verifier wiring",
        ),
        (
            "workspace",
            '            "viewer_audio_mailbox_verifier": (\n'
            '                repo / "scripts/verify-viewer-audio-mailbox.py"\n'
            '            ).read_text(encoding="utf-8"),',
            "independent focused-verifier source binding",
        ),
        (
            "workspace",
            "    validate_viewer_audio_mailbox_contract(sources)\n",
            "independent validator dispatch",
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
    ("client", "pub const AUDIO_FRAME_QUEUE_CAPACITY: usize = 8;", "pub const AUDIO_FRAME_QUEUE_CAPACITY: usize = 8000;", "frame bound"),
    ("client", "pub const MAX_AUDIO_FRAME_QUEUE_AGE: Duration = Duration::from_secs(1);", "pub const MAX_AUDIO_FRAME_QUEUE_AGE: Duration = Duration::from_secs(10);", "freshness bound"),
    ("client", "format: Option<AudioFormat>", "formats: Vec<AudioFormat>", "single pending format"),
    ("client", "format_key: Option<(u32, u32)>", "format_key: Vec<(u32, u32)>", "pinned format identity"),
    ("client", "impl Drop for AudioMailboxSender", "impl AudioMailboxSender", "sender-drop finality"),
    ("client", "impl Drop for AudioMailboxReceiver", "impl AudioMailboxReceiver", "receiver-drop finality"),
    ("client", "if state.format_key.is_none()", "if false && state.format_key.is_none()", "pre-format refusal"),
    ("client", "state.frames.pop_front();", "state.frames.pop_back();", "oldest-frame retirement"),
    ("client", "if audio_frame_is_fresh(frame.queued_at", "if true || audio_frame_is_fresh(frame.queued_at", "dequeue freshness"),
    ("client", "if let Some(format) = state.format.take()", "if false { let Some(format) = state.format.take() else { unreachable!() };", "format-first delivery"),
    ("client", "fn r_s11hi_audio_mailbox_retires_oldest_frame_at_its_exact_bound()", "fn audio_mailbox_retires_oldest_frame_at_its_exact_bound()", "overflow regression"),
    ("io_loop", "self.audio_thread.admit_format(f)", "self.audio_thread.drop_format(f)", "viewer format caller"),
    ("io_loop", "self.audio_thread.admit_frame(frame)", "self.audio_thread.drop_frame(frame)", "viewer frame caller"),
    ("connection", "match decoder.admit_format(format)", "match AudioFormatAdmission::Closed", "controlled first-format caller"),
    ("connection", "audio.decoder.admit_frame(frame)", "AudioFrameAdmission::Queued", "controlled frame caller"),
    ("requirements", '<span class="id">R-S11hi</span>', '<span class="id">R-S11hi-disabled</span>', "requirement"),
    ("requirements", "<tr><td>369</td>", "<tr><td>369-disabled</td>", "Appendix C row"),
    ("hardening", "R-S11hi/R-S11e-246 — bounded format-first peer-audio decoder mailbox", "R-S11hi-disabled/R-S11e-246 — bounded format-first peer-audio decoder mailbox", "hardening ledger"),
    ("verify", "python3 scripts/verify-viewer-audio-mailbox.py --repo . --self-test", "true # peer-audio mailbox verifier disabled", "shared gate"),
    ("apple", "python3 scripts/verify-viewer-audio-mailbox.py --repo . --self-test", "true # peer-audio mailbox verifier disabled", "Apple gate"),
    (
        "workspace",
        '            "viewer_audio_mailbox_verifier": (\n'
        '                repo / "scripts/verify-viewer-audio-mailbox.py"\n'
        '            ).read_text(encoding="utf-8"),',
        '            "viewer_audio_mailbox_verifier_disabled": (\n'
        '                repo / "scripts/verify-viewer-audio-mailbox.py"\n'
        '            ).read_text(encoding="utf-8"),',
        "independent source binding",
    ),
    (
        "workspace",
        "    validate_viewer_audio_mailbox_contract(sources)\n",
        "    validate_viewer_audio_mailbox_contract_disabled(sources)\n",
        "independent dispatch",
    ),
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
        print(f"viewer audio mailbox verifier self-test passed ({len(MUTATIONS)} mutations)")
    else:
        print("viewer audio mailbox verifier passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VerificationError as error:
        print(f"viewer audio mailbox verifier failed: {error}")
        raise SystemExit(1)
