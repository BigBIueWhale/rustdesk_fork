#!/usr/bin/env python3
"""Verify event-driven worker and exact voice-call input ownership."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Dict, Tuple


class VerificationError(RuntimeError):
    pass


def require(source: str, needle: str, label: str) -> None:
    if needle not in source:
        raise VerificationError(f"missing {label}")


def require_exact_count(source: str, needle: str, count: int, label: str) -> None:
    actual = source.count(needle)
    if actual != count:
        raise VerificationError(f"{label}: expected {count}, found {actual}")


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
        "io_loop": (repo / "src/client/io_loop.rs").read_text(encoding="utf-8"),
        "client": (repo / "src/client.rs").read_text(encoding="utf-8"),
        "audio": (repo / "src/server/audio_service.rs").read_text(encoding="utf-8"),
        "connection": (repo / "src/server/connection.rs").read_text(encoding="utf-8"),
        "requirements": (repo / "requirements.html").read_text(encoding="utf-8"),
        "hardening": (repo / "HARDENING_STATUS.md").read_text(encoding="utf-8"),
        "verify": (repo / "scripts/verify.sh").read_text(encoding="utf-8"),
        "dart_verify": (repo / "scripts/dart-verify.sh").read_text(encoding="utf-8"),
        "apple": (repo / "scripts/apple-conform-check.sh").read_text(encoding="utf-8"),
    }


def validate(sources: Dict[str, str]) -> None:
    io_loop = sources["io_loop"]
    owner = extract_rust_item(io_loop, "struct VoiceCallAudio", "voice-call owner")
    for needle, label in (
        ("subscription: Option<ConnInner>", "exact subscription owner"),
        ("input_lease: Option<audio_service::VoiceCallInputLease>", "exact input lease owner"),
        ("receiver: AudioEgressReceiver", "bounded audio receiver owner"),
    ):
        require(owner, needle, label)
    for forbidden in (
        "AtomicBool",
        "JoinHandle",
        "UnboundedSender",
        "UnboundedReceiver",
        "thread:",
    ):
        if forbidden in owner:
            raise VerificationError(
                f"voice-call owner retains superseded worker/queue state {forbidden!r}"
            )

    stop = extract_rust_item(
        io_loop,
        "fn stop(&mut self)",
        "voice-call stop",
    )
    require_order(
        stop,
        (
            "if let Some(subscription) = self.subscription.take()",
            "CLIENT_SERVER",
            ".write()",
            ".unwrap()",
            ".subscribe(",
            "audio_service::NAME",
            "subscription",
            "false",
            "drop(self.input_lease.take());",
        ),
        "exact unsubscribe before input-lease release",
    )
    for forbidden in (
        "try_recv",
        "thread::sleep",
        "Runtime::new",
        "block_on",
        "JoinHandle",
        ".join()",
    ):
        if forbidden in stop:
            raise VerificationError(f"voice-call stop retains polling/runtime shape {forbidden!r}")

    owner_drop = extract_rust_item(io_loop, "impl Drop for VoiceCallAudio", "voice-call Drop")
    require(owner_drop, "self.stop();", "hard-Drop exact owner retirement")

    receive = extract_rust_item(
        io_loop, "async fn recv_voice_call_audio(", "event-driven voice-call receive"
    )
    require_order(
        receive,
        (
            "voice_call.as_mut()",
            "Some(voice_call)",
            "voice_call.receiver.recv().await",
            ".map(|(_, message)| message)",
            "None => std::future::pending().await",
        ),
        "event-driven exact-owner receive with disabled absent branch",
    )
    for forbidden in (
        "try_recv",
        "blocking_recv",
        "thread::sleep",
        "tokio::spawn",
        "Runtime::new",
        "block_on",
        "unbounded_channel",
    ):
        if forbidden in receive:
            raise VerificationError(
                f"voice-call receive retains polling/detached-runtime shape {forbidden!r}"
            )
    require_exact_count(
        io_loop,
        "async fn recv_voice_call_audio(",
        2,
        "non-iOS receive plus iOS disabled branch",
    )
    ios_receive_marker = '#[cfg(target_os = "ios")]\nasync fn recv_voice_call_audio('
    require(
        io_loop,
        ios_receive_marker,
        "iOS disabled voice-call receive branch",
    )
    ios_receive_start = io_loop.index(ios_receive_marker)
    ios_receive_end = io_loop.index("// R-S11ed:", ios_receive_start)
    ios_receive = io_loop[ios_receive_start:ios_receive_end]
    require_order(
        ios_receive,
        (
            "let _ = voice_call;",
            "std::future::pending().await",
        ),
        "iOS voice-call receive remains permanently disabled",
    )

    remote = extract_rust_item(io_loop, "pub struct Remote", "outgoing viewer owner")
    require(
        remote,
        "voice_call_audio: Option<VoiceCallAudio>",
        "outgoing exact audio owner slot",
    )

    io_round = extract_rust_item(io_loop, "pub async fn io_loop(", "outgoing I/O round")
    require_order(
        io_round,
        (
            "voice_call_audio = recv_voice_call_audio(&mut self.voice_call_audio)",
            "let Some(message) = voice_call_audio",
            "self.stop_voice_call().await;",
            "peer.send(&message as &Message).await",
        ),
        "bounded receiver to sole peer writer",
    )
    audio_branch_start = io_round.index(
        "voice_call_audio = recv_voice_call_audio(&mut self.voice_call_audio)"
    )
    audio_branch_end = io_round.index("_msg = rx_clip_client.recv()", audio_branch_start)
    audio_branch = io_round[audio_branch_start:audio_branch_end]
    for forbidden in (
        "self.sender.send",
        "Data::Message",
        "unbounded_channel",
        "tokio::spawn",
        "std::thread",
    ):
        if forbidden in audio_branch:
            raise VerificationError(
                f"voice-call sole-writer branch retains intermediate path {forbidden!r}"
            )

    start = extract_rust_item(
        io_loop,
        "fn start_voice_call(&mut self) -> Option<VoiceCallAudio>",
        "voice-call start",
    )
    require_order(
        start,
        (
            "let input_lease =",
            "match crate::audio_service::acquire_voice_call_input(",
            "get_default_sound_input()",
            "let (tx_audio_data, rx_audio_data) = audio_egress_channel();",
            "let client_conn_inner =",
            "ConnInner::with_audio(conn_id, None, None, Some(tx_audio_data))",
            "client_conn_inner.clone()",
            "true",
            "VoiceCallAudio::new(",
            "client_conn_inner",
            "input_lease",
            "rx_audio_data",
        ),
        "input lease, bounded subscription, and composite owner construction",
    )
    for forbidden in (
        "std::sync::mpsc::channel",
        "unbounded_channel",
        "rx.try_recv()",
        "rx_audio_data.try_recv()",
        "TryRecvError",
        "std::thread::spawn(move ||",
        "std::thread::Builder",
        "rustdesk-viewer-voice-call",
        "tx_audio.send(Data::Message",
        "cleanup_subscription",
        "stop_requested",
    ):
        if forbidden in start:
            raise VerificationError(
                f"voice-call start retains legacy worker/queue shape {forbidden!r}"
            )
    if "set_voice_call_input_device(None" in start:
        raise VerificationError("outgoing worker retains ambient global input cleanup")

    shutdown = extract_rust_item(io_loop, "async fn shutdown_workers", "viewer worker shutdown")
    require_exact_count(
        io_loop,
        "voice_call_audio.stop()",
        2,
        "explicit voice-call audio stop sinks",
    )
    require_order(
        shutdown,
        (
            "if let Some(mut voice_call_audio) = self.voice_call_audio.take()",
            "voice_call_audio.stop();",
            "Self::join_workers(workers).await;",
        ),
        "voice-call retirement before unrelated media-worker joins",
    )
    for forbidden in (
        'reap_media_worker("voice-call"',
        "rustdesk-viewer-voice-call",
        "VoiceCallThread",
        "voice_call_thread",
    ):
        if forbidden in io_loop:
            raise VerificationError(
                f"outgoing voice call retains retired worker authority {forbidden!r}"
            )

    connection = sources["connection"]
    audio_state = extract_rust_item(
        connection, "struct AudioEgressState", "bounded audio egress state"
    )
    require(
        connection,
        "const AUDIO_EGRESS_WAKE_CAPACITY: usize = 1;",
        "capacity-one audio wake",
    )
    require(
        audio_state,
        "format: Option<(Instant, Arc<Message>)>",
        "single pending audio format",
    )
    require(
        audio_state,
        "frame: Option<(Instant, Arc<Message>)>",
        "single pending audio frame",
    )
    audio_channel = extract_rust_item(
        connection,
        "pub(crate) fn audio_egress_channel()",
        "bounded audio channel construction",
    )
    require(
        audio_channel,
        "mpsc::channel(AUDIO_EGRESS_WAKE_CAPACITY)",
        "bounded capacity-one audio wake channel",
    )
    if "unbounded_channel" in audio_channel:
        raise VerificationError("audio mailbox construction regained an unbounded wake channel")

    audio_sender = extract_rust_item(
        connection, "impl AudioEgressSender", "bounded audio sender"
    )
    require_order(
        audio_sender,
        (
            "Some(message::Union::AudioFrame(_))",
            "state.frame = Some(queued);",
            "Some(misc::Union::AudioFormat(_))",
            "state.format = Some(queued);",
            "state.frame = None;",
            "self.wake.try_send(())",
            "TrySendError::Full(_)",
            "TrySendError::Closed(_)",
            "state.format = None;",
            "state.frame = None;",
        ),
        "latest-frame coalescing, generation retirement, and closed-receiver release",
    )
    for forbidden in (
        ".await",
        "blocking_send",
        "unbounded_channel",
        "thread::",
        "Runtime::new",
        "block_on",
    ):
        if forbidden in audio_sender:
            raise VerificationError(
                f"audio producer regained blocking/runtime behavior {forbidden!r}"
            )

    audio_receiver = extract_rust_item(
        connection, "impl AudioEgressReceiver", "event-driven audio receiver"
    )
    require_order(
        audio_receiver,
        (
            "state.format.take().or_else(|| state.frame.take())",
            "pub(crate) async fn recv(&mut self)",
            "if let Some(queued) = self.take_next()",
            "self.wake.recv().await?",
        ),
        "format-first event-driven audio receive",
    )
    require(
        connection,
        "#[cfg(test)]\n    fn blocking_recv(&mut self)",
        "test-only blocking audio receiver",
    )
    for forbidden in ("try_recv", "thread::sleep", "Runtime::new", "block_on"):
        if forbidden in audio_receiver:
            raise VerificationError(
                f"audio receiver regained polling/runtime behavior {forbidden!r}"
            )
    audio_receiver_drop = extract_rust_item(
        connection,
        "impl Drop for AudioEgressReceiver",
        "audio receiver retained-state retirement",
    )
    require_order(
        audio_receiver_drop,
        (
            "self.wake.close();",
            "lock_audio_egress_state(&self.state)",
            "state.format = None;",
            "state.frame = None;",
        ),
        "receiver close before retained audio release",
    )
    if ".await" in audio_receiver_drop:
        raise VerificationError("audio receiver Drop contains asynchronous cleanup")

    subscriber = extract_rust_item(
        connection, "impl Subscriber for ConnInner", "audio subscriber routing"
    )
    require_order(
        subscriber,
        (
            "let tx_by_audio = match &msg.union",
            "Some(message::Union::AudioFrame(_))",
            "Some(misc::Union::AudioFormat(_))",
            "if tx_by_audio",
            "self.tx_audio.as_ref()",
            "tx.send(msg);",
            "return;",
            "match &msg.union",
            "Some(message::Union::VideoFrame(_))",
            "video frame bypassed exact acknowledgement-round enqueue",
            "Some(misc::Union::SwitchDisplay(_))",
            "self.retire_video_frames(tx.send_switch_display(msg));",
        ),
        "audio routing before general/video queues",
    )

    controlled = extract_rust_item(
        connection, "pub async fn start(", "controlled connection writer"
    )
    require_order(
        controlled,
        (
            "let (tx, mut rx) = mpsc::unbounded_channel::<(Instant, Arc<Message>)>();",
            "let (tx_audio, mut rx_audio) = audio_egress_channel();",
            "ConnInner::with_audio(id, Some(tx), Some(tx_video), Some(tx_audio))",
            "Some((instant, value)) = rx_audio.recv()",
            "instant.elapsed() > Duration::from_secs(1)",
            "Some(message::Union::AudioFrame(_))",
            "conn.stream.send(&value as &Message).await",
            "Some((_instant, value)) = rx.recv()",
        ),
        "controlled bounded audio branch before general queue branch",
    )
    general_start = controlled.index("Some((_instant, value)) = rx.recv()")
    general_end = controlled.index("_ = second_timer.tick()", general_start)
    if "AudioFrame" in controlled[general_start:general_end]:
        raise VerificationError("general controlled queue regained audio-frame handling")

    for test_name in (
        "r_s11eh_audio_egress_retains_only_the_latest_frame",
        "r_s11eh_audio_format_precedes_its_latest_frame",
        "r_s11eh_new_audio_format_retires_an_old_pending_frame",
        "r_s11eh_conn_inner_routes_audio_away_from_control_and_video",
        "r_s11eh_audio_egress_closes_after_the_exact_sender_retires",
        "r_s11eh_async_audio_egress_waits_without_polling_and_closes",
    ):
        require_exact_count(
            connection,
            f"fn {test_name}()",
            1,
            f"focused bounded-audio test {test_name}",
        )
    require(
        connection,
        "receiver retirement must release retained audio without another producer send",
        "receiver-retirement retained-audio behavior assertion",
    )

    audio = sources["audio"]
    input_state = extract_rust_item(
        audio, "struct VoiceCallInputState", "voice-call input state"
    )
    require(input_state, "device: Option<String>", "shared selected input")
    require(input_state, "owners: usize", "active input owner count")
    acquire_state = extract_rust_item(
        audio,
        "fn acquire(&mut self, default_device: Option<String>)",
        "voice-call input state acquisition",
    )
    require_order(
        acquire_state,
        (
            "self.owners.checked_add(1)",
            "self.owners = owners;",
            "if self.device.is_none() && default_device.is_some()",
            "self.device = default_device;",
        ),
        "bounded owner acquisition and first-owner default",
    )
    release_state = extract_rust_item(
        audio, "fn release(&mut self)", "voice-call input state release"
    )
    require_order(
        release_state,
        (
            "self.owners.checked_sub(1)",
            "self.owners = owners;",
            "if owners == 0",
            "self.device.take().is_some()",
        ),
        "final-owner-only input reset",
    )
    input_lease = extract_rust_item(
        audio, "pub struct VoiceCallInputLease", "private voice-call input lease"
    )
    require(input_lease, "_private: ()", "non-forgeable input lease")
    input_drop = extract_rust_item(
        audio, "impl Drop for VoiceCallInputLease", "voice-call input lease Drop"
    )
    require_order(
        input_drop,
        (
            "VOICE_CALL_INPUT_STATE.lock().unwrap().release()",
            "std::process::abort();",
            "if restart_required",
            "restart();",
        ),
        "exact lease release and invariant failure",
    )
    acquire_input = extract_rust_item(
        audio,
        "pub fn acquire_voice_call_input(",
        "voice-call input lease acquisition",
    )
    require_order(
        acquire_input,
        (
            ".acquire(default_device)",
            "if restart_required",
            "restart();",
            "Ok(VoiceCallInputLease { _private: () })",
        ),
        "state acquisition before private lease construction",
    )
    setter = extract_rust_item(
        audio,
        "pub fn set_voice_call_input_device(device: String)",
        "voice-call device selection",
    )
    require(setter, ".select_device(device)", "device selection without owner mutation")
    select_device = extract_rust_item(
        audio,
        "fn select_device(&mut self, device: String)",
        "non-clearing voice-call device selection",
    )
    require(
        select_device,
        "self.device = Some(device);",
        "selected voice-call device installation",
    )
    if "set_if_present" in audio:
        raise VerificationError("voice-call input retains boolean ownership ambiguity")
    for test_name in (
        "r_s11e83_voice_call_input_remains_selected_until_the_final_owner_releases",
        "r_s11e83_voice_call_input_owner_count_fails_closed",
    ):
        require_exact_count(audio, f"fn {test_name}()", 1, f"focused test {test_name}")

    require(
        connection,
        "voice_call_input: Option<audio_service::VoiceCallInputLease>",
        "controlled exact input owner",
    )
    if "voice_calling" in connection:
        raise VerificationError("controlled call retains parallel boolean ownership")
    handle_voice = extract_rust_item(
        connection,
        "pub async fn handle_voice_call(&mut self, accepted: bool)",
        "controlled voice-call acceptance",
    )
    require_order(
        handle_voice,
        (
            "crate::audio_service::acquire_voice_call_input(",
            "self.voice_call_input = Some(input_lease);",
            "let msg = new_voice_call_response(ts.get(), accepted);",
            "self.send(msg).await;",
        ),
        "lease-before-response acceptance ownership",
    )
    close_voice = extract_rust_item(
        connection,
        "pub async fn close_voice_call(&mut self)",
        "controlled voice-call close",
    )
    require_order(
        close_voice,
        (
            "drop(self.voice_call_input.take());",
            "self.voice_call_request_timestamp = None;",
            "self.stop_controlled_audio().await;",
        ),
        "exact input release before decoder drain",
    )
    on_close = extract_rust_item(connection, "async fn on_close", "connection close")
    require_order(
        on_close,
        (
            "drop(self.voice_call_input.take());",
            "self.stop_controlled_audio().await;",
        ),
        "connection close input release before await",
    )
    connection_drop = extract_rust_item(
        connection, "impl Drop for Connection", "connection Drop"
    )
    require(
        connection_drop,
        "drop(self.voice_call_input.take());",
        "cancellation-safe controlled input release",
    )
    require_exact_count(
        connection,
        "drop(self.voice_call_input.take());",
        3,
        "controlled input release sinks",
    )
    if "set_voice_call_input_device(None" in connection:
        raise VerificationError("controlled call retains ambient global input cleanup")

    for key, needle, label in (
        ("requirements", '<span class="id">R-S11bp</span>', "R-S11bp requirement"),
        ("requirements", "<tr><td>209</td>", "Appendix C #209"),
        ("requirements", '<span class="id">R-S11bq</span>', "R-S11bq requirement"),
        ("requirements", "<tr><td>210</td>", "Appendix C #210"),
        (
            "hardening",
            "R-S11bp/R-S11e-82 — outgoing voice-call capture is event-driven and exact-subscription-owned",
            "voice-call worker hardening ledger",
        ),
        (
            "hardening",
            "R-S11bq/R-S11e-83 — voice-call input selection has exact concurrent owners",
            "voice-call input ownership ledger",
        ),
        ("requirements", '<span class="id">R-S11eh</span>', "R-S11eh requirement"),
        ("requirements", "<tr><td>287</td>", "Appendix C #287"),
        (
            "hardening",
            "R-S11eh/R-S11e-152",
            "bounded audio egress hardening ledger",
        ),
        (
            "verify",
            "python3 scripts/verify-viewer-voice-call-worker.py --repo . --self-test",
            "shared focused-verifier wiring",
        ),
        (
            "verify",
            "server::connection::audio_egress_tests::r_s11eh_ -- --test-threads=1",
            "shared bounded-audio behavior wiring",
        ),
        (
            "dart_verify",
            "server::connection::audio_egress_tests::r_s11eh_",
            "generated-bridge bounded-audio behavior wiring",
        ),
        (
            "apple",
            "python3 scripts/verify-viewer-voice-call-worker.py --repo . --self-test",
            "Apple focused-verifier wiring",
        ),
    ):
        require(sources[key], needle, label)


Mutation = Tuple[str, str, str, str]

MUTATIONS: Tuple[Mutation, ...] = (
    ("io_loop", "struct VoiceCallAudio", "struct VoiceCallThread", "exact audio owner type"),
    ("io_loop", "subscription: Option<ConnInner>", "subscription_removed: Option<ConnInner>", "subscription owner"),
    ("io_loop", "input_lease: Option<audio_service::VoiceCallInputLease>", "input_lease_removed: Option<audio_service::VoiceCallInputLease>", "input lease owner"),
    ("io_loop", "receiver: AudioEgressReceiver", "receiver_removed: AudioEgressReceiver", "bounded receiver owner"),
    ("io_loop", "if let Some(subscription) = self.subscription.take()", "if false", "exact unsubscribe"),
    ("io_loop", ".subscribe(audio_service::NAME, subscription, false)", ".subscribe(audio_service::NAME, subscription, true)", "exact unsubscribe action"),
    ("io_loop", "drop(self.input_lease.take());", "", "exact input release"),
    ("io_loop", "impl Drop for VoiceCallAudio", "impl VoiceCallAudio", "hard-Drop retirement"),
    ("io_loop", "voice_call.receiver.recv().await", "voice_call.receiver.blocking_recv()", "async event-driven receive"),
    ("io_loop", "None => std::future::pending().await", "None => return None", "disabled absent-owner branch"),
    ("io_loop", '#[cfg(target_os = "ios")]\nasync fn recv_voice_call_audio(', '#[cfg(any())]\nasync fn recv_voice_call_audio(', "iOS disabled receive branch"),
    ("io_loop", "voice_call_audio: Option<VoiceCallAudio>", "voice_call_audio_removed: Option<VoiceCallAudio>", "outgoing exact owner slot"),
    ("io_loop", "voice_call_audio = recv_voice_call_audio(&mut self.voice_call_audio)", "voice_call_audio = std::future::pending()", "direct select receive"),
    ("io_loop", "peer.send(&message as &Message).await", "self.sender.send(Data::Message((*message).clone()))", "sole peer writer"),
    ("io_loop", "let (tx_audio_data, rx_audio_data) = audio_egress_channel();", "let (tx_audio_data, rx_audio_data) = mpsc::unbounded_channel();", "bounded mailbox construction"),
    ("io_loop", "ConnInner::with_audio(conn_id, None, None, Some(tx_audio_data))", "ConnInner::new(conn_id, Some(tx_audio_data), None)", "audio-only subscription route"),
    ("io_loop", "VoiceCallAudio::new(", "VoiceCallAudio::new_removed(", "composite owner construction"),
    ("io_loop", "match crate::audio_service::acquire_voice_call_input(", "match crate::audio_service::acquire_voice_call_input_removed(", "outgoing input acquisition"),
    ("io_loop", "voice_call_audio.stop()", "drop(voice_call_audio)", "shutdown exact stop sink"),
    ("connection", "const AUDIO_EGRESS_WAKE_CAPACITY: usize = 1;", "const AUDIO_EGRESS_WAKE_CAPACITY: usize = 1024;", "bounded audio wake capacity"),
    ("connection", "format: Option<(Instant, Arc<Message>)>", "formats: Vec<(Instant, Arc<Message>)>", "single pending audio format"),
    ("connection", "frame: Option<(Instant, Arc<Message>)>", "frames: Vec<(Instant, Arc<Message>)>", "single pending audio frame"),
    ("connection", "mpsc::channel(AUDIO_EGRESS_WAKE_CAPACITY)", "mpsc::unbounded_channel()", "bounded audio wake channel"),
    ("connection", "state.frame = Some(queued);", "state.frames.push(queued);", "latest-frame coalescing"),
    ("connection", "state.format = Some(queued);", "state.formats.push(queued);", "single format replacement"),
    ("connection", "self.wake.try_send(())", "self.wake.blocking_send(())", "nonblocking producer wake"),
    ("connection", "state.format.take().or_else(|| state.frame.take())", "state.frame.take().or_else(|| state.format.take())", "format-before-frame ordering"),
    ("connection", "self.wake.recv().await?", "self.wake.try_recv().ok()?;", "event-driven async receive"),
    ("connection", "#[cfg(test)]\n    fn blocking_recv(&mut self)", "fn blocking_recv(&mut self)", "test-only blocking receive"),
    ("connection", "impl Drop for AudioEgressReceiver", "impl AudioEgressReceiver", "receiver retained-state retirement"),
    ("connection", "if tx_by_audio {", "if false && tx_by_audio {", "audio route admission"),
    ("connection", "video frame bypassed exact acknowledgement-round enqueue", "video frame accepted outside exact acknowledgement-round enqueue", "video frame acknowledgement-route isolation"),
    ("connection", "self.retire_video_frames(tx.send_switch_display(msg));", "let _ = tx.send_switch_display(msg);", "switch-display retires queued video"),
    ("connection", "let (tx_audio, mut rx_audio) = audio_egress_channel();", "let (tx_audio, mut rx_audio) = mpsc::unbounded_channel();", "controlled bounded audio mailbox"),
    ("connection", "Some((instant, value)) = rx_audio.recv()", "Some((instant, value)) = rx.recv()", "controlled direct audio receive"),
    ("connection", "fn r_s11eh_audio_egress_retains_only_the_latest_frame()", "fn audio_egress_retains_only_the_latest_frame()", "latest-frame behavior regression"),
    ("connection", "fn r_s11eh_new_audio_format_retires_an_old_pending_frame()", "fn new_audio_format_retires_an_old_pending_frame()", "codec-generation behavior regression"),
    ("connection", "fn r_s11eh_async_audio_egress_waits_without_polling_and_closes()", "fn async_audio_egress_waits_without_polling_and_closes()", "async receive behavior regression"),
    ("connection", "receiver retirement must release retained audio without another producer send", "receiver retirement retained audio", "receiver-retirement behavior assertion"),
    ("requirements", '<span class="id">R-S11bp</span>', '<span class="id">R-S11bp-disabled</span>', "normative requirement"),
    ("requirements", "<tr><td>209</td>", "<tr><td>209-disabled</td>", "Appendix disposition"),
    ("hardening", "R-S11bp/R-S11e-82 — outgoing voice-call capture is event-driven and exact-subscription-owned", "R-S11bp/R-S11e-82 — outgoing voice-call capture polls", "hardening ledger"),
    ("audio", "self.owners.checked_add(1)", "self.owners.saturating_add(1)", "bounded owner acquisition"),
    ("audio", "if owners == 0", "if owners <= 1", "final-owner-only reset"),
    ("audio", "pub fn set_voice_call_input_device(device: String)", "pub fn set_voice_call_input_device(device: Option<String>)", "non-clearing explicit selection API"),
    ("audio", "self.device = Some(device);", "self.device = None;", "selected device installation"),
    ("audio", "pub struct VoiceCallInputLease {\n    _private: (),", "pub struct VoiceCallInputLease;\n//", "non-forgeable lease"),
    ("audio", "VOICE_CALL_INPUT_STATE.lock().unwrap().release()", "Ok(false)", "lease Drop release"),
    ("audio", "fn r_s11e83_voice_call_input_remains_selected_until_the_final_owner_releases()", "fn voice_call_input_remains_selected_until_the_final_owner_releases()", "concurrent-owner regression"),
    ("audio", "fn r_s11e83_voice_call_input_owner_count_fails_closed()", "fn voice_call_input_owner_count_fails_closed()", "owner-bound regression"),
    ("connection", "voice_call_input: Option<audio_service::VoiceCallInputLease>", "voice_call_input_removed: Option<audio_service::VoiceCallInputLease>", "controlled lease owner"),
    ("connection", "self.voice_call_input = Some(input_lease);", "drop(input_lease);", "controlled lease installation"),
    ("connection", "drop(self.voice_call_input.take());", "self.voice_call_input.take();", "controlled exact release"),
    ("requirements", '<span class="id">R-S11bq</span>', '<span class="id">R-S11bq-disabled</span>', "input ownership requirement"),
    ("requirements", "<tr><td>210</td>", "<tr><td>210-disabled</td>", "input ownership Appendix disposition"),
    ("hardening", "R-S11bq/R-S11e-83 — voice-call input selection has exact concurrent owners", "R-S11bq/R-S11e-83 — voice-call input selection is ambient", "input ownership ledger"),
    ("requirements", '<span class="id">R-S11eh</span>', '<span class="id">R-S11eh-disabled</span>', "bounded audio requirement"),
    ("requirements", "<tr><td>287</td>", "<tr><td>287-disabled</td>", "bounded audio Appendix disposition"),
    ("hardening", "R-S11eh/R-S11e-152", "R-S11eh-disabled/R-S11e-152", "bounded audio hardening ledger"),
    ("verify", "server::connection::audio_egress_tests::r_s11eh_ -- --test-threads=1", "server::connection::audio_egress_tests::disabled_ -- --test-threads=1", "shared bounded-audio behavior gate"),
    ("dart_verify", "server::connection::audio_egress_tests::r_s11eh_", "server::connection::audio_egress_tests::disabled_", "generated-bridge bounded-audio behavior gate"),
    ("verify", "python3 scripts/verify-viewer-voice-call-worker.py --repo . --self-test", "python3 scripts/verify-viewer-voice-call-worker.py --repo .", "shared gate self-test"),
    ("apple", "python3 scripts/verify-viewer-voice-call-worker.py --repo . --self-test", "python3 scripts/verify-viewer-voice-call-worker.py --repo .", "Apple gate self-test"),
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
        print(f"viewer voice-call worker verifier self-test passed ({len(MUTATIONS)} mutations)")
    else:
        print("viewer voice-call worker verifier passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VerificationError as error:
        print(f"viewer voice-call worker verifier failed: {error}")
        raise SystemExit(1)
