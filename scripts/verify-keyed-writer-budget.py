#!/usr/bin/env python3
"""Verify exact count-and-byte ownership for every keyed TCP writer frame."""

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


def load_sources(repo: Path) -> Dict[str, str]:
    paths = {
        "tcp": "libs/hbb_common/src/tcp.rs",
        "codec": "libs/hbb_common/src/bytes_codec.rs",
        "cpace": "libs/hbb_common/src/cpace.rs",
        "transport": "docs/TRANSPORT-SECURITY.md",
        "crypto_scope": "docs/CRYPTO-AUDIT-SCOPE.md",
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
    tcp = sources["tcp"]
    for needle, label in (
        ("const WRITER_CHANNEL_CAP: usize = 512;", "retained-frame ceiling"),
        (
            "const WRITER_RETAINED_CIPHERTEXT_PACKETS: usize = 2;",
            "two-packet ciphertext budget",
        ),
        ("struct WriterFrameReservation", "exact frame reservation"),
        ("_frame: OwnedSemaphorePermit", "owned frame permit"),
        (
            "_ciphertext_bytes: OwnedSemaphorePermit",
            "owned ciphertext-byte permit",
        ),
        ("struct WriterAdmission", "shared keyed-writer admission"),
        ("writer_admission: WriterAdmission", "keyed-stream admission owner"),
        ("reservation: WriterFrameReservation", "frame-command reservation owner"),
    ):
        require(tcp, needle, label)
    forbid(tcp, "Outbound frames are server-generated", "false outbound-size trust claim")
    forbid(tcp, "encoder-bounded, not attacker-controlled", "false encoder-bound claim")

    admission = extract_braced_item(tcp, "impl WriterAdmission", "writer admission")
    constructor = extract_braced_item(
        admission, "fn new(max_ciphertext_bytes: usize)", "writer admission constructor"
    )
    require_order(
        constructor,
        (
            "max_ciphertext_bytes >= mac_bytes",
            "max_ciphertext_bytes <= u32::MAX as usize",
            "Semaphore::MAX_PERMITS / WRITER_RETAINED_CIPHERTEXT_PACKETS",
            "max_ciphertext_bytes * WRITER_RETAINED_CIPHERTEXT_PACKETS",
            "Semaphore::new(WRITER_CHANNEL_CAP)",
            "Semaphore::new(max_retained_ciphertext_bytes)",
        ),
        "representable count-and-byte admission construction",
    )
    reserve_plaintext = extract_braced_item(
        admission, "fn reserve_plaintext(", "plaintext admission"
    )
    require_order(
        reserve_plaintext,
        (
            ".checked_add(sodiumoxide::crypto::secretbox::MACBYTES)",
            '"R-T18: outbound keyed frame size overflow"',
            "self.reserve_ciphertext(ciphertext_bytes)",
        ),
        "checked ciphertext sizing before ownership",
    )
    reserve_ciphertext = extract_braced_item(
        admission, "fn reserve_ciphertext(", "ciphertext admission"
    )
    require_order(
        reserve_ciphertext,
        (
            "if ciphertext_bytes > self.max_ciphertext_bytes",
            "u32::try_from(ciphertext_bytes)",
            "try_acquire_owned()",
            "TryAcquireError::NoPermits",
            ".try_acquire_many_owned(permit_count)",
            "WriterFrameReservation {",
        ),
        "nonblocking size/count/byte admission",
    )
    for forbidden, label in (
        ("saturating_", "lossy writer admission arithmetic"),
        (".acquire().await", "blocking writer frame admission"),
        (".acquire_many(permit_count).await", "blocking writer byte admission"),
    ):
        forbid(admission, forbidden, label)

    for signature, label in (
        ("async fn send_bytes_raw(&mut self, bytes: Bytes)", "ordinary keyed send"),
        (
            "async fn send_bytes_raw_with_receipt(&mut self, bytes: Bytes)",
            "tracked keyed send",
        ),
    ):
        send = extract_braced_item(tcp, signature, label)
        require_order(
            send,
            (
                "k.writer_admission.reserve_plaintext(bytes.len())?",
                "k.seal.seal(&bytes)",
                "sealed.len() != reservation.ciphertext_bytes",
                ".try_send(WriterCommand::Frame {",
                "reservation,",
            ),
            f"reserve-before-seal {label}",
        )
    if tcp.count("k.writer_admission.reserve_plaintext(bytes.len())?") != 2:
        raise VerificationError("both and only both keyed send paths must reserve before seal")
    if tcp.count("let sealed = Bytes::from(k.seal.seal(&bytes));") != 2:
        raise VerificationError("both keyed send paths must retain producer-side sealing")

    set_keys = extract_braced_item(tcp, "pub fn set_session_keys(", "keying transition")
    require_order(
        set_keys,
        (
            "framed.codec().max_packet_length() != usize::MAX",
            "WriterAdmission::new(framed.codec().max_packet_length())",
            "let (sink, read) = framed.split();",
            "mpsc::channel::<WriterCommand>(WRITER_CHANNEL_CAP)",
            "tokio::spawn(writer_task(sink, writer_rx))",
            "writer_admission,",
        ),
        "engaged-ceiling writer admission and sole task construction",
    )

    writer = extract_braced_item(tcp, "async fn writer_task(", "sole writer task")
    require_order(
        writer,
        (
            "WriterCommand::Frame {",
            "reservation,",
            "sink.send(bytes).await",
            "if failed {",
        ),
        "frame ownership reaches exact sink send",
    )
    failed = extract_braced_item(writer, "if failed", "failed sink finality")
    require_order(
        failed,
        (
            "drop(sink);",
            "drop(reservation);",
            "completion.send(result)",
            "return;",
        ),
        "failed sink bytes retire before reservation release",
    )
    if writer.count("drop(reservation);") != 2:
        raise VerificationError(
            "writer must release the reservation exactly once on success and once on failure"
        )
    success_tail = writer[writer.find(failed) + len(failed) :]
    require_order(
        success_tail,
        ("drop(reservation);", "completion.send(result)"),
        "successful flush releases reservation before exact receipt",
    )

    poison = extract_braced_item(
        tcp, "fn poison_and_retire_writer(&mut self)", "fatal writer retirement"
    )
    require_order(
        poison,
        (
            "self.poison = true;",
            "k.writer_admission.close();",
            "k.writer.abort();",
        ),
        "fatal admission closure and writer abort",
    )
    if tcp.count("self.poison_and_retire_writer();") != 4:
        raise VerificationError(
            "send, tracked send, drain, and receive failures must share exact writer retirement"
        )
    flush = extract_braced_item(tcp, "pub async fn flush_writer(", "writer drain")
    require_order(
        flush,
        (
            "let result = match &mut self.state",
            "let keyed_result: ResultType<()> = async {",
            "writer_tx.send(WriterCommand::Drain(ack_tx))",
            "tokio::time::timeout(WRITER_DRAIN_TIMEOUT, ack_rx)",
            "}\n                .await;\n                keyed_result",
            "if result.is_err()",
            "self.poison_and_retire_writer();",
        ),
        "keyed drain errors reach common fatal retirement",
    )
    stream_drop = extract_braced_item(tcp, "impl Drop for FramedStream", "stream drop")
    require_order(
        stream_drop,
        ("k.writer_admission.close();", "k.writer.abort();"),
        "hard drop closes admission before abort",
    )

    for test in (
        "r_s11gx_writer_admission_checks_size_count_and_bytes_before_ownership",
        "r_s11gx_active_and_queued_frames_share_one_exact_budget_until_abort",
        "r_s11gx_failed_drain_retires_writer_admission",
        "r_s11gx_oversized_plaintext_is_rejected_before_peer_delivery",
    ):
        require(tcp, test, f"deterministic {test} regression")
    for needle, label in (
        (
            "keyed.writer_tx.capacity() == WRITER_CHANNEL_CAP",
            "dequeued-channel-capacity regression",
        ),
        (
            "admission.frames.available_permits() == WRITER_CHANNEL_CAP - 1",
            "active-frame ownership regression",
        ),
        (
            "admission.ciphertext_bytes.available_permits() == 64",
            "active-byte ownership regression",
        ),
        (
            "admission.ciphertext_bytes.available_permits() != 128",
            "abort byte-release regression",
        ),
        (
            "assert_eq!(receiver.recv_counter(), 0);",
            "oversize pre-delivery regression",
        ),
    ):
        require(tcp, needle, label)

    require(
        sources["codec"],
        "if n > self.max_packet_length",
        "receive-side keyed frame ceiling",
    )
    require(
        sources["cpace"],
        "pub const MAX_SESSION_PACKET: usize = 32 * 1024 * 1024;",
        "production keyed packet ceiling",
    )
    for key, needle, label in (
        (
            "transport",
            "Admission is reserved before secretbox sealing",
            "transport reserve-before-seal claim",
        ),
        (
            "transport",
            "active sink frame still owns its permits",
            "transport active-frame ownership claim",
        ),
        (
            "crypto_scope",
            "WriterAdmission",
            "external crypto scope admission anchor",
        ),
        (
            "requirements",
            '<div class="req"><span class="id">R-T18</span>',
            "normative keyed writer requirement",
        ),
        (
            "requirements",
            '<div class="req"><span class="id">R-S11gx</span>',
            "connection-hardening keyed writer requirement",
        ),
        ("requirements", "<tr><td>359</td>", "Appendix C keyed writer row"),
        (
            "hardening",
            "### R-S11gx/R-S11e-236 — exact keyed-writer count-and-byte ownership",
            "hardening ledger entry",
        ),
        (
            "verify",
            "python3 scripts/verify-keyed-writer-budget.py --repo . --self-test",
            "shared focused gate",
        ),
        (
            "verify",
            "cargo test -p hbb_common --lib r_s11gx_ --color never",
            "shared Rust behavior gate",
        ),
        (
            "apple",
            "python3 scripts/verify-keyed-writer-budget.py --repo . --self-test",
            "Apple/shared focused gate",
        ),
        (
            "workspace",
            "def validate_keyed_writer_budget_contract(sources):",
            "independent workspace contract",
        ),
        (
            "workspace",
            "validate_keyed_writer_budget_contract(sources)",
            "independent workspace dispatch",
        ),
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
        raise VerificationError("independent keyed-writer dispatch owner is absent")
    dispatches = [
        node
        for node in validate_sources_function.body
        if isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Name)
        and node.value.func.id == "validate_keyed_writer_budget_contract"
    ]
    if len(dispatches) != 1:
        raise VerificationError("independent keyed-writer dispatch must occur exactly once")

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
    ("tcp", "const WRITER_CHANNEL_CAP: usize = 512;", "const WRITER_CHANNEL_CAP: usize = usize::MAX;", "frame ceiling"),
    ("tcp", "const WRITER_RETAINED_CIPHERTEXT_PACKETS: usize = 2;", "const WRITER_RETAINED_CIPHERTEXT_PACKETS: usize = 8;", "byte ceiling"),
    ("tcp", ".checked_add(sodiumoxide::crypto::secretbox::MACBYTES)", ".saturating_add(sodiumoxide::crypto::secretbox::MACBYTES)", "checked ciphertext sizing"),
    ("tcp", "if ciphertext_bytes > self.max_ciphertext_bytes", "if false", "individual frame ceiling"),
    ("tcp", "try_acquire_owned()", "acquire_owned().await", "nonblocking frame admission"),
    ("tcp", ".try_acquire_many_owned(permit_count)", ".acquire_many_owned(permit_count).await", "nonblocking byte admission"),
    ("tcp", "reservation: WriterFrameReservation,", "// reservation removed", "command reservation owner"),
    ("tcp", "k.writer_admission.reserve_plaintext(bytes.len())?;", "k.writer_admission.reserve_plaintext(0)?;", "plaintext-sized admission"),
    ("tcp", "let writer_admission = WriterAdmission::new(framed.codec().max_packet_length());", "let writer_admission = WriterAdmission::new(usize::MAX);", "engaged ceiling authority"),
    ("tcp", "drop(sink);\n                    drop(reservation);", "drop(reservation);\n                    drop(sink);", "failure physical-byte finality"),
    ("tcp", "drop(reservation);\n                if let Some(completion)", "if let Some(completion)", "successful reservation finality"),
    ("tcp", "k.writer_admission.close();\n            k.writer.abort();", "k.writer.abort();", "fatal admission closure"),
    ("tcp", "}\n                .await;\n                keyed_result\n            }", "}\n                .await?;\n                Ok(())\n            }", "drain error containment"),
    ("tcp", "fn r_s11gx_active_and_queued_frames_share_one_exact_budget_until_abort", "fn active_frame_is_not_counted", "active ownership regression"),
    ("tcp", "fn r_s11gx_failed_drain_retires_writer_admission", "fn failed_drain_keeps_writer_admission_open", "drain retirement regression"),
    ("tcp", "assert_eq!(receiver.recv_counter(), 0);", "assert_eq!(receiver.recv_counter(), 1);", "oversize pre-delivery regression"),
    ("transport", "Admission is reserved before secretbox sealing", "Secretbox sealing precedes admission", "transport reserve-before-seal claim"),
    ("crypto_scope", "WriterAdmission", "WriterCapacity", "external audit anchor"),
    ("verify", "python3 scripts/verify-keyed-writer-budget.py --repo . --self-test", "true # keyed writer gate disabled", "shared gate wiring"),
    ("apple", "python3 scripts/verify-keyed-writer-budget.py --repo . --self-test", "true # keyed writer gate disabled", "Apple gate wiring"),
    ("requirements", '<div class="req"><span class="id">R-T18</span>', '<div class="req"><span class="id">R-T18-disabled</span>', "transport requirement"),
    ("requirements", '<div class="req"><span class="id">R-S11gx</span>', '<div class="req"><span class="id">R-S11gx-disabled</span>', "hardening requirement"),
    ("requirements", "<tr><td>359</td>", "<tr><td>359-disabled</td>", "Appendix disposition"),
    ("hardening", "### R-S11gx/R-S11e-236 — exact keyed-writer count-and-byte ownership", "### R-S11gx-disabled/R-S11e-236 — exact keyed-writer count-and-byte ownership", "hardening ledger"),
    ("workspace", "    validate_controlled_control_egress_contract(sources)\n    validate_cm_egress_budget_contract(sources)\n    validate_keyed_writer_budget_contract(sources)\n    validate_display_selection_finality_contract(sources)", "    validate_controlled_control_egress_contract(sources)\n    validate_cm_egress_budget_contract(sources)\n    validate_keyed_writer_budget_contract_disabled(sources)\n    validate_display_selection_finality_contract(sources)", "independent dispatch"),
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
        print(f"keyed writer budget verifier self-test passed ({len(MUTATIONS)} mutations)")
    else:
        print("keyed writer budget verifier passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VerificationError as error:
        print(f"keyed writer budget verifier failed: {error}")
        raise SystemExit(1)
