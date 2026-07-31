#!/usr/bin/env python3
"""Verify exact, bounded Flutter software-RGBA publication semantics."""

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
        "flutter": "src/flutter.rs",
        "ffi": "src/flutter_ffi.rs",
        "ui_session": "src/ui_session_interface.rs",
        "model": "flutter/lib/models/model.dart",
        "native_model": "flutter/lib/models/native_model.dart",
        "web_model": "flutter/lib/models/web_model.dart",
        "web_bridge": "flutter/lib/web/bridge.dart",
        "ios_app": "flutter/ios/Runner/AppDelegate.swift",
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
    flutter = sources["flutter"]
    ffi = sources["ffi"]

    require(
        flutter,
        "HashMap<(SessionID, usize), RgbaData>",
        "exact session/display mailbox key",
    )
    require(
        flutter,
        "rgba_publication_counter: Arc<AtomicU64>",
        "handler-wide publication counter",
    )

    rgba_data = extract_braced_item(flutter, "struct RgbaData", "RGBA mailbox state")
    require_order(
        rgba_data,
        (
            "data: Vec<u8>",
            "valid: bool",
            "publication: u64",
            "pending: Option<Vec<u8>>",
            "spare: Vec<u8>",
        ),
        "one published, one pending, and reusable-capacity mailbox state",
    )

    offer_swap = extract_braced_item(
        flutter, "fn offer_swap<F>", "single-consumer swap admission"
    )
    require_order(
        offer_swap,
        (
            "if !self.valid",
            "let publication = next_publication()?",
            "std::mem::swap(incoming, &mut self.data);",
            "self.publication = publication;",
            "if let Some(pending) = self.pending.as_mut()",
            "std::mem::swap(incoming, pending);",
            "self.pending = Some(std::mem::take(&mut self.spare));",
        ),
        "zero-copy initial publication and latest-only pending replacement",
    )
    forbid(offer_swap, ".push(", "unbounded swap-path queue")

    offer_copy = extract_braced_item(
        flutter, "fn offer_copy<F>", "independent-consumer copy admission"
    )
    require_order(
        offer_copy,
        (
            "if !self.valid",
            "let publication = next_publication()?",
            "self.data.extend_from_slice(incoming);",
            "if self.pending.is_none()",
            "self.pending = Some(std::mem::take(&mut self.spare));",
            "pending.clear();",
            "pending.extend_from_slice(incoming);",
        ),
        "independent stable storage and latest-only copy replacement",
    )
    forbid(offer_copy, ".push(", "unbounded copy-path queue")

    copy = extract_braced_item(flutter, "fn copy(&self", "exact publication copy")
    require(
        copy,
        "self.valid && self.publication == publication",
        "exact-token copy admission",
    )
    require(copy, "self.data.clone()", "owned bridge result")

    acknowledge = extract_braced_item(
        flutter, "fn acknowledge<F>", "exact publication acknowledgement"
    )
    require_order(
        acknowledge,
        (
            "if !self.valid || self.publication != publication",
            "RgbaAcknowledgement::Ignored",
            "let Some(mut latest) = self.pending.take()",
            "self.valid = false;",
            "RgbaAcknowledgement::Drained",
            "let Some(publication) = next_publication()",
            "RgbaAcknowledgement::Exhausted",
            "std::mem::swap(&mut self.data, &mut latest);",
            "self.spare = latest;",
            "self.publication = publication;",
            "RgbaAcknowledgement::Promoted(publication)",
        ),
        "stale rejection, drain, checked promotion, and exhaustion",
    )

    next_publication = extract_braced_item(
        flutter, "fn next_rgba_publication", "checked publication allocation"
    )
    require_order(
        next_publication,
        (
            ".fetch_update(",
            ".checked_add(1)",
            ".filter(|next| *next <= i64::MAX as u64)",
        ),
        "positive checked Dart-compatible publication sequence",
    )

    offer_sessions = extract_braced_item(
        flutter, "fn offer_rgba_to_sessions(", "exact consumer publication"
    )
    require_order(
        offer_sessions,
        (
            "session_ids.split_last()",
            ".entry((*session_id, display))",
            ".offer_copy(incoming, || self.next_rgba_publication())",
            ".entry((*last, display))",
            ".offer_swap(incoming, || self.next_rgba_publication())",
        ),
        "independent preceding consumers and swap-based common consumer",
    )

    handler_copy = extract_braced_item(
        flutter, "fn copy_rgba(", "handler exact publication copy"
    )
    require_order(
        handler_copy,
        (
            ".get(&(*session_id, display))",
            ".and_then(|rgba| rgba.copy(publication))",
        ),
        "exact session/display/token copy",
    )

    next_rgba = extract_braced_item(
        flutter, "fn next_rgba(&self", "handler exact acknowledgement"
    )
    require_order(
        next_rgba,
        (
            ".get_mut(&(*session_id, display))",
            "mailbox.acknowledge(publication",
            "RgbaAcknowledgement::Exhausted",
            "mailboxes.remove(&(*session_id, display));",
            "RgbaAcknowledgement::Promoted(next_publication)",
            "EventToUI::Rgba(display, next_publication)",
            ".remove(&(*session_id, display));",
        ),
        "exact promotion notification and failed-stream retirement",
    )

    replay = extract_braced_item(
        flutter, "fn replay_ready_rgba", "event-stream publication replay"
    )
    require_order(
        replay,
        (
            "let publications = self.ready_rgba_publications(session_id);",
            ".get(session_id)",
            "EventToUI::Rgba(display, publication)",
        ),
        "exact display/token replay",
    )

    soft_render = extract_braced_item(
        flutter, "fn on_rgba_soft_render", "software RGBA producer"
    )
    require_order(
        soft_render,
        (
            "let handlers = self.session_handlers.read().unwrap();",
            "handler.event_stream.as_ref().map(|_| *session_id)",
            "self.offer_rgba_to_sessions(&session_ids, display, &mut rgba.raw)",
            "for (session_id, publication) in notifications",
            "EventToUI::Rgba(display, publication)",
            "mailboxes.remove(&(session_id, display));",
        ),
        "eligible exact consumers and exact initial delivery",
    )
    forbid(
        soft_render,
        "if rgba_data.valid {\n                return;",
        "oldest-frame early return",
    )

    session_start = extract_braced_item(
        flutter, "pub fn session_start_(", "session stream installation"
    )
    require_order(
        session_start,
        (
            "h.event_stream = Some(event_stream);",
            "session.ui_handler.replay_ready_rgba(session_id)",
            "rollback_failed_session_start(session_id);",
            'bail!("Outgoing session event stream rejected pending video")',
        ),
        "visible replay failure and exact rollback",
    )

    for needle, label in (
        ("retire_rgba_session(id);", "ordinary session retirement"),
        (
            "retire_rgba_displays_except(&session_id, &value);",
            "display-switch retirement",
        ),
        (
            "retire_rgba_session(&stale_handler_id);",
            "mobile predecessor retirement",
        ),
        (
            "retire_rgba_session(owned_handler_id);",
            "mobile owner retirement",
        ),
    ):
        require(flutter, needle, label)

    exported_copy = extract_braced_item(
        flutter, "pub fn session_copy_rgba(", "exact public bridge copy"
    )
    require(
        exported_copy,
        ".copy_rgba(&session_id, display, publication)",
        "public exact copy delegation",
    )
    exported_ack = extract_braced_item(
        flutter, "pub fn session_next_rgba(", "exact public acknowledgement"
    )
    require(
        exported_ack,
        ".next_rgba(&session_id, display, publication)",
        "public exact acknowledgement delegation",
    )
    for forbidden in (
        "pub extern \"C\" fn session_get_rgba",
        "pub fn session_get_rgba_size",
        "fn char_to_session_id",
    ):
        forbid(flutter, forbidden, "raw size/pointer RGBA protocol")

    trait = sources["ui_session"]
    forbid(trait, "fn get_rgba(", "display-only generic RGBA lookup")
    forbid(trait, "fn next_rgba(", "display-only generic RGBA acknowledgement")

    event = extract_braced_item(ffi, "pub enum EventToUI", "Flutter event enum")
    require(event, "Rgba(usize, u64)", "display/publication event payload")
    ffi_copy = extract_braced_item(
        ffi, "pub fn session_copy_rgba(", "generated-bridge copy wrapper"
    )
    require(
        ffi_copy,
        "SyncReturn<Option<Vec<u8>>>",
        "owned optional byte result",
    )
    require(ffi_copy, "publication: u64", "copy publication argument")
    ffi_ack = extract_braced_item(
        ffi, "pub fn session_next_rgba(", "generated-bridge acknowledgement wrapper"
    )
    require(ffi_ack, "publication: u64", "acknowledgement publication argument")

    native = sources["native_model"]
    require(native, "Uint8List? copyRgba(", "native owned-copy wrapper")
    require(native, "_ffiBind.sessionCopyRgba(", "generated native copy call")
    require(
        native,
        "void nextRgba(SessionID sessionId, int display, int publication)",
        "native exact-token acknowledgement",
    )
    for forbidden in (
        "_session_get_rgba",
        'lookupFunction<F3Dart, F3>("session_get_rgba")',
        "asTypedList(bufSize)",
        "toNativeUtf8()",
    ):
        forbid(native, forbidden, "borrowed native RGBA pointer path")

    model = sources["model"]
    on_rgba = extract_braced_item(
        model, "Future<void> onRgba(", "asynchronous RGBA decode"
    )
    require_order(
        on_rgba,
        (
            "await decodeAndUpdate(expectedSessionId, display, rgba);",
            "if (publication != null)",
            "platformFFI.nextRgba(expectedSessionId, display, publication);",
        ),
        "decode completion before exact-token acknowledgement",
    )
    listener = model[
        model.index("} else if (message is EventToUI_Rgba)") :
        model.index("} else if (message is EventToUI_Texture)")
    ]
    require_order(
        listener,
        (
            "final display = message.field0;",
            "final publication = message.field1;",
            "platformFFI.copyRgba(activeSessionId, display, publication)",
            "await imageModel.onRgba(",
            "activeSessionId, display, rgba, publication",
            "platformFFI.nextRgba(activeSessionId, display, publication);",
        ),
        "exact event copy/decode/ack wiring",
    )
    forbid(listener, "getRgbaSize", "size-then-pointer Dart protocol")
    forbid(listener, "getRgba(", "raw-pointer Dart protocol")

    web_model = sources["web_model"]
    require(
        web_model,
        "Uint8List? copyRgba(SessionID sessionId, int display, int publication)",
        "web model signature parity",
    )
    require(
        web_model,
        "void nextRgba(SessionID sessionId, int display, int publication)",
        "web acknowledgement signature parity",
    )
    web_bridge = sources["web_bridge"]
    require_order(
        web_bridge,
        (
            "const factory EventToUI.rgba(",
            "int field0,",
            "int field1,",
            "class EventToUI_Rgba",
            "final int f0;",
            "final int f1;",
            "int get field1 => f1;",
        ),
        "web event display/publication parity",
    )
    require(
        web_bridge,
        "required int publication",
        "web acknowledgement publication stub",
    )

    forbid(
        sources["ios_app"],
        "session_get_rgba(",
        "iOS raw-pointer linker reference",
    )

    for test in (
        "r_s11ew_rgba_mailbox_keeps_published_frame_stable_and_promotes_only_latest",
        "r_s11ew_rgba_mailboxes_are_exact_per_ui_session_and_display",
        "r_s11ew_rgba_without_a_live_consumer_retains_no_frame",
        "r_s11ew_display_switch_retires_only_obsolete_exact_mailboxes",
        "r_s11ew_rgba_publication_exhaustion_fails_closed",
    ):
        require(flutter, f"fn {test}()", f"{test} behavior regression")

    for key, needle, label in (
        (
            "requirements",
            '<div class="req"><span class="id">R-S11ew</span>',
            "R-S11ew requirement",
        ),
        ("requirements", "<tr><td>305</td>", "Appendix C #305"),
        (
            "hardening",
            "**R-S11ew/R-S11e-184 exact, bounded, latest-wins Flutter software-RGBA publication",
            "RGBA mailbox hardening ledger",
        ),
        (
            "verify",
            "cargo test --lib --features linux-pkg-config,flutter r_s11ew_ --color never",
            "shared behavior-test wiring",
        ),
        (
            "verify",
            "python3 scripts/verify-viewer-rgba-mailbox.py --repo . --self-test",
            "shared focused-verifier wiring",
        ),
        (
            "apple",
            "python3 scripts/verify-viewer-rgba-mailbox.py --repo . --self-test",
            "Apple/shared focused-verifier wiring",
        ),
        (
            "workspace",
            '"viewer_rgba_mailbox_verifier": (',
            "independent verifier source binding",
        ),
        (
            "workspace",
            "validate_viewer_rgba_mailbox_contract(sources)",
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
    ("flutter", "HashMap<(SessionID, usize), RgbaData>", "HashMap<usize, RgbaData>", "exact mailbox key"),
    ("flutter", "rgba_publication_counter: Arc<AtomicU64>", "rgba_publication_counter: Arc<AtomicUsize>", "publication counter"),
    ("flutter", "pending: Option<Vec<u8>>", "pending: Vec<Vec<u8>>", "single pending frame"),
    ("flutter", "std::mem::swap(incoming, &mut self.data);", "self.data.clone_from(incoming);", "initial buffer swap"),
    ("flutter", "std::mem::swap(incoming, pending);", "pending.extend_from_slice(incoming);", "latest pending replacement"),
    ("flutter", "self.valid && self.publication == publication", "self.valid", "copy token check"),
    ("flutter", "self.data.clone()", "Vec::new()", "owned copy bytes"),
    ("flutter", "if !self.valid || self.publication != publication", "if !self.valid", "stale acknowledgement"),
    ("flutter", "let Some(publication) = next_publication()", "let publication = self.publication", "promotion token"),
    ("flutter", ".filter(|next| *next <= i64::MAX as u64)", ".filter(|_| true)", "Dart token bound"),
    ("flutter", ".entry((*session_id, display))", ".entry((SessionID::nil(), display))", "independent session copy"),
    ("flutter", ".and_then(|rgba| rgba.copy(publication))", ".map(|rgba| rgba.data.clone())", "exact public copy"),
    ("flutter", "mailbox.acknowledge(publication", "mailbox.acknowledge(0", "exact acknowledgement"),
    ("flutter", "EventToUI::Rgba(display, next_publication)", "EventToUI::Rgba(display, publication)", "promoted event token"),
    ("flutter", "EventToUI::Rgba(display, publication)", "EventToUI::Rgba(display, 0)", "initial/replay event token"),
    ("flutter", "session.ui_handler.replay_ready_rgba(session_id)", "true", "stream replay"),
    ("flutter", "retire_rgba_displays_except(&session_id, &value);", "retire_rgba_session(&session_id);", "exact display retirement"),
    ("flutter", "pub fn session_copy_rgba(", "pub fn session_get_rgba_size(", "owned copy API"),
    ("ffi", "Rgba(usize, u64)", "Rgba(usize)", "event token payload"),
    ("ffi", "SyncReturn<Option<Vec<u8>>>", "SyncReturn<usize>", "owned bridge result"),
    ("ui_session", "fn update_record_status", "fn get_rgba(&self, display: usize) -> *const u8;\n    fn update_record_status", "display-only trait authority"),
    ("native_model", "Uint8List? copyRgba(", "Uint8List? getRgba(", "native owned copy"),
    ("native_model", "_ffiBind.sessionCopyRgba(", "_session_get_rgba!(", "generated bridge copy"),
    ("model", "final publication = message.field1;", "final publication = 0;", "Dart event token"),
    ("model", "platformFFI.copyRgba(activeSessionId, display, publication)", "platformFFI.copyRgba(activeSessionId, display, 0)", "Dart exact copy"),
    ("model", "activeSessionId, display, rgba, publication", "activeSessionId, display, rgba, 0", "Dart exact decode acknowledgement"),
    ("web_bridge", "final int f1;", "final bool f1;", "web token parity"),
    ("ios_app", "dummy_method_to_enforce_bundling();", "dummy_method_to_enforce_bundling();\n    session_get_rgba(nil, 0);", "iOS raw pointer"),
    ("flutter", "fn r_s11ew_rgba_publication_exhaustion_fails_closed()", "fn rgba_publication_exhaustion_fails_closed()", "exhaustion regression"),
    ("requirements", '<div class="req"><span class="id">R-S11ew</span>', '<div class="req"><span class="id">R-S11ew-disabled</span>', "normative requirement"),
    ("requirements", "<tr><td>305</td>", "<tr><td>305-disabled</td>", "Appendix disposition"),
    ("hardening", "**R-S11ew/R-S11e-184 exact, bounded, latest-wins Flutter software-RGBA publication", "**R-S11ew-disabled/R-S11e-184 exact, bounded, latest-wins Flutter software-RGBA publication", "hardening ledger"),
    ("verify", "cargo test --lib --features linux-pkg-config,flutter r_s11ew_ --color never", "cargo test --lib --features linux-pkg-config,flutter disabled_ --color never", "shared behavior gate"),
    ("verify", "python3 scripts/verify-viewer-rgba-mailbox.py --repo . --self-test", "python3 scripts/verify-viewer-rgba-mailbox.py --repo .", "shared mutation gate"),
    ("apple", "python3 scripts/verify-viewer-rgba-mailbox.py --repo . --self-test", "python3 scripts/verify-viewer-rgba-mailbox.py --repo .", "Apple mutation gate"),
    ("workspace", '"viewer_rgba_mailbox_verifier": (', '"viewer_rgba_mailbox_verifier_disabled": (', "independent source binding"),
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
            "viewer RGBA mailbox verifier self-test passed "
            f"({len(MUTATIONS)} mutations)"
        )
    else:
        print("viewer RGBA mailbox verifier passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VerificationError as error:
        print(f"viewer RGBA mailbox verifier failed: {error}")
        raise SystemExit(1)
