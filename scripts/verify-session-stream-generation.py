#!/usr/bin/env python3
"""Verify exact Dart session-event-stream replacement generations."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
from typing import Dict, Tuple


class VerificationError(RuntimeError):
    pass


def require(source: str, needle: str, label: str) -> None:
    if needle not in source:
        raise VerificationError(f"missing {label}")


def forbid(source: str, needle: str, label: str) -> None:
    if needle in source:
        raise VerificationError(f"forbidden {label}")


def require_count(source: str, needle: str, count: int, label: str) -> None:
    actual = source.count(needle)
    if actual != count:
        raise VerificationError(f"{label}: expected {count}, found {actual}")


def require_order(source: str, needles: Tuple[str, ...], label: str) -> None:
    position = -1
    for needle in needles:
        position = source.find(needle, position + 1)
        if position < 0:
            raise VerificationError(f"{label}: missing or misordered {needle!r}")


def extract_item(source: str, signature: str, label: str) -> str:
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
        "model": (repo / "flutter/lib/models/model.dart").read_text(encoding="utf-8"),
        "generation": (
            repo / "flutter/lib/models/session_stream_finality.dart"
        ).read_text(encoding="utf-8"),
        "test": (repo / "flutter/test/session_stream_finality_test.dart").read_text(
            encoding="utf-8"
        ),
        "dart_verify": (repo / "scripts/dart-verify.sh").read_text(encoding="utf-8"),
        "verify": (repo / "scripts/verify.sh").read_text(encoding="utf-8"),
        "apple": (repo / "scripts/apple-conform-check.sh").read_text(
            encoding="utf-8"
        ),
        "requirements": (repo / "requirements.html").read_text(encoding="utf-8"),
        "hardening": (repo / "HARDENING_STATUS.md").read_text(encoding="utf-8"),
        "native_watch": (repo / "docs/NATIVE-CODEC-WATCH.md").read_text(
            encoding="utf-8"
        ),
    }


def validate(sources: Dict[str, str]) -> None:
    generation = sources["generation"]
    binding = extract_item(
        generation,
        "class SessionStreamBinding<Owner>",
        "exact session-stream binding",
    )
    require_order(
        binding,
        (
            "const SessionStreamBinding._(this.owner, this.generation);",
            "final Owner owner;",
            "final int generation;",
        ),
        "immutable exact session-stream binding",
    )

    owner = extract_item(
        generation,
        "class SessionStreamGeneration<Owner>",
        "exact session-stream generation owner",
    )
    require_order(
        owner,
        (
            "int _generation = 0;",
            "SessionStreamBinding<Owner>? _current;",
            "SessionStreamBinding<Owner> reserve(Owner owner)",
            "final binding = SessionStreamBinding<Owner>._(owner, ++_generation);",
            "_current = binding;",
            "return binding;",
            "bool isCurrent(SessionStreamBinding<Owner> binding)",
            "identical(_current, binding)",
            "bool retireOwner(Owner owner)",
            "if (current != null && current.owner != owner)",
            "return false;",
            "_current = null;",
            "return true;",
        ),
        "one-current monotonic session-stream generation owner",
    )
    for forbidden in (
        "List<",
        "Map<",
        "Set<",
        "Queue<",
        "StreamSubscription",
        "Timer",
        "Future",
        "retry",
    ):
        forbid(owner, forbidden, "session-stream history or scheduling owner")

    model = sources["model"]
    reserve = extract_item(
        model,
        "  SessionStreamBinding<_SessionOwner> _reserveSessionStream(",
        "Dart session-stream reservation",
    )
    require_order(
        reserve,
        (
            "final owner = _SessionOwner(expectedSessionId, clientOwnerId);",
            "owner != _sessionOwner",
            "!isCurrentSessionOwner(expectedSessionId, clientOwnerId)",
            "throw StateError('session owner changed before stream reservation');",
            "return _sessionStreams.reserve(owner);",
        ),
        "exact owner before stream-generation reservation",
    )
    current = extract_item(
        model,
        "  bool _isCurrentSessionStream(",
        "Dart exact current-stream predicate",
    )
    require_order(
        current,
        (
            "_sessionStreams.isCurrent(expected)",
            "expected.owner == _sessionOwner",
            "isCurrentSessionOwner(",
            "expected.owner.sessionId, expected.owner.clientOwnerId",
        ),
        "binding, owner, and live-session current-stream conjunction",
    )
    retire = extract_item(
        model,
        "  void _retireSessionOwner(",
        "exact session-owner retirement",
    )
    require_order(
        retire,
        (
            "final retiringOwner =",
            "_SessionOwner(retiringSessionId, clientOwnerId);",
            "final sessionStreamRetired = _sessionStreams.retireOwner(retiringOwner);",
            "final sessionEventsRetired = _sessionEvents.retire(retiringOwner);",
            "if (!sessionStreamRetired ||",
            "throw StateError('session owner changed before retirement');",
        ),
        "stream generation retires with its exact session owner",
    )

    mobile = extract_item(
        model,
        "  Future<void> _runMobileSessionStart(",
        "mobile session start",
    )
    require_order(
        mobile,
        (
            "if (!isCurrentSession(request.sessionId))",
            "late final SessionStreamBinding<_SessionOwner> streamBinding;",
            "streamBinding = _reserveSessionStream(request.sessionId);",
            "stream = bind.sessionStart(",
            "_listenToSessionStream(\n        stream, streamBinding, request.sessionId",
        ),
        "mobile pre-native stream-generation reservation",
    )

    listener = extract_item(
        model,
        "  void _listenToSessionStream(",
        "exact session-stream listener",
    )
    require_order(
        listener,
        (
            "SessionStreamBinding<_SessionOwner> streamBinding",
            "final streamOwner = streamBinding.owner;",
            "if (!_isCurrentSessionStream(streamBinding))",
            "final sessionEvents = _sessionEvents;",
            "platformFFI.setRgbaCallback((int display, Uint8List data)",
            "if (!_isCurrentSessionStream(streamBinding)) return;",
            "      });\n      return;\n    }\n\n    final cb = ffiModel.startEventListener(",
            "stream.listen((message)",
            "if (!_isCurrentSessionStream(streamBinding)) return;",
            "streamFinality.acceptExpectedClose();",
            "onError: (Object error, StackTrace stackTrace)",
            "if (!_isCurrentSessionStream(streamBinding)) return;",
            "sessionEvents.retire(streamOwner);",
            "onDone: ()",
            "if (!_isCurrentSessionStream(streamBinding)) return;",
            "sessionEvents.retire(streamOwner);",
        ),
        "exact stream binding before every callback and terminal effect",
    )
    require_count(
        listener,
        "_isCurrentSessionStream(streamBinding)",
        5,
        "listener, web, message, error, and done exact-binding checks",
    )
    forbid(
        listener,
        "if (closed || sessionId != activeSessionId) return;",
        "session-only stream callback admission",
    )

    start_begin = model.find("  SessionID start(")
    start_end = model.find("\n  Future<bool> _initializeFirstImage(", start_begin)
    if start_begin < 0 or start_end < 0:
        raise VerificationError("missing desktop session start")
    start = model[start_begin:start_end]
    require_order(
        start,
        (
            "late final SessionStreamBinding<_SessionOwner> streamBinding;",
            "streamBinding = _reserveSessionStream(activeSessionId);",
            "stream = bind.sessionStart(",
            "_listenToSessionStream(\n        stream, streamBinding, activeSessionId",
        ),
        "desktop pre-native stream-generation reservation",
    )

    tests = sources["test"]
    for needle, label in (
        (
            "replacement invalidates the predecessor with the same owner",
            "same-owner replacement behavior test",
        ),
        ("expect(predecessor.generation, 1);", "predecessor generation proof"),
        ("expect(replacement.generation, 2);", "replacement generation proof"),
        (
            "expect(generations.isCurrent(predecessor), isFalse);",
            "predecessor invalidation proof",
        ),
        (
            "owner retirement cannot retire a different current owner",
            "different-owner retirement behavior test",
        ),
        (
            "expect(generations.retireOwner('session-a'), isFalse);",
            "different-owner retirement refusal proof",
        ),
        (
            "expect(generations.retireOwner('session-b'), isTrue);",
            "exact-owner retirement proof",
        ),
    ):
        require(tests, needle, label)

    require_count(
        sources["dart_verify"],
        "test/session_stream_finality_test.dart",
        2,
        "Dart stream-finality behavior gate",
    )
    for gate in ("verify", "apple"):
        require(
            sources[gate],
            "python3 scripts/verify-session-stream-generation.py --repo . --self-test",
            f"{gate} exact stream-generation focused gate",
        )
    require(
        sources["requirements"],
        '<span class="id">R-S11ix</span>',
        "R-S11ix requirement",
    )
    require(sources["requirements"], "<tr><td>409</td>", "Appendix C #409")
    require(
        sources["hardening"],
        "R-S11ix/R-S11e-287 — exact Dart event-stream consumer generation",
        "R-S11e-287 hardening ledger",
    )
    requirements_digest = hashlib.sha256(
        sources["requirements"].encode("utf-8")
    ).hexdigest()
    require(
        sources["native_watch"],
        f"Requirements hash: {requirements_digest}",
        "exact requirements digest",
    )
    require(
        sources["native_watch"],
        "The same identity additionally binds R-S11ix and Appendix C #409.",
        "R-S11ix requirements-identity binding",
    )


MUTATIONS = (
    ("generation", "class SessionStreamBinding<Owner>", "class SessionStreamBindingDisabled<Owner>", "binding type"),
    ("generation", "final int generation;", "int generation;", "immutable binding generation"),
    ("generation", "int _generation = 0;", "int _generation = -1;", "generation origin"),
    ("generation", "SessionStreamBinding<Owner>? _current;", "final List<SessionStreamBinding<Owner>> _current = [];", "one-current storage"),
    ("generation", "final binding = SessionStreamBinding<Owner>._(owner, ++_generation);", "final binding = SessionStreamBinding<Owner>._(owner, _generation);", "strict generation advance"),
    ("generation", "_current = binding;\n    return binding;", "return binding;", "current binding publication"),
    ("generation", "identical(_current, binding)", "_current?.owner == binding.owner", "binding identity"),
    ("generation", "if (current != null && current.owner != owner)", "if (false)", "different-owner retirement refusal"),
    ("generation", "_current = null;\n    return true;", "return true;", "binding retirement"),
    ("model", "owner != _sessionOwner ||", "false &&", "reservation owner proof"),
    ("model", "!isCurrentSessionOwner(expectedSessionId, clientOwnerId)", "false", "reservation live-session proof"),
    ("model", "return _sessionStreams.reserve(owner);", "throw StateError('stream reservation disabled');", "stream reservation commit"),
    ("model", "_sessionStreams.isCurrent(expected) &&", "true &&", "exact current binding proof"),
    ("model", "expected.owner == _sessionOwner &&", "true &&", "binding session-owner proof"),
    ("model", "final sessionStreamRetired = _sessionStreams.retireOwner(retiringOwner);", "final sessionStreamRetired = true;", "owner retirement"),
    ("model", "streamBinding = _reserveSessionStream(request.sessionId);\n      stream = bind.sessionStart(", "stream = bind.sessionStart(\n          // reservation moved after native replacement\n", "mobile pre-native reservation"),
    ("model", "streamBinding = _reserveSessionStream(activeSessionId);\n      stream = bind.sessionStart(", "stream = bind.sessionStart(\n          // reservation moved after native replacement\n", "desktop pre-native reservation"),
    ("model", "final streamOwner = streamBinding.owner;", "final streamOwner = _SessionOwner(activeSessionId, clientOwnerId);", "listener binding owner"),
    ("model", "if (!_isCurrentSessionStream(streamBinding)) {\n      return;\n    }\n    final sessionEvents", "final sessionEvents", "listener installation refusal"),
    ("model", "if (!_isCurrentSessionStream(streamBinding)) return;\n        // JS/Wasm", "// JS/Wasm", "web callback refusal"),
    ("model", "      });\n      return;\n    }\n\n    final cb = ffiModel.startEventListener(activeSessionId, peerId);", "      });\n    }\n\n    final cb = ffiModel.startEventListener(activeSessionId, peerId);", "web branch final return"),
    ("model", "if (!_isCurrentSessionStream(streamBinding)) return;\n      if (tabWindowId", "if (closed || sessionId != activeSessionId) return;\n      if (tabWindowId", "native message generation refusal"),
    ("model", "}, onError: (Object error, StackTrace stackTrace) {\n      if (!_isCurrentSessionStream(streamBinding)) return;", "}, onError: (Object error, StackTrace stackTrace) {", "predecessor error refusal"),
    ("model", "onDone: () {\n      if (!_isCurrentSessionStream(streamBinding)) return;", "onDone: () {", "predecessor completion refusal"),
    ("test", "replacement invalidates the predecessor with the same owner", "replacement preserves the predecessor with the same owner", "replacement behavior test"),
    ("test", "expect(predecessor.generation, 1);", "expect(predecessor.generation, 0);", "predecessor generation proof"),
    ("test", "expect(generations.isCurrent(predecessor), isFalse);", "expect(generations.isCurrent(predecessor), isTrue);", "predecessor invalidation proof"),
    ("test", "owner retirement cannot retire a different current owner", "owner retirement may retire a different current owner", "retirement behavior test"),
    ("test", "expect(generations.retireOwner('session-a'), isFalse);", "expect(generations.retireOwner('session-a'), isTrue);", "different-owner refusal proof"),
    ("dart_verify", "test/session_stream_finality_test.dart", "test/session_stream_finality_test_disabled.dart", "Dart behavior gate"),
    ("verify", "python3 scripts/verify-session-stream-generation.py --repo . --self-test", "true # stream generation gate disabled", "shared focused gate"),
    ("apple", "python3 scripts/verify-session-stream-generation.py --repo . --self-test", "true # stream generation gate disabled", "Apple focused gate"),
    ("requirements", '<span class="id">R-S11ix</span>', '<span class="id">R-S11ix-disabled</span>', "requirement"),
    ("requirements", "<tr><td>409</td>", "<tr><td>409-disabled</td>", "Appendix disposition"),
    ("hardening", "R-S11ix/R-S11e-287 — exact Dart event-stream consumer generation", "R-S11ix-disabled/R-S11e-287 — exact Dart event-stream consumer generation", "hardening ledger"),
    ("native_watch", "Requirements hash: ", "Requirements digest: ", "requirements digest"),
    ("native_watch", "The same identity additionally binds R-S11ix and Appendix C #409.", "The same identity additionally binds R-S11ix-disabled and Appendix C #409.", "requirements identity binding"),
)


def run_self_test(sources: Dict[str, str]) -> None:
    for source_name, old, new, label in MUTATIONS:
        source = sources[source_name]
        if old not in source:
            raise VerificationError(f"mutation fixture missing {label}: {old!r}")
        mutated = dict(sources)
        mutated[source_name] = source.replace(old, new, 1)
        try:
            validate(mutated)
        except VerificationError:
            continue
        raise VerificationError(f"mutation survived: {label}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=".", help="repository root")
    parser.add_argument("--self-test", action="store_true", help="reject deliberate regressions")
    args = parser.parse_args()
    sources = load_sources(Path(args.repo).resolve())
    validate(sources)
    if args.self_test:
        run_self_test(sources)
        print(
            "verify-session-stream-generation: "
            f"{len(MUTATIONS)} mutations rejected"
        )
    else:
        print("verify-session-stream-generation: ok")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VerificationError as error:
        print(f"verify-session-stream-generation: {error}", file=__import__("sys").stderr)
        raise SystemExit(1)
