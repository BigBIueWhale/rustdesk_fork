#!/usr/bin/env python3
"""Static structural verification for desktop sensitive-password IPC.

This is deliberately narrower than a Rust parser and stronger than text grep.  It lexes executable
Rust tokens (discarding comments and literal contents), extracts named item/function bodies, and
proves the security-relevant call graph and ordering implemented across the password codec, IPC
listeners, Linux/macOS peer authentication, mutation coordinators, and desktop callers.
"""

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping, Sequence


class VerificationError(RuntimeError):
    pass


@dataclass(frozen=True)
class Token:
    kind: str
    text: str
    offset: int


def _quoted_end(source: str, quote: int) -> int:
    escaped = False
    cursor = quote + 1
    while cursor < len(source):
        char = source[cursor]
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == source[quote]:
            return cursor + 1
        cursor += 1
    raise VerificationError("unterminated Rust quoted literal")


def _raw_string_end(source: str, start: int) -> int | None:
    marker = start
    if source.startswith(("br", "cr"), start):
        marker += 2
    elif source.startswith("r", start):
        marker += 1
    else:
        return None
    hashes = 0
    while marker + hashes < len(source) and source[marker + hashes] == "#":
        hashes += 1
    quote = marker + hashes
    if quote >= len(source) or source[quote] != '"':
        return None
    terminator = '"' + ("#" * hashes)
    end = source.find(terminator, quote + 1)
    if end == -1:
        raise VerificationError("unterminated Rust raw string")
    return end + len(terminator)


def _char_literal_end(source: str, start: int) -> int | None:
    quote = start + 1 if source.startswith("b'", start) else start
    if quote >= len(source) or source[quote] != "'":
        return None
    cursor = quote + 1
    if cursor >= len(source):
        return None
    cursor += 2 if source[cursor] == "\\" else 1
    return cursor + 1 if cursor < len(source) and source[cursor] == "'" else None


def lex_rust(source: str) -> list[Token]:
    """Tokenize stable Rust syntax while making comments/literal contents non-executable."""
    tokens: list[Token] = []
    cursor = 0
    operators = (
        "<<=",
        ">>=",
        "::",
        "=>",
        "->",
        "==",
        "!=",
        "<=",
        ">=",
        "&&",
        "||",
        "..=",
        "..",
        "+=",
        "-=",
        "*=",
        "/=",
        "%=",
        "&=",
        "|=",
        "^=",
        "<<",
        ">>",
    )
    while cursor < len(source):
        char = source[cursor]
        if char.isspace():
            cursor += 1
            continue
        if source.startswith("//", cursor):
            newline = source.find("\n", cursor + 2)
            cursor = len(source) if newline == -1 else newline + 1
            continue
        if source.startswith("/*", cursor):
            depth = 1
            end = cursor + 2
            while end < len(source) and depth:
                if source.startswith("/*", end):
                    depth += 1
                    end += 2
                elif source.startswith("*/", end):
                    depth -= 1
                    end += 2
                else:
                    end += 1
            if depth:
                raise VerificationError("unterminated Rust block comment")
            cursor = end
            continue
        raw_end = _raw_string_end(source, cursor)
        if raw_end is not None:
            tokens.append(Token("literal", source[cursor:raw_end], cursor))
            cursor = raw_end
            continue
        string_quote = cursor + 1 if source.startswith(("b\"", "c\""), cursor) else cursor
        if string_quote < len(source) and source[string_quote] == '"':
            end = _quoted_end(source, string_quote)
            tokens.append(Token("literal", source[cursor:end], cursor))
            cursor = end
            continue
        char_end = _char_literal_end(source, cursor)
        if char_end is not None:
            tokens.append(Token("literal", source[cursor:char_end], cursor))
            cursor = char_end
            continue
        if char.isalpha() or char == "_":
            end = cursor + 1
            while end < len(source) and (source[end].isalnum() or source[end] == "_"):
                end += 1
            tokens.append(Token("identifier", source[cursor:end], cursor))
            cursor = end
            continue
        if char.isdigit():
            end = cursor + 1
            decimal_point_seen = False
            while end < len(source):
                if source[end].isalnum() or source[end] == "_":
                    end += 1
                    continue
                if (
                    source[end] == "."
                    and not decimal_point_seen
                    and end + 1 < len(source)
                    and source[end + 1].isdigit()
                ):
                    decimal_point_seen = True
                    end += 1
                    continue
                break
            tokens.append(Token("literal", source[cursor:end], cursor))
            cursor = end
            continue
        operator = next((item for item in operators if source.startswith(item, cursor)), None)
        if operator is not None:
            tokens.append(Token("punctuation", operator, cursor))
            cursor += len(operator)
            continue
        tokens.append(Token("punctuation", char, cursor))
        cursor += 1
    return tokens


def delimiter_maps(tokens: Sequence[Token]) -> tuple[dict[int, int], dict[int, int | None]]:
    opening_for = {")": "(", "]": "[", "}": "{"}
    stack: list[int] = []
    pairs: dict[int, int] = {}
    brace_parent: dict[int, int | None] = {}
    for index, token in enumerate(tokens):
        brace_parent[index] = next(
            (opening for opening in reversed(stack) if tokens[opening].text == "{"), None
        )
        if token.text in ("(", "[", "{"):
            stack.append(index)
        elif token.text in opening_for:
            if not stack or tokens[stack[-1]].text != opening_for[token.text]:
                raise VerificationError(f"unbalanced Rust delimiter near byte {token.offset}")
            opening = stack.pop()
            pairs[opening] = index
            pairs[index] = opening
    if stack:
        raise VerificationError("unclosed Rust delimiter")
    return pairs, brace_parent


@dataclass(frozen=True)
class OptionalToken:
    text: str


OPTIONAL_COMMA = OptionalToken(",")
PatternToken = str | OptionalToken
TokenPattern = Sequence[PatternToken] | str


def _as_tuple(sequence: TokenPattern) -> tuple[PatternToken, ...]:
    if isinstance(sequence, str):
        return (sequence,)
    return tuple(sequence)


@dataclass(frozen=True)
class Region:
    rust: "RustSource"
    start: int
    end: int
    label: str

    @property
    def values(self) -> list[str]:
        return [token.text for token in self.rust.tokens[self.start : self.end]]

    def positions(self, sequence: TokenPattern) -> list[int]:
        expected = _as_tuple(sequence)
        matches: list[int] = []
        for index in range(self.start, self.end):
            cursor = index
            for part in expected:
                if isinstance(part, OptionalToken):
                    if cursor < self.end and self.rust.tokens[cursor].text == part.text:
                        cursor += 1
                    continue
                if cursor >= self.end or self.rust.tokens[cursor].text != part:
                    break
                cursor += 1
            else:
                matches.append(index)
        return matches

    def require(
        self,
        sequence: TokenPattern,
        label: str,
        *,
        unique: bool = False,
    ) -> int:
        matches = self.positions(sequence)
        if not matches:
            raise VerificationError(f"{self.label}: missing {label}")
        if unique and len(matches) != 1:
            raise VerificationError(
                f"{self.label}: {label} must occur exactly once, found {len(matches)}"
            )
        return matches[0]

    def forbid(self, sequence: TokenPattern, label: str) -> None:
        if self.positions(sequence):
            raise VerificationError(f"{self.label}: forbidden {label}")

    def require_order(
        self, requirements: Sequence[tuple[TokenPattern, str]], *, unique: bool = False
    ) -> list[int]:
        selected: list[int] = []
        previous = self.start - 1
        for sequence, label in requirements:
            matches = self.positions(sequence)
            if unique and len(matches) != 1:
                raise VerificationError(
                    f"{self.label}: {label} must occur exactly once, found {len(matches)}"
                )
            position = next((candidate for candidate in matches if candidate > previous), None)
            if position is None:
                labels = " -> ".join(item_label for _, item_label in requirements)
                raise VerificationError(f"{self.label}: required executable order is {labels}")
            selected.append(position)
            previous = position
        return selected

    def require_identifier_absent(self, names: Iterable[str], label: str) -> None:
        identifiers = {
            token.text
            for token in self.rust.tokens[self.start : self.end]
            if token.kind == "identifier"
        }
        present = sorted(set(names) & identifiers)
        if present:
            raise VerificationError(f"{self.label}: {label}: {', '.join(present)}")


@dataclass(frozen=True)
class RustSource:
    path: str
    text: str
    tokens: tuple[Token, ...]
    pairs: Mapping[int, int]
    brace_parent: Mapping[int, int | None]

    @classmethod
    def parse(cls, path: str, text: str) -> "RustSource":
        tokens = tuple(lex_rust(text))
        pairs, brace_parent = delimiter_maps(tokens)
        return cls(path, text, tokens, pairs, brace_parent)

    def all(self, label: str | None = None) -> Region:
        return Region(self, 0, len(self.tokens), label or self.path)

    def _block_after(self, marker: int, parent: int | None, label: str) -> Region:
        for index in range(marker + 1, len(self.tokens)):
            token = self.tokens[index]
            if token.text == "{" and self.brace_parent[index] == parent:
                return Region(self, index + 1, self.pairs[index], f"{self.path}:{label}")
        raise VerificationError(f"{self.path}: {label} has no structural body")

    def function(self, name: str, *, parent: int | None = None) -> Region:
        regions = self.functions(name, parent=parent)
        if len(regions) != 1:
            raise VerificationError(
                f"{self.path}: expected one function {name} at requested scope, found {len(regions)}"
            )
        return regions[0]

    def functions(self, name: str, *, parent: int | None = None) -> list[Region]:
        matches = [
            index
            for index in range(len(self.tokens) - 1)
            if self.tokens[index].text == "fn"
            and self.tokens[index + 1].text == name
            and self.brace_parent[index] == parent
        ]
        return [self._block_after(index + 1, parent, f"fn {name}") for index in matches]

    def item(self, kind: str, name: str) -> Region:
        matches = [
            index
            for index in range(len(self.tokens) - 1)
            if self.tokens[index].text == kind
            and self.tokens[index + 1].text == name
            and self.brace_parent[index] is None
        ]
        if len(matches) != 1:
            raise VerificationError(
                f"{self.path}: expected one {kind} {name}, found {len(matches)}"
            )
        return self._block_after(matches[0] + 1, None, f"{kind} {name}")

    def impl(self, marker: Sequence[str], label: str) -> Region:
        sequence = tuple(marker)
        matches = self.all().positions(sequence)
        matches = [index for index in matches if self.brace_parent[index] is None]
        if len(matches) != 1:
            raise VerificationError(f"{self.path}: expected one {label}, found {len(matches)}")
        return self._block_after(matches[0] + len(sequence) - 1, None, label)

    def method(self, impl_marker: Sequence[str], method: str, label: str) -> Region:
        impl_region = self.impl(impl_marker, label)
        impl_open = impl_region.start - 1
        return self.function(method, parent=impl_open)


REQUIRED_SOURCES = (
    "src/ipc.rs",
    "src/ipc/password.rs",
    "src/ipc/auth.rs",
    "src/ipc/fs.rs",
    "src/core_main.rs",
    "src/ui_interface.rs",
    "src/flutter_ffi.rs",
    "src/common.rs",
    "src/platform/linux.rs",
    "src/platform/windows.rs",
    "src/server.rs",
    "libs/hbb_common/src/config.rs",
)


def load_sources(repo: Path) -> dict[str, str]:
    return {
        relative: (repo / relative).read_text(encoding="utf-8") for relative in REQUIRED_SOURCES
    }


def parse_sources(sources: Mapping[str, str]) -> dict[str, RustSource]:
    missing = sorted(set(REQUIRED_SOURCES) - set(sources))
    if missing:
        raise VerificationError(f"missing verifier sources: {', '.join(missing)}")
    return {path: RustSource.parse(path, sources[path]) for path in REQUIRED_SOURCES}


def non_definition_calls(rust: RustSource, name: str) -> list[int]:
    return [
        index
        for index in range(1, len(rust.tokens) - 1)
        if rust.tokens[index].text == name
        and rust.tokens[index + 1].text == "("
        and rust.tokens[index - 1].text != "fn"
    ]


def verify_raw_wire(rust: Mapping[str, RustSource]) -> None:
    password = rust["src/ipc/password.rs"]
    ipc = rust["src/ipc.rs"]
    production_end = password.all().require(("#", "[", "cfg", "(", "test", ")", "]", "mod", "tests"), "test module", unique=True)
    production = Region(password, 0, production_end, "src/ipc/password.rs production")
    production.require_identifier_absent(
        {
            "Bytes",
            "BytesMut",
            "BytesCodec",
            "Deserialize",
            "Framed",
            "Serialize",
            "serde",
            "serde_json",
            "tokio_util",
        },
        "sensitive wire must not expose serde or generic framing identifiers",
    )

    ipc.all().require(
        ("pub", "(", "crate", ")", "const", "UNATTENDED_PASSWORD_MAX_BYTES", ":", "usize", "=", "4096", ";"),
        "fixed password body limit",
        unique=True,
    )
    production.require(
        ("const", "MACOS_AUTHORIZATION_MAX_BYTES", ":", "usize", "=", "1024", ";"),
        "fixed authorization body limit",
        unique=True,
    )
    production.require(
        ("const", "CREDENTIAL_REPLICA_BYTES", ":", "usize", "=", "44", ";"),
        "canonical Linux PRS replica length",
        unique=True,
    )
    production.require(("const", "REQUEST_HEADER_BYTES", ":", "usize", "=", "36", ";"), "36-byte request header", unique=True)
    production.require(("const", "STATUS_FRAME_BYTES", ":", "usize", "=", "32", ";"), "32-byte status frame", unique=True)
    production.require(("const", "ACK_FRAME_BYTES", ":", "usize", "=", "28", ";"), "28-byte acknowledgement frame", unique=True)
    production.require(
        (
            "const",
            "REQUEST_BODY_MAX_BYTES",
            ":",
            "usize",
            "=",
            "UNATTENDED_PASSWORD_MAX_BYTES",
            "+",
            "MACOS_AUTHORIZATION_MAX_BYTES",
            ";",
        ),
        "fixed request-body maximum",
        unique=True,
    )

    header = password.impl(("impl", "SensitiveRequestHeader"), "impl SensitiveRequestHeader")
    header.require_order(
        (
            (("operation_id", ".", "as_bytes", "(", ")", ".", "iter", "(", ")", ".", "all"), "nil UUID rejection"),
            (("password_len", ">", "UNATTENDED_PASSWORD_MAX_BYTES"), "password length bound"),
            (("Password", "if", "self", ".", "authorization_len", "!=", "0"), "password-only auxiliary-data rejection"),
            (("PasswordWithAuthorization", "if", "self", ".", "authorization_len", "==", "0"), "authorization presence check"),
            (("checked_add", "(", "self", ".", "authorization_len", ")"), "overflow-safe body length"),
            (("filter", "(", "|", "total", "|", "*", "total", "<=", "REQUEST_BODY_MAX_BYTES", ")"), "combined body bound"),
        )
    )
    header.require(
        (
            "CredentialSnapshotRequest", "if", "self", ".", "password_len", "!=", "0",
            "||", "self", ".", "authorization_len", "!=", "0",
        ),
        "bodyless credential snapshot request",
        unique=True,
    )
    header.require(
        (
            "CredentialReplica", "if", "self", ".", "authorization_len", "!=", "0",
            "||", "!", "matches", "!", "(", "self", ".", "password_len", ",", "0",
            "|", "CREDENTIAL_REPLICA_BYTES", ")",
        ),
        "empty-or-exact canonical credential replica length",
        unique=True,
    )
    payload_kind = password.item("enum", "SensitivePayloadKind")
    payload_kind.require(("CredentialSnapshotRequest", "=", "3"), "snapshot wire kind", unique=True)
    payload_kind.require(("CredentialReplica", "=", "4"), "replica wire kind", unique=True)
    from_wire = password.method(
        ("impl", "SensitivePayloadKind"), "from_wire", "impl SensitivePayloadKind"
    )
    from_wire.require(("3", "=>", "Ok", "(", "Self", "::", "CredentialSnapshotRequest", ")"), "snapshot kind decode", unique=True)
    from_wire.require(("4", "=>", "Ok", "(", "Self", "::", "CredentialReplica", ")"), "replica kind decode", unique=True)
    encode = password.method(("impl", "SensitiveRequestHeader"), "encode", "impl SensitiveRequestHeader")
    encode.require_order(
        (
            (("bytes", "[", "..", "8", "]", ".", "copy_from_slice", "(", "&", "REQUEST_MAGIC", ")"), "request magic"),
            (("bytes", "[", "8", "]", "=", "PROTOCOL_VERSION"), "request version"),
            (("bytes", "[", "9", "]", "=", "0"), "canonical flags"),
            (("bytes", "[", "10", "]", "=", "self", ".", "kind", "as", "u8"), "payload kind"),
            (("bytes", "[", "11", "]", "=", "0"), "canonical reserved byte"),
            (("bytes", "[", "12", "..", "28", "]", ".", "copy_from_slice", "(", "self", ".", "operation_id", ".", "as_bytes", "(", ")", ")"), "operation UUID"),
            (("password_len", "as", "u32", ")", ".", "to_be_bytes", "(", ")"), "network-order password length"),
            (("authorization_len", "as", "u32", ")", ".", "to_be_bytes", "(", ")"), "network-order authorization length"),
        ),
        unique=True,
    )
    decode = password.method(("impl", "SensitiveRequestHeader"), "decode", "impl SensitiveRequestHeader")
    decode.require_order(
        (
            ((("bytes", "[", "..", "8", "]", "!=", "REQUEST_MAGIC")), "request magic validation"),
            ((("bytes", "[", "8", "]", "!=", "PROTOCOL_VERSION")), "protocol version validation"),
            ((("bytes", "[", "9", "]", "!=", "0", "||", "bytes", "[", "11", "]", "!=", "0")), "canonical flag validation"),
            ((("SensitivePayloadKind", "::", "from_wire", "(", "bytes", "[", "10", "]", ")")), "payload-kind decoding"),
            ((("kind", "!=", "expected_kind")), "endpoint-kind binding"),
            ((("uuid", ".", "copy_from_slice", "(", "&", "bytes", "[", "12", "..", "28", "]", ")")), "operation UUID decoding"),
            ((("Self", "::", "new", "(", "operation_id", ",", "kind", ",", "password_len", ",", "authorization_len", ")")), "validated header construction"),
        )
    )

    fixed_body = password.impl(("impl", "FixedSensitiveBody"), "impl FixedSensitiveBody")
    fixed_body.require_order(
        (
            (("try_reserve_exact", "(", "REQUEST_BODY_MAX_BYTES", ")"), "exact bounded reservation"),
            (("resize", "(", "REQUEST_BODY_MAX_BYTES", ",", "0", ")"), "fixed initialized allocation"),
            (("into_boxed_slice", "(", ")"), "non-growing boxed body"),
        )
    )
    fixed_drop = password.method(("impl", "Drop", "for", "FixedSensitiveBody"), "drop", "impl Drop for FixedSensitiveBody")
    fixed_drop.require(("zeroize_sensitive_bytes", "(", "&", "mut", "self", ".", "bytes", ")"), "body zeroization", unique=True)

    storage_erase = password.method(
        ("impl", "SensitivePasswordStorage"),
        "erase",
        "impl SensitivePasswordStorage",
    )
    storage_erase.require_order(
        (
            (("Origin", "(", "value", ")", "=>", "zeroize_sensitive_string", "(", "value", ")"), "origin-string zeroization"),
            (("Inbound", "{", "bytes", ",", "..", "}", "=>", "zeroize_sensitive_bytes", "(", "bytes", ")"), "inbound-buffer zeroization"),
        ),
        unique=True,
    )
    storage_drop = password.method(
        ("impl", "Drop", "for", "SensitivePasswordStorage"),
        "drop",
        "impl Drop for SensitivePasswordStorage",
    )
    storage_drop.require(("self", ".", "erase", "(", ")"), "storage drop zeroization", unique=True)
    into_password = password.method(
        ("impl", "InboundSensitiveRequest"),
        "into_password",
        "impl InboundSensitiveRequest",
    )
    into_password.require_order(
        (
            (("self", ".", "validate_utf8", "(", ")"), "strict UTF-8 validation"),
            (("zeroize_sensitive_bytes", "(", "&", "mut", "body", ".", "bytes", "[", "password_len", "..", "]", ")"), "non-password tail zeroization"),
            (("std", "::", "mem", "::", "replace", "(", "&", "mut", "body", ".", "bytes", ",", "Box", "::", "new", "(", "[", "]", ")", ")"), "single buffer ownership transfer"),
            (("SensitivePassword", "::", "from_inbound", "(", "bytes", ",", "password_len", ")"), "sensitive wrapper construction"),
        ),
        unique=True,
    )

    receive = password.function("receive_request_unix")
    receive.require_order(
        (
            (("SensitiveStackBytes", "::", "<", "REQUEST_HEADER_BYTES", ">", "::", "zeroed", "(", ")"), "fixed stack header"),
            (("with_deadline", "(", "deadline", ",", "stream", ".", "read_exact", "(", "&", "mut", "header_bytes", ".", "0", ")", ")"), "bounded exact header read"),
            (("SensitiveRequestHeader", "::", "decode", "(", "&", "header_bytes", ".", "0", ",", "expected_kind", ")"), "header validation"),
            (("InboundSensitiveRequest", "::", "allocate", "(", "header", ")"), "post-header bounded allocation"),
            (("with_deadline", "(", "deadline", ",", "stream", ".", "read_exact", "(", "request", ".", "body_mut", "(", ")", ")", ")"), "bounded exact body read"),
            (("request", ".", "validate_utf8", "(", ")"), "password UTF-8 validation"),
            (("SensitiveStackBytes", "::", "<", "1", ">", "::", "zeroed", "(", ")"), "trailing-byte probe"),
            (("if", "read", "!=", "0"), "trailing-byte rejection"),
        ),
        unique=True,
    )
    snapshot_send = password.function("send_credential_snapshot_request_unix")
    snapshot_send.require_order(
        (
            (("SensitiveRequestHeader", "::", "new", "(", "operation_id", ",", "SensitivePayloadKind", "::", "CredentialSnapshotRequest", ",", "0", ",", "0"), "bodyless operation-bound snapshot header"),
            (("remaining_millis", "(", "deadline", ")"), "snapshot deadline preflight"),
            (("with_deadline", "(", "deadline", ",", "stream", ".", "write_all", "(", "&", "header", ")"), "bounded snapshot header write"),
            (("with_deadline", "(", "deadline", ",", "stream", ".", "shutdown", "(", ")", ")"), "snapshot half-close"),
        )
    )
    replica_send = password.function("send_credential_replica_unix")
    replica_send.require_order(
        (
            (("SensitivePayloadKind", "::", "CredentialReplica"), "replica kind"),
            (("replica", ".", "as_bytes", "(", ")", ".", "len", "(", ")"), "validated replica length"),
            (("remaining_millis", "(", "deadline", ")"), "replica deadline preflight"),
            (("with_deadline", "(", "deadline", ",", "stream", ".", "write_all", "(", "&", "header", ")"), "bounded replica header write"),
            (("with_deadline", "(", "deadline", ",", "stream", ".", "write_all", "(", "replica", ".", "as_bytes", "(", ")", ")"), "bounded replica body write"),
            (("with_deadline", "(", "deadline", ",", "stream", ".", "shutdown", "(", ")", ")"), "replica half-close"),
        )
    )
    snapshot_receive = password.function("receive_credential_snapshot_request_unix")
    snapshot_receive.require_order(
        (
            (("receive_request_unix", "(", "stream", ",", "SensitivePayloadKind", "::", "CredentialSnapshotRequest", ",", "deadline"), "kind-bound snapshot receive"),
            (("request", ".", "operation_id", "(", ")"), "snapshot operation UUID"),
        )
    )
    replica_receive = password.function("receive_credential_replica_unix")
    replica_receive.require_order(
        (
            (("receive_request_unix", "(", "stream", ",", "SensitivePayloadKind", "::", "CredentialReplica", ",", "deadline"), "kind-bound replica receive"),
            (("request", ".", "operation_id", "(", ")", "!=", "expected_operation_id"), "replica UUID binding"),
            (("request", ".", "into_password", "(", ")"), "sensitive replica ownership"),
        )
    )
    with_deadline = password.function("with_deadline")
    with_deadline.require(
        ("tokio", "::", "time", "::", "timeout_at", "(", "deadline", ",", "future", ")"),
        "absolute deadline",
        unique=True,
    )
    send = password.function("send_request_unix")
    send.require_order(
        (
            (("SensitiveRequestHeader", "::", "new", "(", "operation_id", ",", "kind"), "validated outbound header"),
            (("remaining_millis", "(", "deadline", ")"), "preflight live deadline"),
            (("with_deadline", "(", "deadline", ",", "stream", ".", "write_all", "(", "&", "header", ")", ")"), "header write"),
            (("with_deadline", "(", "deadline", ",", "stream", ".", "write_all", "(", "password", ".", "as_bytes", "(", ")", ")", ")"), "password write"),
            (("with_deadline", "(", "deadline", ",", "stream", ".", "shutdown", "(", ")", ")"), "bounded write shutdown"),
        )
    )
    send_error = password.item("enum", "UnixSensitivePasswordSendError")
    send_error.require(("NotSent", "(", "hbb_common", "::", "anyhow", "::", "Error", ")"), "pre-send failure class", unique=True)
    send_error.require(("Uncertain", "(", "hbb_common", "::", "anyhow", "::", "Error", ")"), "post-start uncertainty class", unique=True)
    send.require(
        ("map_err", "(", "UnixSensitivePasswordSendError", "::", "NotSent", ")"),
        "preflight NotSent classification",
    )
    send.require(
        ("map_err", "(", "UnixSensitivePasswordSendError", "::", "Uncertain", ")"),
        "started-write uncertainty classification",
    )

    status_encode = password.function("encode_status")
    status_encode.require_order(
        (
            (("bytes", "[", "..", "8", "]", ".", "copy_from_slice", "(", "&", "STATUS_MAGIC", ")"), "status magic"),
            (("bytes", "[", "8", "]", "=", "PROTOCOL_VERSION"), "status version"),
            (("bytes", "[", "9", "]", "=", "0"), "status canonical flags"),
            (("bytes", "[", "10", "]", "=", "status"), "status code"),
            (("bytes", "[", "11", "]", "=", "0"), "status canonical reserved byte"),
            (("bytes", "[", "12", "..", "28", "]", ".", "copy_from_slice", "(", "operation_id", ".", "as_bytes", "(", ")", ")"), "status UUID binding"),
        ),
        unique=True,
    )
    status_decode = password.function("decode_status")
    status_decode.require_order(
        (
            (("bytes", "[", "..", "8", "]", "!=", "STATUS_MAGIC"), "status magic validation"),
            (("bytes", "[", "28", "..", "]", ".", "iter", "(", ")", ".", "any"), "reserved-byte validation"),
            (("bytes", "[", "12", "..", "28", "]", "!=", "expected_operation_id", ".", "as_bytes"), "expected UUID comparison"),
        )
    )
    receive_status = password.function("receive_status_unix")
    receive_status.require_order(
        (
            (("SensitiveStackBytes", "::", "<", "STATUS_FRAME_BYTES", ">", "::", "zeroed"), "fixed status allocation"),
            (("with_deadline", "(", "deadline", ",", "stream", ".", "read_exact"), "bounded status read"),
            (("decode_status", "(", "&", "bytes", ".", "0", ",", "operation_id", ")"), "operation-bound status decode"),
            (("with_deadline", "(", "deadline", ",", "stream", ".", "read"), "bounded trailing-byte probe"),
        )
    )
    send_status = password.function("send_status_unix")
    send_status.require_order(
        (
            (("encode_status", "(", "operation_id", ",", "status", ")"), "canonical status encoding"),
            (("with_deadline", "(", "deadline", ",", "stream", ".", "write_all", "(", "&", "bytes", ")", ")"), "bounded status write"),
            (("with_deadline", "(", "deadline", ",", "stream", ".", "shutdown", "(", ")", ")"), "bounded status shutdown"),
        ),
        unique=True,
    )
    ack_encode = password.function("encode_ack")
    ack_encode.require_order(
        (
            (("bytes", "[", "..", "8", "]", ".", "copy_from_slice", "(", "&", "ACK_MAGIC", ")"), "acknowledgement magic"),
            (("bytes", "[", "8", "]", "=", "PROTOCOL_VERSION"), "acknowledgement version"),
            (("bytes", "[", "12", "..", "28", "]", ".", "copy_from_slice", "(", "operation_id", ".", "as_bytes", "(", ")", ")"), "acknowledgement UUID binding"),
        ),
        unique=True,
    )
    ack_decode = password.function("decode_ack")
    ack_decode.require_order(
        (
            (("bytes", "[", "..", "8", "]", "!=", "ACK_MAGIC"), "acknowledgement magic validation"),
            (("bytes", "[", "8", "]", "!=", "PROTOCOL_VERSION"), "acknowledgement version validation"),
            (("bytes", "[", "9", "..", "12", "]", ".", "iter", "(", ")", ".", "any"), "acknowledgement reserved-byte validation"),
            (("bytes", "[", "12", "..", "28", "]", "!=", "expected_operation_id", ".", "as_bytes"), "acknowledgement UUID validation"),
        )
    )


def verify_endpoint_ownership(rust: Mapping[str, RustSource]) -> None:
    config = rust["libs/hbb_common/src/config.rs"]
    service_postfix = config.function("is_service_ipc_postfix")
    service_postfix.require(
        ("matches", "!", "(", "postfix", ",", '"_service"', "|", '"_service_password"', ")"),
        "ordinary and password service endpoint classification",
        unique=True,
    )
    service_postfix.require(
        ("cfg", "!", "(", "any", "(", "target_os", "=", '"linux"', ",", "target_os", "=", '"macos"', ")", ")", "&&", "postfix", "==", '"_service_credential"'),
        "Linux/macOS credential replica service endpoint classification",
        unique=True,
    )
    parent_path = config.function("ipc_parent_dir_for_uid")
    parent_path.require_order(
        (
            (("is_service_ipc_postfix", "(", "postfix", ")"), "service classification"),
            (("format", "!", "(", '"/tmp/{app_name}-service"', ")"), "root-owned shared service parent"),
            (("format", "!", "(", '"/tmp/{app_name}-{uid}"', ")"), "UID-owned user parent"),
        )
    )
    ipc_path_for_uid = config.method(("impl", "Config"), "ipc_path_for_uid", "impl Config")
    ipc_path_for_uid.require_order(
        (
            (("ipc_parent_dir_for_uid", "(", "uid", ",", "postfix", ")"), "classified parent"),
            (("format", "!", "(", '"{parent}/ipc{postfix}"', ")"), "postfix-bound socket name"),
        ),
        unique=True,
    )

    fs = rust["src/ipc/fs.rs"]
    mode = fs.function("expected_ipc_parent_mode")
    mode.require_order(
        (
            (("is_service_ipc_postfix", "(", "postfix", ")"), "service classification"),
            (("0o0711",), "service directory mode"),
            (("0o0700",), "user directory mode"),
        ),
        unique=True,
    )
    open_parent = fs.function("open_ipc_parent_dir_fd")
    for required, label in (
        (("O_DIRECTORY",), "directory-only open"),
        (("O_CLOEXEC",), "close-on-exec"),
        (("O_NOFOLLOW",), "symlink refusal"),
    ):
        open_parent.require(required, label, unique=True)
    secure_parent = fs.function("ensure_secure_ipc_parent_dir")
    secure_parent.require_order(
        (
            (("open_ipc_parent_dir_fd", "(", "&", "parent_c", ")"), "no-follow parent open"),
            (("fstat", "(", "fd"), "same-inode metadata read"),
            (("S_IFDIR",), "directory type validation"),
            (("expected_uid", "=", "unsafe", "{", "hbb_common", "::", "libc", "::", "geteuid"), "effective owner binding"),
            (("recreate_foreign_service_ipc_parent_dir", "(", "parent_dir", ",", "postfix", ")"), "foreign service parent replacement"),
            (("if", "owner_uid", "!=", "expected_uid"), "post-replacement owner rejection"),
            (("expected_ipc_parent_mode", "(", "postfix", ")"), "exact expected mode"),
            (("fchmod", "(", "fd", ",", "expected_mode"), "same-inode mode enforcement"),
        )
    )
    recreate = fs.function("recreate_foreign_service_ipc_parent_dir")
    recreate.require_order(
        (
            (("open_ipc_parent_dir_fd", "(", "&", "gp_c", ")"), "no-follow grandparent open"),
            (("openat", "(", "gp_fd"), "foreign child open relative to grandparent"),
            (("scrub_preexisting_ipc_parent_entries", "(", "foreign_fd"), "known artifact scrub"),
            (("remove_parent_entry_via_fd", "(", "gp_fd"), "relative directory removal"),
            (("mkdirat", "(", "gp_fd"), "fresh directory creation"),
            (("openat", "(", "gp_fd"), "fresh directory reopen"),
        )
    )
    recreate.require(("O_NOFOLLOW",), "no-follow relative opens")

    ipc = rust["src/ipc.rs"]
    listener = ipc.function("new_listener")
    listener.require_order(
        (
            (("Config", "::", "ipc_path", "(", "postfix", ")"), "classified socket path"),
            (("ensure_secure_ipc_parent_dir", "(", "&", "path", ",", "postfix", ")"), "parent ownership/mode proof"),
            (("check_pid", "(", "postfix", ")"), "live listener check"),
            (("scrub_secure_ipc_parent_dir", "(", "&", "path", ",", "postfix", ")"), "stale artifact scrub"),
            (("Endpoint", "::", "new", "(", "path", ".", "clone", "(", ")", ")"), "endpoint construction after hardening"),
            (("is_service_ipc_postfix", "(", "postfix", ")"), "socket-mode classification"),
            (("0o0666",), "world-connectable authenticated service socket"),
            (("0o0600",), "owner-only user socket"),
            (("set_permissions", "(", "&", "path"), "post-bind socket mode enforcement"),
            (("remove_file", "(", "&", "path", ")"), "failed-mode cleanup"),
            (("return", "Err", "(", "err", ".", "into", "(", ")", ")"), "failed-mode fail closed"),
        )
    )


def verify_raw_endpoint_separation(rust: Mapping[str, RustSource]) -> None:
    ipc = rust["src/ipc.rs"]
    ordinary_request = ipc.item("enum", "MainIpcRequest")
    ordinary_request.require(
        ("PasswordMutationStatus", "{", "operation_id", ":", "String", ",", "}"),
        "non-secret recovery query",
        unique=True,
    )
    ordinary_request.require_identifier_absent(
        {
            "BeginServiceOwnedUnattendedPasswordChange",
            "BeginUserOwnedPermanentPassword",
            "CommitServiceOwnedUnattendedPasswordChange",
            "Password",
            "SensitivePassword",
            "SetPermanentPassword",
            "value",
        },
        "ordinary serde request carries a password or begin operation",
    )
    ipc.all().require_identifier_absent(
        {
            "BeginServiceOwnedUnattendedPasswordChange",
            "BeginUserOwnedPermanentPassword",
            "CommitServiceOwnedUnattendedPasswordChange",
        },
        "obsolete password-bearing ordinary IPC variant remains live",
    )

    for name in ("connect", "connect_with_path"):
        function = ipc.function(name)
        reject = function.require_order(
            (
                (("USER_PASSWORD_IPC_POSTFIX", "|", "password", "::", "SERVICE_PASSWORD_IPC_POSTFIX"), "both sensitive endpoints"),
                (("bail", "!", "(", '"sensitive password endpoints require the raw transport"', ")"), "raw-only rejection"),
                (("postfix", "==", "password", "::", "SERVICE_CREDENTIAL_IPC_POSTFIX"), "Linux credential endpoint"),
                (("bail", "!", "(", '"the service credential endpoint requires the raw transport"', ")"), "credential raw-only rejection"),
            )
        )[-1]
        endpoint_positions = function.positions(("Endpoint", "::", "connect")) + function.positions(
            ("connect_windows_named_pipe",)
        )
        if endpoint_positions and reject >= min(endpoint_positions):
            raise VerificationError(f"{function.label}: sensitive endpoint rejection occurs after connect")

    connect_raw = ipc.function("connect_sensitive_unix")
    connect_raw.require_order(
        (
            (("Config", "::", "ipc_path", "(", "postfix", ")"), "ordinary caller-owned raw endpoint path"),
            (("timeout", "(", "password", "::", "remaining_millis", "(", "deadline", ")", "?", ",", "Endpoint", "::", "connect"), "raw bounded connect"),
            (("match", "postfix", "{"), "finite endpoint dispatch"),
            (("USER_PASSWORD_IPC_POSTFIX", "=>"), "user endpoint proof"),
            (("geteuid", "(", ")"), "user-owned caller UID"),
            (("ensure_user_owned_password_server_is_trusted", "(", "&", "stream", ",", "expected_uid", ")"), "user-owned server UID/executable/argv proof"),
            (("SERVICE_PASSWORD_IPC_POSTFIX", "=>"), "service endpoint proof"),
            (("ensure_linux_root_service_stream", "(", "&", "stream", ",", "postfix", ")"), "service server kernel uid/PID proof"),
            (("_", "=>", "bail", "!", "(", '"unsupported sensitive Unix IPC endpoint"'), "unknown endpoint rejection"),
            (("remaining_millis", "(", "deadline", ")"), "post-proof deadline check"),
        )
    )
    connect_raw.forbid(
        ("authenticate_linux_service_owned_password_replica_server", "("),
        "service-owned child writer authority in the ordinary raw connector",
    )
    connect_raw.forbid(("service_owned_replica",), "detached service-owned replica Boolean")
    connect_raw.forbid(("Config", "::", "ipc_path_for_uid"), "root-to-child route selection")
    connect_raw.forbid(("ConnectionTmpl", "::"), "generic framed connection construction")
    connect_raw.forbid(("send_json",), "JSON transport")

    main_prepares = ipc.functions("prepare_main_ipc")
    if len(main_prepares) != 1:
        raise VerificationError("src/ipc.rs: expected one prepared main IPC owner")
    main_prepare = main_prepares[0]
    main_prepare.require_order(
        (
            (("new_listener", "(", '""', ")"), "ordinary main listener"),
            (("new_listener", "(", "password", "::", "USER_PASSWORD_IPC_POSTFIX", ")"), "separate raw password listener"),
        )
    )
    main_listener = ipc.function("run_main_ipc")
    main_listener.require_order(
        (
            (("next_sensitive_main_listener_event", "(", "&", "mut", "password_events", ")"), "raw accept lane"),
            (("sensitive_main_ipc_authority", "(", "&", "stream", ")"), "raw peer authorization"),
            (("try_acquire_sensitive_main_ipc_transaction_slot", "(", "authority", ".", "mutation_kind", "(", ")", OPTIONAL_COMMA, ")"), "typed raw bounded admission"),
            (("transactions", ".", "spawn", "(", "handle_sensitive_main_ipc_transaction"), "raw handler spawn"),
            (("Connection", "::", "new_main", "(", "stream", ")"), "ordinary framed main lane"),
        )
    )
    service_entry = ipc.function("start_service_ipc")
    service_entry.require_order(
        (
            (("prepare_service_ipc", "(", "postfix", ")", ".", "await"), "service listener preparation"),
            (("run_service_ipc", "(", "postfix", ",", "listeners", ")", ".", "await"), "service listener execution"),
        )
    )
    service_prepare = ipc.function("prepare_service_ipc")
    service_prepare.require_order(
        (
            (("new_listener", "(", "postfix", ")"), "ordinary service listener"),
            (("new_listener", "(", "password", "::", "SERVICE_PASSWORD_IPC_POSTFIX", ")"), "separate raw service-password listener"),
            (("new_listener", "(", "password", "::", "SERVICE_CREDENTIAL_IPC_POSTFIX", ")"), "separate raw service-credential listener"),
        )
    )
    service_listener = ipc.function("run_service_ipc")
    service_listener.require_order(
        (
            (("password_incoming", ".", "next", "(", ")"), "raw service accept lane"),
            (("try_acquire_service_password_ipc_transaction_slot", "(", ")"), "raw service bounded admission"),
            (("authenticate_linux_service_owned_password_requester", "(", "&", "stream", ")"), "exact Linux password-requester generation and role proof"),
            (("transactions", ".", "spawn", "(", "handle_sensitive_linux_service_ipc_transaction"), "raw Linux handler spawn"),
            (("Connection", "::", "new_protected_service", "(", "stream", ")"), "ordinary framed service lane"),
        )
    )
    credential_capacity = ipc.function("try_acquire_service_credential_ipc_transaction_slot")
    credential_capacity.require_order(
        (
            (("SERVICE_CREDENTIAL_IPC_TRANSACTION_SLOTS", ".", "get_or_init"), "dedicated credential semaphore"),
            (("Semaphore", "::", "new", "(", "SERVICE_CREDENTIAL_IPC_TRANSACTION_BUDGET", ")"), "dedicated credential budget"),
            (("try_acquire_owned", "(", ")"), "nonblocking bounded admission"),
        ),
        unique=True,
    )
    service_listener.require_order(
        (
            (("credential_incoming", ".", "next", "(", ")"), "raw credential accept lane"),
            (("try_acquire_service_credential_ipc_transaction_slot", "(", ")"), "credential work admission"),
            (("LinuxServiceOwnedCredentialReplicaRequester", "::", "authenticate", "(", "&", "stream", OPTIONAL_COMMA, ")"), "typed exact-child proof before request read"),
            (("transactions", ".", "spawn", "(", "handle_linux_service_credential_snapshot_transaction"), "owned credential handler"),
        )
    )
    for listener in (main_prepare, main_listener, service_prepare, service_listener):
        listener.require_identifier_absent(
            {"body_mut", "into_password", "read_exact", "receive_request_unix"},
            "listener reads a secret body outside its authenticated raw handler",
        )
    for handler_name, owner in (
        ("handle_sensitive_main_ipc_transaction", main_listener),
        ("handle_sensitive_linux_service_ipc_transaction", service_listener),
        ("handle_linux_service_credential_snapshot_transaction", service_listener),
    ):
        calls = non_definition_calls(ipc, handler_name)
        if len(calls) != 1 or not owner.start <= calls[0] < owner.end:
            raise VerificationError(
                f"src/ipc.rs: {handler_name} must have exactly one call from its authenticated listener"
            )

    main_authority = ipc.function("sensitive_main_ipc_authority")
    ipc.all().require(
        (
            "fn", "sensitive_main_ipc_authority", "(", "stream", ":", "&", "Conn", ")",
            "->", "Option", "<", "SensitiveMainPasswordAuthority", ">",
        ),
        "typed sensitive-main authority result",
        unique=True,
    )
    main_authority.require_order(
        (
            (("MainIpcAuthority", "::", "for_current_process", "(", ")", "==", "MainIpcAuthority", "::", "ServiceOwned"), "service-owned process selection"),
            (("LinuxServiceOwnedPasswordReplicaReceiver", "::", "authenticate", "(", "stream", ")"), "typed exact-parent receiver proof"),
            (("Ok", "(", "receiver", ")", "=>", "Some", "(", "SensitiveMainPasswordAuthority", "::", "ServiceOwnedRuntimePrs", "(", "receiver", ")", ")"), "retained service-owned receiver authority"),
            (("ensure_user_owned_password_client_is_trusted", "(", "stream", ",", "password", "::", "USER_PASSWORD_IPC_POSTFIX", ")"), "user client UID/executable proof"),
            (("Ok", "(", "(", ")", ")", "=>", "Some", "(", "SensitiveMainPasswordAuthority", "::", "UserOwned", ")"), "typed user-owned authority result"),
        )
    )
    main_authority.forbid(
        ("authenticate_linux_service_owned_password_parent", "("),
        "detached generic parent proof",
    )
    main_authority.forbid(
        ("Some", "(", "PasswordMutationKind", "::", "ServiceOwned", ")"),
        "service authority collapsed to a kind",
    )


def verify_linux_identity_and_authority(rust: Mapping[str, RustSource]) -> None:
    auth = rust["src/ipc/auth.rs"]
    peer_identity_record = auth.item("struct", "PeerProcessIdentity")
    peer_identity_record.require(
        ("argv", ":", "Vec", "<", "String", ">"),
        "complete retained process argv",
        unique=True,
    )
    peer_identity_record.forbid(("first_arg",), "first-argument-only process role identity")
    peer_identity_debug = auth.method(
        ("impl", "fmt", "::", "Debug", "for", "PeerProcessIdentity"),
        "fmt",
        "impl Debug for PeerProcessIdentity",
    )
    peer_identity_debug.require(
        ("field", "(", '"argv_len"', ",", "&", "self", ".", "argv", ".", "len", "(", ")", ")"),
        "non-secret argv cardinality diagnostic",
        unique=True,
    )
    peer_identity_debug.forbid(
        ("field", "(", '"argv"'),
        "untrusted complete argv disclosure in Debug",
    )
    allowed_uid = auth.function("is_allowed_service_peer_uid")
    allowed_uid.require(
        ("peer_uid", "==", "0", "||", "active_uid", ".", "is_some_and", "(", "|", "uid", "|", "uid", "==", "peer_uid", ")"),
        "root-or-current-active-user UID policy",
        unique=True,
    )
    fresh_candidates = [
        function
        for function in auth.functions("active_uid_fresh")
        if function.positions(("get_active_userid_fresh", "(", ")"))
    ]
    if len(fresh_candidates) != 1:
        raise VerificationError(
            "src/ipc/auth.rs: expected one Linux active_uid_fresh implementation"
        )
    fresh_uid = fresh_candidates[0]
    fresh_uid.require(("get_active_userid_fresh", "(", ")"), "fresh Linux session owner lookup", unique=True)

    snapshot = auth.function("service_scoped_ipc_authorization_snapshot_from_stream")
    snapshot.require_order(
        (
            (("peer_uid_from_fd", "(", "fd", ")"), "socket peer UID"),
            (("let", "peer_pid", "=", "peer_pid_from_fd", "(", "fd", ")"), "Linux socket peer PID binding"),
            (("active_uid_fresh", "(", ")"), "fresh active session UID"),
            (("is_allowed_service_peer_uid", "(", "uid", ",", "active_uid", ")"), "session authority decision"),
        )
    )
    authorize_snapshot = auth.function("authorize_service_scoped_ipc_authorization_snapshot")
    authorize_snapshot.require_order(
        (
            (("if", "!", "authorization", ".", "uid_authorized"), "UID rejection"),
            (("return", "false", ";"), "fail-closed UID result"),
            (("ensure_peer_executable_matches_current_by_pid_opt", "(", "authorization", ".", "peer_pid"), "same-executable proof"),
            (("return", "false", ";"), "fail-closed executable result"),
            (("true",), "authorized result"),
        )
    )

    process_identity = auth.function("linux_process_identity_by_pid")
    process_identity.require_order(
        (
            (("if", "pid", "==", "0"), "PID zero rejection"),
            (("ensure_peer_executable_matches_current_by_pid", "(", "pid", ",", "postfix", ")"), "same-executable proof"),
            (("linux_process_identity_fields_by_pid", "(", "pid", ")"), "live identity fields"),
        )
    )
    process_identity_fields = auth.function("linux_process_identity_fields_by_pid")
    process_identity_fields.require_order(
        (
            (("linux_proc_cmdline_args", "(", "pid", ")"), "live argv capture"),
            (("uid", ":", "linux_proc_uid", "(", "pid", ")"), "proc UID capture"),
            (("start_time", ":", "linux_proc_start_time", "(", "pid", ")"), "PID generation capture"),
            (("argv", ":", "args", ",", "cm_launch_token"), "complete process role capture"),
        )
    )
    service_child_identity = auth.function("linux_service_child_process_identity_by_pid")
    service_child_identity.require_order(
        (
            (("if", "pid", "==", "0"), "service-child PID zero rejection"),
            (("service_child_executable_identity_matches", "(", "pid", ")"), "selected child inode proof"),
            (("linux_process_identity_fields_by_pid", "(", "pid", ")"), "live service-child identity fields"),
        )
    )
    peer_identity = auth.function("peer_process_identity_from_stream")
    peer_identity.require_order(
        (
            (("peer_pid_from_fd", "(", "fd", ")"), "SO_PEERCRED PID"),
            (("peer_uid_from_fd", "(", "fd", ")"), "SO_PEERCRED UID"),
            (("linux_process_identity_by_pid", "(", "peer_pid", ",", "postfix", ")"), "proc identity"),
            (("if", "identity", ".", "uid", "!=", "peer_uid"), "socket/proc UID consistency"),
        )
    )
    live_identity = auth.function("peer_process_identity_is_live")
    live_identity.require(
        (
            "is_allowed_service_peer_uid",
            "(",
            "identity",
            ".",
            "uid",
            ",",
            "active_uid_fresh",
            "(",
            ")",
            ")",
        ),
        "fresh final active-session UID authority",
        unique=True,
    )
    session_gate = (
        "if", "!", "is_allowed_service_peer_uid", "(", "identity", ".", "uid", ",",
        "active_uid_fresh", "(", ")", ")", "{", "return", "false", ";", "}",
    )
    conjunctive_session_gate = (
        "is_allowed_service_peer_uid", "(", "identity", ".", "uid", ",",
        "active_uid_fresh", "(", ")", ")", "&&", "linux_process_identity_by_pid",
    )
    if not (
        live_identity.positions(session_gate)
        or live_identity.positions(conjunctive_session_gate)
    ):
        raise VerificationError(
            f"{live_identity.label}: fresh active-session UID must gate final identity acceptance"
        )
    live_identity.require_order(
        (
            (("linux_process_identity_by_pid", "(", "identity", ".", "pid", ",", "postfix", ")"), "fresh full identity"),
            (("live", "==", "*", "identity"), "PID/UID/start-time/full-argv equality"),
            (("linux_process_has_ancestor", "(", "identity", ".", "pid", ",", "identity", ".", "cm_launch_parent", ")"), "live launch ancestry"),
        )
    )

    exact_argv = auth.function("process_argv_is_exact")
    expected_exact_argv = [
        "args", ".", "len", "(", ")", "==", "expected_args", ".", "len", "(", ")", "+", "1",
        "&&", "expected_args", ".", "iter", "(", ")", ".", "enumerate", "(", ")", ".", "all", "(",
        "|", "(", "index", ",", "expected", ")", "|", "args", "[", "index", "+", "1", "]", "==", "*", "expected", ")",
    ]
    if exact_argv.values != expected_exact_argv:
        raise VerificationError(
            f"{exact_argv.label}: argv equality must require one executable plus every and only expected argument"
        )

    password_role = auth.function("linux_service_owned_password_client_argv_is_expected")
    expected_linux_password_role = [
        "process_argv_is_exact", "(", "args", ",", "&", "[", "]", ")",
        "||", "process_argv_is_exact", "(", "args", ",", "&", "[", '"--password"', "]", ")",
        "||", "process_argv_is_exact", "(", "args", ",", "&", "[", '"--password-stdin"', "]", ")",
    ]
    if password_role.values != expected_linux_password_role:
        raise VerificationError(
            f"{password_role.label}: requester roles must be exactly interactive UI, --password, or --password-stdin"
        )

    password_requester = auth.function("authenticate_linux_service_owned_password_requester")
    password_requester.require_order(
        (
            (("let", "postfix", "=", "super", "::", "password", "::", "SERVICE_PASSWORD_IPC_POSTFIX"), "fixed privileged endpoint"),
            (("peer_process_identity_from_stream", "(", "stream", ",", "postfix", ")"), "SO_PEERCRED/current-executable/full-identity capture"),
            (("if", "!", "linux_service_owned_password_client_argv_is_expected", "(", "&", "identity", ".", "argv", ")"), "finite exact requester role"),
            (("linux_service_owned_password_requester_is_live", "(", "&", "identity", ")"), "same-generation pre-body finality"),
            (("Ok", "(", "identity", ")"), "admitted exact identity"),
        )
    )
    password_requester_live = auth.function(
        "linux_service_owned_password_requester_is_live"
    )
    password_requester_live.require_order(
        (
            (("linux_service_owned_password_client_argv_is_expected", "(", "&", "identity", ".", "argv", ")"), "exact role recheck"),
            (("&&", "peer_process_identity_is_live", "(", "identity", ",", "super", "::", "password", "::", "SERVICE_PASSWORD_IPC_POSTFIX", ")"), "full live identity re-read"),
        ),
        unique=True,
    )

    auth_tests = auth.item("mod", "tests")
    password_role_regression = auth.function(
        "r_s11e261_linux_service_owned_password_client_roles_are_finite",
        parent=auth_tests.start - 1,
    )
    for admitted in ('"--password"', '"--password-stdin"'):
        password_role_regression.require((admitted,), f"admitted {admitted} role")
    for rejected in (
        '"--server"',
        "SERVICE_OWNED_SERVER_ARG",
        '"--service"',
        '"--tray"',
        '"--cm"',
        '"extra"',
        '"--unexpected"',
    ):
        password_role_regression.require((rejected,), f"rejected {rejected} role")

    user_server_argv = auth.function("user_owned_main_server_argv_is_expected")
    user_server_argv.require(("args", ".", "len", "(", ")", "==", "2"), "exact user server argv length", unique=True)
    user_server_argv.require(("Some", "(", '"--server"', ")"), "user server role", unique=True)
    service_owned_argv = auth.function("linux_service_owned_server_argv_is_expected")
    service_owned_argv.require(("args", ".", "len", "(", ")", "==", "3"), "exact service-owned child argv length", unique=True)
    service_owned_argv.require(("Some", "(", '"--server"', ")"), "service-owned child server role", unique=True)
    service_owned_argv.require(("Some", "(", "crate", "::", "common", "::", "SERVICE_OWNED_SERVER_ARG", ")"), "service-owned child marker", unique=True)

    root_service_peer = auth.function("validate_linux_root_service_peer")
    root_service_peer.require_order(
        (
            (("peer_uid", ".", "ok_or_else"), "kernel peer UID presence"),
            (("peer_uid", "!=", "0"), "root principal requirement"),
            (("peer_pid", ".", "ok_or_else"), "kernel peer PID presence"),
            (("peer_pid", "==", "0"), "positive PID requirement"),
            (("Ok", "(", "peer_pid", ")"), "validated PID result"),
        )
    )
    for forbidden in (
        "linux_proc_cmdline_args",
        "peer_exe_canonical_path_by_pid",
        "peer_process_identity_from_stream",
        "linux_proc_environ_value",
        "linux_proc_start_time",
    ):
        root_service_peer.forbid((forbidden,), f"ptrace/procfs-dependent root service proof: {forbidden}")
    root_service_connection = auth.function("ensure_linux_root_service_connection")
    root_service_connection.require(
        ("validate_linux_root_service_peer", "(", "stream", ".", "peer_uid", "(", ")", ",", "stream", ".", "peer_pid", "(", ")", ",", "postfix", ")"),
        "framed service connection uses the common kernel peer decision",
        unique=True,
    )
    root_service_stream = auth.function("ensure_linux_root_service_stream")
    root_service_stream.require_order(
        (
            (("stream", ".", "as_raw_fd", "(", ")"), "raw stream descriptor"),
            (("validate_linux_root_service_peer"), "common kernel peer decision"),
            (("peer_uid_from_fd", "(", "fd", ")"), "SO_PEERCRED UID"),
            (("peer_pid_from_fd", "(", "fd", ")"), "SO_PEERCRED PID"),
        )
    )
    auth.all().require_identifier_absent(
        {
            "ensure_linux_service_password_server_is_trusted",
            "ensure_linux_service_server_is_trusted",
            "linux_service_executable_is_trusted",
            "linux_service_process_argv_is_expected",
            "linux_trusted_service_executable_file_metadata",
            "linux_trusted_service_executable_parent_metadata",
        },
        "obsolete unprivileged root-procfs service proof",
    )
    user_server = auth.function("ensure_user_owned_password_server_is_trusted")
    user_server.require_order(
        (
            (("peer_uid_from_fd", "(", "fd", ")"), "server UID"),
            (("peer_uid", "!=", "expected_uid"), "expected UID enforcement"),
            (("peer_pid_from_fd", "(", "fd", ")"), "server PID"),
            (("ensure_peer_executable_matches_current_by_pid", "(", "peer_pid"), "same executable"),
            (("main_server_cmdline_args", "(", "peer_pid", ")"), "live argv"),
            (("user_owned_main_server_argv_is_expected", "(", "&", "args", ")"), "exact --server role"),
        )
    )
    user_main_server = auth.function("ensure_user_owned_main_server_is_trusted")
    user_main_server.require_order(
        (
            (("peer_uid", "!=", "current_uid"), "same-UID main server"),
            (("ensure_peer_executable_matches_current_by_pid", "(", "peer_pid", ",", '""', ")"), "same main-server executable"),
            (("main_server_cmdline_args", "(", "peer_pid", ")"), "live main-server argv"),
            (("user_owned_main_server_argv_is_expected", "(", "&", "args", ")"), "exact user main-server role"),
        )
    )
    user_client = auth.function("ensure_user_owned_password_client_is_trusted")
    user_client.require_order(
        (
            (("peer_uid_from_fd", "(", "fd", ")"), "client UID"),
            (("libc", "::", "geteuid", "(", ")"), "server UID"),
            (("peer_uid", "!=", "current_uid"), "same-UID enforcement"),
            (("peer_pid_from_fd", "(", "fd", ")"), "client PID"),
            (("ensure_peer_executable_matches_current_by_pid", "(", "peer_pid", ",", "postfix", ")"), "same-executable enforcement"),
        )
    )
    parent = auth.function("authenticate_linux_service_owned_password_parent")
    auth.all().require(
        (
            "pub", "(", "super", ")", "fn", "authenticate_linux_service_owned_password_parent", "<", "T", ">",
            "(", "stream", ":", "&", "T", ",", "postfix", ":", "&", "str", OPTIONAL_COMMA, ")",
            "->", "ResultType", "<", "LinuxProcessIdentity", ">",
        ),
        "parent-module-only retained Linux parent identity proof",
        unique=True,
    )
    parent.require_order(
        (
            (("peer_uid_from_fd", "(", "fd", ")"), "kernel parent UID"),
            (("peer_uid", "!=", "0"), "root parent requirement"),
            (("peer_pid_from_fd", "(", "fd", ")"), "kernel parent PID"),
            (("linux_kernel_process_identity_by_pid", "(", "peer_pid", ")"), "PID/UID/start-time parent generation"),
            (("identity", ".", "uid", "!=", "peer_uid"), "socket/proc UID continuity"),
            (("SERVICE_OWNED_SERVER_LAUNCH_PARENT_ENV",), "launch-parent authority"),
            (("linux_proc_parent_pid", "(", "std", "::", "process", "::", "id", "(", ")", ")"), "actual child parent PID"),
            (("peer_pid", "!=", "expected_parent"), "exact parent PID"),
            (("actual_parent", "!=", "expected_parent"), "direct parent binding"),
            (("Ok", "(", "identity", ")"), "retained accepted parent identity"),
        )
    )
    parent.forbid(
        ("peer_process_identity_from_stream",),
        "direct child proof cannot depend on ptrace-gated root procfs",
    )
    auth.all().forbid(
        ("pub", "(", "crate", ")", "fn", "authenticate_linux_service_owned_password_parent"),
        "crate-visible generic Linux parent proof",
    )
    replica = auth.function("authenticate_linux_service_owned_password_replica_server")
    replica.require_order(
        (
            (("service_child_peer_process_identity_from_stream", "(", "stream", ",", "postfix", ")"), "postfix-bound exact child executable identity"),
            (("linux_service_owned_server_argv_is_expected", "(", "&", "args", ")"), "exact replica argv"),
            (("SERVICE_OWNED_SERVER_LAUNCH_PARENT_ENV",), "replica launch-parent binding"),
            (("linux_proc_parent_pid", "(", "identity", ".", "pid", ")"), "actual replica parent PID"),
            (("SERVICE_OWNED_SERVER_GENERATION_ENV",), "replica generation capture"),
            (("actual_parent", "!=", "expected_parent"), "direct replica parent binding"),
            (("service_runtime_generation_matches", "(", "&", "generation", ")"), "current runtime generation binding"),
        )
    )
    service_owned_main = auth.function("authenticate_linux_service_owned_main_server")
    service_owned_main.require_order(
        (
            (("service_child_peer_process_identity", "(", "stream", ",", '""', ")"), "exact child main-server identity"),
            (("linux_service_owned_server_argv_is_expected", "(", "&", "args", ")"), "exact child main-server argv"),
            (("expected_parent", "=", "std", "::", "process", "::", "id", "(", ")"), "current service parent binding"),
            (("SERVICE_OWNED_SERVER_LAUNCH_PARENT_ENV",), "child launch-parent marker"),
            (("linux_proc_parent_pid", "(", "identity", ".", "pid", ")"), "actual child parent PID"),
            (("SERVICE_OWNED_SERVER_GENERATION_ENV",), "child generation capture"),
            (("actual_parent", "!=", "expected_parent"), "direct child parent binding"),
            (("service_runtime_generation_matches", "(", "&", "generation", ")"), "current child generation binding"),
        )
    )

    platform = rust["src/platform/linux.rs"]
    generation_match = platform.function("service_runtime_generation_matches")
    generation_match.require_order(
        (
            (("SERVICE_RUNTIME_GENERATION", ".", "get", "(", ")"), "root runtime generation owner"),
            (("is_some_and", "(", "|", "generation", "|", "generation", "==", "candidate", ")"), "exact generation equality"),
        ),
        unique=True,
    )
    executable_match = platform.function("service_child_executable_identity_matches")
    executable_match.require_order(
        (
            (("SERVICE_CHILD_EXECUTABLE_IDENTITY", ".", "get", "(", ")"), "selected child executable identity owner"),
            (("fs", "::", "metadata", "(", "format", "!", "(", '"/proc/{pid}/exe"', ")"), "live child executable inode"),
            (("executable", ".", "dev", "(", ")", ",", "executable", ".", "ino", "(", ")"), "live child executable identity"),
        )
    )

    ipc = rust["src/ipc.rs"]
    polkit_subject = ipc.function("linux_polkit_subject_for_identity")
    polkit_subject.require_order(
        (
            (("identity", ".", "pid", "(", ")"), "subject PID"),
            (("identity", ".", "start_time", "(", ")"), "subject PID generation"),
            (("identity", ".", "uid", "(", ")"), "subject UID"),
        ),
        unique=True,
    )
    polkit = ipc.function("linux_pkcheck_authorizes_service_owned_password_change")
    polkit.require_order(
        (
            (("trusted_linux_pkcheck_path", "(", ")"), "trusted fixed pkcheck path"),
            (("Command", "::", "new", "(", "pkcheck", ")"), "trusted command execution"),
            (("arg", "(", '"--action-id"', ")"), "polkit action argument"),
            (("arg", "(", "SET_UNATTENDED_PASSWORD_POLKIT_ACTION", ")"), "fixed action ID"),
            (("arg", "(", '"--process"', ")"), "process subject mode"),
            (("arg", "(", "&", "subject", ")"), "PID/start-time/UID subject"),
            (("arg", "(", '"--allow-user-interaction"', ")"), "interactive authorization"),
            (("Instant", "::", "now", "(", ")", "+", "PKCHECK_AUTHORIZATION_TIMEOUT"), "bounded authorization deadline"),
            (("Ok", "(", "Some", "(", "status", ")", ")", "if", "status", ".", "success", "(", ")", "=>", "return", "true"), "successful pkcheck exit as the only authorization result"),
            (("shutdown", ".", "is_cancelled", "(", ")"), "shutdown cancellation"),
            (("terminate_and_reap_linux_pkcheck", "(", "&", "mut", "child"), "child termination and reap"),
        )
    )
    admission_type = ipc.item("struct", "LinuxServiceOwnedPasswordAdmission")
    admission_type.require(
        ("requester", ":", "PeerProcessIdentity"),
        "retained full Linux requester identity",
        unique=True,
    )
    ipc.all().forbid(
        ("derive", "(", "Clone", ")", "]", "struct", "LinuxServiceOwnedPasswordAdmission"),
        "cloneable Linux password admission",
    )

    grant = ipc.function("grant_linux_service_owned_password_admission")
    ipc.all().require(
        (
            "async", "fn", "grant_linux_service_owned_password_admission", "(",
            "identity", ":", "&", "PeerProcessIdentity", OPTIONAL_COMMA, ")", "->",
            "Option", "<", "LinuxServiceOwnedPasswordAdmission", ">",
        ),
        "typed Linux password admission grant",
        unique=True,
    )
    grant.require_order(
        (
            (("linux_polkit_subject_for_identity", "(", "identity", ")"), "socket-derived polkit subject"),
            (("linux_pkcheck_authorizes_service_owned_password_change", "(", "subject", ",", "shutdown", ")"), "bounded polkit proof"),
            (("Ok", "(", "true", ")", "=>", "{"), "successful authorization branch"),
            (("linux_service_owned_password_requester_is_live", "(", "identity", ")"), "post-authorization full requester replay"),
            (("Some", "(", "LinuxServiceOwnedPasswordAdmission", "{", "requester", ":", "identity", ".", "clone", "(", ")"), "non-cloneable action admission grant"),
        ),
        unique=True,
    )
    grant.require(
        ("if", "!", "linux_service_owned_password_requester_is_live", "(", "identity", ")"),
        "fail-closed post-authorization requester guard",
        unique=True,
    )
    ipc.all().require(
        (
            "Some", "(", "LinuxServiceOwnedPasswordAdmission", "{",
            "requester", ":", "identity", ".", "clone", "(", ")", OPTIONAL_COMMA, "}", ")",
        ),
        "sole production Linux password admission construction",
        unique=True,
    )

    admission_commit = ipc.method(
        ("impl", "LinuxServiceOwnedPasswordAdmission"),
        "admit_commit",
        "Linux service-owned password admission capability",
    )
    ipc.all().require(
        (
            "fn", "admit_commit", "(", "self", ",", "coordinator", ":", "&",
            "LinuxPasswordAdmissionCoordinator", ",", "operation_id", ":", "&", "str", ",",
            "value", ":", "&", "str", OPTIONAL_COMMA, ")", "->", "ResultType", "<", "bool", ">",
        ),
        "consuming Linux password admission method",
        unique=True,
    )
    admission_commit.require_order(
        (
            (("LinuxPasswordCaller", "::", "from", "(", "&", "self", ".", "requester", ")"), "capability-derived ledger caller"),
            (("password_mutation_id_is_valid", "(", "operation_id", ")"), "canonical operation identifier"),
            (("service_owned_password_value_is_valid", "(", '"Linux"', ",", "value", ")"), "bounded credential value"),
            (("linux_service_owned_password_requester_is_live", "(", "&", "self", ".", "requester", ")"), "final full requester replay"),
            (("cancel_authorization", "(", "operation_id", ",", "value", ",", "&", "caller", ")"), "exact pre-admission cancellation"),
            (("admit_authorized", "(", "&", "self", ",", "operation_id", ",", "value", ")"), "capability-typed ledger transition"),
        )
    )
    admission_commit.require(
        (
            "if", "!", "password_mutation_id_is_valid", "(", "operation_id", ")",
            "||", "!", "service_owned_password_value_is_valid", "(", '"Linux"', ",", "value", ")",
            "||", "!", "linux_service_owned_password_requester_is_live", "(", "&", "self", ".", "requester", ")",
        ),
        "conjunctive operation, value, and requester validation",
        unique=True,
    )
    admission_commit.forbid(("authority_allowed",), "detached Linux authority Boolean")
    admission_commit.forbid(("admitted",), "detached Linux admission Boolean")

    coordinator_scope = ipc.impl(
        ("impl", "LinuxPasswordAdmissionCoordinator"),
        "Linux password admission coordinator",
    )
    coordinator_scope.require(
        (
            "fn", "admit_authorized", "(", "&", "self", ",", "admission", ":", "&",
            "LinuxServiceOwnedPasswordAdmission", ",",
        ),
        "action-specific coordinator admission parameter",
        unique=True,
    )
    coordinator_admission = ipc.method(
        ("impl", "LinuxPasswordAdmissionCoordinator"),
        "admit_authorized",
        "Linux password admission coordinator",
    )
    coordinator_admission.require_order(
        (
            (("LinuxPasswordCaller", "::", "from", "(", "&", "admission", ".", "requester", ")"), "capability-derived caller"),
            (("fingerprint", "=", "ledger", ".", "fingerprint", "(", "value", ")"), "exact value fingerprint"),
            (("entry", ".", "kind", "!=", "PasswordMutationKind", "::", "ServiceOwned"), "fixed service-owned kind"),
            (("entry", ".", "fingerprint", "!=", "fingerprint"), "value equality"),
            (("entry", ".", "caller", "!=", "caller"), "requester equality"),
            (("entry", ".", "state", "!=", "LinuxPasswordAdmissionState", "::", "Authorizing"), "sole pre-admission state"),
            (("entry", ".", "state", "=", "LinuxPasswordAdmissionState", "::", "Committing"), "irreversible admitted transition"),
        )
    )
    coordinator_admission.forbid(("bool",), "detached coordinator authority parameter")

    cancellation = ipc.method(
        ("impl", "LinuxPasswordAdmissionCoordinator"),
        "cancel_authorization",
        "Linux password admission coordinator",
    )
    cancellation.require_order(
        (
            (("fingerprint", "=", "ledger", ".", "fingerprint", "(", "value", ")"), "exact denied value fingerprint"),
            (("entry", ".", "kind", "!=", "PasswordMutationKind", "::", "ServiceOwned"), "denied service-owned kind"),
            (("entry", ".", "fingerprint", "!=", "fingerprint"), "denied value equality"),
            (("entry", ".", "caller", "!=", "*", "caller"), "denied requester equality"),
            (("entry", ".", "state", "!=", "LinuxPasswordAdmissionState", "::", "Authorizing"), "denied pre-admission state"),
            (("ledger", ".", "entries", ".", "remove", "(", "operation_id", ")"), "exact denied claim removal"),
        )
    )

    test_module = ipc.all().require(
        ("#", "[", "cfg", "(", "test", ")", "]", "mod", "test"),
        "IPC test module",
        unique=True,
    )
    production = Region(ipc, 0, test_module, "src/ipc.rs production")
    production.require(
        ("grant_linux_service_owned_password_admission", "(", "identity", ")", ".", "await"),
        "sole real Linux admission grant call",
        unique=True,
    )
    production.require(
        ("coordinator", ".", "admit_authorized", "(", "&", "self", ",", "operation_id", ",", "value", ")"),
        "sole capability-owned coordinator admission call",
        unique=True,
    )
    production.forbid(
        ("linux_peer_is_authorized_for_service_owned_password_change",),
        "obsolete Boolean Linux authority adapter",
    )
    production.forbid(("finish_authorization",), "obsolete Boolean ledger transition")


def verify_macos_identity_and_authority(rust: Mapping[str, RustSource]) -> None:
    auth = rust["src/ipc/auth.rs"]
    ipc = rust["src/ipc.rs"]

    requester_record = auth.item("struct", "MacosServiceOwnedPasswordRequester")
    requester_record.require(
        ("identity", ":", "MacosPeerProcessIdentity"),
        "retained macOS audit-token process generation",
        unique=True,
    )
    requester_record.require(
        ("argv", ":", "Vec", "<", "String", ">"),
        "retained complete macOS requester argv",
        unique=True,
    )

    audit_token_match = auth.function("macos_audit_token_matches_socket_identity")
    expected_audit_token_match = [
        "pid", "!=", "0",
        "&&", "macos_audit_token_word", "(", "token", ",", "MACOS_AUDIT_TOKEN_EUID_WORD", ")", "==", "uid",
        "&&", "macos_audit_token_word", "(", "token", ",", "MACOS_AUDIT_TOKEN_PID_WORD", ")", "==", "pid",
    ]
    if audit_token_match.values != expected_audit_token_match:
        raise VerificationError(
            f"{audit_token_match.label}: audit-token EUID and PID must exactly match the socket identity"
        )

    identity_constructor = auth.function(
        "macos_peer_process_identity_from_socket_components"
    )
    expected_identity_constructor = [
        "if", "!", "macos_audit_token_matches_socket_identity", "(", "&", "audit_token", ",", "uid", ",", "pid", ")", "{",
        "return", "None", ";", "}",
        "Some", "(", "MacosPeerProcessIdentity", "{", "uid", ",", "pid", ",", "audit_token", ",", "}", ")",
    ]
    if identity_constructor.values != expected_identity_constructor:
        raise VerificationError(
            f"{identity_constructor.label}: identity must be constructed only after explicit audit-token/socket rejection"
        )

    stream_identity = auth.function("macos_peer_process_identity_from_stream")
    stream_identity.require_order(
        (
            (("peer_uid_from_fd", "(", "fd", ")"), "socket UID"),
            (("peer_pid_from_fd", "(", "fd", ")"), "socket effective PID"),
            (("peer_audit_token_from_fd", "(", "fd", ")"), "socket audit token"),
            (("macos_peer_process_identity_from_socket_components", "(", "uid", ",", "pid", ",", "audit_token", ")"), "consistent identity constructor"),
        ),
        unique=True,
    )

    service_snapshot = auth.function(
        "service_scoped_ipc_authorization_snapshot_from_stream"
    )
    service_snapshot.require_order(
        (
            (("Some", "(", "uid", ")", ",", "Some", "(", "pid", ")", ",", "Some", "(", "audit_token", ")", ")", "=>", "{"), "complete socket components"),
            (("macos_peer_process_identity_from_socket_components", "(", "uid", ",", "pid", ",", "audit_token", ")"), "consistent identity constructor"),
        ),
        unique=True,
    )

    password_role = auth.function("macos_service_owned_password_client_argv_is_expected")
    expected_macos_password_role = [
        "process_argv_is_exact", "(", "args", ",", "&", "[", "]", ")",
        "||", "process_argv_is_exact", "(", "args", ",", "&", "[", '"--password"', "]", ")",
        "||", "process_argv_is_exact", "(", "args", ",", "&", "[", '"--password-stdin"', "]", ")",
    ]
    if password_role.values != expected_macos_password_role:
        raise VerificationError(
            f"{password_role.label}: requester roles must be exactly interactive UI, --password, or --password-stdin"
        )

    generation_live = auth.function(
        "macos_service_owned_password_requester_generation_is_live"
    )
    generation_live.require_order(
        (
            (("macos_peer_code", "(", "identity", ",", '"installed app generation"', ")"), "audit-token dynamic-code lookup"),
            (("macos_peer_code_satisfies_requirement", "("), "live installed-app code requirement"),
            (("macos_peer_code_path", "(", "&", "code", ",", '"installed app generation"', ")"), "live code path"),
            (("macos_executable_matches_expected_path", "(", "&", "path", ",", "&", "macos_installed_app_executable_path", "(", ")", ")"), "exact installed executable"),
            (("is_allowed_service_peer_uid", "(", "identity", ".", "uid", ",", "active_uid_fresh", "(", ")", ")"), "post-capture fresh root-or-console UID"),
        )
    )

    identity_live = auth.function("macos_service_owned_password_requester_identity_is_live")
    identity_live.require_order(
        (
            (("is_allowed_service_peer_uid", "(", "identity", ".", "uid", ",", "active_uid_fresh", "(", ")", ")"), "root-or-fresh-console UID"),
            (("&&", "macos_peer_is_trusted_installed_app", "(", "identity", ")"), "audit-token and installed-layout proof"),
        ),
        unique=True,
    )

    requester_auth = auth.function("authenticate_macos_service_owned_password_requester")
    requester_auth.require_order(
        (
            (("authorization", ".", "postfix", "!=", "super", "::", "password", "::", "SERVICE_PASSWORD_IPC_POSTFIX"), "fixed raw password endpoint"),
            (("if", "!", "authorization", ".", "uid_authorized"), "snapshot UID authority"),
            (("macos_peer_identity", ".", "ok_or_else"), "accepted-socket audit-token identity"),
            (("macos_service_owned_password_requester_identity_is_live", "(", "&", "identity", ")"), "fresh complete installed-app proof"),
            (("macos_process_cmdline_args", "(", "identity", ".", "pid", ")"), "complete requester argv capture"),
            (("macos_service_owned_password_client_argv_is_expected", "(", "&", "argv", ")"), "finite exact requester role"),
            (("macos_service_owned_password_requester_generation_is_live", "(", "&", "identity", ")"), "post-argv audit-token generation and fresh-UID finality"),
            (("Ok", "(", "MacosServiceOwnedPasswordRequester", "{", "identity", ",", "argv", "}", ")"), "retained exact requester"),
        )
    )

    right_requester_auth = auth.function(
        "authenticate_macos_service_owned_password_right_requester"
    )
    right_requester_auth.require_order(
        (
            (("authorization", ".", "postfix", "!=", "crate", "::", "POSTFIX_SERVICE"), "fixed generic service endpoint"),
            (("if", "!", "authorization", ".", "uid_authorized"), "snapshot UID authority"),
            (("macos_peer_identity", ".", "ok_or_else"), "retained accepted-socket audit-token identity"),
            (("macos_service_owned_password_requester_identity_is_live", "(", "&", "identity", ")"), "fresh complete installed-app proof"),
            (("macos_process_cmdline_args", "(", "identity", ".", "pid", ")"), "complete readiness requester argv capture"),
            (("macos_service_owned_password_client_argv_is_expected", "(", "&", "requester_argv", ")"), "finite exact readiness requester role"),
            (("macos_service_owned_password_requester_generation_is_live", "(", "&", "identity", ")"), "post-argv audit-token generation and fresh-UID finality"),
            (("Ok", "(", "MacosServiceOwnedPasswordRequester", "{", "identity", ",", "argv", ":", "requester_argv", ",", "}", ")"), "retained exact readiness requester"),
        )
    )

    requester_live = auth.function("macos_service_owned_password_requester_is_live")
    requester_live.require_order(
        (
            (("macos_service_owned_password_requester_identity_is_live", "(", "&", "requester", ".", "identity", ")"), "fresh complete installed-app replay"),
            (("macos_process_cmdline_args", "(", "requester", ".", "identity", ".", "pid", ")"), "fresh complete argv"),
            (("argv", "==", "requester", ".", "argv"), "retained/fresh argv equality"),
            (("macos_service_owned_password_client_argv_is_expected", "(", "&", "argv", ")"), "finite role replay"),
            (("macos_service_owned_password_requester_generation_is_live", "(", "&", "requester", ".", "identity", ")"), "post-argv audit-token and fresh-UID finality"),
        )
    )
    requester_live.require(
        (
            "argv", "==", "requester", ".", "argv",
            "&&", "macos_service_owned_password_client_argv_is_expected", "(", "&", "argv", ")",
            "&&", "macos_service_owned_password_requester_generation_is_live", "(", "&", "requester", ".", "identity", ")",
        ),
        "conjunctive retained-argv, finite-role, and audit-token-generation replay",
        unique=True,
    )

    post_request_last_owner = auth.function(
        "macos_service_owned_password_requester_matches_post_request_last_owner"
    )
    expected_post_request_last_owner = [
        "let", "Ok", "(", "identity", ")", "=", "macos_peer_process_identity_from_stream", "(",
        "stream", ",", '"post-request macOS service-owned password requester last owner"', ",", ")",
        "else", "{", "return", "false", ";", "}", ";",
        "identity", ".", "uid", "==", "requester", ".", "identity", ".", "uid",
        "&&", "identity", ".", "pid", "==", "requester", ".", "identity", ".", "pid",
        "&&", "identity", ".", "audit_token", "==", "requester", ".", "identity", ".", "audit_token",
    ]
    if post_request_last_owner.values != expected_post_request_last_owner:
        raise VerificationError(
            f"{post_request_last_owner.label}: post-request socket last owner must exactly replay UID, PID, and full audit token"
        )

    right_post_request = auth.function(
        "macos_service_owned_password_right_requester_matches_post_request_authorization"
    )
    expected_right_post_request = [
        "if", "authorization", ".", "postfix", "!=", "crate", "::", "POSTFIX_SERVICE",
        "||", "!", "authorization", ".", "uid_authorized", "{", "return", "false", ";", "}",
        "let", "Some", "(", "post_request_identity", ")", "=", "authorization", ".", "macos_peer_identity",
        "else", "{", "return", "false", ";", "}", ";",
        "post_request_identity", ".", "uid", "==", "requester", ".", "identity", ".", "uid",
        "&&", "post_request_identity", ".", "pid", "==", "requester", ".", "identity", ".", "pid",
        "&&", "post_request_identity", ".", "audit_token", "==", "requester", ".", "identity", ".", "audit_token",
    ]
    if right_post_request.values != expected_right_post_request:
        raise VerificationError(
            f"{right_post_request.label}: post-request readiness authority must exactly replay endpoint, UID authority, PID, and full audit token"
        )

    proof_task = ipc.function("authenticate_macos_service_owned_password_requester_for_task")
    proof_task.require_order(
        (
            (("run_bounded_macos_security_proof", "(", "deadline", ",", '"macos-password-ipc-proof"'), "exactly owned bounded proof"),
            (("authenticate_macos_service_owned_password_requester", "(", "authorization", ")"), "action-specific admission"),
            (("Ok", "(", "requester", ")", "=>", "Some", "(", "requester", ")"), "retained requester result"),
            (("Err", "(", "err", ")"), "fail-closed proof error"),
            (("None",), "rejected result"),
        )
    )

    run_service = ipc.function("run_service_ipc")
    password_branch_start = run_service.require(
        ("result", "=", "password_incoming", ".", "next", "(", ")"),
        "raw service-password branch",
        unique=True,
    )
    ordinary_branch_start = run_service.require(
        ("result", "=", "incoming", ".", "next", "(", ")"),
        "ordinary service branch",
        unique=True,
    )
    password_branch = Region(
        run_service.rust,
        password_branch_start,
        ordinary_branch_start,
        "macOS raw service-password admission branch",
    )
    password_branch.require_order(
        (
            (("try_acquire_service_password_ipc_transaction_slot", "(", ")"), "fixed transaction permit"),
            (("try_acquire_macos_service_password_ipc_authorization_slot", "(", ")"), "fixed proof permit"),
            (("service_scoped_ipc_authorization_snapshot_from_stream", "(", "&", "stream", ",", "password", "::", "SERVICE_PASSWORD_IPC_POSTFIX"), "pre-task socket identity snapshot"),
            (("transactions", ".", "spawn", "(", "async", "move"), "owned transaction"),
            (("authenticate_macos_service_owned_password_requester_for_task", "("), "action-specific proof"),
            (("handle_sensitive_macos_service_ipc_transaction", "(", "stream", ",", "requester", ",", "permit", ",", "deadline"), "retained requester dispatch"),
        )
    )
    password_branch.forbid(
        ("authorize_macos_service_scoped_password_stream_for_task", "("),
        "generic macOS password admission fallback",
    )
    password_branch.forbid(("receive_request_unix", "("), "secret read before action proof")

    service_proof = ipc.function("authorize_macos_service_scoped_ipc_connection_for_task")
    service_proof.require_order(
        (
            (("authorization", ".", "clone", "(", ")"), "retained pre-task authorization snapshot"),
            (("authorize_service_scoped_ipc_authorization_snapshot", "(", "authorization", ")"), "generic installed-app/helper proof"),
            (("Ok", "(", "(", "retained_authorization", ",", "authorized", ")", ")"), "proof and retained identity result"),
            (("Ok", "(", "(", "authorization", ",", "true", ")", ")", "=>", "Some", "(", "authorization", ")"), "authorized retained identity"),
            (("Ok", "(", "(", "_authorization", ",", "false", ")", ")", "=>", "None"), "generic denial"),
        )
    )

    run_service.require_order(
        (
            (("result", "=", "incoming", ".", "next", "(", ")"), "generic service-control branch"),
            (("try_acquire_service_ipc_transaction_slot", "(", ")"), "fixed service transaction permit"),
            (("try_acquire_macos_service_ipc_authorization_slot", "(", ")"), "fixed generic proof permit"),
            (("service_scoped_ipc_authorization_snapshot", "(", "&", "stream", ",", "postfix"), "pre-task socket identity snapshot"),
            (("transactions", ".", "spawn", "(", "async", "move"), "owned transaction"),
            (("authorize_macos_service_scoped_ipc_connection_for_task", "(", "authorization"), "retained generic proof"),
            (("handle_service_ipc_transaction", "(", "stream", ",", "&", "postfix", ",", "authorization", ")"), "retained identity dispatch"),
        )
    )

    service_transaction = ipc.function("handle_service_ipc_transaction")
    service_transaction.require_order(
        (
            (("next_service_request_timeout", "(", "SERVICE_IPC_REQUEST_TIMEOUT_MS", ")"), "bounded closed request read"),
            (("handle_service_request", "(", "request", ",", "&", "mut", "stream", ",", "authorization", ")"), "retained identity request dispatch"),
        )
    )

    service_handler = ipc.function("handle_service_request")
    service_handler.require_order(
        (
            (("ServiceIpcRequest", "::", "EnsurePasswordRightReady"), "password-right readiness operation"),
            (("macos_service_owned_password_authorization_right_is_ready", "(", "_authorization", ",", "stream", ",", "deadline"), "retained identity readiness dispatch"),
            (("ServiceIpcResponse", "::", "PasswordRightReady", "{", "ready", "}"), "typed readiness result"),
        )
    )

    readiness = ipc.function("macos_service_owned_password_authorization_right_is_ready")
    readiness.require_order(
        (
            (("try_acquire_macos_service_password_ipc_authorization_slot", "(", ")"), "fixed password proof permit"),
            (("service_scoped_ipc_authorization_snapshot", "(", "stream", ",", "crate", "::", "POSTFIX_SERVICE", ")"), "post-request socket identity snapshot"),
            (("run_bounded_macos_security_proof", "(", "deadline", ",", '"macos-password-right-proof"'), "bounded action proof"),
            (("authenticate_macos_service_owned_password_right_requester", "(", "authorization", ")"), "exact readiness requester admission"),
            (("grant_macos_service_owned_password_right_admission", "(", "requester", ",", "post_request_authorization"), "consuming exact-requester admission"),
            (("admission", ".", "ensure_ready", "(", ")"), "capability-owned authorization policy write"),
        )
    )
    readiness.forbid(
        ("macos_service_owned_password_right_requester_matches_post_request_authorization", "("),
        "direct post-request identity proof outside admission grant",
    )
    readiness.forbid(
        ("ensure_service_owned_unattended_password_authorization_right", "("),
        "direct policy write outside admission capability",
    )

    right_admission_type = ipc.item("struct", "MacosServiceOwnedPasswordRightAdmission")
    right_admission_type.require(
        ("requester", ":", "MacosServiceOwnedPasswordRequester"),
        "exact password-right requester ownership",
        unique=True,
    )
    ipc.all().forbid(
        ("derive", "(", "Clone", ")", "]", "struct", "MacosServiceOwnedPasswordRightAdmission"),
        "cloneable macOS password-right admission",
    )
    ipc.all().forbid(
        ("derive", "(", "Copy", ")", "]", "struct", "MacosServiceOwnedPasswordRightAdmission"),
        "copyable macOS password-right admission",
    )

    right_admission_grant = ipc.function("grant_macos_service_owned_password_right_admission")
    ipc.all().require(
        (
            "fn", "grant_macos_service_owned_password_right_admission", "(",
            "requester", ":", "MacosServiceOwnedPasswordRequester", ",",
            "post_request_authorization", ":", "ipc_auth", "::",
            "ServiceScopedIpcAuthorization", OPTIONAL_COMMA, ")", "->", "Option", "<",
            "MacosServiceOwnedPasswordRightAdmission", ">",
        ),
        "consuming typed macOS password-right admission constructor",
        unique=True,
    )
    right_admission_grant.require_order(
        (
            (("macos_service_owned_password_right_requester_matches_post_request_authorization", "(", "&", "requester", ",", "post_request_authorization"), "post-request full-identity replay"),
            (("Some", "(", "MacosServiceOwnedPasswordRightAdmission", "{", "requester", "}", ")"), "action admission mint"),
        )
    )
    right_admission_grant.require(
        (
            "if", "!", "macos_service_owned_password_right_requester_matches_post_request_authorization", "(",
            "&", "requester", ",", "post_request_authorization", OPTIONAL_COMMA, ")",
        ),
        "fail-closed post-request password-right identity equality",
        unique=True,
    )
    right_admission_grant.forbid(("bool",), "detached Boolean password-right admission")
    ipc.all().require(
        (
            "Some", "(", "MacosServiceOwnedPasswordRightAdmission", "{", "requester", "}", ")",
        ),
        "sole macOS password-right admission construction",
        unique=True,
    )

    right_admission_action = ipc.method(
        ("impl", "MacosServiceOwnedPasswordRightAdmission"),
        "ensure_ready",
        "macOS password-right action admission capability",
    )
    ipc.all().require(
        ("fn", "ensure_ready", "(", "self", ")", "->", "bool"),
        "consuming macOS password-right action",
        unique=True,
    )
    right_admission_action.require_order(
        (
            (("macos_service_owned_password_requester_is_live", "(", "&", "self", ".", "requester", ")"), "final complete role/generation replay"),
            (("ensure_service_owned_unattended_password_authorization_right", "(", ")"), "authorization policy write"),
        )
    )
    right_admission_action.require(
        (
            "macos_service_owned_password_requester_is_live", "(", "&", "self", ".", "requester", ")",
            "&&", "crate", "::", "platform", "::", "ensure_service_owned_unattended_password_authorization_right", "(", ")",
        ),
        "final requester replay and policy write conjunction",
        unique=True,
    )

    sensitive = ipc.function("handle_sensitive_macos_service_ipc_transaction")
    sensitive.require_order(
        (
            (("password", "::", "receive_request_unix", "("), "bounded secret request read"),
            (("SensitivePayloadKind", "::", "PasswordWithAuthorization"), "password-plus-capability wire"),
            (("run_bounded_macos_security_proof", "("), "owned capability and finality proof"),
            (("grant_macos_service_owned_password_admission", "(", "requester", ",", "request", ".", "authorization", "(", ")"), "action-specific admission grant"),
            (("Ok", "(", "(", "request", ",", "admission", ")", ")"), "retained request and admission result"),
            (("request", ".", "into_password", "(", ")"), "secret ownership transfer"),
            (("admission", ".", "prepare_mutation", "(", "&", "stream"), "capability-owned final replay and ledger admission"),
            (("MacosServiceOwnedPasswordPreparation", "::", "Prepared"), "new prepared mutation dispatch"),
            (("handle_macos_service_owned_unattended_password_request", "("), "privileged mutation admission"),
            (("MacosServiceOwnedPasswordPreparation", "::", "Status"), "authorized status-only dispatch"),
            (("resolve_macos_service_owned_unattended_password_status", "("), "status-only resolution"),
        )
    )
    sensitive.forbid(
        ("capability_and_requester_are_live",),
        "detached macOS capability/requester Boolean",
    )
    sensitive.forbid(("authority_allowed",), "detached macOS mutation-authority Boolean")

    admission_type = ipc.item("struct", "MacosServiceOwnedPasswordAdmission")
    admission_type.require(
        ("requester", ":", "MacosServiceOwnedPasswordRequester"),
        "exact requester ownership",
        unique=True,
    )
    ipc.all().forbid(
        ("derive", "(", "Clone", ")", "]", "struct", "MacosServiceOwnedPasswordAdmission"),
        "cloneable macOS password admission",
    )

    prepared_type = ipc.item("struct", "PreparedMacosServiceOwnedPasswordMutation")
    for field in (
        ("operation_id", ":", "String"),
        ("password", ":", "SensitivePassword"),
    ):
        prepared_type.require(field, "prepared mutation ownership", unique=True)
    prepared_type.forbid(
        ("preparation", ":", "PasswordMutationPreparation"),
        "unproven ledger preparation in prepared mutation",
    )

    preparation_type = ipc.item("enum", "MacosServiceOwnedPasswordPreparation")
    preparation_type.require(
        (
            "Prepared", "(", "PreparedMacosServiceOwnedPasswordMutation", ")", ",",
            "Status", "{", "operation_id", ":", "String", ",",
            "status", ":", "PasswordMutationStatus",
        ),
        "separate prepared-mutation and secret-free status outcomes",
        unique=True,
    )
    preparation_type.forbid(("SensitivePassword",), "secret-bearing replay status")

    admission_grant = ipc.function("grant_macos_service_owned_password_admission")
    ipc.all().require(
        (
            "fn", "grant_macos_service_owned_password_admission", "(",
            "requester", ":", "MacosServiceOwnedPasswordRequester", ",",
            "authorization", ":", "&", "[", "u8", "]", OPTIONAL_COMMA, ")",
            "->", "Option", "<", "MacosServiceOwnedPasswordAdmission", ">",
        ),
        "typed macOS password admission constructor",
        unique=True,
    )
    admission_grant.require_order(
        (
            (("ensure_service_owned_unattended_password_authorization_right", "(", ")"), "exact right definition"),
            (("verify_service_owned_unattended_password_authorization", "(", "authorization", ")"), "Authorization Services capability verification"),
            (("macos_service_owned_password_requester_is_live", "(", "&", "requester", ")"), "post-authorization exact requester replay"),
            (("Some", "(", "MacosServiceOwnedPasswordAdmission", "{", "requester", "}", ")"), "non-cloneable action admission grant"),
        )
    )
    ipc.all().require(
        ("Some", "(", "MacosServiceOwnedPasswordAdmission", "{", "requester", "}", ")"),
        "sole macOS password admission construction",
        unique=True,
    )
    admission_grant.require(
        ("if", "!", "crate", "::", "platform", "::", "ensure_service_owned_unattended_password_authorization_right", "(", ")"),
        "fail-closed right normalization guard",
        unique=True,
    )
    admission_grant.require(
        ("if", "!", "crate", "::", "platform", "::", "verify_service_owned_unattended_password_authorization", "(", "authorization", ")"),
        "fail-closed Authorization Services guard",
        unique=True,
    )
    admission_grant.require(
        ("if", "!", "macos_service_owned_password_requester_is_live", "(", "&", "requester", ")"),
        "fail-closed post-authorization requester guard",
        unique=True,
    )
    admission_grant.forbid(("bool",), "Boolean macOS admission result")

    admission_prepare = ipc.method(
        ("impl", "MacosServiceOwnedPasswordAdmission"),
        "prepare_mutation",
        "macOS service-owned password admission capability",
    )
    ipc.all().require(
        (
            "fn", "prepare_mutation", "(", "self", ",", "stream", ":", "&", "Conn", ",",
            "operation_id", ":", "String", ",", "password", ":", "SensitivePassword",
            OPTIONAL_COMMA, ")", "->", "Option", "<",
            "MacosServiceOwnedPasswordPreparation", ">",
        ),
        "consuming action-specific admission method",
        unique=True,
    )
    admission_prepare.require_order(
        (
            (("password_mutation_id_is_valid", "(", "&", "operation_id", ")"), "canonical operation identifier"),
            (("service_owned_password_value_is_valid", "(", '"macOS"', ",", "password", ".", "as_str", "(", ")"), "bounded credential value"),
            (("macos_service_owned_password_requester_is_live", "(", "&", "self", ".", "requester", ")"), "final requester generation replay"),
            (("macos_service_owned_password_requester_matches_post_request_last_owner", "(", "&", "self", ".", "requester", ",", "stream"), "post-request socket last-owner replay"),
            (("prepare_macos_service_owned", "(", "&", "self", ",", "&", "operation_id", ",", "password", ".", "as_str", "(", ")"), "capability-typed ledger admission"),
            (("if", "preparation", ".", "owns_preparation"), "new Prepared insertion proof"),
            (("MacosServiceOwnedPasswordPreparation", "::", "Prepared"), "prepared outcome"),
            (("PreparedMacosServiceOwnedPasswordMutation", "{"), "prepared service-owned mutation"),
            (("MacosServiceOwnedPasswordPreparation", "::", "Status"), "secret-free authorized status outcome"),
        )
    )
    admission_prepare.require(
        (
            "if", "!", "password_mutation_id_is_valid", "(", "&", "operation_id", ")",
            "||", "!", "service_owned_password_value_is_valid", "(", '"macOS"', ",",
            "password", ".", "as_str", "(", ")", OPTIONAL_COMMA, ")",
        ),
        "conjunctive identifier and value validation",
        unique=True,
    )
    admission_prepare.require(
        ("if", "!", "macos_service_owned_password_requester_is_live", "(", "&", "self", ".", "requester", ")"),
        "fail-closed final requester guard",
        unique=True,
    )
    admission_prepare.require(
        (
            "if", "!", "macos_service_owned_password_requester_matches_post_request_last_owner", "(",
            "&", "self", ".", "requester", ",", "stream", OPTIONAL_COMMA, ")",
        ),
        "fail-closed post-request last-owner guard",
        unique=True,
    )
    admission_prepare.forbid(("authority_allowed",), "detached final authority Boolean")
    admission_prepare.forbid(("admission_allowed",), "detached ledger-admission Boolean")

    prepare_calls = non_definition_calls(ipc, "prepare_macos_service_owned")
    if len(prepare_calls) != 1 or not (
        admission_prepare.start <= prepare_calls[0] < admission_prepare.end
    ):
        raise VerificationError(
            "macOS service-owned password ledger admission must have exactly one capability-owned caller"
        )

    coordinator_scope = ipc.impl(
        ("impl", "PasswordMutationCoordinator"),
        "password mutation coordinator",
    )
    coordinator_admission = ipc.method(
        ("impl", "PasswordMutationCoordinator"),
        "prepare_macos_service_owned",
        "password mutation coordinator",
    )
    coordinator_scope.require(
        (
            "fn", "prepare_macos_service_owned", "(", "&", "self", ",",
            "_admission", ":", "&", "MacosServiceOwnedPasswordAdmission", ",",
        ),
        "action-specific admission parameter",
        unique=True,
    )
    coordinator_admission.require_order(
        (
            (("prepare_if_allowed", "("), "shared ledger state machine"),
            (("PasswordMutationKind", "::", "ServiceOwned"), "service-owned mutation kind"),
            (("true",), "capability-authorized insertion"),
        )
    )

    mac_password_mutation = ipc.function(
        "handle_macos_service_owned_unattended_password_request"
    )
    ipc.all().require(
        (
            "async", "fn", "handle_macos_service_owned_unattended_password_request", "(",
            "mutation", ":", "PreparedMacosServiceOwnedPasswordMutation", OPTIONAL_COMMA, ")",
            "->", "PasswordMutationStatus",
        ),
        "prepared mutation input",
        unique=True,
    )
    mac_password_mutation.require_order(
        (
            (("let", "PreparedMacosServiceOwnedPasswordMutation", "{"), "prepared mutation consumption"),
            (("try_acquire_main_ipc_blocking_mutation_slot", "("), "prepared mutation permit"),
            (("acknowledge", "(", "&", "operation_id"), "prepared ledger acknowledgement"),
            (("spawn_password_mutation", "("), "service-owned mutation worker"),
        )
    )
    mac_password_mutation.forbid(("authority_allowed",), "detached handler authority Boolean")
    mac_password_mutation.forbid(("admission_allowed",), "detached handler admission Boolean")
    mac_password_mutation.forbid(("prepare_if_allowed", "("), "direct Boolean ledger admission")
    mac_password_mutation.forbid(
        ("preparation", ".", "owns_preparation"),
        "handler-side preparation-state inference",
    )
    handler_calls = non_definition_calls(
        ipc, "handle_macos_service_owned_unattended_password_request"
    )
    if len(handler_calls) != 1 or not (
        sensitive.start <= handler_calls[0] < sensitive.end
    ):
        raise VerificationError(
            "prepared macOS service-owned password handler must have exactly one sensitive-transaction caller"
        )

    status_resolver = ipc.function(
        "resolve_macos_service_owned_unattended_password_status"
    )
    status_resolver.require_order(
        (
            (("match", "status"), "authorized status classification"),
            (("PasswordMutationStatus", "::", "Complete"), "completed replay"),
            (("PasswordMutationStatus", "::", "Prepared"), "in-flight prepared replay"),
            (("password_mutations", "(", ")", ".", "wait_for_complete"), "bounded completion wait"),
        )
    )
    for forbidden, label in (
        (("SensitivePassword",), "secret-bearing status resolution"),
        (("prepare_if_allowed", "("), "status resolver ledger admission"),
        (("prepare_macos_service_owned", "("), "status resolver typed ledger admission"),
        (("acknowledge", "("), "status resolver acknowledgement"),
        (("spawn_password_mutation", "("), "status resolver mutation worker"),
    ):
        status_resolver.forbid(forbidden, label)
    status_calls = non_definition_calls(
        ipc, "resolve_macos_service_owned_unattended_password_status"
    )
    if len(status_calls) != 1 or not (
        sensitive.start <= status_calls[0] < sensitive.end
    ):
        raise VerificationError(
            "macOS password status resolver must have exactly one sensitive-transaction caller"
        )

    tests = auth.item("mod", "tests")
    regression = auth.function(
        "r_s11e262_macos_service_owned_password_client_roles_are_finite",
        parent=tests.start - 1,
    )
    for admitted in ('"--password"', '"--password-stdin"'):
        regression.require((admitted,), f"admitted macOS {admitted} role")
    for rejected in (
        '"--server"',
        "SERVICE_OWNED_SERVER_ARG",
        '"--service"',
        '"--tray"',
        '"--cm"',
        '"extra"',
        '"--unexpected"',
    ):
        regression.require((rejected,), f"rejected macOS {rejected} role")

    identity_regression = auth.function(
        "r_s11e262_macos_audit_token_must_match_socket_identity",
        parent=tests.start - 1,
    )
    identity_regression.require_order(
        (
            (("macos_audit_token_matches_socket_identity", "(", "&", "token", ",", "uid", ",", "pid", ")"), "matching identity admitted"),
            (("uid", "+", "1"), "mismatched EUID rejected"),
            (("pid", "+", "1"), "mismatched PID rejected"),
            (("&", "token", ",", "uid", ",", "0"), "zero PID rejected"),
        )
    )


def verify_mutation_coordinators(rust: Mapping[str, RustSource]) -> None:
    ipc = rust["src/ipc.rs"]
    for name, value in (
        ("PASSWORD_MUTATION_RESULT_BUDGET", "64"),
        ("SERVICE_PASSWORD_IPC_TRANSACTION_BUDGET", "4"),
        ("MAIN_PASSWORD_IPC_TRANSACTION_BUDGET", "16"),
        ("MAIN_IPC_BLOCKING_MUTATION_BUDGET", "1"),
    ):
        ipc.all().require(
            ("const", name, ":", "usize", "=", value, ";"),
            f"fixed {name} capacity",
            unique=True,
        )

    ipc.all().require(
        (
            "pub",
            "const",
            "PASSWORD_MUTATION_RECOVERY_TIMEOUT_SECONDS",
            ":",
            "u64",
            "=",
            "600",
            ";",
        ),
        "exported overall password mutation recovery bound",
        unique=True,
    )
    ipc.all().require(
        (
            "const",
            "PASSWORD_MUTATION_RECOVERY_TIMEOUT",
            ":",
            "std",
            "::",
            "time",
            "::",
            "Duration",
            "=",
            "std",
            "::",
            "time",
            "::",
            "Duration",
            "::",
            "from_secs",
            "(",
            "PASSWORD_MUTATION_RECOVERY_TIMEOUT_SECONDS",
            ")",
            ";",
        ),
        "overall password mutation recovery deadline derivation",
        unique=True,
    )

    for function_name, budget in (
        (
            "try_acquire_service_password_ipc_transaction_slot",
            "SERVICE_PASSWORD_IPC_TRANSACTION_BUDGET",
        ),
        (
            "try_acquire_sensitive_main_ipc_transaction_slot",
            "MAIN_PASSWORD_IPC_TRANSACTION_BUDGET",
        ),
        (
            "try_acquire_main_ipc_blocking_mutation_slot",
            "MAIN_IPC_BLOCKING_MUTATION_BUDGET",
        ),
    ):
        admission = ipc.function(function_name)
        admission.require_order(
            (
                (("Semaphore", "::", "new", "(", budget, ")"), "bounded semaphore construction"),
                (("try_acquire_owned", "(", ")"), "non-waiting admission"),
            )
        )
        admission.forbid(("acquire_owned", "(", ")"), "waiting admission")

    fingerprint = ipc.function("password_mutation_fingerprint")
    fingerprint.require(
        (
            "hmacsha256",
            "::",
            "authenticate",
            "(",
            "value",
            ".",
            "as_bytes",
            "(",
            ")",
            ",",
            "key",
            ")",
        ),
        "keyed password digest",
        unique=True,
    )
    fingerprint_drop = ipc.method(
        ("impl", "Drop", "for", "PasswordMutationFingerprint"),
        "drop",
        "impl Drop for PasswordMutationFingerprint",
    )
    fingerprint_drop.require(("zeroize_sensitive_bytes", "(", "&", "mut", "self", ".", "0", ".", "0", ")"), "digest zeroization", unique=True)
    for ledger_name in ("PasswordMutationLedger", "LinuxPasswordAdmissionLedger"):
        new = ipc.method(("impl", ledger_name), "new", f"impl {ledger_name}")
        new.require(("hmacsha256", "::", "gen_key", "(", ")"), "process-random digest key", unique=True)
        clear = ipc.method(("impl", ledger_name), "clear_sensitive_state", f"impl {ledger_name}")
        clear.require_order(
            (
                (("entries", ".", "clear", "(", ")"), "entry/digest eviction"),
                (("zeroize_sensitive_bytes", "(", "&", "mut", "self", ".", "fingerprint_key", ".", "0", ")"), "digest-key zeroization"),
            ),
            unique=True,
        )
        evict = ipc.method(("impl", ledger_name), "evict_oldest_complete", f"impl {ledger_name}")
        evict.require_order(
            (
                (("Complete", "(", "_", ",", "completed_at", ")"), "terminal-only eviction candidates"),
                (("min_by_key", "(", "|", "(", "_", ",", "completed_at", ")", "|", "*", "completed_at", ")"), "oldest terminal selection"),
                (("entries", ".", "remove", "(", "&", "operation_id", ")"), "selected terminal eviction"),
            )
        )

    valid_id = ipc.function("password_mutation_id_is_valid")
    valid_id.require_order(
        (
            (("operation_id", ".", "len", "(", ")", "==", "PASSWORD_MUTATION_ID_BYTES"), "canonical UUID text length"),
            (("Uuid", "::", "parse_str", "(", "operation_id", ")"), "UUID parse"),
            (("id", ".", "to_string", "(", ")", "==", "operation_id"), "canonical UUID spelling"),
        )
    )

    prepare = ipc.method(("impl", "PasswordMutationCoordinator"), "prepare_if_allowed", "impl PasswordMutationCoordinator")
    prepare.require_order(
        (
            (("password_mutation_id_is_valid", "(", "operation_id", ")"), "operation ID validation"),
            (("ledger", ".", "fingerprint", "(", "value", ")"), "password digest"),
            (("entry", ".", "kind", "!=", "kind", "||", "entry", ".", "fingerprint", "!=", "fingerprint"), "kind/digest replay consistency"),
            (("if", "!", "admission_allowed"), "authority admission gate"),
            (("if", "ledger", ".", "shutting_down"), "shutdown non-admission"),
            (("entries", ".", "len", "(", ")", ">=", "PASSWORD_MUTATION_RESULT_BUDGET"), "ledger capacity bound"),
            (("ledger", ".", "evict_oldest_complete", "(", ")"), "terminal-only capacity reclamation"),
            (("state", ":", "PasswordMutationState", "::", "Prepared"), "prepared admission"),
        )
    )
    acknowledge = ipc.method(("impl", "PasswordMutationCoordinator"), "acknowledge", "impl PasswordMutationCoordinator")
    acknowledge.require_order(
        (
            (("ledger", ".", "fingerprint", "(", "value", ")"), "password digest"),
            (("entry", ".", "kind", "!=", "kind"), "kind consistency"),
            (("entry", ".", "fingerprint", "!=", "fingerprint"), "digest consistency"),
            (("entry", ".", "state", "!=", "PasswordMutationState", "::", "Prepared"), "prepared-only acknowledgement"),
            (("entry", ".", "state", "=", "PasswordMutationState", "::", "Pending"), "pending transition"),
        )
    )
    complete = ipc.method(("impl", "PasswordMutationCoordinator"), "complete", "impl PasswordMutationCoordinator")
    complete.require_order(
        (
            (("entry", ".", "kind", "!=", "kind", "||", "entry", ".", "state", "!=", "PasswordMutationState", "::", "Pending"), "kind/pending consistency"),
            (("entry", ".", "state", "=", "PasswordMutationState", "::", "Complete", "(", "result", ",", "std", "::", "time", "::", "Instant", "::", "now", "(", ")", ")"), "timestamped terminal transition"),
            (("notify_waiters", "(", ")"), "finality notification"),
        )
    )
    fail = ipc.method(("impl", "PasswordMutationCoordinator"), "fail_admitted", "impl PasswordMutationCoordinator")
    fail.require_order(
        (
            (("ledger", ".", "fingerprint", "(", "value", ")"), "failure digest"),
            (("entry", ".", "kind", "!=", "kind"), "failure kind consistency"),
            (("entry", ".", "fingerprint", "!=", "fingerprint"), "failure digest consistency"),
            (("Prepared", "|", "PasswordMutationState", "::", "Pending"), "admitted state restriction"),
            (("Complete", "(", "IpcMutationResult", "::", "InternalFailure", ",", "std", "::", "time", "::", "Instant", "::", "now", "(", ")", OPTIONAL_COMMA, ")"), "timestamped terminal internal failure"),
            (("notify_waiters", "(", ")"), "failure finality notification"),
        )
    )
    status = ipc.method(("impl", "PasswordMutationCoordinator"), "status", "impl PasswordMutationCoordinator")
    status.require_order(
        (
            (("password_mutation_id_is_valid", "(", "operation_id", ")"), "query ID validation"),
            (("filter", "(", "|", "entry", "|", "entry", ".", "kind", "==", "kind", ")"), "query kind isolation"),
            (("password_mutation_status", "(", "entry", ".", "state", ")"), "state projection"),
        )
    )
    begin_mutation = ipc.function("begin_user_owned_password_mutation")
    begin_mutation.require_order(
        (
            (("kind", "=", "PasswordMutationKind", "::", "UserOwned"), "fixed user-owned mutation kind"),
            (("prepare_if_allowed", "(", "&", "operation_id", ",", "kind", ",", "value", ".", "as_str"), "prepare/bind operation"),
            (("if", "!", "preparation", ".", "owns_preparation"), "replay without duplicate worker"),
            (("try_acquire_main_ipc_blocking_mutation_slot", "(", ")"), "single blocking mutation admission"),
            (("fail_admitted", "(", "&", "operation_id", ",", "kind", ",", "value", ".", "as_str"), "capacity failure finalization"),
            (("acknowledge", "(", "&", "operation_id", ",", "kind", ",", "value", ".", "as_str"), "prepared acknowledgement"),
            (("spawn_password_mutation", "(", "operation_id", ".", "clone", "(", ")", ",", "value", ",", "kind", ",", "permit", ")"), "owned commit worker"),
            (("PasswordMutationStatus", "::", "Prepared", ",", "Some", "(", "worker", ")"), "acknowledged begin response"),
        )
    )
    completion_drop = ipc.method(
        ("impl", "Drop", "for", "PasswordMutationCompletion"),
        "drop",
        "impl Drop for PasswordMutationCompletion",
    )
    completion_drop.require(
        ("coordinator", ".", "complete", "(", "&", "self", ".", "operation_id", ",", "self", ".", "kind", ",", "self", ".", "result", ")"),
        "RAII terminal-state recording",
        unique=True,
    )
    worker = ipc.function("spawn_password_mutation")
    worker.require_order(
        (
            (("Arc", "::", "clone", "(", "password_mutations", "(", ")", ")"), "coordinator ownership"),
            (("spawn_blocking", "(", "move", "||", "{"), "dedicated blocking worker"),
            (("let", "_permit", "=", "permit"), "capacity permit ownership"),
            (("result", ":", "IpcMutationResult", "::", "InternalFailure"), "panic/error-safe default"),
            (("Config", "::", "set_permanent_password_persisted", "(", "value", ".", "as_str", "(", ")", ")"), "durable non-replica authority"),
            (("completion", ".", "result", "=", "result"), "RAII final result update"),
        )
    )
    worker.forbid(
        ("set_permanent_password_prs_for_runtime", "("),
        "generic worker runtime-PRS installation",
    )
    worker.forbid(
        ("is_service_owned_server_process", "("),
        "ambient process-role runtime-PRS selection",
    )
    worker.forbid(("service_owned_runtime_replica",), "detached runtime-replica Boolean")

    linux_begin = ipc.method(("impl", "LinuxPasswordAdmissionCoordinator"), "begin", "impl LinuxPasswordAdmissionCoordinator")
    linux_begin.require_order(
        (
            (("ledger", ".", "fingerprint", "(", "value", ")"), "Linux password digest"),
            (("entry", ".", "kind", "!=", "kind", "||", "entry", ".", "fingerprint", "!=", "fingerprint", "||", "entry", ".", "caller", "!=", "*", "caller"), "operation/kind/digest/caller replay binding"),
            (("Authorizing", "|", "LinuxPasswordAdmissionState", "::", "Committing"), "in-flight wait"),
            (("Recoverable", "=>", "{"), "recoverable commit state"),
            (("entry", ".", "state", "=", "LinuxPasswordAdmissionState", "::", "Committing"), "single recovery owner"),
            (("if", "ledger", ".", "shutting_down"), "Linux shutdown non-admission"),
            (("entries", ".", "len", "(", ")", ">=", "PASSWORD_MUTATION_RESULT_BUDGET"), "Linux ledger capacity"),
            (("ledger", ".", "evict_oldest_complete", "(", ")"), "Linux terminal-only capacity reclamation"),
            (("caller", ":", "caller", ".", "clone", "(", ")"), "caller identity retention"),
            (("state", ":", "LinuxPasswordAdmissionState", "::", "Authorizing"), "new authority state"),
        )
    )
    cancel_auth = ipc.method(("impl", "LinuxPasswordAdmissionCoordinator"), "cancel_authorization", "impl LinuxPasswordAdmissionCoordinator")
    cancel_auth.forbid(
        ("LinuxPasswordAdmissionState", "::", "Complete", "(", "IpcMutationResult", "::", "Rejected"),
        "durable replay entry for a denied authorization",
    )
    release = ipc.method(("impl", "LinuxPasswordAdmissionCoordinator"), "release_failed_commit", "impl LinuxPasswordAdmissionCoordinator")
    release.require_order(
        (
            (("entry", ".", "caller", "!=", "*", "caller"), "failed-commit caller binding"),
            (("entry", ".", "state", "!=", "LinuxPasswordAdmissionState", "::", "Committing"), "committing-only release"),
            (("entry", ".", "state", "=", "LinuxPasswordAdmissionState", "::", "Recoverable"), "recoverable transition"),
            (("notify_waiters", "(", ")"), "recovery notification"),
        )
    )
    linux_complete = ipc.method(
        ("impl", "LinuxPasswordAdmissionCoordinator"),
        "complete",
        "impl LinuxPasswordAdmissionCoordinator",
    )
    linux_complete.require_order(
        (
            (("entry", ".", "caller", "!=", "*", "caller"), "completion caller binding"),
            (("Complete", "(", "existing", ",", "_", ")", "=", "entry", ".", "state"), "idempotent terminal replay"),
            (("return", "existing", "==", "result"), "terminal result consistency"),
            (("entry", ".", "state", "!=", "LinuxPasswordAdmissionState", "::", "Committing"), "committing-only completion"),
            (("entry", ".", "state", "=", "LinuxPasswordAdmissionState", "::", "Complete", "(", "result", ",", "std", "::", "time", "::", "Instant", "::", "now", "(", ")", ")"), "timestamped Linux terminal transition"),
            (("notify_waiters", "(", ")"), "Linux finality notification"),
        )
    )

    windows_ledger_new = ipc.method(
        ("impl", "WindowsCredentialOperationLedger"),
        "new",
        "impl WindowsCredentialOperationLedger",
    )
    windows_ledger_new.require(
        ("hmacsha256", "::", "gen_key", "(", ")"),
        "process-random Windows request key",
        unique=True,
    )
    windows_ledger_evict = ipc.method(
        ("impl", "WindowsCredentialOperationLedger"),
        "evict_oldest_complete",
        "impl WindowsCredentialOperationLedger",
    )
    windows_ledger_evict.require_order(
        (
            (("Complete", "(", "_", ",", "completed_at", ")"), "Windows terminal-only eviction candidates"),
            (("Active", "=>", "None"), "Windows live-operation retention"),
            (("min_by_key", "(", "|", "(", "_", ",", "completed_at", ")", "|", "*", "completed_at", ")"), "oldest Windows terminal selection"),
            (("entries", ".", "remove", "(", "&", "operation_id", ")"), "selected Windows terminal eviction"),
        )
    )
    windows_ledger_admit = ipc.method(
        ("impl", "WindowsCredentialOperationLedger"),
        "admit",
        "impl WindowsCredentialOperationLedger",
    )
    windows_ledger_admit.require_order(
        (
            (("self", ".", "shutting_down", "||", "transaction_active"), "Windows shutdown/active transaction non-admission"),
            (("entries", ".", "contains_key", "(", "operation_id", ")"), "Windows duplicate non-admission"),
            (("entries", ".", "len", "(", ")", ">=", "self", ".", "capacity"), "Windows ledger capacity"),
            (("self", ".", "evict_oldest_complete", "(", ")"), "Windows terminal-only capacity reclamation"),
            (("WindowsCredentialOperationState", "::", "Active"), "Windows live admission"),
        )
    )
    windows_ledger_complete = ipc.method(
        ("impl", "WindowsCredentialOperationLedger"),
        "complete",
        "impl WindowsCredentialOperationLedger",
    )
    windows_ledger_complete.require_order(
        (
            (("entry", ".", "state", "!=", "WindowsCredentialOperationState", "::", "Active"), "Windows active-only completion"),
            (("WindowsCredentialOperationState", "::", "Complete", "(", "result", ",", "std", "::", "time", "::", "Instant", "::", "now", "(", ")", ")"), "timestamped Windows terminal transition"),
        )
    )


def verify_windows_password_admission_authority(rust: Mapping[str, RustSource]) -> None:
    ipc = rust["src/ipc.rs"]
    auth = rust["src/ipc/auth.rs"]
    windows = rust["src/platform/windows.rs"]

    user_capability = ipc.item("struct", "WindowsUserOwnedPasswordAdmission")
    user_capability.require(
        ("_requester", ":", "ipc_auth", "::", "WindowsSensitivePipeClientProof"),
        "retained user-owned requester proof",
        unique=True,
    )
    service_capability = ipc.item("struct", "WindowsServiceOwnedPasswordAdmission")
    service_capability.require(
        ("_requester", ":", "WindowsServiceOwnedPasswordRequester"),
        "retained service-owned requester authority",
        unique=True,
    )
    service_requester = ipc.item("enum", "WindowsServiceOwnedPasswordRequester")
    service_requester.require(
        (
            "Authenticated",
            "{",
            "_proof",
            ":",
            "ipc_auth",
            "::",
            "WindowsSensitivePipeClientProof",
            OPTIONAL_COMMA,
            "}",
        ),
        "production authenticated requester proof",
        unique=True,
    )
    for item_name in (
        "WindowsUserOwnedPasswordAdmission",
        "WindowsServiceOwnedPasswordAdmission",
    ):
        declaration = ipc.all().require(("struct", item_name), f"{item_name} declaration", unique=True)
        preceding = ipc.all().values[max(0, declaration - 12) : declaration]
        if "Clone" in preceding or "Copy" in preceding:
            raise VerificationError(f"src/ipc.rs: {item_name} must be non-cloneable")

    proof_impl = ("impl", "WindowsSensitivePipeClientProof")
    revalidate = auth.method(proof_impl, "revalidate", "impl WindowsSensitivePipeClientProof")
    revalidate.require_order(
        (
            (("windows_named_pipe_client_pid", "(", "pipe", ")"), "stable pipe client PID"),
            (("process", ".", "require_running", "("), "retained process liveness"),
            (("windows_process_creation_time", "("), "same process generation"),
            (("process", ".", "fresh_identity", "(", ")"), "fresh immutable identity"),
            (("process", ".", "live_token_proof", "(", ")"), "fresh process token"),
            (("windows_named_pipe_client_token_proof", "("), "fresh impersonated pipe token"),
            (("windows_sensitive_pipe_security_at_deadline", "("), "fresh endpoint security"),
            (("process_token", "!=", "self", ".", "process_token"), "retained token equality"),
            (("windows_sensitive_auth_deadline_live", "("), "final deadline sample"),
        )
    )
    auth.impl(proof_impl, "impl WindowsSensitivePipeClientProof").forbid(
        ("pub", "(", "crate", ")", "fn", "revalidate"),
        "externally callable detached Windows proof revalidation",
    )

    user_mint = auth.method(
        proof_impl,
        "into_user_owned_password_admission",
        "impl WindowsSensitivePipeClientProof",
    )
    user_mint.require_order(
        (
            (("self", ".", "postfix", "!=", "super", "::", "password", "::", "USER_PASSWORD_IPC_POSTFIX"), "exact user endpoint"),
            (("self", ".", "revalidate", "(", "pipe", ",", "deadline", ")"), "final live proof"),
            (("WindowsUserOwnedPasswordAdmission", "{", "_requester", ":", "self", "}"), "consuming user admission mint"),
        )
    )
    service_mint = auth.method(
        proof_impl,
        "into_service_owned_password_admission",
        "impl WindowsSensitivePipeClientProof",
    )
    service_mint.require_order(
        (
            (("self", ".", "postfix", "!=", "super", "::", "password", "::", "SERVICE_PASSWORD_IPC_POSTFIX"), "exact service endpoint"),
            (("self", ".", "revalidate", "(", "pipe", ",", "deadline", ")"), "final live proof"),
            (("WindowsServiceOwnedPasswordRequester", "::", "Authenticated", "{", "_proof", ":", "self", OPTIONAL_COMMA, "}"), "consuming service admission mint"),
        )
    )
    auth.all().require(
        (
            "pub", "(", "crate", ")", "fn", "into_user_owned_password_admission", "(",
            "self", ",", "pipe", ":", "HANDLE", ",", "deadline", ":", "Instant",
            OPTIONAL_COMMA, ")", "->", "ResultType", "<", "super", "::",
            "WindowsUserOwnedPasswordAdmission", ">",
        ),
        "consuming typed user admission signature",
        unique=True,
    )
    auth.all().require(
        (
            "pub", "(", "crate", ")", "fn", "into_service_owned_password_admission", "(",
            "self", ",", "pipe", ":", "HANDLE", ",", "deadline", ":", "Instant",
            OPTIONAL_COMMA, ")", "->", "ResultType", "<", "super", "::",
            "WindowsServiceOwnedPasswordAdmission", ">",
        ),
        "consuming typed service admission signature",
        unique=True,
    )

    user_request = windows.item("struct", "WindowsUserOwnedPasswordRequest")
    user_request.require_order(
        (
            (("admission", ":", "ipc", "::", "WindowsUserOwnedPasswordAdmission"), "typed user admission"),
            (("operation_id", ":", "String"), "operation ID"),
            (("value", ":", "ipc", "::", "SensitivePassword"), "owned secret"),
            (("response", ":", "std_mpsc", "::", "SyncSender", "<", "ipc", "::", "PasswordMutationStatus", ">"), "status channel"),
        ),
        unique=True,
    )
    service_request = windows.item("struct", "WindowsServiceOwnedPasswordRequest")
    service_request.require_order(
        (
            (("admission", ":", "ipc", "::", "WindowsServiceOwnedPasswordAdmission"), "typed service admission"),
            (("operation_id", ":", "String"), "operation ID"),
            (("value", ":", "ipc", "::", "SensitivePassword"), "owned secret"),
            (("response", ":", "std_mpsc", "::", "SyncSender", "<", "ipc", "::", "PasswordMutationStatus", ">"), "status channel"),
        ),
        unique=True,
    )
    sender = windows.item("enum", "WindowsSensitivePasswordRequestSender")
    sender.require_order(
        (
            (("UserOwned", "(", "mpsc", "::", "Sender", "<", "WindowsUserOwnedPasswordRequest", ">", ")"), "user request channel"),
            (("ServiceOwned", "(", "mpsc", "::", "Sender", "<", "WindowsServiceOwnedPasswordRequest", ">", ")"), "service request channel"),
        ),
        unique=True,
    )
    sender_postfix = windows.method(
        ("impl", "WindowsSensitivePasswordRequestSender"),
        "postfix",
        "impl WindowsSensitivePasswordRequestSender",
    )
    sender_postfix.require_order(
        (
            (("Self", "::", "UserOwned", "(", "_", ")", "=>", "ipc", "::", "password", "::", "USER_PASSWORD_IPC_POSTFIX"), "fixed user endpoint"),
            (("Self", "::", "ServiceOwned", "(", "_", ")", "=>", "ipc", "::", "password", "::", "SERVICE_PASSWORD_IPC_POSTFIX"), "fixed service endpoint"),
        )
    )

    handler = windows.function("handle_windows_sensitive_password_pipe")
    handler.require_order(
        (
            (("postfix", "=", "requests", ".", "postfix", "(", ")"), "sender-derived endpoint"),
            (("preauthorize_windows_sensitive_pipe_client", "("), "bounded preauthorization"),
            (("read_message", "(", "&", "mut", "header_bytes", ".", "0"), "header read"),
            (("authorize_windows_sensitive_pipe_client", "("), "complete client proof"),
            (("read_message", "(", "request", ".", "body_mut", "(", ")"), "body read"),
            (("request", ".", "validate_utf8", "(", ")"), "body validation"),
            (("WindowsSensitivePasswordRequestSender", "::", "UserOwned", "(", "requests", ")", "=>"), "user action branch"),
            (("proof", ".", "into_user_owned_password_admission", "(", "pipe", ".", "handle", ".", "0", ",", "deadline", ")"), "final user admission"),
            (("WindowsUserOwnedPasswordRequest", "{", "admission", ","), "typed user handoff"),
            (("WindowsSensitivePasswordRequestSender", "::", "ServiceOwned", "(", "requests", ")", "=>"), "service action branch"),
            (("proof", ".", "into_service_owned_password_admission", "(", "pipe", ".", "handle", ".", "0", ",", "deadline", ")"), "final service admission"),
            (("WindowsServiceOwnedPasswordRequest", "{", "admission", ","), "typed service handoff"),
            (("encode_status", "(", "operation_id", ",", "status", ")"), "operation-bound status"),
            (("decode_ack", "(", "&", "acknowledgement", ".", "0", ",", "operation_id", ")"), "operation-bound acknowledgement"),
        )
    )
    handler.forbid(("postfix", ":", "&", "'static", "str"), "caller-selected endpoint")
    handler.forbid(("proof", ".", "revalidate", "("), "detached final proof")
    enqueue = windows.function("enqueue_windows_sensitive_password_request")
    enqueue.require(("requests", ".", "try_send", "(", "request", ")"), "bounded typed enqueue", unique=True)

    windows.all().require(
        ("fn", "start_windows_sensitive_password_listener", "(", "requests", ":", "WindowsSensitivePasswordRequestSender"),
        "private typed listener signature",
        unique=True,
    )
    windows.all().forbid(
        ("pub", "(", "crate", ")", "fn", "start_windows_sensitive_password_listener"),
        "public generic listener authority surface",
    )
    windows.all().forbid(
        ("struct", "WindowsSensitivePasswordRequest"),
        "generic password request authority surface",
    )
    user_listener = windows.function("start_windows_user_owned_password_listener")
    user_listener.require(
        ("WindowsSensitivePasswordRequestSender", "::", "UserOwned", "(", "requests", ")"),
        "fixed user listener action",
        unique=True,
    )
    service_listener = windows.function("start_windows_service_owned_password_listener")
    service_listener.require(
        ("WindowsSensitivePasswordRequestSender", "::", "ServiceOwned", "(", "requests", ")"),
        "fixed service listener action",
        unique=True,
    )

    main_prepare = ipc.function("prepare_main_ipc")
    main_prepare.require(
        (
            "start_windows_user_owned_password_listener",
            "(",
            "password_request_tx",
            OPTIONAL_COMMA,
            ")",
        ),
        "typed user listener startup",
        unique=True,
    )
    main_runners = ipc.functions("run_main_ipc")
    if len(main_runners) != 1:
        raise VerificationError("src/ipc.rs: expected one retained main IPC runner")
    main_run = main_runners[0]
    main_run.require_order(
        (
            (("request", ".", "into_parts", "(", ")"), "typed user request destruction"),
            (("begin_windows_user_owned_password_mutation", "(", "admission", ",", "operation_id", ",", "value", ",", "authority_allowed"), "consuming user admission"),
        )
    )
    user_begin = ipc.function("begin_windows_user_owned_password_mutation")
    user_begin.require(
        ("begin_user_owned_password_mutation", "(", "operation_id", ",", "value", ",", "authority_allowed", ")"),
        "fixed user-owned mutation kind",
        unique=True,
    )
    ipc.all().require(
        ("fn", "begin_windows_user_owned_password_mutation", "(", "_admission", ":", "WindowsUserOwnedPasswordAdmission"),
        "consuming user-owned admission signature",
        unique=True,
    )

    ipc.all().require(
        ("pub", "(", "crate", ")", "fn", "status", "(", "&", "self", ",", "_admission", ":", "&", "WindowsServiceOwnedPasswordAdmission"),
        "service replay query capability signature",
        unique=True,
    )
    ipc.all().require(
        ("pub", "(", "crate", ")", "fn", "classify_during_shutdown", "(", "&", "self", ",", "admission", ":", "&", "WindowsServiceOwnedPasswordAdmission"),
        "service shutdown query capability signature",
        unique=True,
    )
    ipc.all().require(
        ("pub", "(", "crate", ")", "fn", "admit", "(", "&", "mut", "self", ",", "_admission", ":", "WindowsServiceOwnedPasswordAdmission"),
        "consuming service ledger admission signature",
        unique=True,
    )
    run_service = windows.function("run_service")
    run_service.require_order(
        (
            (("start_windows_service_owned_password_listener", "(", "credential_request_tx", OPTIONAL_COMMA, ")"), "typed service listener startup"),
            (("WindowsServiceOwnedPasswordRequest", "{", "admission", ",", "operation_id", ",", "value", ",", "response", ",", "}", "=", "request"), "typed service request destruction"),
            (("credential_ledger", ".", "status", "(", "&", "admission", ",", "&", "operation_id", ",", "value", ".", "as_str", "(", ")"), "capability-bound replay query"),
            (("credential_ledger", ".", "classify_during_shutdown", "(", "&", "admission", ",", "&", "operation_id", ",", "value", ".", "as_str", "(", ")"), "capability-bound shutdown query"),
            (("credential_ledger", ".", "admit", "(", "admission", ",", "&", "operation_id", ",", "value", ".", "as_str", "(", ")"), "consuming service ledger admission"),
        )
    )
    if len(run_service.positions(("WindowsServiceOwnedPasswordRequest", "{", "admission", ","))) != 2:
        raise VerificationError(
            "src/platform/windows.rs: live and shutdown service request paths must both retain typed admission"
        )
    if len(run_service.positions(("credential_ledger", ".", "classify_during_shutdown", "(", "&", "admission"))) != 2:
        raise VerificationError(
            "src/platform/windows.rs: live and drained service requests must both query with typed admission"
        )
    run_service.forbid(
        ("credential_ledger", ".", "admit", "(", "&", "admission"),
        "borrowed rather than consumed service admission",
    )

    main_shutdown = ipc.method(
        ("impl", "PasswordMutationCoordinator"),
        "begin_shutdown",
        "impl PasswordMutationCoordinator",
    )
    main_shutdown.require_order(
        (
            (("ledger", ".", "shutting_down", "=", "true"), "main admission stop"),
            (("drop", "(", "ledger", ")"), "main shutdown lock release"),
            (("notify_waiters", "(", ")"), "main shutdown notification"),
        ),
        unique=True,
    )
    main_drain = ipc.method(
        ("impl", "PasswordMutationCoordinator"),
        "drain",
        "impl PasswordMutationCoordinator",
    )
    main_drain.require_order(
        (
            (("notified", "=", "self", ".", "changed", ".", "notified", "(", ")"), "missed-wakeup-safe waiter registration"),
            (("ledger", "=", "self", ".", "ledger", ".", "lock", "(", ")", ".", "unwrap", "(", ")"), "terminal-state snapshot"),
            (("all", "(", "|", "entry", "|", "matches", "!", "(", "entry", ".", "state", ",", "PasswordMutationState", "::", "Complete", "(", "_", ",", "_", ")", ")", ")"), "all-terminal drain condition"),
            (("if", "drained", "{", "return", ";", "}"), "terminal drain exit"),
            (("notified", ".", "await"), "lock-free finality wait"),
        )
    )
    main_clear = ipc.method(
        ("impl", "PasswordMutationCoordinator"),
        "clear_after_transactions_drain",
        "impl PasswordMutationCoordinator",
    )
    main_clear.require_order(
        (
            (("all", "(", "|", "entry", "|", "matches", "!", "(", "entry", ".", "state", ",", "PasswordMutationState", "::", "Complete", "(", "_", ",", "_", ")", ")", ")"), "all-terminal clear invariant"),
            (("std", "::", "process", "::", "abort", "(", ")"), "unresolved main mutation fail-stop"),
            (("ledger", ".", "clear_sensitive_state", "(", ")"), "main ledger zeroization"),
        )
    )
    linux_shutdown = ipc.method(
        ("impl", "LinuxPasswordAdmissionCoordinator"),
        "begin_shutdown",
        "impl LinuxPasswordAdmissionCoordinator",
    )
    linux_shutdown.require_order(
        (
            (("ledger", ".", "shutting_down", "=", "true"), "Linux admission stop"),
            (("drop", "(", "ledger", ")"), "Linux shutdown lock release"),
            (("notify_waiters", "(", ")"), "Linux shutdown notification"),
        ),
        unique=True,
    )


def verify_flow_finality_and_shutdown(rust: Mapping[str, RustSource]) -> None:
    ipc = rust["src/ipc.rs"]
    auth = rust["src/ipc/auth.rs"]
    main_handler = ipc.function("handle_sensitive_main_ipc_transaction")
    ipc.all().require(
        (
            "async", "fn", "handle_sensitive_main_ipc_transaction", "(",
            "mut", "stream", ":", "Conn", ",",
            "authority", ":", "SensitiveMainPasswordAuthority", ",",
            "_permit", ":", "OwnedSemaphorePermit", OPTIONAL_COMMA, ")",
        ),
        "typed sensitive-main handler authority",
        unique=True,
    )
    main_handler.require_order(
        (
            (("Instant", "::", "now", "(", ")", "+", "std", "::", "time", "::", "Duration", "::", "from_millis", "(", "MAIN_IPC_TRANSACTION_TIMEOUT_MS", ")"), "one absolute transaction deadline"),
            (("receive_request_unix", "(", "&", "mut", "stream", ",", "password", "::", "SensitivePayloadKind", "::", "Password", ",", "deadline", OPTIONAL_COMMA, ")"), "raw bounded request"),
            (("operation_id", "=", "request", ".", "operation_id", "(", ")"), "wire operation ID"),
            (("request", ".", "into_password", "(", ")"), "owned secret extraction"),
            (("match", "authority", "{"), "typed action dispatch"),
            (("SensitiveMainPasswordAuthority", "::", "UserOwned", "=>"), "user-owned action"),
            (("begin_user_owned_password_mutation", "(", "operation_id", ".", "to_string", "(", ")", ",", "value", ",", "authority_allowed", OPTIONAL_COMMA, ")"), "fixed user-owned admission"),
            (("SensitiveMainPasswordAuthority", "::", "ServiceOwnedRuntimePrs", "(", "receiver", ")", "=>"), "service-owned runtime-PRS action"),
            (("receiver", ".", "admit", "(", "&", "stream", ")"), "consuming final parent-generation replay"),
            (("begin_linux_service_owned_runtime_prs_mutation", "("), "typed service-owned admission"),
            (("ServiceOwnedRuntimePrsReplica", "{", "value", "}"), "generic inbound bytes become typed PRS only after final proof"),
            (("send_status_unix", "(", "&", "mut", "stream", ",", "operation_id", ",", "status", ",", "deadline", ")"), "operation-bound begin acknowledgement"),
            (("worker", ".", "await"), "owned commit completion"),
        )
    )
    main_handler.forbid(
        ("begin_password_mutation", "("),
        "generic caller-selected mutation kind",
    )
    main_handler.forbid(
        ("authenticate_linux_service_owned_password_parent", "("),
        "handler-side detached parent proof",
    )
    main_handler.forbid(
        ("set_permanent_password_prs_for_runtime", "("),
        "direct runtime PRS write",
    )
    service_handler = ipc.function("handle_sensitive_linux_service_ipc_transaction")
    service_handler.require_order(
        (
            (("Instant", "::", "now", "(", ")", "+", "std", "::", "time", "::", "Duration", "::", "from_millis", "(", "SERVICE_IPC_REQUEST_TIMEOUT_MS", ")"), "one absolute service deadline"),
            (("receive_request_unix", "(", "&", "mut", "stream", ",", "password", "::", "SensitivePayloadKind", "::", "Password", ",", "deadline", OPTIONAL_COMMA, ")"), "raw bounded service request"),
            (("operation_id", "=", "request", ".", "operation_id", "(", ")"), "service operation ID"),
            (("execute_linux_service_owned_unattended_password_request", "(", "operation_id", ".", "to_string", "(", ")", ",", "value", ",", "identity", OPTIONAL_COMMA, ")"), "identity-bound authority/commit"),
            (("send_status_unix", "(", "&", "mut", "stream", ",", "operation_id", ",", "status", ",", "deadline", ")"), "operation-bound status"),
        )
    )
    credential_handler = ipc.function("handle_linux_service_credential_snapshot_transaction")
    credential_handler.require_order(
        (
            (("Instant", "::", "now", "(", ")", "+", "std", "::", "time", "::", "Duration", "::", "from_millis", "(", "SERVICE_IPC_REQUEST_TIMEOUT_MS", ")"), "one absolute credential deadline"),
            (("receive_credential_snapshot_request_unix", "(", "&", "mut", "stream", ",", "deadline"), "bodyless credential request"),
            (("requester", ".", "admit", "(", "&", "stream", ",", "operation_id", ")"), "consuming post-request authority admission"),
            (("admission", ".", "respond", "(", "&", "mut", "stream", ",", "deadline", ")"), "capability-owned PRS response"),
        )
    )
    credential_handler.require_identifier_absent(
        {"authenticate_linux_service_owned_password_replica_server", "service_owned_runtime_prs_replica", "send_credential_replica_unix"},
        "credential handler bypasses typed requester/admission authority",
    )

    runtime_prs = ipc.item("struct", "ServiceOwnedRuntimePrsReplica")
    runtime_prs.require(
        ("value", ":", "SensitivePassword"),
        "sensitive canonical PRS payload",
        unique=True,
    )
    mutation_request = ipc.item("enum", "MainPasswordMutationRequest")
    mutation_request.require_order(
        (
            (("UserOwned", "(", "&", "'", "a", "MainPasswordMutationValue", ")"), "typed user-owned password"),
            (("ServiceOwnedRuntimePrs", "(", "&", "'", "a", "ServiceOwnedRuntimePrsReplica", ")"), "typed service-owned runtime PRS"),
        ),
        unique=True,
    )
    mutation_value = ipc.method(
        ("impl", "MainPasswordMutationRequest"),
        "value",
        "typed main password mutation value",
    )
    mutation_value.require_order(
        (
            (("Self", "::", "UserOwned", "(", "value", ")", "=>", "value"), "user-owned value projection"),
            (("Self", "::", "ServiceOwnedRuntimePrs", "(", "replica", ")", "=>", "replica", ".", "as_sensitive_password", "(", ")"), "PRS-only value projection"),
        ),
        unique=True,
    )
    mutation_kind = ipc.method(
        ("impl", "MainPasswordMutationRequest"),
        "is_service_owned",
        "typed main password mutation kind",
    )
    mutation_kind.require_order(
        (
            (("Self", "::", "UserOwned", "(", "_", ")", "=>", "false"), "user-owned classification"),
            (("Self", "::", "ServiceOwnedRuntimePrs", "(", "_", ")", "=>", "true"), "service-owned classification"),
        ),
        unique=True,
    )

    writer = ipc.item("struct", "LinuxServiceOwnedPasswordReplicaWriter")
    writer.require_order(
        (
            (("stream", ":", "ConnClient"), "owned connected raw stream"),
            (("server", ":", "PeerProcessIdentity"), "retained complete child identity"),
        ),
        unique=True,
    )
    attempt = ipc.item("enum", "LinuxServiceOwnedPasswordReplicaAttempt")
    attempt.require_order(
        (
            (("Status", "(", "PasswordMutationStatus", ")"), "operation-bound status"),
            (("NotSent", "(", "anyhow", "::", "Error", ")"), "pre-send failure"),
            (("Uncertain", "(", "anyhow", "::", "Error", ")"), "uncertain-send failure"),
        ),
        unique=True,
    )
    for item_kind, item_name in (
        ("struct", "ServiceOwnedRuntimePrsReplica"),
        ("enum", "MainPasswordMutationRequest"),
        ("struct", "LinuxServiceOwnedPasswordReplicaWriter"),
        ("enum", "LinuxServiceOwnedPasswordReplicaAttempt"),
    ):
        declaration = ipc.all().require(
            (item_kind, item_name),
            f"{item_name} declaration",
            unique=True,
        )
        preceding = ipc.all().values[max(0, declaration - 12) : declaration]
        if "Clone" in preceding or "Copy" in preceding:
            raise VerificationError(f"src/ipc.rs: {item_name} must be non-cloneable")

    writer_connect = ipc.method(
        ("impl", "LinuxServiceOwnedPasswordReplicaWriter"),
        "connect",
        "Linux service-owned PRS writer connection",
    )
    writer_connect.require_order(
        (
            (("!", "crate", "::", "platform", "::", "is_root", "(", ")", "||", "!", "crate", "::", "common", "::", "is_service_supervisor_process", "(", ")"), "exact root supervisor role"),
            (("user_main_ipc_server_uid", "(", ")"), "exact current child UID selection"),
            (("Config", "::", "ipc_path_for_uid", "(", "expected_uid", ",", "password", "::", "USER_PASSWORD_IPC_POSTFIX", ")"), "fixed child password endpoint"),
            (("timeout", "(", "password", "::", "remaining_millis", "(", "deadline", ")", "?", ",", "Endpoint", "::", "connect", "(", "path", ")"), "bounded raw child connect"),
            (("authenticate_linux_service_owned_password_replica_server", "(", "&", "stream", ",", "password", "::", "USER_PASSWORD_IPC_POSTFIX", OPTIONAL_COMMA, ")"), "exact child generation proof"),
            (("server", ".", "uid", "(", ")", "!=", "expected_uid"), "selected UID binding"),
            (("password", "::", "remaining_millis", "(", "deadline", ")", "?", ";", "Ok", "(", "Self"), "post-proof deadline"),
            (("Self", "{", "stream", ",", "server", "}"), "typed writer construction"),
        ),
        unique=True,
    )
    writer_connect.forbid(("connect_sensitive_unix", "("), "ordinary postfix-selectable connector")
    writer_connect.forbid(("UserMainIpcScope",), "ambient thread-local route authority")
    writer_connect.forbid(("Config", "::", "ipc_path", "("), "caller-owned IPC path")

    writer_reauthenticate = ipc.method(
        ("impl", "LinuxServiceOwnedPasswordReplicaWriter"),
        "reauthenticate",
        "Linux service-owned PRS writer final proof",
    )
    writer_reauthenticate.require_order(
        (
            (("!", "crate", "::", "platform", "::", "is_root", "(", ")", "||", "!", "crate", "::", "common", "::", "is_service_supervisor_process", "(", ")"), "fresh root supervisor role"),
            (("authenticate_linux_service_owned_password_replica_server", "(", "&", "self", ".", "stream", ",", "password", "::", "USER_PASSWORD_IPC_POSTFIX", OPTIONAL_COMMA, ")"), "fresh exact child proof"),
            (("refreshed", "!=", "self", ".", "server"), "complete accepted-child continuity"),
        ),
        unique=True,
    )

    writer_begin = ipc.method(
        ("impl", "LinuxServiceOwnedPasswordReplicaWriter"),
        "begin",
        "Linux service-owned PRS writer transaction",
    )
    ipc.all().require(
        (
            "async", "fn", "begin", "(", "mut", "self", ",",
            "operation_id", ":", "hbb_common", "::", "uuid", "::", "Uuid", ",",
            "replica", ":", "&", "ServiceOwnedRuntimePrsReplica", ",",
            "deadline", ":", "tokio", "::", "time", "::", "Instant",
            OPTIONAL_COMMA, ")", "->", "LinuxServiceOwnedPasswordReplicaAttempt",
        ),
        "consuming typed Linux PRS writer transaction signature",
        unique=True,
    )
    writer_begin.require_order(
        (
            (("self", ".", "reauthenticate", "(", ")"), "final child proof before secret send"),
            (("NotSent", "(", "err", ")"), "pre-send proof failure classification"),
            (("send_request_unix", "(", "&", "mut", "self", ".", "stream", ",", "operation_id", ",", "replica", ".", "as_sensitive_password", "(", ")", ",", "None", ",", "deadline"), "typed UUID-bound PRS send"),
            (("receive_status_unix", "(", "&", "mut", "self", ".", "stream", ",", "operation_id", ",", "deadline"), "same-operation finality response"),
            (("Status", "(", "status", ")"), "terminal status classification"),
            (("Uncertain", "(", "err", ")"), "post-send response uncertainty"),
            (("UnixSensitivePasswordSendError", "::", "NotSent", "(", "err", ")"), "raw pre-send classification"),
            (("LinuxServiceOwnedPasswordReplicaAttempt", "::", "NotSent", "(", "err", ")"), "typed pre-send classification"),
            (("UnixSensitivePasswordSendError", "::", "Uncertain", "(", "err", ")"), "raw uncertain-send classification"),
            (("LinuxServiceOwnedPasswordReplicaAttempt", "::", "Uncertain", "(", "err", ")"), "typed uncertain-send classification"),
        )
    )
    writer_begin.forbid(("SensitivePassword",), "generic password parameter")
    writer_begin.forbid(("USER_PASSWORD_IPC_POSTFIX",), "transaction-time endpoint selection")

    credential_requester = ipc.item(
        "struct", "LinuxServiceOwnedCredentialReplicaRequester"
    )
    credential_requester.require(
        ("identity", ":", "PeerProcessIdentity"),
        "complete Linux credential requester identity",
        unique=True,
    )
    credential_admission = ipc.item(
        "struct", "LinuxServiceOwnedCredentialReplicaAdmission"
    )
    credential_admission.require_order(
        (
            (("_requester", ":", "LinuxServiceOwnedCredentialReplicaRequester"), "retained exact requester"),
            (("operation_id", ":", "hbb_common", "::", "uuid", "::", "Uuid"), "operation-bound response authority"),
        ),
        unique=True,
    )
    for capability in (
        "LinuxServiceOwnedCredentialReplicaRequester",
        "LinuxServiceOwnedCredentialReplicaAdmission",
    ):
        for trait in ("Clone", "Copy"):
            if f"#[derive({trait})]\nstruct {capability}" in ipc.text:
                raise VerificationError(
                    f"src/ipc.rs: {capability} must not derive {trait}"
                )

    credential_authenticate = ipc.method(
        ("impl", "LinuxServiceOwnedCredentialReplicaRequester"),
        "authenticate",
        "Linux credential requester authentication",
    )
    credential_authenticate.require_order(
        (
            (("authenticate_linux_service_owned_password_replica_server", "(", "stream", ",", "password", "::", "SERVICE_CREDENTIAL_IPC_POSTFIX", OPTIONAL_COMMA, ")"), "fixed credential-endpoint child proof"),
            (("Self", "{", "identity", "}"), "typed requester construction"),
        ),
        unique=True,
    )
    credential_admit = ipc.method(
        ("impl", "LinuxServiceOwnedCredentialReplicaRequester"),
        "admit",
        "Linux credential response admission",
    )
    credential_admit.require_order(
        (
            (("Self", "::", "authenticate", "(", "stream", ")"), "fresh exact-child replay"),
            (("refreshed", ".", "identity", "!=", "self", ".", "identity"), "accepted-generation continuity"),
            (("LinuxServiceOwnedCredentialReplicaAdmission", "{"), "typed admission construction"),
            (("_requester", ":", "self"), "retained requester transfer"),
            (("operation_id", OPTIONAL_COMMA), "operation binding transfer"),
        ),
        unique=True,
    )
    credential_respond = ipc.method(
        ("impl", "LinuxServiceOwnedCredentialReplicaAdmission"),
        "respond",
        "Linux credential capability response",
    )
    credential_respond.require_order(
        (
            (("service_owned_runtime_prs_replica", "(", '"Linux"', ")"), "root-owned PRS snapshot"),
            (("send_credential_replica_unix", "(", "stream", ",", "self", ".", "operation_id", ",", "replica", ".", "as_sensitive_password", "(", ")", ",", "deadline"), "operation-bound typed PRS response"),
        ),
        unique=True,
    )
    for text, label in (
        (
            "    fn admit<T>(\n        self,\n        stream: &T,\n        operation_id: hbb_common::uuid::Uuid,",
            "consuming requester and operation-bound admission signature",
        ),
        (
            "impl LinuxServiceOwnedCredentialReplicaAdmission {\n"
            "    async fn respond(\n        self,\n        stream: &mut Conn,\n        deadline: tokio::time::Instant,",
            "consuming capability-owned response signature",
        ),
    ):
        if text not in ipc.text:
            raise VerificationError(f"src/ipc.rs: missing {label}")
    auth.all().require(
        ("pub", "(", "super", ")", "fn", "authenticate_linux_service_owned_password_replica_server"),
        "module-private generic Linux replica proof",
        unique=True,
    )
    auth.all().forbid(
        ("pub", "(", "crate", ")", "fn", "authenticate_linux_service_owned_password_replica_server"),
        "crate-visible generic Linux replica proof",
    )
    admission_construction = credential_admit.require(
        ("LinuxServiceOwnedCredentialReplicaAdmission", "{"),
        "sole admission construction",
        unique=True,
    )
    admission_mentions = ipc.all().positions(
        ("LinuxServiceOwnedCredentialReplicaAdmission", "{")
    )
    if len(admission_mentions) != 3 or admission_construction not in admission_mentions:
        raise VerificationError(
            "src/ipc.rs: Linux credential replica admission must have one construction in its consuming requester method"
        )

    operation = ipc.function("execute_linux_service_owned_password_operation")
    ipc.all().require(
        (
            "async", "fn", "execute_linux_service_owned_password_operation", "<", "Commit", ",",
            "CommitFuture", ">", "(", "coordinator", ":", "&",
            "LinuxPasswordAdmissionCoordinator", ",", "operation_id", ":", "&", "str", ",",
            "value", ":", "&", "str", ",", "identity", ":", "&", "PeerProcessIdentity", ",",
            "mut", "commit", ":", "Commit", OPTIONAL_COMMA, ")", "->", "ResultType", "<",
            "IpcMutationResult", ">",
        ),
        "noninjectable typed Linux password operation",
        unique=True,
    )
    operation.require_order(
        (
            (("kind", "=", "PasswordMutationKind", "::", "ServiceOwned"), "fixed service-owned kind"),
            (("caller", "=", "LinuxPasswordCaller", "::", "from", "(", "identity", ")"), "full-identity-derived ledger caller"),
            (("coordinator", ".", "begin", "(", "operation_id", ",", "kind", ",", "value", ",", "&", "caller", ")"), "bound admission/replay"),
            (("Authorize", "=>", "{"), "new authority branch"),
            (("grant_linux_service_owned_password_admission", "(", "identity", ")", ".", "await"), "typed interactive authority"),
            (("cancel_authorization", "(", "operation_id", ",", "value", ",", "&", "caller", ")"), "exact denied claim cancellation"),
            (("admission", ".", "admit_commit", "(", "coordinator", ",", "operation_id", ",", "value", ")"), "consuming typed ledger admission"),
            (("Wait", "=>", "{"), "in-flight replay wait"),
            (("shutdown", ".", "cancelled", "(", ")"), "shutdown-aware wait"),
            (("Recover", "=>", "{"), "recovery ownership"),
            (("Complete", "(", "result", ")", "=>", "return", "Ok", "(", "result", ")"), "terminal replay"),
            (("commit", "(", ")", ".", "await"), "commit after authority/admission"),
            (("release_failed_commit", "(", "operation_id", ",", "&", "caller", ")"), "transport failure recovery"),
            (("coordinator", ".", "complete", "(", "operation_id", ",", "&", "caller", ",", "result", ")"), "terminal result recording"),
        )
    )
    operation.forbid(("authorize", "(", ")"), "generic Linux authority callback")
    operation.forbid(("finish_authorization", "("), "Boolean authority finalization")
    operation.forbid(("admitted",), "detached Linux admission Boolean")
    commit = ipc.function("commit_service_owned_unattended_password_change")
    commit.require_order(
        (
            (("durable_value", "=", "value", ".", "clone", "(", ")"), "root-owned plaintext copy"),
            (("spawn_blocking", "(", "move", "||", "{", "Config", "::", "set_permanent_password_persisted", "(", "durable_value", ".", "as_str", "(", ")", ")"), "root durable credential write"),
            (("if", "!", "durable_result", "{", "return", "Ok", "(", "IpcMutationResult", "::", "Rejected", ")"), "no-replica result before durable acceptance"),
            (("service_owned_runtime_prs_replica", "(", '"Linux"', ")"), "root PRS extraction after persistence"),
            (("request_graceful_shutdown_after_authority_failure", "(", ")"), "fail-stop on post-persistence PRS failure"),
            (("complete_main_password_mutation", "(", "operation_id", ",", "MainPasswordMutationRequest", "::", "ServiceOwnedRuntimePrs", "(", "&", "replica", ")", ",", "ms_timeout", OPTIONAL_COMMA, ")"), "typed same-operation PRS child convergence"),
            (("Ok", "(", "IpcMutationResult", "::", "Applied", ")", "=>", "Ok", "(", "IpcMutationResult", "::", "Applied", ")"), "exact applied convergence"),
            (("request_graceful_shutdown_after_authority_failure", "(", ")"), "fail-stop on non-applied child result"),
            (("request_graceful_shutdown_after_authority_failure", "(", ")"), "fail-stop on child transport/finality failure"),
        )
    )
    commit.forbid(
        ("MainPasswordMutationRequest", "::", "UserOwned", "(", "&", "value", ")"),
        "plaintext forwarding to the service-owned child",
    )
    commit.forbid(("ServiceOwnedRuntimePrsReplica", "{"), "local plaintext-to-PRS type forgery")
    commit.forbid(("loop", "{"), "outer unbounded finality loop")
    commit.forbid(("sleep", "(", "0.1", ")", ".", "await"), "outer finality retry")
    commit.forbid(("Uuid", "::", "new_v4"), "operation ID regeneration during recovery")

    root_replica = ipc.function("service_owned_runtime_prs_replica")
    ipc.all().require(
        (
            "fn", "service_owned_runtime_prs_replica", "(", "platform", ":", "&", "str", ")",
            "->", "ResultType", "<", "ServiceOwnedRuntimePrsReplica", ">",
        ),
        "typed canonical PRS loader result",
        unique=True,
    )
    root_replica.require_order(
        (
            (("Config", "::", "read_permanent_password_prs", "(", ")"), "root credential read"),
            (("Available", "(", "prs", ")", "=>", "{", "Ok", "(", "ServiceOwnedRuntimePrsReplica", "{", "value", ":", "SensitivePassword", "::", "new", "(", "prs", ")"), "available typed PRS replica"),
            (("PermanentPasswordPrsRead", "::", "Empty", "=>"), "explicit empty replica"),
            (("ServiceOwnedRuntimePrsReplica", "{", "value", ":", "SensitivePassword", "::", "new", "(", "String", "::", "new", "(", ")", ")"), "typed empty replica"),
            (("UndecryptableStorage", "=>"), "undecryptable storage branch"),
            (("bail", "!", "(", '"{platform} root service credential storage is undecryptable"', ")"), "undecryptable fail closed"),
        )
    )

    refresh = ipc.function("refresh_linux_service_owned_permanent_password_snapshot")
    refresh.require_order(
        (
            (("is_service_owned_server_process", "(", ")"), "exact service-owned role"),
            (("service_child_is_unsupervised_recovery_fixture", "(", ")"), "debug fixture branch"),
            (("set_permanent_password_prs_for_runtime", "(", '""', ")"), "fixture explicit empty override"),
            (("LinuxServiceOwnedCredentialReplicaReceiver", "::", "connect", "(", "deadline", ")", ".", "await"), "typed credential receiver connection"),
            (("receiver", ".", "receive_and_admit", "(", "deadline", ")", ".", "await"), "consuming credential response admission"),
            (("admission", ".", "install", "(", ")"), "capability-bound runtime install"),
        )
    )
    refresh.forbid(("Endpoint", "::", "connect"), "raw credential connection")
    refresh.forbid(
        ("receive_credential_replica_unix",),
        "raw credential response outside the typed receiver",
    )
    refresh.forbid(
        ("set_permanent_password_prs_for_runtime", "(", "replica"),
        "direct received-secret runtime sink",
    )

    server = rust["src/server.rs"]
    start_server_candidates = [
        function
        for function in server.functions("start_server")
        if function.positions(("refresh_linux_service_owned_permanent_password_snapshot",))
    ]
    if len(start_server_candidates) != 1:
        raise VerificationError(
            "src/server.rs: expected one desktop start_server credential bootstrap"
        )
    start_server = start_server_candidates[0]
    snapshot = start_server.require(
        ("refresh_linux_service_owned_permanent_password_snapshot", "(", "10_000", ")", ".", "await"),
        "service-child credential snapshot before admission",
        unique=True,
    )
    invariant = start_server.require(
        ("direct_service", "::", "assert_startup_invariants", "(", ")"),
        "first ordinary startup invariant",
        unique=True,
    )
    if snapshot >= invariant:
        raise VerificationError(
            f"{start_server.label}: credential snapshot must precede startup invariants/listeners"
        )
    authority_failure = server.function("request_graceful_shutdown_after_authority_failure")
    authority_failure.require_order(
        (
            (("SHUTDOWN_FAILURE_LATCHED", ".", "store", "(", "true", ",", "Ordering", "::", "Release", ")"), "failure latch"),
            (("request_graceful_shutdown", "(", ")"), "service cancellation"),
        ),
        unique=True,
    )

    complete_main = ipc.function("complete_main_password_mutation")
    ipc.all().require(
        (
            "async", "fn", "complete_main_password_mutation", "(", "operation_id", ":", "String", ",",
            "mutation", ":", "MainPasswordMutationRequest", "<", "'", "_", ">", ",", "ms_timeout", ":", "u64",
            OPTIONAL_COMMA, ")", "->", "ResultType", "<", "IpcMutationResult", ">",
        ),
        "typed main-password completion signature",
        unique=True,
    )
    complete_main.require_order(
        (
            (("service_owned", "=", "mutation", ".", "is_service_owned", "(", ")"), "enum-derived authority class"),
            (("value", "=", "mutation", ".", "value", "(", ")"), "enum-derived secret value"),
            (("Uuid", "::", "parse_str", "(", "&", "operation_id", ")"), "single operation UUID parse"),
            (("query_only", "=", "false"), "begin state"),
            (("recovery_required", "=", "service_owned"), "service-parent prior admission finality"),
            (("recovery_deadline", "=", "tokio", "::", "time", "::", "Instant", "::", "now", "(", ")", "+", "PASSWORD_MUTATION_RECOVERY_TIMEOUT"), "overall bounded recovery deadline"),
            (("loop", "{"), "retry loop"),
            (("recovery_required", "&&", "tokio", "::", "time", "::", "Instant", "::", "now", "(", ")", ">=", "recovery_deadline"), "overall recovery deadline enforcement"),
            (("deadline", "=", "tokio", "::", "time", "::", "Instant", "::", "now", "(", ")", "+", "std", "::", "time", "::", "Duration", "::", "from_millis", "(", "ms_timeout", ")"), "per-attempt absolute deadline"),
            (("if", "query_only", "{"), "status-only recovery branch"),
            (("authenticate_linux_service_owned_main_server", "(", "&", "stream", ")"), "service child identity proof for query"),
            (("main_ipc_request_on_stream_deadline", "(", "stream"), "absolute-deadline query"),
            (("PasswordMutationStatus", "{", "operation_id", ":", "operation_id", ".", "clone", "(", ")"), "same-operation ordinary query argument"),
            (("query_only", "=", "matches", "!", "(", "response", ",", "PasswordMutationStatus", "::", "Prepared", "|", "PasswordMutationStatus", "::", "Pending", ")"), "prepared/pending query transition"),
            (("LinuxServiceOwnedPasswordReplicaWriter", "::", "connect", "(", "deadline", ")"), "typed authenticated raw child writer"),
            (("MainPasswordMutationRequest", "::", "ServiceOwnedRuntimePrs", "(", "replica", ")", "=>", "*", "replica"), "typed PRS extraction"),
            (("writer", ".", "begin", "(", "operation_uuid", ",", "replica", ",", "deadline", ")"), "consuming UUID-bound PRS transaction"),
            (("LinuxServiceOwnedPasswordReplicaAttempt", "::", "Uncertain", "(", "err", ")", "=>", "{", "recovery_required", "=", "true"), "typed uncertain-send finality transition"),
            (("connect_user_owned_password_stream", "(", "deadline", ")"), "user-owned raw connection"),
            (("send_request_unix", "(", "&", "mut", "stream", ",", "operation_uuid", ",", "value", ",", "None", ",", "deadline", ")"), "same UUID/value user-owned raw begin"),
            (("receive_status_unix", "(", "&", "mut", "stream", ",", "operation_uuid", ",", "deadline", ")"), "same UUID user-owned status"),
            (("Err", "(", "password", "::", "UnixSensitivePasswordSendError", "::", "Uncertain", "(", "err", ")", ")", "=>", "{", "recovery_required", "=", "true"), "Unix uncertain-send finality transition"),
            (("query_only", "=", "matches", "!", "(", "response", ",", "PasswordMutationStatus", "::", "Prepared", "|", "PasswordMutationStatus", "::", "Pending", ")"), "begin acknowledgement query transition"),
        )
    )
    complete_main.forbid(("service_owned", ":", "bool"), "caller-supplied service-owned Boolean")
    complete_main.forbid(("connect_service_owned_password_replica_stream",), "untyped service-owned raw connector")
    complete_main.forbid(("ServiceOwnedRuntimePrsReplica", "{"), "completion-time PRS type forgery")
    complete_main.forbid(("main_ipc_request_on_stream", "(", "stream", ",", "request"), "password-bearing ordinary IPC fallback")
    complete_main.forbid(("Uuid", "::", "new_v4"), "operation ID regeneration inside retry loop")

    service_client = ipc.function("set_service_owned_unattended_password_with_ack")
    service_client.require_order(
        (
            (("operation_id", "=", "hbb_common", "::", "uuid", "::", "Uuid", "::", "new_v4", "(", ")"), "one operation UUID before retry loop"),
            (("recovery_required", "=", "false"), "pre-admission state"),
            (("recovery_deadline", "=", "tokio", "::", "time", "::", "Instant", "::", "now", "(", ")", "+", "PASSWORD_MUTATION_RECOVERY_TIMEOUT"), "overall bounded recovery deadline"),
            (("loop", "{"), "service retry loop"),
            (("recovery_required", "&&", "tokio", "::", "time", "::", "Instant", "::", "now", "(", ")", ">=", "recovery_deadline"), "overall recovery deadline enforcement"),
            (("deadline", "=", "tokio", "::", "time", "::", "Instant", "::", "now"), "per-attempt absolute deadline"),
            (("connect_sensitive_unix", "(", "deadline", ",", "password", "::", "SERVICE_PASSWORD_IPC_POSTFIX", ")"), "raw service endpoint"),
            (("send_request_unix", "(", "&", "mut", "stream", ",", "operation_id", ",", "&", "v"), "same UUID/value request"),
            (("receive_status_unix", "(", "&", "mut", "stream", ",", "operation_id", ",", "deadline", ")"), "same UUID status"),
            (("Err", "(", "password", "::", "UnixSensitivePasswordSendError", "::", "Uncertain", "(", "err", ")", ")", "=>", "{", "recovery_required", "=", "true"), "uncertain response finality"),
            (("windows_credential_client_decision", "(", "status", ",", "recovery_required", ")"), "terminality policy"),
        )
    )
    uuid_position = service_client.require(("Uuid", "::", "new_v4", "(", ")"), "operation UUID", unique=True)
    loop_position = service_client.require(("loop", "{"), "retry loop", unique=True)
    if uuid_position >= loop_position:
        raise VerificationError(f"{service_client.label}: operation UUID must be created before retries")

    windows_service_client = ipc.function(
        "set_windows_service_owned_unattended_password_with_ack"
    )
    windows_service_client.require_order(
        (
            (("operation_id", "=", "hbb_common", "::", "uuid", "::", "Uuid", "::", "new_v4", "(", ")"), "one Windows operation UUID"),
            (("recovery_required", "=", "false"), "Windows pre-admission state"),
            (("recovery_deadline", "=", "tokio", "::", "time", "::", "Instant", "::", "now", "(", ")", "+", "PASSWORD_MUTATION_RECOVERY_TIMEOUT"), "Windows overall bounded recovery deadline"),
            (("loop", "{"), "Windows service retry loop"),
            (("recovery_required", "&&", "tokio", "::", "time", "::", "Instant", "::", "now", "(", ")", ">=", "recovery_deadline"), "Windows recovery deadline enforcement"),
            (("transact_sensitive_password", "(", "password", "::", "SERVICE_PASSWORD_IPC_POSTFIX", ",", "operation_id", ",", "&", "value"), "same Windows UUID/value request"),
            (("windows_credential_client_decision", "(", "status", ",", "recovery_required", ")"), "Windows terminality policy"),
        )
    )
    windows_uuid_position = windows_service_client.require(
        ("Uuid", "::", "new_v4", "(", ")"), "Windows operation UUID", unique=True
    )
    windows_loop_position = windows_service_client.require(
        ("loop", "{"), "Windows retry loop", unique=True
    )
    if windows_uuid_position >= windows_loop_position:
        raise VerificationError(
            f"{windows_service_client.label}: operation UUID must be created before retries"
        )

    decision = ipc.function("windows_credential_client_decision")
    decision.require_order(
        (
            (("Prepared", "|", "PasswordMutationStatus", "::", "Pending"), "accepted/in-flight continuation"),
            (("Complete", "(", "IpcMutationResult", "::", "Applied", ")", "=>", "{", "WindowsCredentialClientDecision", "::", "Applied"), "application terminality"),
            (("Complete", "(", "IpcMutationResult", "::", "Rejected", ")", "=>", "{", "WindowsCredentialClientDecision", "::", "Rejected"), "rejection terminality"),
            (("Complete", "(", "IpcMutationResult", "::", "InternalFailure", ")", "=>", "{", "WindowsCredentialClientDecision", "::", "InternalFailure"), "internal-failure terminality"),
            (("ShuttingDown", "=>", "WindowsCredentialClientDecision", "::", "NotAdmitted"), "shutdown terminality"),
            (("Unknown", "if", "recovery_required", "=>", "{", "WindowsCredentialClientDecision", "::", "Continue"), "explicitly unknown recovery"),
            (("Unknown", "=>", "WindowsCredentialClientDecision", "::", "NotAdmitted"), "pre-admission unknown terminality"),
        )
    )

    main_listener = ipc.function("run_main_ipc")
    main_listener.require_order(
        (
            (("password_mutations", "(", ")", ".", "begin_shutdown", "(", ")"), "main mutation non-admission"),
            (("transactions", ".", "join_next", "(", ")", ".", "await"), "raw/main transaction drain"),
            (("password_mutations", "(", ")", ".", "drain", "(", ")", ".", "await"), "worker finality drain"),
            (("password_mutations", "(", ")", ".", "clear_after_transactions_drain", "(", ")"), "post-drain digest/key zeroization"),
            (("drop", "(", "listener_guard", ")"), "listener deactivation after finality"),
        )
    )
    service_listener = ipc.function("run_service_ipc")
    service_listener.require_order(
        (
            (("linux_password_admissions", "(", ")", ".", "begin_shutdown", "(", ")"), "service admission stop"),
            (("transactions", ".", "join_next", "(", ")", ".", "await"), "authority/commit transaction drain"),
            (("linux_password_admissions", "(", ")", ".", "clear_after_transactions_drain", "(", ")"), "post-drain Linux digest/key zeroization"),
            (("drop", "(", "listener_guard", ")"), "listener deactivation after authority drain"),
        )
    )
    linux_clear = ipc.method(("impl", "LinuxPasswordAdmissionCoordinator"), "clear_after_transactions_drain", "impl LinuxPasswordAdmissionCoordinator")
    linux_clear.require_order(
        (
            (("all", "(", "|", "entry", "|", "matches", "!", "(", "entry", ".", "state", ",", "LinuxPasswordAdmissionState", "::", "Complete", "(", "_", ",", "_", ")", ")", ")"), "all-terminal invariant"),
            (("std", "::", "process", "::", "abort", "(", ")"), "unresolved authority fail-stop"),
            (("ledger", ".", "clear_sensitive_state", "(", ")"), "terminal ledger zeroization"),
        )
    )


def verify_linux_runtime_prs_receiver_authority(rust: Mapping[str, RustSource]) -> None:
    ipc = rust["src/ipc.rs"]
    runtime_prs = ipc.item("struct", "ServiceOwnedRuntimePrsReplica")
    install_runtime_prs = ipc.method(
        ("impl", "ServiceOwnedRuntimePrsReplica"),
        "install_for_runtime",
        "typed service-owned runtime PRS",
    )
    ipc.all().require(
        ("fn", "install_for_runtime", "(", "self", ")", "->", "ResultType", "<", "bool", ">"),
        "consuming PRS installation",
        unique=True,
    )
    install_runtime_prs.require(
        ("Config", "::", "set_permanent_password_prs_for_runtime", "(", "self", ".", "value", ".", "as_str", "(", ")", ")"),
        "sole typed runtime-state write",
        unique=True,
    )
    runtime_prs.forbid(("pub",), "public runtime PRS payload")

    receiver = ipc.item("struct", "LinuxServiceOwnedPasswordReplicaReceiver")
    receiver.require(
        ("parent", ":", "LinuxProcessIdentity"),
        "retained root-parent process generation",
        unique=True,
    )
    admission = ipc.item("struct", "LinuxServiceOwnedRuntimePrsAdmission")
    admission.require(
        ("_receiver", ":", "LinuxServiceOwnedPasswordReplicaReceiver"),
        "consumed exact-parent receiver authority",
        unique=True,
    )
    authority = ipc.item("enum", "SensitiveMainPasswordAuthority")
    authority.require_order(
        (
            (("UserOwned", ","), "typed user-owned action"),
            (("ServiceOwnedRuntimePrs", "(", "LinuxServiceOwnedPasswordReplicaReceiver", ")"), "typed retained service-owned action"),
        ),
        unique=True,
    )
    authority_kind = ipc.method(
        ("impl", "SensitiveMainPasswordAuthority"),
        "mutation_kind",
        "typed sensitive-main capacity classification",
    )
    authority_kind.require_order(
        (
            (("Self", "::", "UserOwned", "=>", "PasswordMutationKind", "::", "UserOwned"), "fixed user-owned kind"),
            (("Self", "::", "ServiceOwnedRuntimePrs", "(", "_", ")", "=>", "PasswordMutationKind", "::", "ServiceOwned"), "fixed service-owned kind"),
        ),
        unique=True,
    )
    for type_name in (
        "LinuxServiceOwnedPasswordReplicaReceiver",
        "LinuxServiceOwnedRuntimePrsAdmission",
    ):
        ipc.all().forbid(
            ("derive", "(", "Clone", ")", "]", "struct", type_name),
            f"cloneable {type_name}",
        )
        ipc.all().forbid(
            ("derive", "(", "Copy", ")", "]", "struct", type_name),
            f"copyable {type_name}",
        )
        ipc.all().forbid(
            ("pub", "struct", type_name),
            f"public {type_name}",
        )
        ipc.all().forbid(
            ("pub", "(", "crate", ")", "struct", type_name),
            f"crate-visible {type_name}",
        )
    ipc.all().forbid(
        ("derive", "(", "Clone", ")", "]", "enum", "SensitiveMainPasswordAuthority"),
        "cloneable SensitiveMainPasswordAuthority",
    )
    ipc.all().forbid(
        ("derive", "(", "Copy", ")", "]", "enum", "SensitiveMainPasswordAuthority"),
        "copyable SensitiveMainPasswordAuthority",
    )

    authenticate = ipc.method(
        ("impl", "LinuxServiceOwnedPasswordReplicaReceiver"),
        "authenticate",
        "Linux runtime PRS receiver",
    )
    authenticate.require_order(
        (
            (("is_service_owned_server_process", "(", ")"), "exact service-owned child role"),
            (("authenticate_linux_service_owned_password_parent", "(", "stream", ",", "password", "::", "USER_PASSWORD_IPC_POSTFIX", OPTIONAL_COMMA, ")"), "fixed _password parent-generation proof"),
            (("Ok", "(", "Self", "{", "parent", "}", ")"), "retained parent generation"),
        )
    )
    authenticate.forbid(
        ("postfix", ":", "&", "str"),
        "caller-selectable receiver endpoint",
    )

    admit = ipc.method(
        ("impl", "LinuxServiceOwnedPasswordReplicaReceiver"),
        "admit",
        "Linux runtime PRS receiver",
    )
    ipc.all().require(
        (
            "fn", "admit", "<", "T", ">", "(", "self", ",", "stream", ":", "&", "T", ")",
            "->", "ResultType", "<", "LinuxServiceOwnedRuntimePrsAdmission", ">",
        ),
        "consuming final runtime-PRS receiver admission",
        unique=True,
    )
    admit.require_order(
        (
            (("is_service_owned_server_process", "(", ")"), "fresh exact child role"),
            (("authenticate_linux_service_owned_password_parent", "(", "stream", ",", "password", "::", "USER_PASSWORD_IPC_POSTFIX", OPTIONAL_COMMA, ")"), "fresh fixed-endpoint parent proof"),
            (("if", "refreshed", "!=", "self", ".", "parent"), "accepted parent PID/UID/start-time continuity"),
            (("Ok", "(", "LinuxServiceOwnedRuntimePrsAdmission", "{", "_receiver", ":", "self", "}", ")"), "sole typed admission construction"),
        )
    )
    admission_constructions = ipc.all().positions(
        ("LinuxServiceOwnedRuntimePrsAdmission", "{")
    )
    admitted_at = admit.require(
        ("LinuxServiceOwnedRuntimePrsAdmission", "{"),
        "typed admission construction",
        unique=True,
    )
    if len(admission_constructions) != 2 or admitted_at not in admission_constructions:
        raise VerificationError(
            "src/ipc.rs: Linux runtime PRS admission must be constructed only by the consuming receiver"
        )

    coordinator_prepare = ipc.method(
        ("impl", "PasswordMutationCoordinator"),
        "prepare_linux_service_owned_runtime_prs",
        "password mutation coordinator",
    )
    ipc.all().require(
        (
            "fn", "prepare_linux_service_owned_runtime_prs", "(", "&", "self", ",",
            "_admission", ":", "LinuxServiceOwnedRuntimePrsAdmission", ",",
            "operation_id", ":", "&", "str", ",",
            "replica", ":", "&", "ServiceOwnedRuntimePrsReplica", OPTIONAL_COMMA, ")",
            "->", "PasswordMutationPreparation",
        ),
        "typed runtime-PRS ledger admission",
        unique=True,
    )
    coordinator_prepare.require_order(
        (
            (("prepare_if_allowed", "("), "shared replay/finality state machine"),
            (("PasswordMutationKind", "::", "ServiceOwned"), "fixed service-owned kind"),
            (("replica", ".", "as_sensitive_password", "(", ")", ".", "as_str", "(", ")"), "typed PRS fingerprint"),
            (("len", "(", ")", "<=", "UNATTENDED_PASSWORD_MAX_BYTES"), "defensive PRS bound"),
        )
    )
    coordinator_prepare.forbid(
        ("admission_allowed", ":", "bool"),
        "detached runtime-PRS ledger authority Boolean",
    )

    begin = ipc.function("begin_linux_service_owned_runtime_prs_mutation")
    ipc.all().require(
        (
            "fn", "begin_linux_service_owned_runtime_prs_mutation", "(",
            "admission", ":", "LinuxServiceOwnedRuntimePrsAdmission", ",",
            "operation_id", ":", "String", ",",
            "replica", ":", "ServiceOwnedRuntimePrsReplica", OPTIONAL_COMMA, ")",
        ),
        "consuming typed runtime-PRS mutation entry",
        unique=True,
    )
    begin.require_order(
        (
            (("kind", "=", "PasswordMutationKind", "::", "ServiceOwned"), "fixed service-owned result kind"),
            (("prepare_linux_service_owned_runtime_prs", "(", "admission", ",", "&", "operation_id", ",", "&", "replica", OPTIONAL_COMMA, ")"), "capability-bound ledger preparation"),
            (("if", "!", "preparation", ".", "owns_preparation"), "replay without duplicate worker"),
            (("try_acquire_main_ipc_blocking_mutation_slot", "(", ")"), "bounded blocking mutation admission"),
            (("fail_admitted", "(", "&", "operation_id", ",", "kind", ",", "value", ")"), "capacity failure finality"),
            (("acknowledge", "(", "&", "operation_id", ",", "kind", ",", "value", ")"), "prepared-to-pending transition"),
            (("spawn_linux_service_owned_runtime_prs_mutation", "(", "operation_id", ".", "clone", "(", ")", ",", "replica", ",", "permit", ")"), "typed owned runtime worker"),
        )
    )
    begin.forbid(("authority_allowed",), "detached runtime-PRS authority Boolean")
    begin.forbid(("begin_user_owned_password_mutation", "("), "user-owned admission fallback")
    begin.forbid(("spawn_password_mutation", "("), "generic durable worker fallback")

    worker = ipc.function("spawn_linux_service_owned_runtime_prs_mutation")
    ipc.all().require(
        (
            "fn", "spawn_linux_service_owned_runtime_prs_mutation", "(",
            "operation_id", ":", "String", ",",
            "replica", ":", "ServiceOwnedRuntimePrsReplica", ",",
            "permit", ":", "OwnedSemaphorePermit", OPTIONAL_COMMA, ")",
        ),
        "owned typed runtime-PRS worker input",
        unique=True,
    )
    worker.require_order(
        (
            (("spawn_blocking", "(", "move", "||", "{"), "dedicated blocking worker"),
            (("let", "_permit", "=", "permit"), "capacity ownership"),
            (("kind", "=", "PasswordMutationKind", "::", "ServiceOwned"), "fixed finality kind"),
            (("replica", ".", "install_for_runtime", "(", ")"), "consuming typed runtime install"),
            (("completion", ".", "result", "=", "result"), "RAII terminal result"),
        )
    )
    worker.forbid(
        ("Config", "::", "set_permanent_password_persisted"),
        "durable credential write from runtime-replica worker",
    )

    authority_owner = ipc.function("sensitive_main_ipc_authority")
    receiver_authentications = ipc.all().positions(
        (
            "LinuxServiceOwnedPasswordReplicaReceiver", "::", "authenticate", "(",
            "stream", ")",
        )
    )
    if (
        len(receiver_authentications) != 1
        or not authority_owner.start <= receiver_authentications[0] < authority_owner.end
    ):
        raise VerificationError(
            "src/ipc.rs: Linux runtime PRS receiver authentication must have exactly one typed authority owner"
        )

    for function_name, owner in (
        ("begin_linux_service_owned_runtime_prs_mutation", ipc.function("handle_sensitive_main_ipc_transaction")),
        ("spawn_linux_service_owned_runtime_prs_mutation", begin),
    ):
        calls = non_definition_calls(ipc, function_name)
        if len(calls) != 1 or not owner.start <= calls[0] < owner.end:
            raise VerificationError(
                f"src/ipc.rs: {function_name} must have exactly one typed authority owner"
            )


def verify_linux_credential_runtime_prs_receiver_authority(
    rust: Mapping[str, RustSource],
) -> None:
    ipc = rust["src/ipc.rs"]
    receiver = ipc.item("struct", "LinuxServiceOwnedCredentialReplicaReceiver")
    receiver.require_order(
        (
            (("stream", ":", "ConnClient"), "owned fixed credential stream"),
            (("parent", ":", "LinuxProcessIdentity"), "retained root-parent generation"),
        ),
        unique=True,
    )
    admission = ipc.item(
        "struct", "LinuxServiceOwnedCredentialRuntimePrsAdmission"
    )
    admission.require_order(
        (
            (("_receiver", ":", "LinuxServiceOwnedCredentialReplicaReceiver"), "consumed receiver authority"),
            (("replica", ":", "ServiceOwnedRuntimePrsReplica"), "typed received PRS"),
        ),
        unique=True,
    )
    for type_name in (
        "LinuxServiceOwnedCredentialReplicaReceiver",
        "LinuxServiceOwnedCredentialRuntimePrsAdmission",
    ):
        ipc.all().forbid(
            ("derive", "(", "Clone", ")", "]", "struct", type_name),
            f"cloneable {type_name}",
        )
        ipc.all().forbid(
            ("derive", "(", "Copy", ")", "]", "struct", type_name),
            f"copyable {type_name}",
        )
        ipc.all().forbid(("pub", "struct", type_name), f"public {type_name}")
        ipc.all().forbid(
            ("pub", "(", "crate", ")", "struct", type_name),
            f"crate-visible {type_name}",
        )

    connect = ipc.method(
        ("impl", "LinuxServiceOwnedCredentialReplicaReceiver"),
        "connect",
        "Linux service credential receiver",
    )
    ipc.all().require(
        (
            "impl", "LinuxServiceOwnedCredentialReplicaReceiver", "{", "async", "fn", "connect", "(",
            "deadline", ":", "tokio", "::", "time", "::", "Instant", ")",
            "->", "ResultType", "<", "Self", ">",
        ),
        "private typed receiver connection signature",
        unique=True,
    )
    connect.require_order(
        (
            (("is_service_owned_server_process", "(", ")"), "exact service-owned child role"),
            (("Config", "::", "ipc_path_for_uid", "(", "0", ",", "password", "::", "SERVICE_CREDENTIAL_IPC_POSTFIX", ")"), "fixed UID-0 credential endpoint"),
            (("password", "::", "remaining_millis", "(", "deadline", ")"), "pre-connect absolute deadline"),
            (("Endpoint", "::", "connect", "(", "path", ")"), "owned credential connection"),
            (("let", "parent", "=", "authenticate_linux_service_owned_password_parent", "(", "&", "stream", ",", "password", "::", "SERVICE_CREDENTIAL_IPC_POSTFIX", OPTIONAL_COMMA, ")"), "retained initial root-parent generation proof"),
            (("password", "::", "remaining_millis", "(", "deadline", ")"), "post-proof absolute deadline"),
            (("Ok", "(", "Self", "{", "stream", ",", "parent", "}", ")"), "typed receiver construction"),
        )
    )
    connect.forbid(("postfix", ":", "&", "str"), "caller-selected endpoint")
    connect.forbid(
        ("USER_PASSWORD_IPC_POSTFIX",),
        "ordinary password endpoint for initial credential snapshot",
    )

    receive = ipc.method(
        ("impl", "LinuxServiceOwnedCredentialReplicaReceiver"),
        "receive_and_admit",
        "Linux service credential receiver",
    )
    ipc.all().require(
        (
            "async", "fn", "receive_and_admit", "(", "mut", "self", ",",
            "deadline", ":", "tokio", "::", "time", "::", "Instant", OPTIONAL_COMMA, ")",
            "->", "ResultType", "<", "LinuxServiceOwnedCredentialRuntimePrsAdmission", ">",
        ),
        "consuming credential-response admission signature",
        unique=True,
    )
    receive.require_order(
        (
            (("is_service_owned_server_process", "(", ")"), "fresh exact child role"),
            (("Uuid", "::", "new_v4", "(", ")"), "single snapshot operation UUID"),
            (("send_credential_snapshot_request_unix", "(", "&", "mut", "self", ".", "stream", ",", "operation_id", ",", "deadline"), "same-stream UUID-bound request"),
            (("receive_credential_replica_unix", "(", "&", "mut", "self", ".", "stream", ",", "operation_id", ",", "deadline"), "same-stream UUID-bound response"),
            (("let", "refreshed", "=", "authenticate_linux_service_owned_password_parent", "(", "&", "self", ".", "stream", ",", "password", "::", "SERVICE_CREDENTIAL_IPC_POSTFIX", OPTIONAL_COMMA, ")"), "retained final same-stream parent-generation proof"),
            (("password", "::", "remaining_millis", "(", "deadline", ")"), "post-proof absolute deadline"),
            (("if", "refreshed", "!=", "self", ".", "parent"), "exact accepted-parent generation continuity"),
            (("LinuxServiceOwnedCredentialRuntimePrsAdmission", "{", "_receiver", ":", "self", ",", "replica", ":", "ServiceOwnedRuntimePrsReplica", "{", "value", "}"), "typed response admission construction"),
        )
    )
    receive.forbid(("postfix", ":", "&", "str"), "caller-selected endpoint")
    receive.forbid(
        ("SensitivePassword", "::", "new"),
        "generic plaintext-to-PRS type forgery",
    )
    admission_constructions = ipc.all().positions(
        ("LinuxServiceOwnedCredentialRuntimePrsAdmission", "{")
    )
    admitted_at = receive.require(
        ("LinuxServiceOwnedCredentialRuntimePrsAdmission", "{"),
        "typed credential admission construction",
        unique=True,
    )
    if len(admission_constructions) != 3 or admitted_at not in admission_constructions:
        raise VerificationError(
            "src/ipc.rs: Linux credential runtime PRS admission must be constructed only by its consuming receiver"
        )

    install = ipc.method(
        ("impl", "LinuxServiceOwnedCredentialRuntimePrsAdmission"),
        "install",
        "Linux credential runtime PRS admission",
    )
    ipc.all().require(
        (
            "impl", "LinuxServiceOwnedCredentialRuntimePrsAdmission", "{",
            "fn", "install", "(", "self", ")", "->", "ResultType", "<", "bool", ">",
        ),
        "consuming capability-bound install",
        unique=True,
    )
    install.require(
        ("self", ".", "replica", ".", "install_for_runtime", "(", ")"),
        "sole typed runtime-PRS sink",
        unique=True,
    )
    install.forbid(
        ("Config", "::", "set_permanent_password_prs_for_runtime"),
        "direct runtime-state sink",
    )

    refresh = ipc.function("refresh_linux_service_owned_permanent_password_snapshot")
    for needle, label, expected_calls in (
        (("LinuxServiceOwnedCredentialReplicaReceiver", "::", "connect", "(", "deadline", ")"), "typed receiver connection", 1),
        (("receiver", ".", "receive_and_admit", "(", "deadline", ")"), "consuming response admission", 2),
        (("admission", ".", "install", "(", ")"), "capability-bound install", 2),
    ):
        calls = ipc.all().positions(needle)
        at = refresh.require(needle, label, unique=True)
        if len(calls) != expected_calls or at not in calls:
            raise VerificationError(
                f"src/ipc.rs: Linux credential {label} must have exactly one typed owner"
            )


def verify_linux_credential_replica_bootstrap(rust: Mapping[str, RustSource]) -> None:
    config = rust["libs/hbb_common/src/config.rs"]
    runtime_prs = config.method(
        ("impl", "Config"), "set_permanent_password_prs_for_runtime", "impl Config"
    )
    runtime_prs.require_order(
        (
            (("if", "!", "prs", ".", "is_empty", "(", ")"), "explicit empty replica support"),
            (("base64", "::", "decode", "(", "prs", ".", "as_bytes", "(", ")", ",", "base64", "::", "Variant", "::", "Original", ")"), "strict base64 decode"),
            (("base64", "::", "encode", "(", "&", "decoded", ",", "base64", "::", "Variant", "::", "Original", ")"), "canonical re-encoding"),
            (("decoded", ".", "len", "(", ")", "==", "PERMANENT_PASSWORD_H1_LEN", "&&", "canonical", "==", "prs"), "exact canonical PRS validation"),
            (("memzero", "(", "&", "mut", "decoded", ")"), "decoded PRS wipe"),
            (("memzero", "(", "unsafe", "{", "canonical", ".", "as_mut_vec", "(", ")", "}", ")"), "canonical temporary wipe"),
            (("runtime_prs", ".", "as_deref", "(", ")", "==", "Some", "(", "prs", ")"), "same-value no-op"),
            (("if", "let", "Some", "(", "previous", ")", "=", "runtime_prs", ".", "as_mut", "(", ")"), "previous replica ownership"),
            (("memzero", "(", "unsafe", "{", "previous", ".", "as_mut_vec", "(", ")", "}", ")"), "previous replica wipe"),
            (("*", "runtime_prs", "=", "Some", "(", "prs", ".", "to_owned", "(", ")", ")"), "nonpersistent process replica install"),
            (("advance_permanent_password_credential_generation", "(", "&", "mut", "generation", ")"), "credential generation advance"),
        )
    )
    runtime_prs.forbid(("store_result",), "runtime replica persistence")

    platform = rust["src/platform/linux.rs"]
    platform.all().forbid(("SYS_ptrace",), "ptrace is not the exec nondumpability boundary")
    platform.all().forbid(("PTRACE_TRACEME",), "ptrace cannot close procfs memory access")
    nondumpable = platform.function("make_service_owned_process_nondumpable")
    nondumpable.require_order(
        (
            (("service_owned_process_dumpability", "(", ")"), "initial dumpability read"),
            (("get_current_uid", "(", ")", "!=", "0"), "active-user-only initial invariant"),
            (("started_dumpable", "!=", "0"), "fail-closed initial image state"),
            (("SYS_prctl", ",", "hbb_common", "::", "libc", "::", "PR_SET_DUMPABLE", ",", "0"), "disable dumpability"),
            (("service_owned_process_dumpability", "(", ")"), "read-back verification"),
            (("if", "dumpable", "!=", "0"), "fail-closed nondumpable result"),
        )
    )

    configure = platform.function("configure_service_child_pre_exec")
    configure.require_order(
        (
            (("SYS_setresuid",), "final active-user UID transition"),
            (("clear_descriptor_close_on_exec", "(", "executable_fd", ")"), "exact executable descriptor inheritance"),
            (("clear_descriptor_close_on_exec", "(", "bootstrap_fd", ")"), "bootstrap descriptor inheritance"),
            (("PR_SET_NO_NEW_PRIVS",), "no-new-privileges inheritance"),
            (("arm_linux_child_parent_death", "(", "expected_parent", ")"), "parent-death binding"),
        )
    )

    prepare = platform.method(
        ("impl", "ServiceChildBootstrap"), "prepare_stopped", "impl ServiceChildBootstrap"
    )
    prepare.require_order(
        (
            (("wait_for_ready_marker", "(", "deadline", ")"), "nondumpable readiness marker"),
            (("SIGSTOP", ",", "deadline", ",", '"nondumpable readiness stop"'), "stopped publication boundary"),
        )
    )
    resume = platform.method(
        ("impl", "ServiceChildBootstrap"), "resume", "impl ServiceChildBootstrap"
    )
    resume.require(("SIGCONT",), "stopped child continuation", unique=True)
    resume.forbid(("PTRACE",), "ptrace handoff after execute-only exec closure")

    publish_ready = platform.function("publish_service_child_bootstrap_ready")
    publish_ready.require_order(
        (
            (("SYS_write", ",", "bootstrap_fd", ",", "marker", ".", "as_ptr"), "single readiness marker write"),
            (("SYS_close", ",", "bootstrap_fd"), "bootstrap descriptor close"),
            (("SYS_kill", ",", "hbb_common", "::", "libc", "::", "syscall", "(", "hbb_common", "::", "libc", "::", "SYS_getpid", ")", ",", "hbb_common", "::", "libc", "::", "SIGSTOP"), "child readiness stop"),
        )
    )

    child_image = platform.function("open_active_user_service_child_executable")
    child_image.require_order(
        (
            (
                (
                    "custom_flags",
                    "(",
                    "hbb_common",
                    "::",
                    "libc",
                    "::",
                    "O_CLOEXEC",
                    ")",
                ),
                "running service image close-on-exec open",
            ),
            (("open", "(", '"/proc/self/exe"', ")"), "running service image open"),
            (("running_metadata", ".", "mode", "(", ")", "&", "0o7777", "==", "0o711"), "execute-only manual image path"),
            (("running_metadata", ".", "mode", "(", ")", "&", "0o7777", "!=", "0o755"), "readable installed image mode"),
            (("canonicalize", "(", '"/proc/self/exe"', ")"), "fixed primary package path"),
            (("LINUX_INSTALLED_SERVICE_CHILD_EXECUTABLE",), "fixed service-child package path"),
            (("parent_metadata", ".", "mode", "(", ")", "&", "0o022", "!=", "0"), "non-writable service-child parent"),
            (
                (
                    "custom_flags",
                    "(",
                    "hbb_common",
                    "::",
                    "libc",
                    "::",
                    "O_CLOEXEC",
                    "|",
                    "hbb_common",
                    "::",
                    "libc",
                    "::",
                    "O_NOFOLLOW",
                    ")",
                ),
                "installed service-child close-on-exec no-follow open",
            ),
            (("child_metadata", ".", "mode", "(", ")", "&", "0o7777", "!=", "0o711"), "execute-only service-child mode"),
            (("child_metadata", ".", "len", "(", ")", "!=", "running_metadata", ".", "len", "(", ")"), "service-child length equality"),
            (("files_have_exact_contents", "(", "&", "mut", "running", ",", "&", "mut", "child"), "service-child byte equality"),
            (("Ok", "(", "child", ")"), "validated service-child descriptor"),
        )
    )

    spawn = platform.function("try_start_server_")
    spawn.require_order(
        (
            (("open_active_user_service_child_executable", "(", ")"), "selected execute-only child image"),
            (("read_to_string", "(", '"/proc/sys/fs/suid_dumpable"', ")"), "kernel dump policy read"),
            (("suid_dumpable", ".", "trim", "(", ")", "!=", '"0"'), "classic nondumpable exec policy"),
            (("set_service_child_executable_identity", "(", "&", "child_executable_metadata", ")"), "selected child inode proof"),
            (("ServiceChildBootstrap", "::", "create", "(", ")"), "bounded stopped bootstrap"),
            (("env_clear", "(", ")"), "ambient environment removal"),
            (("SERVICE_OWNED_SERVER_GENERATION_ENV", ",", "&", "runtime", ".", "generation"), "runtime generation environment"),
            (("SERVICE_OWNED_SERVER_BOOTSTRAP_FD_ENV", ",", "bootstrap_fd", ".", "to_string", "(", ")"), "bootstrap descriptor environment"),
            (("configure_service_child_pre_exec", "("), "pre-exec hardening"),
            (("command", ".", "spawn", "(", ")"), "child exec"),
            (("bootstrap", ".", "prepare_stopped", "(", "child_pid", ")"), "nondumpable stopped child"),
            (("service_child_record_for_process", "(", "pid", ",", "expected_child_uid", ",", "&", "runtime", ".", "generation", ")"), "exact stopped-child record"),
            (("runtime", ".", "publish_record", "(", "&", "record", ")"), "durable generation publication"),
            (("bootstrap", ".", "resume", "(", "child_pid", ")"), "post-publication admission"),
        )
    )

    entry = platform.function("require_service_owned_server_parent_liveness")
    entry.require_order(
        (
            (("make_service_owned_process_nondumpable", "(", ")"), "first-image nondumpability"),
            (("SERVICE_OWNED_SERVER_LAUNCH_PARENT_ENV",), "expected parent environment"),
            (("SERVICE_OWNED_SERVER_GENERATION_ENV",), "generation environment"),
            (("validate_canonical_uuid", "(", "&", "generation", ",", '"service generation"', ")"), "canonical generation"),
            (("service_child_is_unsupervised_recovery_fixture", "(", ")"), "debug fixture decision"),
            (("SERVICE_OWNED_SERVER_BOOTSTRAP_FD_ENV",), "mandatory bootstrap descriptor"),
            (("arm_linux_child_parent_death", "(", "expected_parent", ")"), "final-image parent binding"),
            (("publish_service_child_bootstrap_ready", "(", "bootstrap_fd", ")"), "nondumpable readiness publication"),
        )
    )

    fixture = platform.function("service_child_is_unsupervised_recovery_fixture")
    fixture.require(("#", "[", "cfg", "(", "debug_assertions", ")", "]"), "debug-only fixture read", unique=True)
    fixture.require(("#", "[", "cfg", "(", "not", "(", "debug_assertions", ")", ")", "]", "{", "false", "}"), "release fixture denial", unique=True)
    spawn.forbid(
        ("SERVICE_CHILD_UNSUPERVISED_RECOVERY_FIXTURE_ENV",),
        "real supervisor propagation of the debug recovery fixture",
    )


def verify_callers(rust: Mapping[str, RustSource]) -> None:
    core = rust["src/core_main.rs"]
    parser = core.function("password_cli_input")
    parser.require(("Some", "(", '"--password"', ")", "if", "args", ".", "len", "(", ")", "==", "1", "=>", "Ok", "(", "PasswordCliInput", "::", "Terminal", ")"), "exact interactive CLI shape", unique=True)
    parser.require(("Some", "(", '"--password-stdin"', ")", "if", "args", ".", "len", "(", ")", "==", "1", "=>", "Ok", "(", "PasswordCliInput", "::", "Stdin", ")"), "exact stdin CLI shape", unique=True)
    parser.require(("_", "=>", "Err", "(", "PASSWORD_CLI_USAGE", ")"), "all other argv rejection", unique=True)
    parser.forbid(("args", ".", "get", "(", "1", ")"), "positional password argv read")

    stdin = core.function("read_unattended_password_line")
    stdin.require_order(
        (
            (("UNATTENDED_PASSWORD_MAX_BYTES", "+", "2"), "bounded input allocation"),
            (("reader", ".", "take", "(", "(", "crate", "::", "ipc", "::", "UNATTENDED_PASSWORD_MAX_BYTES", "+", "2", ")", "as", "u64", ")"), "bounded reader"),
            (("read_until", "(", "b'\\n'", ",", "&", "mut", "bytes", ".", "0", ")"), "single-line read"),
            (("bytes", ".", "0", ".", "len", "(", ")", ">", "crate", "::", "ipc", "::", "UNATTENDED_PASSWORD_MAX_BYTES"), "post-read length check"),
            (("String", "::", "from_utf8", "(", "std", "::", "mem", "::", "take", "(", "&", "mut", "bytes", ".", "0", ")", ")"), "strict UTF-8 conversion"),
            (("zeroize_sensitive_bytes", "(", "&", "mut", "invalid", ")"), "invalid input erasure"),
        )
    )
    stdin_mode = core.function("read_unattended_password_from_stdin")
    stdin_mode.require(("stdin", ".", "is_terminal", "(", ")"), "redirect-only stdin mode", unique=True)
    prompt = core.function("prompt_unattended_password")
    prompt.require_order(
        (
            (("rpassword", "::", "prompt_password", "(", '"New permanent password: "', ")"), "non-echoing password prompt"),
            (("rpassword", "::", "prompt_password", "(", '"Confirm permanent password: "'), "non-echoing confirmation"),
            (("matches", "=", "password", ".", "constant_time_eq", "(", "&", "confirmation", ")"), "constant-time confirmation comparison"),
            (("confirmation", ".", "zeroize", "(", ")"), "confirmation erasure"),
            (("if", "!", "matches"), "mismatch rejection"),
        )
    )
    cli_set = core.function("set_cli_permanent_password")
    cli_set.require(("ipc", "::", "set_permanent_password_sensitive", "(", "password", ")"), "sensitive IPC caller", unique=True)
    core_main = core.function("core_main")
    core_main.require_order(
        (
            (("matches", "!", "(", "args", "[", "0", "]", ".", "as_str", "(", ")", ",", '"--password"', "|", '"--password-stdin"', ")"), "finite password command dispatch"),
            (("password_cli_input", "(", "&", "args", ")"), "exact argv validation"),
            (("PasswordCliInput", "::", "Terminal", "=>", "prompt_unattended_password", "(", ")"), "interactive safe input"),
            (("PasswordCliInput", "::", "Stdin", "=>", "read_unattended_password_from_stdin", "(", ")"), "redirected safe input"),
            (("set_cli_permanent_password", "(", "password", ")"), "sensitive mutation path"),
        )
    )

    ui = rust["src/ui_interface.rs"].function("set_permanent_password_with_result")
    ui.require_order(
        (
            (("SensitivePassword", "::", "new", "(", "password", ")"), "immediate sensitive wrapper"),
            (("set_permanent_password_sensitive", "(", "password", ")"), "sensitive IPC API"),
        ),
        unique=True,
    )
    ffi = rust["src/flutter_ffi.rs"].function("main_set_permanent_password_with_result")
    ffi.require(("ui_interface", "::", "set_permanent_password_with_result", "(", "password", ")"), "UI authority path", unique=True)

    ipc = rust["src/ipc.rs"]
    dispatch = ipc.function("set_permanent_password_sensitive")
    dispatch.require_order(
        (
            (("validate_unattended_password_value", "(", "&", "v", ")"), "password size validation"),
            (("is_disable_change_permanent_password", "(", ")"), "policy gate"),
            (("can_request_service_owned_unattended_password_change", "(", ")"), "installed service authority selection"),
            (("set_service_owned_unattended_password_sensitive", "(", "v", ")"), "privileged service path"),
            (("can_set_user_owned_permanent_password", "(", ")"), "user-owned capability fallback"),
            (("set_user_owned_permanent_password_sensitive", "(", "v", ")"), "user-owned raw path"),
            (("bail", "!", "(", '"Changing service-owned unattended password requires administrator authorization"', ")"), "no-authority rejection"),
        )
    )
    dispatch.forbid(("Config", "::", "set_permanent_password"), "caller-side persistence fallback")
    owner_selectors = ipc.functions("can_request_service_owned_unattended_password_change")
    if len(owner_selectors) != 4:
        raise VerificationError(
            "src/ipc.rs: installed-service password owner selector must have exactly four platform definitions"
        )
    installed_selectors = 0
    unsupported_selectors = 0
    for selector in owner_selectors:
        if selector.positions(("crate", "::", "platform", "::", "is_installed", "(", ")")):
            installed_selectors += 1
            selector.require_identifier_absent(
                ("is_root", "is_elevated", "is_daemon", "is_service_running"),
                "authorization or availability fallback in installed ownership selection",
            )
        elif selector.values == ["false"]:
            unsupported_selectors += 1
        else:
            raise VerificationError(
                f"{selector.label}: service-owned password selection is not installation-only"
            )
    if installed_selectors != 3 or unsupported_selectors != 1:
        raise VerificationError(
            "src/ipc.rs: Linux, macOS, and Windows must select service ownership solely from installation state"
        )
    user_call = ipc.function("set_user_owned_permanent_password_with_ack_async")
    user_call.require_order(
        (
            (("Uuid", "::", "new_v4", "(", ")", ".", "to_string", "(", ")"), "operation ID"),
            (("complete_main_password_mutation", "(", "operation_id", ",", "MainPasswordMutationRequest", "::", "UserOwned", "(", "&", "v", ")", ",", "ms_timeout", OPTIONAL_COMMA, ")"), "typed raw user-owned begin/finality"),
        )
    )


def validate_sources(sources: Mapping[str, str]) -> None:
    rust = parse_sources(sources)
    for path in (
        "src/ipc.rs",
        "src/ipc/password.rs",
        "src/ipc/auth.rs",
        "src/ipc/fs.rs",
        "src/core_main.rs",
        "src/ui_interface.rs",
        "src/platform/linux.rs",
        "src/platform/windows.rs",
        "src/server.rs",
    ):
        critical = rust[path].all()
        critical.forbid(("if", "false"), "statically dead if branch in security-critical source")
        critical.forbid(("while", "false"), "statically dead loop in security-critical source")
        critical.forbid(
            ("#", "[", "cfg", "(", "any", "(", ")", ")", "]"),
            "statically dead cfg fixture in security-critical source",
        )
    verify_raw_wire(rust)
    verify_endpoint_ownership(rust)
    verify_raw_endpoint_separation(rust)
    verify_linux_identity_and_authority(rust)
    verify_macos_identity_and_authority(rust)
    verify_mutation_coordinators(rust)
    verify_windows_password_admission_authority(rust)
    verify_flow_finality_and_shutdown(rust)
    verify_linux_runtime_prs_receiver_authority(rust)
    verify_linux_credential_runtime_prs_receiver_authority(rust)
    verify_linux_credential_replica_bootstrap(rust)
    verify_callers(rust)


@dataclass(frozen=True)
class Mutation:
    label: str
    path: str
    old: str
    new: str


def _mutate_once(sources: Mapping[str, str], mutation: Mutation) -> dict[str, str]:
    source = sources[mutation.path]
    count = source.count(mutation.old)
    if count != 1:
        raise VerificationError(
            f"self-test fixture {mutation.label!r} expected one mutation target in "
            f"{mutation.path}, found {count}"
        )
    mutated = dict(sources)
    mutated[mutation.path] = source.replace(mutation.old, mutation.new, 1)
    return mutated


def expect_rejection(sources: Mapping[str, str], mutation: Mutation) -> None:
    mutated = _mutate_once(sources, mutation)
    try:
        validate_sources(mutated)
    except VerificationError:
        return
    raise VerificationError(f"self-test accepted security regression: {mutation.label}")


def self_test(sources: Mapping[str, str]) -> None:
    validate_sources(sources)
    mutations = (
        Mutation(
            "Windows service admission drops its final live proof",
            "src/ipc/auth.rs",
            "        self.revalidate(pipe, deadline)?;\n        Ok(super::WindowsServiceOwnedPasswordAdmission {",
            "        drop((pipe, deadline));\n        Ok(super::WindowsServiceOwnedPasswordAdmission {",
        ),
        Mutation(
            "Windows service proof mints authority for the user endpoint",
            "src/ipc/auth.rs",
            "if self.postfix != super::password::SERVICE_PASSWORD_IPC_POSTFIX {",
            "if self.postfix != super::password::USER_PASSWORD_IPC_POSTFIX {",
        ),
        Mutation(
            "Windows typed listener regains a public endpoint selector",
            "src/platform/windows.rs",
            "fn start_windows_sensitive_password_listener(\n    requests: WindowsSensitivePasswordRequestSender,",
            "pub(crate) fn start_windows_sensitive_password_listener(\n    postfix: &'static str,\n    requests: WindowsSensitivePasswordRequestSender,",
        ),
        Mutation(
            "Windows service request drops its typed admission",
            "src/platform/windows.rs",
            "struct WindowsServiceOwnedPasswordRequest {\n    admission: ipc::WindowsServiceOwnedPasswordAdmission,",
            "struct WindowsServiceOwnedPasswordRequest {\n    admission: bool,",
        ),
        Mutation(
            "Windows service ledger borrows instead of consuming first admission",
            "src/ipc.rs",
            "        _admission: WindowsServiceOwnedPasswordAdmission,\n        operation_id: &str,",
            "        _admission: &WindowsServiceOwnedPasswordAdmission,\n        operation_id: &str,",
        ),
        Mutation(
            "Windows service consumer bypasses capability-bound ledger admission",
            "src/platform/windows.rs",
            "                if !credential_ledger.admit(\n                    admission,",
            "                if !credential_ledger.admit(\n                    &admission,",
        ),
        Mutation(
            "Windows user consumer bypasses the typed mutation entry",
            "src/ipc.rs",
            "                        let (status, worker) = begin_windows_user_owned_password_mutation(\n                            admission,",
            "                        let (status, worker) = begin_password_mutation(\n                            admission,",
        ),
        Mutation(
            "Windows password admission capability becomes cloneable",
            "src/ipc.rs",
            "pub(crate) struct WindowsServiceOwnedPasswordAdmission {",
            "#[derive(Clone)]\npub(crate) struct WindowsServiceOwnedPasswordAdmission {",
        ),
        Mutation(
            "Windows service sender selects the user endpoint",
            "src/platform/windows.rs",
            "Self::ServiceOwned(_) => ipc::password::SERVICE_PASSWORD_IPC_POSTFIX,",
            "Self::ServiceOwned(_) => ipc::password::USER_PASSWORD_IPC_POSTFIX,",
        ),
        Mutation(
            "Linux runtime PRS loses its distinct payload type",
            "src/ipc.rs",
            "struct ServiceOwnedRuntimePrsReplica {\n    value: SensitivePassword,\n}",
            "struct ServiceOwnedRuntimePrsReplica {\n    value: String,\n}",
        ),
        Mutation(
            "main password mutation service variant accepts an ordinary password",
            "src/ipc.rs",
            "ServiceOwnedRuntimePrs(&'a ServiceOwnedRuntimePrsReplica),",
            "ServiceOwnedRuntimePrs(&'a MainPasswordMutationValue),",
        ),
        Mutation(
            "main password mutation misclassifies the PRS action as user-owned",
            "src/ipc.rs",
            "Self::ServiceOwnedRuntimePrs(_) => true,",
            "Self::ServiceOwnedRuntimePrs(_) => false,",
        ),
        Mutation(
            "Linux service-owned PRS writer becomes cloneable",
            "src/ipc.rs",
            "struct LinuxServiceOwnedPasswordReplicaWriter {",
            "#[derive(Clone)]\nstruct LinuxServiceOwnedPasswordReplicaWriter {",
        ),
        Mutation(
            "Linux service-owned PRS writer drops the retained child identity",
            "src/ipc.rs",
            "struct LinuxServiceOwnedPasswordReplicaWriter {\n    stream: ConnClient,\n    server: PeerProcessIdentity,\n}",
            "struct LinuxServiceOwnedPasswordReplicaWriter {\n    stream: ConnClient,\n    server_alive: bool,\n}",
        ),
        Mutation(
            "Linux service-owned PRS writer admits a non-supervisor root process",
            "src/ipc.rs",
            "if !crate::platform::is_root() || !crate::common::is_service_supervisor_process() {\n            bail!(\n                \"Linux service-owned password replica writer requires the exact root service supervisor role\"",
            "if !crate::platform::is_root() && !crate::common::is_service_supervisor_process() {\n            bail!(\n                \"Linux service-owned password replica writer requires the exact root service supervisor role\"",
        ),
        Mutation(
            "Linux service-owned PRS writer selects a caller-owned socket path",
            "src/ipc.rs",
            "let path = Config::ipc_path_for_uid(expected_uid, password::USER_PASSWORD_IPC_POSTFIX);",
            "let path = Config::ipc_path(password::USER_PASSWORD_IPC_POSTFIX);",
        ),
        Mutation(
            "Linux service-owned PRS writer authenticates the wrong endpoint",
            "src/ipc.rs",
            "let server = authenticate_linux_service_owned_password_replica_server(\n            &stream,\n            password::USER_PASSWORD_IPC_POSTFIX,",
            "let server = authenticate_linux_service_owned_password_replica_server(\n            &stream,\n            password::SERVICE_CREDENTIAL_IPC_POSTFIX,",
        ),
        Mutation(
            "Linux service-owned PRS writer bypasses selected child UID binding",
            "src/ipc.rs",
            "if server.uid() != expected_uid {\n            bail!(\n                \"service-owned password replica uid mismatch:",
            "if false && server.uid() != expected_uid {\n            bail!(\n                \"service-owned password replica uid mismatch:",
        ),
        Mutation(
            "Linux service-owned PRS writer loses its final root-supervisor replay",
            "src/ipc.rs",
            "if !crate::platform::is_root() || !crate::common::is_service_supervisor_process() {\n            bail!(\n                \"Linux service-owned password replica writer lost its root service supervisor role\"",
            "if !crate::platform::is_root() {\n            bail!(\n                \"Linux service-owned password replica writer lost its root service supervisor role\"",
        ),
        Mutation(
            "Linux service-owned PRS writer bypasses accepted-child continuity",
            "src/ipc.rs",
            "if refreshed != self.server {\n            bail!(\"Linux service-owned password replica server identity changed before write\");",
            "if false && refreshed != self.server {\n            bail!(\"Linux service-owned password replica server identity changed before write\");",
        ),
        Mutation(
            "Linux service-owned PRS writer transaction borrows its authority",
            "src/ipc.rs",
            "    async fn begin(\n        mut self,",
            "    async fn begin(\n        &mut self,",
        ),
        Mutation(
            "Linux service-owned PRS writer transaction accepts a generic password",
            "src/ipc.rs",
            "        operation_id: hbb_common::uuid::Uuid,\n        replica: &ServiceOwnedRuntimePrsReplica,\n        deadline: tokio::time::Instant,",
            "        operation_id: hbb_common::uuid::Uuid,\n        replica: &SensitivePassword,\n        deadline: tokio::time::Instant,",
        ),
        Mutation(
            "Linux service-owned PRS writer skips its final child replay",
            "src/ipc.rs",
            "if let Err(err) = self.reauthenticate() {\n            return LinuxServiceOwnedPasswordReplicaAttempt::NotSent(err);\n        }",
            "if let Err(err) = Ok::<(), anyhow::Error>(()) {\n            return LinuxServiceOwnedPasswordReplicaAttempt::NotSent(err);\n        }",
        ),
        Mutation(
            "Linux service-owned PRS writer replaces the retained operation UUID",
            "src/ipc.rs",
            "            &mut self.stream,\n            operation_id,\n            replica.as_sensitive_password(),",
            "            &mut self.stream,\n            hbb_common::uuid::Uuid::new_v4(),\n            replica.as_sensitive_password(),",
        ),
        Mutation(
            "Linux service-owned PRS writer loses response uncertainty",
            "src/ipc.rs",
            "Err(err) => LinuxServiceOwnedPasswordReplicaAttempt::Uncertain(err),",
            "Err(err) => LinuxServiceOwnedPasswordReplicaAttempt::NotSent(err),",
        ),
        Mutation(
            "Linux service-owned PRS completion stops entering recovery after uncertainty",
            "src/ipc.rs",
            "LinuxServiceOwnedPasswordReplicaAttempt::Uncertain(err) => {\n                        recovery_required = true;\n                        Err(err)\n                    }",
            "LinuxServiceOwnedPasswordReplicaAttempt::Uncertain(err) => {\n                        recovery_required = false;\n                        Err(err)\n                    }",
        ),
        Mutation(
            "Linux root completion routes plaintext through the user-owned variant",
            "src/ipc.rs",
            "MainPasswordMutationRequest::ServiceOwnedRuntimePrs(&replica),",
            "MainPasswordMutationRequest::UserOwned(&value),",
        ),
        Mutation(
            "Linux runtime PRS installation borrows rather than consumes the typed secret",
            "src/ipc.rs",
            "fn install_for_runtime(self) -> ResultType<bool>",
            "fn install_for_runtime(&self) -> ResultType<bool>",
        ),
        Mutation(
            "Linux credential receiver drops its owned stream and parent generation",
            "src/ipc.rs",
            "struct LinuxServiceOwnedCredentialReplicaReceiver {\n    stream: ConnClient,\n    parent: LinuxProcessIdentity,\n}",
            "struct LinuxServiceOwnedCredentialReplicaReceiver {\n    parent_alive: bool,\n}",
        ),
        Mutation(
            "Linux credential receiver becomes cloneable",
            "src/ipc.rs",
            "struct LinuxServiceOwnedCredentialReplicaReceiver {",
            "#[derive(Clone)]\nstruct LinuxServiceOwnedCredentialReplicaReceiver {",
        ),
        Mutation(
            "Linux credential receiver becomes public",
            "src/ipc.rs",
            "struct LinuxServiceOwnedCredentialReplicaReceiver {",
            "pub struct LinuxServiceOwnedCredentialReplicaReceiver {",
        ),
        Mutation(
            "Linux credential admission drops its consumed receiver authority",
            "src/ipc.rs",
            "    _receiver: LinuxServiceOwnedCredentialReplicaReceiver,",
            "    receiver_authorized: bool,",
        ),
        Mutation(
            "Linux credential admission accepts a generic password",
            "src/ipc.rs",
            "struct LinuxServiceOwnedCredentialRuntimePrsAdmission {\n    _receiver: LinuxServiceOwnedCredentialReplicaReceiver,\n    replica: ServiceOwnedRuntimePrsReplica,\n}",
            "struct LinuxServiceOwnedCredentialRuntimePrsAdmission {\n    _receiver: LinuxServiceOwnedCredentialReplicaReceiver,\n    replica: SensitivePassword,\n}",
        ),
        Mutation(
            "Linux credential admission becomes cloneable",
            "src/ipc.rs",
            "struct LinuxServiceOwnedCredentialRuntimePrsAdmission {",
            "#[derive(Clone)]\nstruct LinuxServiceOwnedCredentialRuntimePrsAdmission {",
        ),
        Mutation(
            "Linux credential receiver admits a non-service-owned child role",
            "src/ipc.rs",
            "if !crate::common::is_service_owned_server_process() {\n            bail!(\"Linux service credential snapshots require the exact service-owned server role\");\n        }\n        let path = Config::ipc_path_for_uid(0, password::SERVICE_CREDENTIAL_IPC_POSTFIX);",
            "if false && !crate::common::is_service_owned_server_process() {\n            bail!(\"Linux service credential snapshots require the exact service-owned server role\");\n        }\n        let path = Config::ipc_path_for_uid(0, password::SERVICE_CREDENTIAL_IPC_POSTFIX);",
        ),
        Mutation(
            "Linux credential receiver selects the ordinary password endpoint",
            "src/ipc.rs",
            "impl LinuxServiceOwnedCredentialReplicaReceiver {\n    async fn connect(deadline: tokio::time::Instant) -> ResultType<Self> {\n        if !crate::common::is_service_owned_server_process() {\n            bail!(\"Linux service credential snapshots require the exact service-owned server role\");\n        }\n        let path = Config::ipc_path_for_uid(0, password::SERVICE_CREDENTIAL_IPC_POSTFIX);",
            "impl LinuxServiceOwnedCredentialReplicaReceiver {\n    async fn connect(deadline: tokio::time::Instant) -> ResultType<Self> {\n        if !crate::common::is_service_owned_server_process() {\n            bail!(\"Linux service credential snapshots require the exact service-owned server role\");\n        }\n        let path = Config::ipc_path_for_uid(0, password::USER_PASSWORD_IPC_POSTFIX);",
        ),
        Mutation(
            "Linux credential receiver discards its initial parent generation",
            "src/ipc.rs",
            "let parent = authenticate_linux_service_owned_password_parent(\n            &stream,\n            password::SERVICE_CREDENTIAL_IPC_POSTFIX,",
            "let _parent = authenticate_linux_service_owned_password_parent(\n            &stream,\n            password::SERVICE_CREDENTIAL_IPC_POSTFIX,",
        ),
        Mutation(
            "Linux credential receiver drops its post-connect proof deadline",
            "src/ipc.rs",
            "            password::SERVICE_CREDENTIAL_IPC_POSTFIX,\n        )?;\n        password::remaining_millis(deadline)?;\n        Ok(Self { stream, parent })",
            "            password::SERVICE_CREDENTIAL_IPC_POSTFIX,\n        )?;\n        drop(deadline);\n        Ok(Self { stream, parent })",
        ),
        Mutation(
            "Linux credential receiver borrows instead of consuming response authority",
            "src/ipc.rs",
            "    async fn receive_and_admit(\n        mut self,\n        deadline: tokio::time::Instant,\n    ) -> ResultType<LinuxServiceOwnedCredentialRuntimePrsAdmission>",
            "    async fn receive_and_admit(\n        &mut self,\n        deadline: tokio::time::Instant,\n    ) -> ResultType<LinuxServiceOwnedCredentialRuntimePrsAdmission>",
        ),
        Mutation(
            "Linux credential receiver loses its final exact child-role replay",
            "src/ipc.rs",
            "if !crate::common::is_service_owned_server_process() {\n            bail!(\"Linux service credential receiver lost the exact service-owned server role\");",
            "if false && !crate::common::is_service_owned_server_process() {\n            bail!(\"Linux service credential receiver lost the exact service-owned server role\");",
        ),
        Mutation(
            "Linux credential response uses a replacement operation UUID",
            "src/ipc.rs",
            "let value =\n            password::receive_credential_replica_unix(&mut self.stream, operation_id, deadline)\n                .await?;\n        let refreshed = authenticate_linux_service_owned_password_parent(",
            "let value =\n            password::receive_credential_replica_unix(&mut self.stream, hbb_common::uuid::Uuid::new_v4(), deadline)\n                .await?;\n        let refreshed = authenticate_linux_service_owned_password_parent(",
        ),
        Mutation(
            "Linux credential receiver replaces the typed replica response decoder",
            "src/ipc.rs",
            "let value =\n            password::receive_credential_replica_unix(&mut self.stream, operation_id, deadline)\n                .await?;\n        let refreshed = authenticate_linux_service_owned_password_parent(",
            "let value =\n            password::receive_request_unix(&mut self.stream, operation_id, deadline)\n                .await?;\n        let refreshed = authenticate_linux_service_owned_password_parent(",
        ),
        Mutation(
            "Linux credential receiver reauthenticates the wrong endpoint",
            "src/ipc.rs",
            "let refreshed = authenticate_linux_service_owned_password_parent(\n            &self.stream,\n            password::SERVICE_CREDENTIAL_IPC_POSTFIX,",
            "let refreshed = authenticate_linux_service_owned_password_parent(\n            &self.stream,\n            password::USER_PASSWORD_IPC_POSTFIX,",
        ),
        Mutation(
            "Linux credential receiver drops its final proof deadline",
            "src/ipc.rs",
            "            password::SERVICE_CREDENTIAL_IPC_POSTFIX,\n        )?;\n        password::remaining_millis(deadline)?;\n        if refreshed != self.parent {",
            "            password::SERVICE_CREDENTIAL_IPC_POSTFIX,\n        )?;\n        drop(deadline);\n        if refreshed != self.parent {",
        ),
        Mutation(
            "Linux credential receiver bypasses parent-generation continuity",
            "src/ipc.rs",
            "if refreshed != self.parent {\n            bail!(\"Linux service credential parent identity changed before runtime PRS admission\");",
            "if false && refreshed != self.parent {\n            bail!(\"Linux service credential parent identity changed before runtime PRS admission\");",
        ),
        Mutation(
            "Linux credential receiver stops minting its typed admission",
            "src/ipc.rs",
            "Ok(LinuxServiceOwnedCredentialRuntimePrsAdmission {\n            _receiver: self,",
            "Ok(LinuxServiceOwnedCredentialRuntimePrsAdmissionDisabled {\n            _receiver: self,",
        ),
        Mutation(
            "Linux credential admission install borrows its authority",
            "src/ipc.rs",
            "impl LinuxServiceOwnedCredentialRuntimePrsAdmission {\n    fn install(self) -> ResultType<bool>",
            "impl LinuxServiceOwnedCredentialRuntimePrsAdmission {\n    fn install(&self) -> ResultType<bool>",
        ),
        Mutation(
            "Linux credential admission bypasses the typed runtime PRS sink",
            "src/ipc.rs",
            "impl LinuxServiceOwnedCredentialRuntimePrsAdmission {\n    fn install(self) -> ResultType<bool> {\n        self.replica.install_for_runtime()",
            "impl LinuxServiceOwnedCredentialRuntimePrsAdmission {\n    fn install(self) -> ResultType<bool> {\n        Config::set_permanent_password_prs_for_runtime(self.replica.as_sensitive_password().as_str())",
        ),
        Mutation(
            "Linux credential snapshot wrapper bypasses the typed receiver",
            "src/ipc.rs",
            "let receiver = LinuxServiceOwnedCredentialReplicaReceiver::connect(deadline).await?;",
            "let receiver = connect_service(ms_timeout).await?;",
        ),
        Mutation(
            "Linux credential snapshot wrapper bypasses capability-bound install",
            "src/ipc.rs",
            "    let admission = receiver.receive_and_admit(deadline).await?;\n    admission.install()\n}\n\n#[cfg(not(any(target_os = \"android\", target_os = \"ios\")))]\npub fn is_permanent_password_set()",
            "    let replica = receiver.receive_and_admit(deadline).await?;\n    Config::set_permanent_password_prs_for_runtime(replica.as_str())\n}\n\n#[cfg(not(any(target_os = \"android\", target_os = \"ios\")))]\npub fn is_permanent_password_set()",
        ),
        Mutation(
            "Linux runtime PRS receiver drops the retained parent generation",
            "src/ipc.rs",
            "struct LinuxServiceOwnedPasswordReplicaReceiver {\n    parent: LinuxProcessIdentity,\n}",
            "struct LinuxServiceOwnedPasswordReplicaReceiver {\n    parent_alive: bool,\n}",
        ),
        Mutation(
            "Linux runtime PRS receiver becomes cloneable",
            "src/ipc.rs",
            "struct LinuxServiceOwnedPasswordReplicaReceiver {",
            "#[derive(Clone)]\nstruct LinuxServiceOwnedPasswordReplicaReceiver {",
        ),
        Mutation(
            "Linux runtime PRS receiver becomes public",
            "src/ipc.rs",
            "struct LinuxServiceOwnedPasswordReplicaReceiver {",
            "pub struct LinuxServiceOwnedPasswordReplicaReceiver {",
        ),
        Mutation(
            "Linux runtime PRS admission becomes cloneable",
            "src/ipc.rs",
            "struct LinuxServiceOwnedRuntimePrsAdmission {",
            "#[derive(Clone)]\nstruct LinuxServiceOwnedRuntimePrsAdmission {",
        ),
        Mutation(
            "sensitive-main service action drops its retained receiver authority",
            "src/ipc.rs",
            "ServiceOwnedRuntimePrs(LinuxServiceOwnedPasswordReplicaReceiver),",
            "ServiceOwnedRuntimePrs(PasswordMutationKind),",
        ),
        Mutation(
            "sensitive-main service action is misclassified as user-owned",
            "src/ipc.rs",
            "Self::ServiceOwnedRuntimePrs(_) => PasswordMutationKind::ServiceOwned,",
            "Self::ServiceOwnedRuntimePrs(_) => PasswordMutationKind::UserOwned,",
        ),
        Mutation(
            "Linux runtime PRS receiver admits a non-service-owned child role",
            "src/ipc.rs",
            "if !crate::common::is_service_owned_server_process() {\n            bail!(\n                \"Linux service-owned password replica receiver requires the exact service-owned server role\"",
            "if false && !crate::common::is_service_owned_server_process() {\n            bail!(\n                \"Linux service-owned password replica receiver requires the exact service-owned server role\"",
        ),
        Mutation(
            "Linux runtime PRS receiver authenticates the credential endpoint instead of _password",
            "src/ipc.rs",
            "let parent = authenticate_linux_service_owned_password_parent(\n            stream,\n            password::USER_PASSWORD_IPC_POSTFIX,",
            "let parent = authenticate_linux_service_owned_password_parent(\n            stream,\n            password::SERVICE_CREDENTIAL_IPC_POSTFIX,",
        ),
        Mutation(
            "Linux runtime PRS receiver borrows authority at final admission",
            "src/ipc.rs",
            "    fn admit<T>(self, stream: &T) -> ResultType<LinuxServiceOwnedRuntimePrsAdmission>",
            "    fn admit<T>(&self, stream: &T) -> ResultType<LinuxServiceOwnedRuntimePrsAdmission>",
        ),
        Mutation(
            "Linux runtime PRS receiver loses its final exact child-role replay",
            "src/ipc.rs",
            "if !crate::common::is_service_owned_server_process() {\n            bail!(\n                \"Linux service-owned password replica receiver lost its exact service-owned server role\"",
            "if false && !crate::common::is_service_owned_server_process() {\n            bail!(\n                \"Linux service-owned password replica receiver lost its exact service-owned server role\"",
        ),
        Mutation(
            "Linux runtime PRS receiver reauthenticates the wrong endpoint",
            "src/ipc.rs",
            "let refreshed = authenticate_linux_service_owned_password_parent(\n            stream,\n            password::USER_PASSWORD_IPC_POSTFIX,",
            "let refreshed = authenticate_linux_service_owned_password_parent(\n            stream,\n            password::SERVICE_CREDENTIAL_IPC_POSTFIX,",
        ),
        Mutation(
            "Linux runtime PRS receiver bypasses accepted-parent generation continuity",
            "src/ipc.rs",
            "if refreshed != self.parent {\n            bail!(\"Linux service-owned password replica parent identity changed before admission\");",
            "if false && refreshed != self.parent {\n            bail!(\"Linux service-owned password replica parent identity changed before admission\");",
        ),
        Mutation(
            "Linux root-parent proof discards PID start-time identity",
            "src/ipc/auth.rs",
            "let peer_pid = peer_pid_from_fd(fd)\n        .filter(|pid| *pid > 0)\n        .ok_or_else(|| anyhow::anyhow!(\"service-owned parent pid is unavailable for {postfix}\"))?;\n    let identity = linux_kernel_process_identity_by_pid(peer_pid)?;",
            "let peer_pid = peer_pid_from_fd(fd)\n        .filter(|pid| *pid > 0)\n        .ok_or_else(|| anyhow::anyhow!(\"service-owned parent pid is unavailable for {postfix}\"))?;\n    let identity = LinuxProcessIdentity { pid: peer_pid, uid: peer_uid, start_time: String::new() };",
        ),
        Mutation(
            "Linux root-parent proof again becomes crate-visible",
            "src/ipc/auth.rs",
            "pub(super) fn authenticate_linux_service_owned_password_parent<T>(",
            "pub(crate) fn authenticate_linux_service_owned_password_parent<T>(",
        ),
        Mutation(
            "Linux runtime PRS ledger borrows rather than consumes admission",
            "src/ipc.rs",
            "        _admission: LinuxServiceOwnedRuntimePrsAdmission,",
            "        _admission: &LinuxServiceOwnedRuntimePrsAdmission,",
        ),
        Mutation(
            "Linux runtime PRS ledger accepts an ordinary password type",
            "src/ipc.rs",
            "        _admission: LinuxServiceOwnedRuntimePrsAdmission,\n        operation_id: &str,\n        replica: &ServiceOwnedRuntimePrsReplica,",
            "        _admission: LinuxServiceOwnedRuntimePrsAdmission,\n        operation_id: &str,\n        replica: &SensitivePassword,",
        ),
        Mutation(
            "Linux runtime PRS ledger records a user-owned action",
            "src/ipc.rs",
            "            PasswordMutationKind::ServiceOwned,\n            replica.as_sensitive_password().as_str(),",
            "            PasswordMutationKind::UserOwned,\n            replica.as_sensitive_password().as_str(),",
        ),
        Mutation(
            "Linux runtime PRS mutation entry accepts detached Boolean authority",
            "src/ipc.rs",
            "    admission: LinuxServiceOwnedRuntimePrsAdmission,\n    operation_id: String,",
            "    admission: bool,\n    operation_id: String,",
        ),
        Mutation(
            "Linux runtime PRS handler skips final parent admission",
            "src/ipc.rs",
            "            match receiver.admit(&stream) {",
            "            match Ok(LinuxServiceOwnedRuntimePrsAdmission { _receiver: receiver }) {",
        ),
        Mutation(
            "Linux runtime PRS mutation entry uses the generic durable worker",
            "src/ipc.rs",
            "spawn_linux_service_owned_runtime_prs_mutation(operation_id.clone(), replica, permit);",
            "spawn_password_mutation(operation_id.clone(), replica.value, kind, permit);",
        ),
        Mutation(
            "Linux runtime PRS worker accepts a generic password",
            "src/ipc.rs",
            "    replica: ServiceOwnedRuntimePrsReplica,\n    permit: OwnedSemaphorePermit,",
            "    replica: SensitivePassword,\n    permit: OwnedSemaphorePermit,",
        ),
        Mutation(
            "Linux runtime PRS worker writes the durable credential store",
            "src/ipc.rs",
            "let result = match replica.install_for_runtime() {",
            "let result = match Config::set_permanent_password_persisted(replica.as_sensitive_password().as_str()) {",
        ),
        Mutation(
            "generic password worker regains ambient runtime-PRS selection",
            "src/ipc.rs",
            "        let result = match Config::set_permanent_password_persisted(value.as_str()) {",
            "        let result = match if kind == PasswordMutationKind::ServiceOwned && crate::common::is_service_owned_server_process() { Config::set_permanent_password_prs_for_runtime(value.as_str()).map(|_| true) } else { Config::set_permanent_password_persisted(value.as_str()) } {",
        ),
        Mutation(
            "sensitive-main authority collapses back to a mutation kind",
            "src/ipc.rs",
            "fn sensitive_main_ipc_authority(stream: &Conn) -> Option<SensitiveMainPasswordAuthority>",
            "fn sensitive_main_ipc_authority(stream: &Conn) -> Option<PasswordMutationKind>",
        ),
        Mutation(
            "sensitive-main handler drops typed action authority",
            "src/ipc.rs",
            "    authority: SensitiveMainPasswordAuthority,",
            "    authority: PasswordMutationKind,",
        ),
        Mutation(
            "Linux credential requester capability becomes cloneable",
            "src/ipc.rs",
            "struct LinuxServiceOwnedCredentialReplicaRequester {",
            "#[derive(Clone)]\nstruct LinuxServiceOwnedCredentialReplicaRequester {",
        ),
        Mutation(
            "Linux credential admission capability becomes cloneable",
            "src/ipc.rs",
            "struct LinuxServiceOwnedCredentialReplicaAdmission {",
            "#[derive(Clone)]\nstruct LinuxServiceOwnedCredentialReplicaAdmission {",
        ),
        Mutation(
            "Linux credential requester authenticates the wrong endpoint",
            "src/ipc.rs",
            "password::SERVICE_CREDENTIAL_IPC_POSTFIX,\n        )?;\n        Ok(Self { identity })",
            "password::USER_PASSWORD_IPC_POSTFIX,\n        )?;\n        Ok(Self { identity })",
        ),
        Mutation(
            "Linux credential listener bypasses its typed requester",
            "src/ipc.rs",
            "let requester = match LinuxServiceOwnedCredentialReplicaRequester::authenticate(\n                        &stream,\n                    ) {",
            "let requester = match authenticate_linux_service_owned_password_replica_server(\n                        &stream, password::SERVICE_CREDENTIAL_IPC_POSTFIX,\n                    ) {",
        ),
        Mutation(
            "Linux credential requester is borrowed rather than consumed at admission",
            "src/ipc.rs",
            "    fn admit<T>(\n        self,",
            "    fn admit<T>(\n        &self,",
        ),
        Mutation(
            "Linux credential admission skips its fresh exact-child replay",
            "src/ipc.rs",
            "let refreshed = Self::authenticate(stream)?;",
            "let refreshed = Self { identity: self.identity.clone() };",
        ),
        Mutation(
            "Linux credential admission bypasses accepted-generation continuity",
            "src/ipc.rs",
            "if refreshed.identity != self.identity {\n            bail!(\"Linux service credential requester identity changed after its request\");",
            "if false && refreshed.identity != self.identity {\n            bail!(\"Linux service credential requester identity changed after its request\");",
        ),
        Mutation(
            "Linux credential admission drops the exact requester",
            "src/ipc.rs",
            "_requester: LinuxServiceOwnedCredentialReplicaRequester,",
            "_requester: bool,",
        ),
        Mutation(
            "Linux credential admission gains a second construction",
            "src/ipc.rs",
            "Ok(LinuxServiceOwnedCredentialReplicaAdmission {\n            _requester: self,\n            operation_id,\n        })",
            "let duplicate = LinuxServiceOwnedCredentialReplicaAdmission { _requester: self, operation_id };\n        Ok(LinuxServiceOwnedCredentialReplicaAdmission { _requester: duplicate._requester, operation_id: duplicate.operation_id })",
        ),
        Mutation(
            "Linux credential response borrows rather than consumes admission",
            "src/ipc.rs",
            "impl LinuxServiceOwnedCredentialReplicaAdmission {\n"
            "    async fn respond(\n        self,",
            "impl LinuxServiceOwnedCredentialReplicaAdmission {\n"
            "    async fn respond(\n        &self,",
        ),
        Mutation(
            "Linux credential response drops its operation binding",
            "src/ipc.rs",
            "        let replica = service_owned_runtime_prs_replica(\"Linux\").map_err(|err| {\n"
            "            log::error!(\"Linux root service credential snapshot is unavailable: {err}\");\n"
            "            err\n"
            "        })?;\n"
            "        password::send_credential_replica_unix(\n"
            "            stream,\n"
            "            self.operation_id,\n"
            "            replica.as_sensitive_password(),",
            "        let replica = service_owned_runtime_prs_replica(\"Linux\").map_err(|err| {\n"
            "            log::error!(\"Linux root service credential snapshot is unavailable: {err}\");\n"
            "            err\n"
            "        })?;\n"
            "        password::send_credential_replica_unix(\n"
            "            stream,\n"
            "            hbb_common::uuid::Uuid::from_bytes([1; 16]),\n"
            "            replica.as_sensitive_password(),",
        ),
        Mutation(
            "Linux credential handler bypasses capability-owned response",
            "src/ipc.rs",
            "if let Err(err) = admission.respond(&mut stream, deadline).await {\n"
            "        log::trace!(\"Linux service credential snapshot could not be returned: {err}\");",
            "if let Err(err) = send_linux_credential_replica_unchecked(&mut stream, admission, deadline).await {\n"
            "        log::trace!(\"Linux service credential snapshot could not be returned: {err}\");",
        ),
        Mutation(
            "Linux generic replica proof regains crate visibility",
            "src/ipc/auth.rs",
            "pub(super) fn authenticate_linux_service_owned_password_replica_server<T>(",
            "pub(crate) fn authenticate_linux_service_owned_password_replica_server<T>(",
        ),
        Mutation(
            "credential replica service endpoint excludes Linux",
            "libs/hbb_common/src/config.rs",
            'cfg!(any(target_os = "linux", target_os = "macos")) && postfix == "_service_credential"',
            'cfg!(target_os = "macos") && postfix == "_service_credential"',
        ),
        Mutation(
            "credential replica listener loses its exact accept lane",
            "src/ipc.rs",
            "result = credential_incoming.next() => {\n                #[cfg(target_os = \"linux\")]",
            "result = incoming.next() => { /* credential_incoming */\n                #[cfg(target_os = \"linux\")]",
        ),
        Mutation(
            "service authorization snapshot loses the Linux socket peer PID",
            "src/ipc/auth.rs",
            "let peer_pid = peer_pid_from_fd(fd);",
            "let peer_pid = None; /* peer_pid_from_fd(fd) */",
        ),
        Mutation(
            "shared service-owned PRS snapshot helper is bypassed",
            "src/ipc.rs",
            "fn service_owned_runtime_prs_replica(platform: &str) -> ResultType<ServiceOwnedRuntimePrsReplica>",
            "fn service_owned_runtime_prs_replica_unchecked(platform: &str) -> ResultType<ServiceOwnedRuntimePrsReplica>",
        ),
        Mutation(
            "interactive confirmation comparison regains ordinary string equality",
            "src/core_main.rs",
            "let matches = password.constant_time_eq(&confirmation);",
            "let matches = password.as_str() == confirmation.as_str();",
        ),
        Mutation(
            "secret body read loses its absolute deadline",
            "src/ipc/password.rs",
            "with_deadline(deadline, stream.read_exact(request.body_mut())).await?;",
            "stream.read_exact(request.body_mut()).await?; /* with_deadline(deadline, ...) */",
        ),
        Mutation(
            "ordinary IPC regains a password-bearing begin variant",
            "src/ipc.rs",
            "    PasswordMutationStatus {\n        operation_id: String,\n    },",
            "    PasswordMutationStatus {\n        operation_id: String,\n    },\n    BeginServiceOwnedUnattendedPasswordChange { value: String },",
        ),
        Mutation(
            "raw main listener bypasses peer authority",
            "src/ipc.rs",
            "let Some(authority) = sensitive_main_ipc_authority(&stream) else {\n                            continue;\n                        };",
            "let authority = SensitiveMainPasswordAuthority::UserOwned; /* sensitive_main_ipc_authority(&stream) */",
        ),
        Mutation(
            "service password listener bypasses exact requester-role authentication",
            "src/ipc.rs",
            "authenticate_linux_service_owned_password_requester(&stream)",
            "peer_process_identity_from_stream(&stream, password::SERVICE_PASSWORD_IPC_POSTFIX) /* authenticate_linux_service_owned_password_requester */",
        ),
        Mutation(
            "Linux process identity retains only a truncated argv",
            "src/ipc/auth.rs",
            "        argv: args,",
            "        argv: args.into_iter().take(2).collect(),",
        ),
        Mutation(
            "Linux exact requester role admits extra arguments",
            "src/ipc/auth.rs",
            "    args.len() == expected_args.len() + 1",
            "    args.len() >= expected_args.len() + 1",
        ),
        Mutation(
            "Linux password requester drops the interactive-UI role",
            "src/ipc/auth.rs",
            "fn linux_service_owned_password_client_argv_is_expected(args: &[String]) -> bool {\n    process_argv_is_exact(args, &[])\n        || process_argv_is_exact(args, &[\"--password\"])\n        || process_argv_is_exact(args, &[\"--password-stdin\"])\n}",
            "fn linux_service_owned_password_client_argv_is_expected(args: &[String]) -> bool {\n    false /* process_argv_is_exact(args, &[]) */\n        || process_argv_is_exact(args, &[\"--password\"])\n        || process_argv_is_exact(args, &[\"--password-stdin\"])\n}",
        ),
        Mutation(
            "Linux password requester drops the terminal password role",
            "src/ipc/auth.rs",
            "fn linux_service_owned_password_client_argv_is_expected(args: &[String]) -> bool {\n    process_argv_is_exact(args, &[])\n        || process_argv_is_exact(args, &[\"--password\"])\n        || process_argv_is_exact(args, &[\"--password-stdin\"])\n}",
            "fn linux_service_owned_password_client_argv_is_expected(args: &[String]) -> bool {\n    process_argv_is_exact(args, &[])\n        || false /* process_argv_is_exact(args, &[\"--password\"]) */\n        || process_argv_is_exact(args, &[\"--password-stdin\"])\n}",
        ),
        Mutation(
            "Linux password requester drops the stdin password role",
            "src/ipc/auth.rs",
            "fn linux_service_owned_password_client_argv_is_expected(args: &[String]) -> bool {\n    process_argv_is_exact(args, &[])\n        || process_argv_is_exact(args, &[\"--password\"])\n        || process_argv_is_exact(args, &[\"--password-stdin\"])\n}",
            "fn linux_service_owned_password_client_argv_is_expected(args: &[String]) -> bool {\n    process_argv_is_exact(args, &[])\n        || process_argv_is_exact(args, &[\"--password\"])\n        || false /* process_argv_is_exact(args, &[\"--password-stdin\"]) */\n}",
        ),
        Mutation(
            "Linux password requester admits the server role",
            "src/ipc/auth.rs",
            "fn linux_service_owned_password_client_argv_is_expected(args: &[String]) -> bool {\n    process_argv_is_exact(args, &[])\n        || process_argv_is_exact(args, &[\"--password\"])\n        || process_argv_is_exact(args, &[\"--password-stdin\"])\n}",
            "fn linux_service_owned_password_client_argv_is_expected(args: &[String]) -> bool {\n    process_argv_is_exact(args, &[])\n        || process_argv_is_exact(args, &[\"--password\"])\n        || process_argv_is_exact(args, &[\"--password-stdin\"])\n        || process_argv_is_exact(args, &[\"--server\"])\n}",
        ),
        Mutation(
            "Linux password requester admission skips its exact role",
            "src/ipc/auth.rs",
            "    if !linux_service_owned_password_client_argv_is_expected(&identity.argv) {",
            "    if false && !linux_service_owned_password_client_argv_is_expected(&identity.argv) {",
        ),
        Mutation(
            "Linux password requester admission skips same-generation pre-body finality",
            "src/ipc/auth.rs",
            "    if !linux_service_owned_password_requester_is_live(&identity) {",
            "    if false && !linux_service_owned_password_requester_is_live(&identity) {",
        ),
        Mutation(
            "Linux password requester finality loses its role recheck",
            "src/ipc/auth.rs",
            "    linux_service_owned_password_client_argv_is_expected(&identity.argv)\n        && peer_process_identity_is_live(identity, super::password::SERVICE_PASSWORD_IPC_POSTFIX)",
            "    peer_process_identity_is_live(identity, super::password::SERVICE_PASSWORD_IPC_POSTFIX) /* linux_service_owned_password_client_argv_is_expected */",
        ),
        Mutation(
            "Linux password exact-role regression is removed",
            "src/ipc/auth.rs",
            "fn r_s11e261_linux_service_owned_password_client_roles_are_finite()",
            "fn linux_service_owned_password_client_roles_are_unchecked()",
        ),
        Mutation(
            "Linux post-polkit password admission becomes cloneable",
            "src/ipc.rs",
            "struct LinuxServiceOwnedPasswordAdmission {",
            "#[derive(Clone)]\nstruct LinuxServiceOwnedPasswordAdmission {",
        ),
        Mutation(
            "Linux post-polkit password admission bypasses its requester replay",
            "src/ipc.rs",
            "if !linux_service_owned_password_requester_is_live(identity) {\n                log::warn!(\n                    \"Rejected service-owned unattended password change: requester changed after pkcheck authorization\"",
            "if false && !linux_service_owned_password_requester_is_live(identity) {\n                log::warn!(\n                    \"Rejected service-owned unattended password change: requester changed after pkcheck authorization\"",
        ),
        Mutation(
            "Linux post-polkit password admission discards its requester capability",
            "src/ipc.rs",
            "Some(LinuxServiceOwnedPasswordAdmission {\n                requester: identity.clone(),\n            })",
            "None /* LinuxServiceOwnedPasswordAdmission requester discarded */",
        ),
        Mutation(
            "Linux post-polkit password admission gains a second production construction",
            "src/ipc.rs",
            "Some(LinuxServiceOwnedPasswordAdmission {\n                requester: identity.clone(),\n            })",
            "let _duplicate = Some(LinuxServiceOwnedPasswordAdmission { requester: identity.clone() });\n            Some(LinuxServiceOwnedPasswordAdmission {\n                requester: identity.clone(),\n            })",
        ),
        Mutation(
            "Linux password admission capability is no longer consumed",
            "src/ipc.rs",
            "    fn admit_commit(\n        self,",
            "    fn admit_commit(\n        &self,",
        ),
        Mutation(
            "Linux password admission capability bypasses operation-id validation",
            "src/ipc.rs",
            "if !password_mutation_id_is_valid(operation_id)\n            || !service_owned_password_value_is_valid(\"Linux\", value)",
            "if false && !password_mutation_id_is_valid(operation_id)\n            || !service_owned_password_value_is_valid(\"Linux\", value)",
        ),
        Mutation(
            "Linux password admission capability bypasses value validation",
            "src/ipc.rs",
            "|| !service_owned_password_value_is_valid(\"Linux\", value)\n            || !linux_service_owned_password_requester_is_live(&self.requester)",
            "|| false && !service_owned_password_value_is_valid(\"Linux\", value)\n            || !linux_service_owned_password_requester_is_live(&self.requester)",
        ),
        Mutation(
            "Linux password admission capability bypasses its final requester replay",
            "src/ipc.rs",
            "|| !linux_service_owned_password_requester_is_live(&self.requester)",
            "|| false && !linux_service_owned_password_requester_is_live(&self.requester)",
        ),
        Mutation(
            "Linux password coordinator accepts a detached Boolean instead of the capability",
            "src/ipc.rs",
            "admission: &LinuxServiceOwnedPasswordAdmission,",
            "admission: bool,",
        ),
        Mutation(
            "Linux password coordinator bypasses the service-owned operation kind",
            "src/ipc.rs",
            "if entry.kind != PasswordMutationKind::ServiceOwned\n            || entry.fingerprint != fingerprint\n            || entry.caller != caller",
            "if entry.fingerprint != fingerprint\n            || entry.caller != caller /* service-owned kind bypassed */",
        ),
        Mutation(
            "Linux password coordinator bypasses the admitted value fingerprint",
            "src/ipc.rs",
            "|| entry.fingerprint != fingerprint\n            || entry.caller != caller",
            "|| entry.caller != caller /* admitted fingerprint bypassed */",
        ),
        Mutation(
            "Linux password coordinator bypasses the admitted requester",
            "src/ipc.rs",
            "|| entry.caller != caller\n            || entry.state != LinuxPasswordAdmissionState::Authorizing",
            "|| entry.state != LinuxPasswordAdmissionState::Authorizing /* admitted requester bypassed */",
        ),
        Mutation(
            "Linux password coordinator bypasses the Authorizing state",
            "src/ipc.rs",
            "|| entry.caller != caller\n            || entry.state != LinuxPasswordAdmissionState::Authorizing\n        {",
            "|| entry.caller != caller\n            || false /* Authorizing state bypassed */\n        {",
        ),
        Mutation(
            "Linux password operation reopens an injected Boolean authorizer",
            "src/ipc.rs",
            "async fn execute_linux_service_owned_password_operation<Commit, CommitFuture>(",
            "async fn execute_linux_service_owned_password_operation<Authorize, Commit, CommitFuture>(",
        ),
        Mutation(
            "Linux password operation bypasses the consuming admission capability",
            "src/ipc.rs",
            "if !admission.admit_commit(coordinator, operation_id, value)? {",
            "if !coordinator.admit_authorized(&admission, operation_id, value) {",
        ),
        Mutation(
            "Linux denied authorization cancellation bypasses its value fingerprint",
            "src/ipc.rs",
            "|| entry.fingerprint != fingerprint\n            || entry.caller != *caller",
            "|| entry.caller != *caller /* denied fingerprint bypassed */",
        ),
        Mutation(
            "Linux denied authorization cancellation can remove admitted work",
            "src/ipc.rs",
            "|| entry.caller != *caller\n            || entry.state != LinuxPasswordAdmissionState::Authorizing\n        {",
            "|| entry.caller != *caller\n            || false /* cancellation state bypassed */\n        {",
        ),
        Mutation(
            "macOS password requester drops its accepted-socket audit-token identity",
            "src/ipc/auth.rs",
            "pub(crate) struct MacosServiceOwnedPasswordRequester {\n    identity: MacosPeerProcessIdentity,\n    argv: Vec<String>,\n}",
            "pub(crate) struct MacosServiceOwnedPasswordRequester {\n    argv: Vec<String>,\n}",
        ),
        Mutation(
            "macOS password requester drops its retained complete argv",
            "src/ipc/auth.rs",
            "pub(crate) struct MacosServiceOwnedPasswordRequester {\n    identity: MacosPeerProcessIdentity,\n    argv: Vec<String>,\n}",
            "pub(crate) struct MacosServiceOwnedPasswordRequester {\n    identity: MacosPeerProcessIdentity,\n}",
        ),
        Mutation(
            "macOS password requester drops the interactive-UI role",
            "src/ipc/auth.rs",
            "fn macos_service_owned_password_client_argv_is_expected(args: &[String]) -> bool {\n    process_argv_is_exact(args, &[])\n        || process_argv_is_exact(args, &[\"--password\"])\n        || process_argv_is_exact(args, &[\"--password-stdin\"])\n}",
            "fn macos_service_owned_password_client_argv_is_expected(args: &[String]) -> bool {\n    false\n        || process_argv_is_exact(args, &[\"--password\"])\n        || process_argv_is_exact(args, &[\"--password-stdin\"])\n}",
        ),
        Mutation(
            "macOS password requester drops the terminal password role",
            "src/ipc/auth.rs",
            "fn macos_service_owned_password_client_argv_is_expected(args: &[String]) -> bool {\n    process_argv_is_exact(args, &[])\n        || process_argv_is_exact(args, &[\"--password\"])\n        || process_argv_is_exact(args, &[\"--password-stdin\"])\n}",
            "fn macos_service_owned_password_client_argv_is_expected(args: &[String]) -> bool {\n    process_argv_is_exact(args, &[])\n        || false\n        || process_argv_is_exact(args, &[\"--password-stdin\"])\n}",
        ),
        Mutation(
            "macOS password requester drops the stdin password role",
            "src/ipc/auth.rs",
            "fn macos_service_owned_password_client_argv_is_expected(args: &[String]) -> bool {\n    process_argv_is_exact(args, &[])\n        || process_argv_is_exact(args, &[\"--password\"])\n        || process_argv_is_exact(args, &[\"--password-stdin\"])\n}",
            "fn macos_service_owned_password_client_argv_is_expected(args: &[String]) -> bool {\n    process_argv_is_exact(args, &[])\n        || process_argv_is_exact(args, &[\"--password\"])\n        || false\n}",
        ),
        Mutation(
            "macOS password requester admits the server role",
            "src/ipc/auth.rs",
            "fn macos_service_owned_password_client_argv_is_expected(args: &[String]) -> bool {\n    process_argv_is_exact(args, &[])\n        || process_argv_is_exact(args, &[\"--password\"])\n        || process_argv_is_exact(args, &[\"--password-stdin\"])\n}",
            "fn macos_service_owned_password_client_argv_is_expected(args: &[String]) -> bool {\n    process_argv_is_exact(args, &[])\n        || process_argv_is_exact(args, &[\"--password\"])\n        || process_argv_is_exact(args, &[\"--password-stdin\"])\n        || process_argv_is_exact(args, &[\"--server\"])\n}",
        ),
        Mutation(
            "macOS password requester bypasses its fixed raw endpoint",
            "src/ipc/auth.rs",
            "if authorization.postfix != super::password::SERVICE_PASSWORD_IPC_POSTFIX {",
            "if false && authorization.postfix != super::password::SERVICE_PASSWORD_IPC_POSTFIX {",
        ),
        Mutation(
            "macOS password requester bypasses snapshot UID authority",
            "src/ipc/auth.rs",
            "if !authorization.uid_authorized {\n        bail!(\"macOS service-owned password requester is not root or the active console user\");",
            "if false && !authorization.uid_authorized {\n        bail!(\"macOS service-owned password requester is not root or the active console user\");",
        ),
        Mutation(
            "macOS socket audit-token consistency admits a zero PID",
            "src/ipc/auth.rs",
            "    pid != 0\n        && macos_audit_token_word(token, MACOS_AUDIT_TOKEN_EUID_WORD) == uid",
            "    pid == 0\n        && macos_audit_token_word(token, MACOS_AUDIT_TOKEN_EUID_WORD) == uid",
        ),
        Mutation(
            "macOS socket identity stops matching the audit-token effective UID",
            "src/ipc/auth.rs",
            "        && macos_audit_token_word(token, MACOS_AUDIT_TOKEN_EUID_WORD) == uid",
            "        && true /* audit-token effective UID */",
        ),
        Mutation(
            "macOS socket identity stops matching the audit-token PID",
            "src/ipc/auth.rs",
            "        && macos_audit_token_word(token, MACOS_AUDIT_TOKEN_PID_WORD) == pid",
            "        && true /* audit-token PID */",
        ),
        Mutation(
            "macOS socket identity constructor bypasses audit-token consistency",
            "src/ipc/auth.rs",
            "    if !macos_audit_token_matches_socket_identity(&audit_token, uid, pid) {",
            "    if !true { /* macos_audit_token_matches_socket_identity */",
        ),
        Mutation(
            "macOS socket identity constructor eagerly constructs a rejected identity",
            "src/ipc/auth.rs",
            "    if !macos_audit_token_matches_socket_identity(&audit_token, uid, pid) {\n"
            "        return None;\n"
            "    }\n"
            "    Some(MacosPeerProcessIdentity {\n"
            "        uid,\n"
            "        pid,\n"
            "        audit_token,\n"
            "    })",
            "    macos_audit_token_matches_socket_identity(&audit_token, uid, pid).then_some(\n"
            "        MacosPeerProcessIdentity {\n"
            "            uid,\n"
            "            pid,\n"
            "            audit_token,\n"
            "        },\n"
            "    )",
        ),
        Mutation(
            "macOS direct stream identity bypasses the consistent constructor",
            "src/ipc/auth.rs",
            "    macos_peer_process_identity_from_socket_components(uid, pid, audit_token).ok_or_else(|| {",
            "    Some(MacosPeerProcessIdentity { uid, pid, audit_token }).ok_or_else(|| { /* consistent constructor */",
        ),
        Mutation(
            "macOS service snapshot bypasses the consistent identity constructor",
            "src/ipc/auth.rs",
            "        (Some(uid), Some(pid), Some(audit_token)) => {\n            macos_peer_process_identity_from_socket_components(uid, pid, audit_token)\n        }",
            "        (Some(uid), Some(pid), Some(audit_token)) => {\n            Some(MacosPeerProcessIdentity { uid, pid, audit_token })\n        }",
        ),
        Mutation(
            "macOS password requester bypasses its complete installed-app proof",
            "src/ipc/auth.rs",
            "if !macos_service_owned_password_requester_identity_is_live(&identity) {\n        bail!(\"macOS service-owned password requester is not the live trusted installed app\");",
            "if false && !macos_service_owned_password_requester_identity_is_live(&identity) {\n        bail!(\"macOS service-owned password requester is not the live trusted installed app\");",
        ),
        Mutation(
            "macOS password requester uses fabricated argv instead of the live process",
            "src/ipc/auth.rs",
            "let argv = macos_process_cmdline_args(identity.pid)?;",
            "let argv = vec![String::new()]; /* macos_process_cmdline_args(identity.pid)? */",
        ),
        Mutation(
            "macOS password requester bypasses its finite exact role",
            "src/ipc/auth.rs",
            "if !macos_service_owned_password_client_argv_is_expected(&argv) {\n        bail!(\"macOS service-owned password requester has an unauthorized process role\");",
            "if false && !macos_service_owned_password_client_argv_is_expected(&argv) {\n        bail!(\"macOS service-owned password requester has an unauthorized process role\");",
        ),
        Mutation(
            "macOS password requester skips post-argv audit-token generation proof",
            "src/ipc/auth.rs",
            "if !macos_service_owned_password_requester_generation_is_live(&identity) {\n        bail!(\"macOS service-owned password requester changed while its role was inspected\");",
            "if false && !macos_service_owned_password_requester_generation_is_live(&identity) {\n        bail!(\"macOS service-owned password requester changed while its role was inspected\");",
        ),
        Mutation(
            "macOS password requester generation proof loses final fresh console UID",
            "src/ipc/auth.rs",
            "macos_executable_matches_expected_path(&path, &macos_installed_app_executable_path())\n        && is_allowed_service_peer_uid(identity.uid, active_uid_fresh())",
            "macos_executable_matches_expected_path(&path, &macos_installed_app_executable_path())",
        ),
        Mutation(
            "macOS password requester retains only truncated argv",
            "src/ipc/auth.rs",
            "Ok(MacosServiceOwnedPasswordRequester { identity, argv })",
            "Ok(MacosServiceOwnedPasswordRequester { identity, argv: argv.into_iter().take(1).collect() })",
        ),
        Mutation(
            "macOS password requester replay bypasses the installed-app identity",
            "src/ipc/auth.rs",
            "if !macos_service_owned_password_requester_identity_is_live(&requester.identity) {\n        return false;",
            "if false && !macos_service_owned_password_requester_identity_is_live(&requester.identity) {\n        return false;",
        ),
        Mutation(
            "macOS password requester replay reuses stale argv",
            "src/ipc/auth.rs",
            "let Ok(argv) = macos_process_cmdline_args(requester.identity.pid) else {",
            "let Ok(argv) = Ok::<_, anyhow::Error>(requester.argv.clone()) else { /* macos_process_cmdline_args */",
        ),
        Mutation(
            "macOS password requester replay accepts changed argv",
            "src/ipc/auth.rs",
            "argv == requester.argv\n        && macos_service_owned_password_client_argv_is_expected(&argv)",
            "argv != requester.argv\n        && macos_service_owned_password_client_argv_is_expected(&argv)",
        ),
        Mutation(
            "macOS password requester replay loses its finite role",
            "src/ipc/auth.rs",
            "&& macos_service_owned_password_client_argv_is_expected(&argv)\n        && macos_service_owned_password_requester_generation_is_live(&requester.identity)",
            "&& true /* macos_service_owned_password_client_argv_is_expected */\n        && macos_service_owned_password_requester_generation_is_live(&requester.identity)",
        ),
        Mutation(
            "macOS password requester replay loses audit-token generation finality",
            "src/ipc/auth.rs",
            "&& macos_service_owned_password_requester_generation_is_live(&requester.identity)",
            "&& true /* macos_service_owned_password_requester_generation_is_live */",
        ),
        Mutation(
            "macOS post-request last-owner replay loses full audit-token equality",
            "src/ipc/auth.rs",
            "        && identity.audit_token == requester.identity.audit_token",
            "        && true /* post-request full audit token */",
        ),
        Mutation(
            "macOS post-request last-owner replay accepts a different effective PID",
            "src/ipc/auth.rs",
            "        && identity.pid == requester.identity.pid",
            "        && identity.pid != requester.identity.pid",
        ),
        Mutation(
            "macOS password listener delays its socket identity snapshot until the proof task",
            "src/ipc.rs",
            "let authorization =\n                        ipc_auth::service_scoped_ipc_authorization_snapshot_from_stream(\n                            &stream,\n                            password::SERVICE_PASSWORD_IPC_POSTFIX,\n                        );\n                    transactions.spawn(async move {",
            "transactions.spawn(async move {\n                        let authorization =\n                            ipc_auth::service_scoped_ipc_authorization_snapshot_from_stream(\n                                &stream,\n                                password::SERVICE_PASSWORD_IPC_POSTFIX,\n                            );",
        ),
        Mutation(
            "macOS password proof task falls back to generic service authorization",
            "src/ipc.rs",
            "authenticate_macos_service_owned_password_requester(authorization)",
            "if ipc_auth::authorize_service_scoped_ipc_authorization_snapshot(authorization) { unreachable!() } else { unreachable!() } /* authenticate_macos_service_owned_password_requester */",
        ),
        Mutation(
            "macOS password admission becomes cloneable",
            "src/ipc.rs",
            "struct MacosServiceOwnedPasswordAdmission {",
            "#[derive(Clone)]\nstruct MacosServiceOwnedPasswordAdmission {",
        ),
        Mutation(
            "macOS password admission bypasses right normalization",
            "src/ipc.rs",
            "if !crate::platform::ensure_service_owned_unattended_password_authorization_right() {",
            "if false && !crate::platform::ensure_service_owned_unattended_password_authorization_right() {",
        ),
        Mutation(
            "macOS password admission bypasses Authorization Services verification",
            "src/ipc.rs",
            "if !crate::platform::verify_service_owned_unattended_password_authorization(authorization) {",
            "if false && !crate::platform::verify_service_owned_unattended_password_authorization(authorization) {",
        ),
        Mutation(
            "macOS password admission bypasses its post-authorization requester replay",
            "src/ipc.rs",
            "if !macos_service_owned_password_requester_is_live(&requester) {\n        log::warn!(\n            \"Rejected macOS service-owned unattended password change: requester changed during authorization\"",
            "if false && !macos_service_owned_password_requester_is_live(&requester) {\n        log::warn!(\n            \"Rejected macOS service-owned unattended password change: requester changed during authorization\"",
        ),
        Mutation(
            "macOS password admission discards its requester capability",
            "src/ipc.rs",
            "Some(MacosServiceOwnedPasswordAdmission { requester })",
            "None /* MacosServiceOwnedPasswordAdmission { requester } discarded */",
        ),
        Mutation(
            "macOS password admission capability gains a second construction site",
            "src/ipc.rs",
            "Some(MacosServiceOwnedPasswordAdmission { requester })",
            "let _duplicate = Some(MacosServiceOwnedPasswordAdmission { requester });\n    Some(MacosServiceOwnedPasswordAdmission { requester })",
        ),
        Mutation(
            "macOS password capability bypasses operation-id validation",
            "src/ipc.rs",
            "if !password_mutation_id_is_valid(&operation_id)\n            || !service_owned_password_value_is_valid(\"macOS\", password.as_str())",
            "if false && !password_mutation_id_is_valid(&operation_id)\n            || !service_owned_password_value_is_valid(\"macOS\", password.as_str())",
        ),
        Mutation(
            "macOS password capability bypasses value validation",
            "src/ipc.rs",
            "|| !service_owned_password_value_is_valid(\"macOS\", password.as_str())",
            "|| false && !service_owned_password_value_is_valid(\"macOS\", password.as_str())",
        ),
        Mutation(
            "macOS password capability bypasses its final requester replay",
            "src/ipc.rs",
            "if !macos_service_owned_password_requester_is_live(&self.requester) {",
            "if false && !macos_service_owned_password_requester_is_live(&self.requester) {",
        ),
        Mutation(
            "macOS password capability bypasses post-request socket ownership",
            "src/ipc.rs",
            "if !macos_service_owned_password_requester_matches_post_request_last_owner(\n            &self.requester,\n            stream,\n        ) {",
            "if false && !macos_service_owned_password_requester_matches_post_request_last_owner(\n            &self.requester,\n            stream,\n        ) {",
        ),
        Mutation(
            "macOS password coordinator accepts a detached Boolean instead of the capability",
            "src/ipc.rs",
            "_admission: &MacosServiceOwnedPasswordAdmission,",
            "_admission: bool,",
        ),
        Mutation(
            "macOS password admission is no longer consumed by preparation",
            "src/ipc.rs",
            "    fn prepare_mutation(\n        self,",
            "    fn prepare_mutation(\n        &self,",
        ),
        Mutation(
            "macOS password preparation fabricates Prepared without ledger ownership",
            "src/ipc.rs",
            "        if preparation.owns_preparation {",
            "        if true { /* preparation.owns_preparation */",
        ),
        Mutation(
            "macOS password status-only outcome retains the credential secret",
            "src/ipc.rs",
            "        status: PasswordMutationStatus,",
            "        status: PasswordMutationStatus,\n        password: SensitivePassword,",
        ),
        Mutation(
            "macOS password handler regains a detached authority Boolean",
            "src/ipc.rs",
            "mutation: PreparedMacosServiceOwnedPasswordMutation,",
            "mutation: PreparedMacosServiceOwnedPasswordMutation,\n    authority_allowed: bool,",
        ),
        Mutation(
            "macOS password handler directly reopens Boolean ledger admission",
            "src/ipc.rs",
            "    let kind = PasswordMutationKind::ServiceOwned;\n    let Some(permit) = try_acquire_main_ipc_blocking_mutation_slot() else {",
            "    let kind = PasswordMutationKind::ServiceOwned;\n    let _bypass = password_mutations().prepare_if_allowed(&operation_id, kind, password.as_str(), true);\n    let Some(permit) = try_acquire_main_ipc_blocking_mutation_slot() else {",
        ),
        Mutation(
            "macOS password status resolver starts a mutation worker",
            "src/ipc.rs",
            "    let kind = PasswordMutationKind::ServiceOwned;\n    let result = match status {",
            "    let kind = PasswordMutationKind::ServiceOwned;\n    let _bypass = spawn_password_mutation(operation_id.clone(), password, kind, permit);\n    let result = match status {",
        ),
        Mutation(
            "macOS password exact-role regression is removed",
            "src/ipc/auth.rs",
            "fn r_s11e262_macos_service_owned_password_client_roles_are_finite()",
            "fn macos_service_owned_password_client_roles_are_unchecked()",
        ),
        Mutation(
            "macOS socket audit-token identity regression is removed",
            "src/ipc/auth.rs",
            "fn r_s11e262_macos_audit_token_must_match_socket_identity()",
            "fn macos_audit_token_socket_identity_is_unchecked()",
        ),
        Mutation(
            "macOS generic service listener delays its identity snapshot until task execution",
            "src/ipc.rs",
            "let authorization = ipc_auth::service_scoped_ipc_authorization_snapshot(\n                    &stream,\n                    postfix,\n                );\n                #[cfg(target_os = \"linux\")]",
            "let authorization = (); /* service_scoped_ipc_authorization_snapshot(&stream, postfix) delayed */\n                #[cfg(target_os = \"linux\")]",
        ),
        Mutation(
            "macOS generic service proof discards the retained accepted identity",
            "src/ipc.rs",
            "Ok((authorization, true)) => Some(authorization),\n"
            "        Ok((_authorization, false)) => None,\n"
            "        Err(err) => {\n"
            "            log::error!(\"macOS _service IPC authorization task failed: {err}\");",
            "Ok((_authorization, true)) => None, /* retained identity discarded */\n"
            "        Ok((_authorization, false)) => None,\n"
            "        Err(err) => {\n"
            "            log::error!(\"macOS _service IPC authorization task failed: {err}\");",
        ),
        Mutation(
            "macOS generic service dispatch drops the retained identity",
            "src/ipc.rs",
            "handle_service_ipc_transaction(stream, &postfix, authorization).await;",
            "handle_service_ipc_transaction(stream, &postfix, ()).await; /* retained identity dropped */",
        ),
        Mutation(
            "macOS password-right requester bypasses its fixed service endpoint",
            "src/ipc/auth.rs",
            "if authorization.postfix != crate::POSTFIX_SERVICE {\n        bail!(\"macOS service-owned password-right requester used the wrong endpoint\");",
            "if false && authorization.postfix != crate::POSTFIX_SERVICE {\n        bail!(\"macOS service-owned password-right requester used the wrong endpoint\");",
        ),
        Mutation(
            "macOS password-right requester bypasses snapshot UID authority",
            "src/ipc/auth.rs",
            "if !authorization.uid_authorized {\n        bail!(\n            \"macOS service-owned password-right requester is not root or the active console user\"",
            "if false && !authorization.uid_authorized {\n        bail!(\n            \"macOS service-owned password-right requester is not root or the active console user\"",
        ),
        Mutation(
            "macOS password-right requester bypasses the installed-app proof",
            "src/ipc/auth.rs",
            "if !macos_service_owned_password_requester_identity_is_live(&identity) {\n        bail!(\"macOS service-owned password-right requester is not the live trusted installed app\");",
            "if false && !macos_service_owned_password_requester_identity_is_live(&identity) {\n        bail!(\"macOS service-owned password-right requester is not the live trusted installed app\");",
        ),
        Mutation(
            "macOS password-right requester fabricates argv",
            "src/ipc/auth.rs",
            "let requester_argv = macos_process_cmdline_args(identity.pid)?;",
            "let requester_argv = vec![String::new()]; /* live argv bypassed */",
        ),
        Mutation(
            "macOS password-right requester bypasses its finite role",
            "src/ipc/auth.rs",
            "if !macos_service_owned_password_client_argv_is_expected(&requester_argv) {",
            "if false && !macos_service_owned_password_client_argv_is_expected(&requester_argv) {",
        ),
        Mutation(
            "macOS password-right requester skips post-argv generation proof",
            "src/ipc/auth.rs",
            "if !macos_service_owned_password_requester_generation_is_live(&identity) {\n        bail!(\"macOS service-owned password-right requester changed while its role was inspected\");",
            "if false && !macos_service_owned_password_requester_generation_is_live(&identity) {\n        bail!(\"macOS service-owned password-right requester changed while its role was inspected\");",
        ),
        Mutation(
            "macOS password-right requester retains truncated argv",
            "src/ipc/auth.rs",
            "argv: requester_argv,",
            "argv: requester_argv.into_iter().take(1).collect(),",
        ),
        Mutation(
            "macOS password-right post-request replay bypasses endpoint authority",
            "src/ipc/auth.rs",
            "if authorization.postfix != crate::POSTFIX_SERVICE || !authorization.uid_authorized {",
            "if false && authorization.postfix != crate::POSTFIX_SERVICE || !authorization.uid_authorized {",
        ),
        Mutation(
            "macOS password-right post-request replay bypasses fresh UID authority",
            "src/ipc/auth.rs",
            "if authorization.postfix != crate::POSTFIX_SERVICE || !authorization.uid_authorized {",
            "if authorization.postfix != crate::POSTFIX_SERVICE || false && !authorization.uid_authorized {",
        ),
        Mutation(
            "macOS password-right post-request replay loses PID equality",
            "src/ipc/auth.rs",
            "&& post_request_identity.pid == requester.identity.pid",
            "&& true /* post-request PID equality bypassed */",
        ),
        Mutation(
            "macOS password-right post-request replay loses full audit-token equality",
            "src/ipc/auth.rs",
            "&& post_request_identity.audit_token == requester.identity.audit_token",
            "&& true /* post-request audit-token equality bypassed */",
        ),
        Mutation(
            "macOS password-right readiness uses generic authorization",
            "src/ipc.rs",
            "let requester = authenticate_macos_service_owned_password_right_requester(authorization)?;",
            "let requester = authenticate_macos_service_owned_password_requester(authorization)?; /* wrong endpoint */",
        ),
        Mutation(
            "macOS password-right readiness omits its post-request socket snapshot",
            "src/ipc.rs",
            "ipc_auth::service_scoped_ipc_authorization_snapshot(stream, crate::POSTFIX_SERVICE);",
            "authorization.clone(); /* post-request socket snapshot omitted */",
        ),
        Mutation(
            "macOS password-right admission becomes cloneable",
            "src/ipc.rs",
            "struct MacosServiceOwnedPasswordRightAdmission {",
            "#[derive(Clone)]\nstruct MacosServiceOwnedPasswordRightAdmission {",
        ),
        Mutation(
            "macOS password-right admission drops exact requester ownership",
            "src/ipc.rs",
            "struct MacosServiceOwnedPasswordRightAdmission {\n    requester: MacosServiceOwnedPasswordRequester,\n}",
            "struct MacosServiceOwnedPasswordRightAdmission {\n    requester_authorized: bool,\n}",
        ),
        Mutation(
            "macOS password-right admission grant borrows reusable requester authority",
            "src/ipc.rs",
            "fn grant_macos_service_owned_password_right_admission(\n    requester: MacosServiceOwnedPasswordRequester,",
            "fn grant_macos_service_owned_password_right_admission(\n    requester: &MacosServiceOwnedPasswordRequester,",
        ),
        Mutation(
            "macOS password-right admission bypasses post-request identity equality",
            "src/ipc.rs",
            "if !macos_service_owned_password_right_requester_matches_post_request_authorization(\n        &requester,",
            "if false && !macos_service_owned_password_right_requester_matches_post_request_authorization(\n        &requester,",
        ),
        Mutation(
            "macOS password-right admission action is reusable",
            "src/ipc.rs",
            "fn ensure_ready(self) -> bool {",
            "fn ensure_ready(&self) -> bool {",
        ),
        Mutation(
            "macOS password-right admission action bypasses final requester replay",
            "src/ipc.rs",
            "macos_service_owned_password_requester_is_live(&self.requester)\n            && crate::platform::ensure_service_owned_unattended_password_authorization_right()",
            "true\n            && crate::platform::ensure_service_owned_unattended_password_authorization_right()",
        ),
        Mutation(
            "macOS password-right admission action disjoins the policy write",
            "src/ipc.rs",
            "&& crate::platform::ensure_service_owned_unattended_password_authorization_right()\n    }\n}",
            "|| crate::platform::ensure_service_owned_unattended_password_authorization_right()\n    }\n}",
        ),
        Mutation(
            "macOS password-right readiness bypasses typed admission",
            "src/ipc.rs",
            "let Some(admission) = grant_macos_service_owned_password_right_admission(",
            "let Some(admission) = grant_macos_service_owned_password_right_admission_disabled(",
        ),
        Mutation(
            "macOS password-right readiness bypasses capability-owned final action",
            "src/ipc.rs",
            "Ok(admission.ensure_ready())",
            "Ok(crate::platform::ensure_service_owned_unattended_password_authorization_right())",
        ),
        Mutation(
            "macOS password-right handler drops retained requester authority",
            "src/ipc.rs",
            "macos_service_owned_password_authorization_right_is_ready(\n                _authorization,\n                stream,",
            "macos_service_owned_password_authorization_right_is_ready(\n                (), /* retained authority dropped */\n                stream,",
        ),
        Mutation(
            "Linux replay no longer binds the password digest",
            "src/ipc.rs",
            "if entry.kind != kind || entry.fingerprint != fingerprint || entry.caller != *caller {",
            "if entry.kind != kind || entry.caller != *caller { /* entry.fingerprint != fingerprint */",
        ),
        Mutation(
            "interactive authority loses final live identity proof",
            "src/ipc.rs",
            "linux_service_owned_password_requester_is_live(identity)",
            "linux_service_owned_password_requester_was_live(identity) /* linux_service_owned_password_requester_is_live */",
        ),
        Mutation(
            "polkit denial is accepted as authorization",
            "src/ipc.rs",
            "Ok(Some(status)) if status.success() => return true,",
            "Ok(Some(status)) if !status.success() => return true,",
        ),
        Mutation(
            "password recovery exported bound changes",
            "src/ipc.rs",
            "pub const PASSWORD_MUTATION_RECOVERY_TIMEOUT_SECONDS: u64 = 600;",
            "pub const PASSWORD_MUTATION_RECOVERY_TIMEOUT_SECONDS: u64 = 0;",
        ),
        Mutation(
            "password recovery duration bypasses its exported bound",
            "src/ipc.rs",
            "const PASSWORD_MUTATION_RECOVERY_TIMEOUT: std::time::Duration =\n    std::time::Duration::from_secs(PASSWORD_MUTATION_RECOVERY_TIMEOUT_SECONDS);",
            "const PASSWORD_MUTATION_RECOVERY_TIMEOUT: std::time::Duration =\n    std::time::Duration::from_secs(600);",
        ),
        Mutation(
            "password recovery loses its overall deadline",
            "src/ipc.rs",
            "let mut recovery_required = service_owned;\n    let recovery_deadline = tokio::time::Instant::now() + PASSWORD_MUTATION_RECOVERY_TIMEOUT;",
            "let mut recovery_required = service_owned;\n    let recovery_deadline = tokio::time::Instant::now() + std::time::Duration::MAX;",
        ),
        Mutation(
            "authoritative rejection becomes nonterminal",
            "src/ipc.rs",
            "PasswordMutationStatus::Complete(IpcMutationResult::Rejected) => {\n            WindowsCredentialClientDecision::Rejected\n        }",
            "PasswordMutationStatus::Complete(IpcMutationResult::Rejected) => {\n            WindowsCredentialClientDecision::Continue\n        }",
        ),
        Mutation(
            "installed Windows credential ownership depends on elevation",
            "src/ipc.rs",
            "#[cfg(target_os = \"windows\")]\npub fn can_request_service_owned_unattended_password_change() -> bool {\n    crate::platform::is_installed()\n}",
            "#[cfg(target_os = \"windows\")]\npub fn can_request_service_owned_unattended_password_change() -> bool {\n    crate::platform::is_installed() && crate::platform::is_root()\n}",
        ),
        Mutation(
            "Windows ledger evicts a live credential operation",
            "src/ipc.rs",
            "WindowsCredentialOperationState::Active => None,",
            "WindowsCredentialOperationState::Active => { return true; } /* None */",
        ),
        Mutation(
            "final live identity proof uses a stale session authority",
            "src/ipc/auth.rs",
            "if !is_allowed_service_peer_uid(identity.uid, active_uid_fresh()) {",
            "if !is_allowed_service_peer_uid(identity.uid, None) { /* active_uid_fresh() */",
        ),
        Mutation(
            "service IPC parent becomes attacker-writable",
            "src/ipc/fs.rs",
            "        0o0711\n",
            "        0o0777\n",
        ),
        Mutation(
            "service password lane uses the ordinary service capacity",
            "src/ipc.rs",
            "Semaphore::new(SERVICE_PASSWORD_IPC_TRANSACTION_BUDGET)",
            "Semaphore::new(SERVICE_IPC_TRANSACTION_BUDGET)",
        ),
        Mutation(
            "credential replica accepts a noncanonical PRS length",
            "src/ipc/password.rs",
            "!matches!(self.password_len, 0 | CREDENTIAL_REPLICA_BYTES)",
            "self.password_len > CREDENTIAL_REPLICA_BYTES /* exact canonical lengths */",
        ),
        Mutation(
            "credential replica lane uses the ordinary service capacity",
            "src/ipc.rs",
            "Semaphore::new(SERVICE_CREDENTIAL_IPC_TRANSACTION_BUDGET)",
            "Semaphore::new(SERVICE_IPC_TRANSACTION_BUDGET)",
        ),
        Mutation(
            "service-owned child persists the machine credential",
            "src/ipc.rs",
            "Config::set_permanent_password_prs_for_runtime(self.value.as_str())",
            "Config::set_permanent_password_persisted(self.value.as_str())",
        ),
        Mutation(
            "post-persistence child rejection no longer fail-stops the generation",
            "src/ipc.rs",
            "Ok(result) => {\n            crate::server::request_graceful_shutdown_after_authority_failure();\n            bail!(",
            "Ok(result) => {\n            crate::server::request_graceful_shutdown();\n            bail!(",
        ),
        Mutation(
            "service child starts without a root credential snapshot",
            "src/server.rs",
            "crate::ipc::refresh_linux_service_owned_permanent_password_snapshot(10_000).await",
            "crate::ipc::refresh_linux_service_owned_permanent_password_snapshot_for_later(10_000).await",
        ),
        Mutation(
            "final Linux child image remains dumpable",
            "src/platform/linux.rs",
            "make_service_owned_process_nondumpable()?;",
            "/* make_service_owned_process_nondumpable()?; */",
        ),
        Mutation(
            "running service image loses close-on-exec",
            "src/platform/linux.rs",
            ".custom_flags(hbb_common::libc::O_CLOEXEC)\n        .open(\"/proc/self/exe\")",
            ".custom_flags(0)\n        .open(\"/proc/self/exe\")",
        ),
        Mutation(
            "installed service-child image loses close-on-exec",
            "src/platform/linux.rs",
            ".custom_flags(hbb_common::libc::O_CLOEXEC | hbb_common::libc::O_NOFOLLOW)",
            ".custom_flags(hbb_common::libc::O_NOFOLLOW)",
        ),
        Mutation(
            "active-user child executable becomes same-uid readable across exec",
            "src/platform/linux.rs",
            "child_metadata.mode() & 0o7777 != 0o711",
            "child_metadata.mode() & 0o7777 != 0o755",
        ),
        Mutation(
            "service-child package image is no longer byte-bound to the running service",
            "src/platform/linux.rs",
            "files_have_exact_contents(&mut running, &mut child, running_metadata.len())",
            "files_have_exact_contents_unchecked(&mut running, &mut child, running_metadata.len())",
        ),
        Mutation(
            "active-user child accepts a dumpable-exec sysctl policy",
            "src/platform/linux.rs",
            "if suid_dumpable.trim() != \"0\" {",
            "if suid_dumpable.trim() == \"0\" {",
        ),
        Mutation(
            "credential replica accepts an indirect or stale-generation child",
            "src/ipc/auth.rs",
            "if launch_parent != expected_parent\n        || actual_parent != expected_parent\n        || !crate::platform::linux::service_runtime_generation_matches(&generation)\n    {\n        bail!(\n            \"service-owned password replica owner mismatch:",
            "if launch_parent != expected_parent {\n        /* actual_parent and service_runtime_generation_matches were bypassed */\n        bail!(\n            \"service-owned password replica owner mismatch:",
        ),
        Mutation(
            "ordinary service-password client accepts a non-root peer",
            "src/ipc/auth.rs",
            "    if peer_uid != 0 {\n        bail!(\n            \"Linux root service uid mismatch",
            "    if false && peer_uid != 0 {\n        bail!(\n            \"Linux root service uid mismatch",
        ),
        Mutation(
            "ordinary service-password client regains a root procfs dependency",
            "src/ipc/auth.rs",
            "    Ok(peer_pid)\n}",
            "    linux_proc_cmdline_args(peer_pid)?;\n    Ok(peer_pid)\n}",
        ),
        Mutation(
            "release builds enable the unsupervised recovery fixture",
            "src/platform/linux.rs",
            "pub(crate) fn service_child_is_unsupervised_recovery_fixture() -> bool {\n    #[cfg(debug_assertions)]\n    {\n        std::env::var_os(SERVICE_CHILD_UNSUPERVISED_RECOVERY_FIXTURE_ENV).as_deref()\n            == Some(std::ffi::OsStr::new(\"1\"))\n    }\n    #[cfg(not(debug_assertions))]\n    {\n        false\n    }\n}",
            "pub(crate) fn service_child_is_unsupervised_recovery_fixture() -> bool {\n    true\n}",
        ),
        Mutation(
            "shutdown clears replay authority before transaction drain",
            "src/ipc.rs",
            "    linux_password_admissions().begin_shutdown();",
            "    /* linux_password_admissions().begin_shutdown(); */",
        ),
        Mutation(
            "CLI accepts a positional password",
            "src/core_main.rs",
            'Some("--password") if args.len() == 1 => Ok(PasswordCliInput::Terminal),',
            'Some("--password") if !args.is_empty() => Ok(PasswordCliInput::Terminal),',
        ),
        Mutation(
            "UI bypasses the sensitive wrapper/API",
            "src/ui_interface.rs",
            "match crate::ipc::set_permanent_password_sensitive(password) {",
            "match crate::ipc::set_permanent_password(password.as_str().to_owned()) {",
        ),
    )
    for mutation in mutations:
        expect_rejection(sources, mutation)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Structurally verify Linux raw sensitive-password IPC and mutation finality."
    )
    parser.add_argument("--repo", default=".", help="repository root")
    parser.add_argument("--self-test", action="store_true", help="run adversarial source mutations")
    args = parser.parse_args()
    try:
        sources = load_sources(Path(args.repo))
        if args.self_test:
            self_test(sources)
        else:
            validate_sources(sources)
    except (OSError, UnicodeError, VerificationError) as exc:
        print(f"verify-linux-service-password-ipc: FAIL: {exc}", file=sys.stderr)
        return 1
    print("verify-linux-service-password-ipc: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
