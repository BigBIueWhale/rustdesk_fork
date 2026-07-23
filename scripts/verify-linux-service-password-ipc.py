#!/usr/bin/env python3
"""Static structural verification for Linux sensitive-password IPC.

This is deliberately narrower than a Rust parser and stronger than text grep.  It lexes executable
Rust tokens (discarding comments and literal contents), extracts named item/function bodies, and
proves the security-relevant call graph and ordering implemented across the password codec, IPC
listeners, Linux peer authentication, mutation coordinators, and desktop callers.
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
        ("cfg", "!", "(", "target_os", "=", '"linux"', ")", "&&", "postfix", "==", '"_service_credential"'),
        "Linux credential replica service endpoint classification",
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
            (("postfix", "==", "password", "::", "USER_PASSWORD_IPC_POSTFIX"), "user endpoint route"),
            (("Config", "::", "ipc_path_for_uid"), "UID-bound user endpoint path"),
            (("timeout", "(", "password", "::", "remaining_millis", "(", "deadline", ")", "?", ",", "Endpoint", "::", "connect"), "raw bounded connect"),
            (("match", "postfix", "{"), "finite endpoint dispatch"),
            (("USER_PASSWORD_IPC_POSTFIX", "=>"), "user endpoint proof"),
            (("authenticate_linux_service_owned_password_replica_server", "(", "&", "stream", ",", "password", "::", "USER_PASSWORD_IPC_POSTFIX", OPTIONAL_COMMA, ")"), "service-owned replica identity/argv proof"),
            (("identity", ".", "uid", "(", ")", "!=", "expected_uid"), "service-owned replica UID binding"),
            (("ensure_user_owned_password_server_is_trusted", "(", "&", "stream", ",", "expected_uid", ")"), "user-owned server UID/executable/argv proof"),
            (("SERVICE_PASSWORD_IPC_POSTFIX", "=>"), "service endpoint proof"),
            (("ensure_linux_root_service_stream", "(", "&", "stream", ",", "postfix", ")"), "service server kernel uid/PID proof"),
            (("_", "=>", "bail", "!", "(", '"unsupported sensitive Unix IPC endpoint"'), "unknown endpoint rejection"),
            (("remaining_millis", "(", "deadline", ")"), "post-proof deadline check"),
        )
    )
    connect_raw.forbid(("ConnectionTmpl", "::"), "generic framed connection construction")
    connect_raw.forbid(("send_json",), "JSON transport")

    main_prepare = ipc.function("prepare_main_ipc")
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
            (("try_acquire_sensitive_main_ipc_transaction_slot", "(", "authority", ")"), "raw bounded admission"),
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
            (("authorize_service_scoped_ipc_authorization_snapshot"), "fresh UID/executable gate"),
            (("service_scoped_ipc_authorization_snapshot_from_stream", "(", "&", "stream"), "socket authorization snapshot supplied to gate"),
            (("peer_process_identity_from_stream", "(", "&", "stream"), "full caller identity capture"),
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
            (("credential_incoming", ".", "as_mut", "(", ")"), "raw credential accept lane"),
            (("try_acquire_service_credential_ipc_transaction_slot", "(", ")"), "credential work admission"),
            (("authenticate_linux_service_owned_password_replica_server", "(", "&", "stream", ",", "password", "::", "SERVICE_CREDENTIAL_IPC_POSTFIX", OPTIONAL_COMMA, ")"), "exact child proof before request read"),
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
    main_authority.require_order(
        (
            (("MainIpcAuthority", "::", "for_current_process", "(", ")", "==", "MainIpcAuthority", "::", "ServiceOwned"), "service-owned process selection"),
            (("authenticate_linux_service_owned_password_parent", "(", "stream", ",", "password", "::", "USER_PASSWORD_IPC_POSTFIX", OPTIONAL_COMMA, ")"), "kernel root peer and direct-parent proof"),
            (("Ok", "(", "_", ")", "=>", "Some", "(", "PasswordMutationKind", "::", "ServiceOwned", ")"), "service-owned authority result"),
            (("ensure_user_owned_password_client_is_trusted", "(", "stream", ",", "password", "::", "USER_PASSWORD_IPC_POSTFIX", ")"), "user client UID/executable proof"),
            (("Ok", "(", "(", ")", ")", "=>", "Some", "(", "PasswordMutationKind", "::", "UserOwned", ")"), "user-owned authority result"),
        )
    )


def verify_linux_identity_and_authority(rust: Mapping[str, RustSource]) -> None:
    auth = rust["src/ipc/auth.rs"]
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
            (("peer_pid_from_fd", "(", "fd", ")"), "socket peer PID"),
            (("peer_uid_from_fd", "(", "fd", ")"), "socket peer UID"),
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
            (("first_arg", ":", "args", ".", "get", "(", "1", ")"), "process role capture"),
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
            (("live", "==", "*", "identity"), "PID/UID/start-time/role equality"),
            (("linux_process_has_ancestor", "(", "identity", ".", "pid", ",", "identity", ".", "cm_launch_parent", ")"), "live launch ancestry"),
        )
    )

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
    parent.require_order(
        (
            (("peer_uid_from_fd", "(", "fd", ")"), "kernel parent UID"),
            (("peer_uid", "!=", "0"), "root parent requirement"),
            (("peer_pid_from_fd", "(", "fd", ")"), "kernel parent PID"),
            (("SERVICE_OWNED_SERVER_LAUNCH_PARENT_ENV",), "launch-parent authority"),
            (("linux_proc_parent_pid", "(", "std", "::", "process", "::", "id", "(", ")", ")"), "actual child parent PID"),
            (("peer_pid", "!=", "expected_parent"), "exact parent PID"),
            (("actual_parent", "!=", "expected_parent"), "direct parent binding"),
        )
    )
    parent.forbid(
        ("peer_process_identity_from_stream",),
        "direct child proof cannot depend on ptrace-gated root procfs",
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
    authority = ipc.function("linux_peer_is_authorized_for_service_owned_password_change")
    proof = authority.require(("linux_pkcheck_authorizes_service_owned_password_change", "(", "subject", ",", "shutdown", ")"), "polkit proof", unique=True)
    live = authority.require(
        (
            "peer_process_identity_is_live",
            "(",
            "identity",
            ",",
            "password",
            "::",
            "SERVICE_PASSWORD_IPC_POSTFIX",
            OPTIONAL_COMMA,
            ")",
        ),
        "final full live identity proof",
        unique=True,
    )
    if live <= proof:
        raise VerificationError(
            f"{authority.label}: final live identity proof must follow successful interactive authority"
        )
    braced_conjunctive_gate = (
        "Ok", "(", "authorized", ")", "=>", "{", "authorized", "&&",
        "peer_process_identity_is_live", "(", "identity", ",",
        "password", "::", "SERVICE_PASSWORD_IPC_POSTFIX", OPTIONAL_COMMA, ")", "}",
    )
    direct_gate = (
        "Ok", "(", "authorized", ")", "=>", "authorized", "&&",
        "peer_process_identity_is_live", "(", "identity", ",",
        "password", "::", "SERVICE_PASSWORD_IPC_POSTFIX", OPTIONAL_COMMA, ")",
    )
    if not (
        authority.positions(braced_conjunctive_gate)
        or authority.positions(direct_gate)
    ):
        raise VerificationError(
            f"{authority.label}: successful polkit and final live identity must jointly gate authority"
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
    begin_mutation = ipc.function("begin_password_mutation")
    begin_mutation.require_order(
        (
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
            (("service_owned_runtime_replica", "=", "kind", "==", "PasswordMutationKind", "::", "ServiceOwned", "&&", "crate", "::", "common", "::", "is_service_owned_server_process", "(", ")"), "exact Linux child runtime selection"),
            (("if", "service_owned_runtime_replica", "{"), "runtime replica branch"),
            (("Config", "::", "set_permanent_password_prs_for_runtime", "(", "value", ".", "as_str", "(", ")", ")", ".", "map", "(", "|", "_", "|", "true", ")"), "nonpersistent PRS replica application"),
            (("else", "{", "Config", "::", "set_permanent_password_persisted", "(", "value", ".", "as_str", "(", ")", ")"), "durable non-replica authority"),
            (("completion", ".", "result", "=", "result"), "RAII final result update"),
        )
    )

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
    finish_auth = ipc.method(("impl", "LinuxPasswordAdmissionCoordinator"), "finish_authorization", "impl LinuxPasswordAdmissionCoordinator")
    finish_auth.require_order(
        (
            (("entry", ".", "caller", "!=", "*", "caller"), "authorization caller consistency"),
            (("entry", ".", "state", "!=", "LinuxPasswordAdmissionState", "::", "Authorizing"), "authorizing-only completion"),
            (("if", "admitted", "{"), "successful authorization branch"),
            (("LinuxPasswordAdmissionState", "::", "Committing"), "admitted commit transition"),
            (("else", "{", "ledger", ".", "entries", ".", "remove", "(", "operation_id", ")"), "denial without durable capacity consumption"),
        )
    )
    finish_auth.forbid(
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
    main_handler = ipc.function("handle_sensitive_main_ipc_transaction")
    main_handler.require_order(
        (
            (("Instant", "::", "now", "(", ")", "+", "std", "::", "time", "::", "Duration", "::", "from_millis", "(", "MAIN_IPC_TRANSACTION_TIMEOUT_MS", ")"), "one absolute transaction deadline"),
            (("receive_request_unix", "(", "&", "mut", "stream", ",", "password", "::", "SensitivePayloadKind", "::", "Password", ",", "deadline", OPTIONAL_COMMA, ")"), "raw bounded request"),
            (("operation_id", "=", "request", ".", "operation_id", "(", ")"), "wire operation ID"),
            (("request", ".", "into_password", "(", ")"), "owned secret extraction"),
            (("begin_password_mutation", "(", "operation_id", ".", "to_string", "(", ")", ",", "value", ",", "kind", ",", "authority_allowed", ")"), "operation/kind/value admission"),
            (("send_status_unix", "(", "&", "mut", "stream", ",", "operation_id", ",", "status", ",", "deadline", ")"), "operation-bound begin acknowledgement"),
            (("worker", ".", "await"), "owned commit completion"),
        )
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
            (("authenticate_linux_service_owned_password_replica_server", "(", "&", "stream", ",", "password", "::", "SERVICE_CREDENTIAL_IPC_POSTFIX", OPTIONAL_COMMA, ")"), "post-read exact-child reauthentication"),
            (("refreshed", "!=", "identity"), "accepted-socket identity continuity"),
            (("linux_service_owned_runtime_prs_replica", "(", ")"), "root-owned PRS snapshot"),
            (("send_credential_replica_unix", "(", "&", "mut", "stream", ",", "operation_id", ",", "&", "replica", ",", "deadline"), "operation-bound PRS response"),
        )
    )

    operation = ipc.function("execute_linux_service_owned_password_operation")
    operation.require_order(
        (
            (("kind", "=", "PasswordMutationKind", "::", "ServiceOwned"), "fixed service-owned kind"),
            (("coordinator", ".", "begin", "(", "operation_id", ",", "kind", ",", "value", ",", "caller", ")"), "bound admission/replay"),
            (("Authorize", "=>", "{"), "new authority branch"),
            (("authorize", "(", ")", ".", "await"), "interactive authority"),
            (("finish_authorization", "(", "operation_id", ",", "caller", ",", "admitted", ")"), "authority finalization"),
            (("Wait", "=>", "{"), "in-flight replay wait"),
            (("shutdown", ".", "cancelled", "(", ")"), "shutdown-aware wait"),
            (("Recover", "=>", "{"), "recovery ownership"),
            (("Complete", "(", "result", ")", "=>", "return", "Ok", "(", "result", ")"), "terminal replay"),
            (("commit", "(", ")", ".", "await"), "commit after authority/admission"),
            (("release_failed_commit", "(", "operation_id", ",", "caller", ")"), "transport failure recovery"),
            (("coordinator", ".", "complete", "(", "operation_id", ",", "caller", ",", "result", ")"), "terminal result recording"),
        )
    )
    commit = ipc.function("commit_service_owned_unattended_password_change")
    commit.require_order(
        (
            (("durable_value", "=", "value", ".", "clone", "(", ")"), "root-owned plaintext copy"),
            (("spawn_blocking", "(", "move", "||", "{", "Config", "::", "set_permanent_password_persisted", "(", "durable_value", ".", "as_str", "(", ")", ")"), "root durable credential write"),
            (("if", "!", "durable_result", "{", "return", "Ok", "(", "IpcMutationResult", "::", "Rejected", ")"), "no-replica result before durable acceptance"),
            (("linux_service_owned_runtime_prs_replica", "(", ")"), "root PRS extraction after persistence"),
            (("request_graceful_shutdown_after_authority_failure", "(", ")"), "fail-stop on post-persistence PRS failure"),
            (("complete_main_password_mutation", "(", "operation_id", ",", "&", "replica", ",", "true", ",", "ms_timeout", ")"), "same-operation PRS child convergence"),
            (("Ok", "(", "IpcMutationResult", "::", "Applied", ")", "=>", "Ok", "(", "IpcMutationResult", "::", "Applied", ")"), "exact applied convergence"),
            (("request_graceful_shutdown_after_authority_failure", "(", ")"), "fail-stop on non-applied child result"),
            (("request_graceful_shutdown_after_authority_failure", "(", ")"), "fail-stop on child transport/finality failure"),
        )
    )
    commit.forbid(
        ("complete_main_password_mutation", "(", "operation_id", ",", "&", "value"),
        "plaintext forwarding to the service-owned child",
    )
    commit.forbid(("loop", "{"), "outer unbounded finality loop")
    commit.forbid(("sleep", "(", "0.1", ")", ".", "await"), "outer finality retry")
    commit.forbid(("Uuid", "::", "new_v4"), "operation ID regeneration during recovery")

    root_replica = ipc.function("linux_service_owned_runtime_prs_replica")
    root_replica.require_order(
        (
            (("Config", "::", "read_permanent_password_prs", "(", ")"), "root credential read"),
            (("Available", "(", "prs", ")", "=>", "{", "Ok", "(", "SensitivePassword", "::", "new", "(", "prs", ")", ")"), "available PRS replica"),
            (("PermanentPasswordPrsRead", "::", "Empty", "=>"), "explicit empty replica"),
            (("UndecryptableStorage", "=>"), "undecryptable storage branch"),
            (("bail", "!", "(", '"Linux root service credential storage is undecryptable"', ")"), "undecryptable fail closed"),
        )
    )

    refresh = ipc.function("refresh_linux_service_owned_permanent_password_snapshot")
    refresh.require_order(
        (
            (("is_service_owned_server_process", "(", ")"), "exact service-owned role"),
            (("service_child_is_unsupervised_recovery_fixture", "(", ")"), "debug fixture branch"),
            (("set_permanent_password_prs_for_runtime", "(", '""', ")"), "fixture explicit empty override"),
            (("Config", "::", "ipc_path_for_uid", "(", "0", ",", "password", "::", "SERVICE_CREDENTIAL_IPC_POSTFIX", ")"), "root credential socket path"),
            (("Endpoint", "::", "connect", "(", "path", ")"), "raw credential connection"),
            (("authenticate_linux_service_owned_password_parent", "(", "&", "stream", ",", "password", "::", "SERVICE_CREDENTIAL_IPC_POSTFIX", OPTIONAL_COMMA, ")"), "kernel root peer and exact direct parent proof"),
            (("send_credential_snapshot_request_unix", "(", "&", "mut", "stream", ",", "operation_id", ",", "deadline"), "operation-bound snapshot request"),
            (("receive_credential_replica_unix", "(", "&", "mut", "stream", ",", "operation_id", ",", "deadline"), "operation-bound snapshot response"),
            (("set_permanent_password_prs_for_runtime", "(", "replica", ".", "as_str", "(", ")", ")"), "nonpersistent runtime install"),
        )
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
    complete_main.require_order(
        (
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
            (("connect_service_owned_password_replica_stream", "(", "deadline", ")"), "authenticated raw child begin"),
            (("send_request_unix", "(", "&", "mut", "stream", ",", "operation_uuid", ",", "value", ",", "None", ",", "deadline", ")"), "same UUID/value raw begin"),
            (("receive_status_unix", "(", "&", "mut", "stream", ",", "operation_uuid", ",", "deadline", ")"), "same UUID status"),
            (("Err", "(", "password", "::", "UnixSensitivePasswordSendError", "::", "Uncertain", "(", "err", ")", ")", "=>", "{", "recovery_required", "=", "true"), "Unix uncertain-send finality transition"),
            (("query_only", "=", "matches", "!", "(", "response", ",", "PasswordMutationStatus", "::", "Prepared", "|", "PasswordMutationStatus", "::", "Pending", ")"), "begin acknowledgement query transition"),
        )
    )
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
            (("connect_sensitive_unix", "(", "deadline", ",", "password", "::", "SERVICE_PASSWORD_IPC_POSTFIX", ",", "false", ")"), "raw service endpoint"),
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
            (("open", "(", '"/proc/self/exe"', ")"), "running service image open"),
            (("running_metadata", ".", "mode", "(", ")", "&", "0o7777", "==", "0o711"), "execute-only manual image path"),
            (("running_metadata", ".", "mode", "(", ")", "&", "0o7777", "!=", "0o755"), "readable installed image mode"),
            (("canonicalize", "(", '"/proc/self/exe"', ")"), "fixed primary package path"),
            (("LINUX_INSTALLED_SERVICE_CHILD_EXECUTABLE",), "fixed service-child package path"),
            (("parent_metadata", ".", "mode", "(", ")", "&", "0o022", "!=", "0"), "non-writable service-child parent"),
            (("O_NOFOLLOW",), "no-follow service-child open"),
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
            (("matches", "=", "password", "==", "confirmation"), "confirmation comparison"),
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
            (("complete_main_password_mutation", "(", "operation_id", ",", "&", "v", ",", "false", ",", "ms_timeout", ")"), "raw user-owned begin/finality"),
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
    verify_mutation_coordinators(rust)
    verify_flow_finality_and_shutdown(rust)
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
    try:
        validate_sources(_mutate_once(sources, mutation))
    except VerificationError:
        return
    raise VerificationError(f"self-test accepted security regression: {mutation.label}")


def self_test(sources: Mapping[str, str]) -> None:
    validate_sources(sources)
    mutations = (
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
            "let Some(authority) = sensitive_main_ipc_authority(&stream) else { continue; };",
            "let authority = PasswordMutationKind::UserOwned; /* sensitive_main_ipc_authority(&stream) */",
        ),
        Mutation(
            "service listener reads identity without fresh session authorization",
            "src/ipc.rs",
            "if !ipc_auth::authorize_service_scoped_ipc_authorization_snapshot(",
            "if false && !ipc_auth::authorize_service_scoped_ipc_authorization_snapshot(",
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
            "peer_process_identity_is_live(identity, password::SERVICE_PASSWORD_IPC_POSTFIX)",
            "peer_process_identity_was_live(identity, password::SERVICE_PASSWORD_IPC_POSTFIX) /* peer_process_identity_is_live */",
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
            "final live identity proof no longer gates successful authority",
            "src/ipc.rs",
            "            authorized\n                && peer_process_identity_is_live(identity, password::SERVICE_PASSWORD_IPC_POSTFIX)",
            "            authorized\n                || peer_process_identity_is_live(identity, password::SERVICE_PASSWORD_IPC_POSTFIX) /* authorized && */",
        ),
        Mutation(
            "final live identity proof uses a stale session authority",
            "src/ipc/auth.rs",
            "is_allowed_service_peer_uid(identity.uid, active_uid_fresh())",
            "is_allowed_service_peer_uid(identity.uid, None) /* active_uid_fresh() */",
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
            "Config::set_permanent_password_prs_for_runtime(value.as_str()).map(|_| true)",
            "Config::set_permanent_password_persisted(value.as_str()).map(|_| true)",
        ),
        Mutation(
            "root forwards plaintext instead of the canonical PRS replica",
            "src/ipc.rs",
            "complete_main_password_mutation(operation_id, &replica, true, ms_timeout)",
            "complete_main_password_mutation(operation_id, &value, true, ms_timeout)",
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
            "    if peer_uid != 0 {\n",
            "    if false && peer_uid != 0 {\n",
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
