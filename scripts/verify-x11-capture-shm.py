#!/usr/bin/env python3
"""Verify X11 capture shared-memory authority and GetImage frame finality."""

from __future__ import annotations

import argparse
import ast
from dataclasses import dataclass
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
        "capturer": (repo / "libs/scrap/src/x11/capturer.rs").read_text(
            encoding="utf-8"
        ),
        "ffi": (repo / "libs/scrap/src/x11/ffi.rs").read_text(encoding="utf-8"),
        "requirements": (repo / "requirements.html").read_text(encoding="utf-8"),
        "hardening": (repo / "HARDENING_STATUS.md").read_text(encoding="utf-8"),
        "verify": (repo / "scripts/verify.sh").read_text(encoding="utf-8"),
        "workspace": (repo / "scripts/verify-verifier-workspace.py").read_text(
            encoding="utf-8"
        ),
    }


def validate(sources: Dict[str, str]) -> None:
    capturer = sources["capturer"]
    ffi = sources["ffi"]

    require(
        capturer,
        "const SHM_OWNER_READ_WRITE: libc::c_int = 0o600;",
        "exact owner-only shared-memory mode",
    )
    create = extract_rust_item(
        capturer, "    fn create(size: usize) -> io::Result<Self>", "shared-memory creation"
    )
    require_order(
        create,
        (
            "if size == 0",
            "libc::shmget(",
            "libc::IPC_PRIVATE",
            "libc::IPC_CREAT | SHM_OWNER_READ_WRITE",
            "if id == -1",
            "let mut memory = Self",
            "libc::shmat(id, ptr::null(), libc::SHM_RDONLY)",
            "if buffer as isize == -1",
            "memory.buffer = buffer.cast();",
        ),
        "owner-only local read attachment with RAII established before shmat",
    )
    for needle in ("libc::IPC_CREAT | 0o777", "libc::IPC_CREAT | 0o666"):
        forbid(capturer, needle, "permissive X11 capture shared-memory mode")

    mark = extract_rust_item(
        capturer,
        "    fn mark_for_removal(&mut self) -> io::Result<()>",
        "deletion-pending transition",
    )
    require_order(
        mark,
        (
            "if self.removal_pending",
            "libc::shmctl(self.id, libc::IPC_RMID, ptr::null_mut())",
            "self.removal_pending = true;",
        ),
        "checked deletion-pending transition",
    )

    memory_drop = extract_rust_item(
        capturer, "impl Drop for SharedMemory", "shared-memory RAII cleanup"
    )
    for needle, label in (
        ("libc::shmdt(self.buffer.cast())", "local detach"),
        ("!self.removal_pending", "pre-RMID cleanup condition"),
        (
            "libc::shmctl(self.id, libc::IPC_RMID, ptr::null_mut())",
            "segment removal",
        ),
        ("failed to detach X11 capture shared memory", "detach failure visibility"),
        ("failed to remove X11 capture shared memory", "removal failure visibility"),
    ):
        require(memory_drop, needle, label)

    request_check = extract_rust_item(
        capturer, "fn check_xcb_request(", "checked XCB request completion"
    )
    require_order(
        request_check,
        (
            "xcb_request_check(server, cookie)",
            "if !error.is_null()",
            "libc::free(error.cast())",
            "xcb_connection_has_error(server)",
        ),
        "XCB protocol and connection error handling",
    )

    constructor = extract_rust_item(
        capturer,
        "    pub fn new(display: Display) -> io::Result<Capturer>",
        "X11 capturer construction",
    )
    require_order(
        constructor,
        (
            ".checked_mul(rect.h as usize)",
            ".and_then(|pixels| pixels.checked_mul(pixel_width))",
            "SharedMemory::create(size)?",
            "xcb_shm_attach_checked(",
            'check_xcb_request(server, attach, "MIT-SHM attach")?',
            "memory.mark_for_removal()",
        ),
        "checked size, X-server attach, then immediate deletion-pending order",
    )
    for needle, label in (
        ("xcb_shm_detach_checked(server, xcbid)", "failed-RMID X-server detach"),
        (
            'check_xcb_request(server, detach, "MIT-SHM cleanup detach")',
            "checked failed-RMID detach",
        ),
    ):
        require(constructor, needle, label)
    forbid(capturer + ffi, "xcb_shm_attach(", "unchecked XCB shared-memory attach")

    capturer_drop = extract_rust_item(
        capturer, "impl Drop for Capturer", "capturer X-server detach"
    )
    require_order(
        capturer_drop,
        (
            "xcb_shm_detach_checked(server, self.xcbid)",
            'check_xcb_request(server, detach, "MIT-SHM drop detach")',
            "failed to detach X11 capture shared memory from XCB",
        ),
        "checked and visible drop-time X-server detach",
    )
    forbid(capturer + ffi, "xcb_shm_detach(", "unchecked XCB shared-memory detach")

    for needle, label in (
        ("pub fn xcb_shm_attach_checked(", "checked XCB attach binding"),
        ("pub fn xcb_request_check(", "XCB request-check binding"),
        ("pub fn xcb_shm_detach_checked(", "checked XCB detach binding"),
    ):
        require(ffi, needle, label)

    get_image_result = extract_rust_item(
        capturer, "fn check_get_image_result(", "MIT-SHM GetImage result classifier"
    )
    require_order(
        get_image_result,
        (
            "if let Some((error_code, major_code, minor_code, resource_id)) = protocol_error",
            "if connection_error != 0",
            "let reply_size = reply_size.ok_or_else",
            "if reply_size != expected_size",
        ),
        "protocol, connection, reply-presence, and exact-size result order",
    )
    for needle, label in (
        ("io::ErrorKind::ConnectionAborted", "connection failure classification"),
        ("io::ErrorKind::InvalidData", "reply-size failure classification"),
        ("X server returned no MIT-SHM GetImage reply", "missing-reply visibility"),
    ):
        require(get_image_result, needle, label)

    get_image = extract_rust_item(
        capturer,
        "    fn get_image(&self) -> io::Result<()>",
        "checked MIT-SHM GetImage transaction",
    )
    require_order(
        get_image,
        (
            "let mut error = ptr::null_mut();",
            "xcb_shm_get_image(",
            "xcb_shm_get_image_reply(server, request, &mut error)",
            "let reply_size = if response.is_null()",
            "let protocol_error = if error.is_null()",
            "libc::free(response.cast())",
            "libc::free(error.cast())",
            "xcb_connection_has_error(server)",
            "check_get_image_result(reply_size, protocol_error, connection_error, self.size)",
        ),
        "checked request/reply ownership and final result validation",
    )
    forbid(capturer + ffi, "xcb_shm_get_image_unchecked(", "unchecked MIT-SHM GetImage")
    for needle, label in (
        ("pub fn xcb_shm_get_image(", "checked MIT-SHM GetImage binding"),
        ("pub fn xcb_shm_get_image_reply(", "MIT-SHM GetImage reply binding"),
    ):
        require(ffi, needle, label)

    frame = extract_rust_item(
        capturer,
        "    pub fn frame<'b>(&'b mut self) -> std::io::Result<&'b [u8]>",
        "X11 frame publication",
    )
    require_order(
        frame,
        (
            "self.get_image()?;",
            "slice::from_raw_parts(self.memory.buffer, self.size)",
            "would_block_if_equal",
            "Ok(result)",
        ),
        "GetImage success before shared-buffer publication",
    )

    for needle, label in (
        (
            "fn r_s11fw_shared_memory_is_owner_only_and_drop_removes_it()",
            "owner-only/removal kernel test",
        ),
        (
            "fn r_s11fw_attached_shared_memory_becomes_deletion_pending()",
            "deletion-pending kernel test",
        ),
        (
            "fn r_s11fx_get_image_accepts_only_an_exact_reply()",
            "exact GetImage reply-size test",
        ),
        (
            "fn r_s11fx_get_image_rejects_protocol_connection_and_missing_reply()",
            "GetImage error-finality test",
        ),
    ):
        require(capturer, needle, label)
    require_count(
        capturer,
        "assert_eq!(status.shm_perm.mode & 0o777, 0o600);",
        2,
        "independent exact-mode kernel assertions",
    )

    require(
        sources["requirements"],
        '<span class="id">R-S11fw</span>',
        "R-S11fw normative requirement",
    )
    require(
        sources["requirements"],
        "<tr><td>331</td>",
        "Appendix C #331 disposition",
    )
    require(
        sources["hardening"],
        "R-S11fw/R-S11e-209 — Linux X11 capture shared-memory authority",
        "R-S11e-209 hardening record",
    )
    require(
        sources["requirements"],
        '<span class="id">R-S11fx</span>',
        "R-S11fx normative requirement",
    )
    require(
        sources["requirements"],
        "<tr><td>332</td>",
        "Appendix C #332 disposition",
    )
    require(
        sources["hardening"],
        "R-S11fx/R-S11e-210 — Linux X11 capture GetImage frame finality",
        "R-S11e-210 hardening record",
    )
    require(
        sources["verify"],
        "scripts/verify-x11-capture-shm.py --repo . --self-test",
        "focused X11 capture shared-memory gate",
    )
    require(
        sources["verify"],
        "x11::capturer::tests::r_s11fw_ -- --test-threads=1",
        "compiled X11 shared-memory kernel tests",
    )
    require(
        sources["verify"],
        "x11::capturer::tests::r_s11fx_ -- --test-threads=1",
        "compiled X11 GetImage finality tests",
    )
    try:
        workspace_module = ast.parse(sources["workspace"])
    except SyntaxError as error:
        raise VerificationError(f"independent workspace does not parse: {error}") from error
    validators = [
        node
        for node in workspace_module.body
        if isinstance(node, ast.FunctionDef) and node.name == "validate_sources"
    ]
    dispatches = (
        [
            node
            for node in ast.walk(validators[0])
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "validate_x11_capture_shared_memory_contract"
        ]
        if len(validators) == 1
        else []
    )
    if len(dispatches) != 1:
        raise VerificationError("independent workspace dispatch is not exact")


@dataclass(frozen=True)
class Mutation:
    source: str
    old: str
    new: str
    label: str


MUTATIONS = (
    Mutation(
        "capturer",
        "const SHM_OWNER_READ_WRITE: libc::c_int = " + "0o600;",
        "const SHM_OWNER_READ_WRITE: libc::c_int = 0o666;",
        "owner-only mode",
    ),
    Mutation(
        "capturer",
        "libc::shmat(id, ptr::null(), libc::SHM_RDONLY)",
        "libc::shmat(id, ptr::null(), 0)",
        "local read-only attachment",
    ),
    Mutation(
        "capturer",
        "xcb_shm_attach_checked(",
        "xcb_shm_attach(",
        "checked X-server attach",
    ),
    Mutation(
        "capturer",
        'check_xcb_request(server, attach, "MIT-SHM attach")?;',
        "let _ = attach;",
        "attach completion",
    ),
    Mutation(
        "capturer",
        "memory.mark_for_removal()",
        "Ok::<(), io::Error>(())",
        "deletion-pending transition",
    ),
    Mutation(
        "ffi",
        "pub fn xcb_request_check(",
        "pub fn xcb_request_check_disabled(",
        "request-check binding",
    ),
    Mutation(
        "capturer",
        'check_xcb_request(server, detach, "MIT-SHM drop detach")',
        'Ok::<(), io::Error>(())',
        "checked drop-time detach",
    ),
    Mutation(
        "capturer",
        "assert_eq!(status.shm_perm.mode & 0o777, 0o600);",
        "assert_eq!(status.shm_perm.mode & 0o777, SHM_OWNER_READ_WRITE as libc::c_ushort);",
        "independent mode assertion",
    ),
    Mutation(
        "capturer",
        "let request = xcb_shm_get_image(",
        "let request = xcb_shm_get_image_unchecked(",
        "checked GetImage request",
    ),
    Mutation(
        "capturer",
        "xcb_shm_get_image_reply(server, request, &mut error)",
        "xcb_shm_get_image_reply(server, request, ptr::null_mut())",
        "GetImage protocol error receipt",
    ),
    Mutation(
        "capturer",
        "libc::free(response.cast());\n            libc::free(error.cast());",
        "libc::free(response.cast());\n            let _ = error;",
        "GetImage protocol error cleanup",
    ),
    Mutation(
        "capturer",
        "if reply_size != expected_size",
        "if false",
        "GetImage exact reply size",
    ),
    Mutation(
        "capturer",
        "self.get_image()?;",
        "let _ = self.get_image();",
        "GetImage result propagation",
    ),
    Mutation(
        "requirements",
        '<span class="id">R-S11fw</span>',
        '<span class="id">R-S11fw-disabled</span>',
        "normative requirement",
    ),
    Mutation(
        "requirements",
        "<tr><td>331</td>",
        "<tr><td>331-disabled</td>",
        "Appendix disposition",
    ),
    Mutation(
        "hardening",
        "R-S11fw/R-S11e-209 — Linux X11 capture shared-memory authority",
        "R-S11fw/R-S11e-209 — permissive Linux X11 capture memory",
        "hardening record",
    ),
    Mutation(
        "requirements",
        '<span class="id">R-S11fx</span>',
        '<span class="id">R-S11fx-disabled</span>',
        "GetImage normative requirement",
    ),
    Mutation(
        "requirements",
        "<tr><td>332</td>",
        "<tr><td>332-disabled</td>",
        "GetImage Appendix disposition",
    ),
    Mutation(
        "hardening",
        "R-S11fx/R-S11e-210 — Linux X11 capture GetImage frame finality",
        "R-S11fx/R-S11e-210 — unchecked X11 frame publication",
        "GetImage hardening record",
    ),
    Mutation(
        "verify",
        "scripts/verify-x11-capture-shm.py --repo . --self-test",
        "scripts/verify-x11-capture-shm.py --repo .",
        "focused mutation gate",
    ),
    Mutation(
        "workspace",
        "    validate_viewer_voice_call_worker_contract(sources)\n"
        "    validate_x11_capture_shared_memory_contract(sources)\n"
        "    validate_viewer_video_mailbox_contract(sources)",
        "    validate_viewer_voice_call_worker_contract(sources)\n"
        "    validate_x11_capture_shared_memory_contract_disabled(sources)\n"
        "    validate_viewer_video_mailbox_contract(sources)",
        "independent workspace dispatch",
    ),
)


def run_self_test(sources: Dict[str, str]) -> None:
    for mutation in MUTATIONS:
        source = sources[mutation.source]
        if mutation.old not in source:
            raise VerificationError(
                f"self-test fixture for {mutation.label} is absent: {mutation.old!r}"
            )
        mutated = dict(sources)
        mutated[mutation.source] = source.replace(mutation.old, mutation.new, 1)
        try:
            validate(mutated)
        except VerificationError:
            continue
        raise VerificationError(f"self-test accepted mutation: {mutation.label}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify X11 capture shared-memory authority and frame finality"
    )
    parser.add_argument("--repo", default=".", help="repository root")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    try:
        sources = load_sources(Path(args.repo).resolve())
        validate(sources)
        if args.self_test:
            run_self_test(sources)
    except (OSError, UnicodeError, VerificationError) as error:
        print(f"verify-x11-capture-shm: FAIL: {error}")
        return 1
    suffix = " and deliberate mutations" if args.self_test else ""
    print(f"verify-x11-capture-shm: ok{suffix}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
