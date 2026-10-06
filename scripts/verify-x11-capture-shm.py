#!/usr/bin/env python3
"""Verify X11 capture shared-memory authority and GetImage frame finality."""

from __future__ import annotations

import argparse
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
    return {
        "capturer": (repo / "libs/scrap/src/x11/capturer.rs").read_text(
            encoding="utf-8"
        ),
        "ffi": (repo / "libs/scrap/src/x11/ffi.rs").read_text(encoding="utf-8"),
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
            "display.row_stride()?",
            ".checked_mul(rect.h as usize)",
            "u32::try_from(size)",
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
            "let (reply_size, reply_depth, reply_visual) = reply.ok_or_else",
            "if reply_depth != expected_depth || reply_visual != expected_visual",
            "if reply_size != expected_size",
        ),
        "protocol, connection, reply-presence, layout, and exact-size result order",
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
            "let reply = if response.is_null()",
            "Some(((*response).size as usize, (*response).depth, (*response).visual))",
            "let protocol_error = if error.is_null()",
            "libc::free(response.cast())",
            "libc::free(error.cast())",
            "xcb_connection_has_error(server)",
            "check_get_image_result(reply, protocol_error, connection_error, self.size,",
            "self.display.depth(), self.display.visual())",
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


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify X11 capture shared-memory authority and frame finality"
    )
    parser.add_argument("--repo", default=".", help="repository root")
    args = parser.parse_args()

    try:
        sources = load_sources(Path(args.repo).resolve())
        validate(sources)
    except (OSError, UnicodeError, VerificationError) as error:
        print(f"verify-x11-capture-shm: FAIL: {error}")
        return 1
    print("verify-x11-capture-shm: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
