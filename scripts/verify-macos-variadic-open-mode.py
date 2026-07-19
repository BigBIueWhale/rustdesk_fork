#!/usr/bin/env python3
"""R-S11av/R-S11e-62 macOS variadic open/openat mode verifier."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Dict, Iterable, Tuple


class VerificationError(RuntimeError):
    pass


def require(source: str, needle: str, label: str) -> None:
    if needle not in source:
        raise VerificationError(f"missing {label}")


def absent(source: str, needle: str, label: str) -> None:
    if needle in source:
        raise VerificationError(f"stale/forbidden {label}")


def region(source: str, start: str, end: str, label: str) -> str:
    begin = source.find(start)
    if begin < 0:
        raise VerificationError(f"missing {label} start")
    finish = source.find(end, begin + len(start))
    if finish < 0:
        raise VerificationError(f"missing {label} end")
    return source[begin:finish]


def require_all(source: str, needles: Iterable[Tuple[str, str]]) -> None:
    for needle, label in needles:
        require(source, needle, label)


def load_sources(repo: Path) -> Dict[str, str]:
    paths = {
        "config": "libs/hbb_common/src/config.rs",
        "transfer": "libs/hbb_common/src/fs.rs",
        "ipc_fs": "src/ipc/fs.rs",
        "paste_task": "libs/clipboard/src/platform/unix/macos/paste_task.rs",
        "pasteboard": "libs/clipboard/src/platform/unix/macos/pasteboard_context.rs",
        "requirements": "requirements.html",
        "hardening": "HARDENING_STATUS.md",
        "verify": "scripts/verify.sh",
        "apple": "scripts/apple-conform-check.sh",
    }
    return {
        key: (repo / relative).read_text(encoding="utf-8")
        for key, relative in paths.items()
    }


def validate(sources: Dict[str, str]) -> None:
    config_transaction = region(
        sources["config"],
        "fn store_config_bytes_transaction_unix(",
        "\n#[cfg(windows)]\nfn store_config_bytes_transaction(",
        "Unix config-store transaction",
    )
    require_all(
        config_transaction,
        (
            (
                "0o600 as crate::libc::c_uint,",
                "config openat variadic mode promotion",
            ),
            (
                "crate::libc::fchmod(fd, 0o600 as crate::libc::mode_t)",
                "config fixed-prototype fchmod mode_t",
            ),
            ("crate::libc::O_CREAT", "config exclusive-create flag"),
            ("crate::libc::O_EXCL", "config exclusive-create collision guard"),
            ("crate::libc::O_NOFOLLOW", "config no-follow create guard"),
        ),
    )
    absent(
        config_transaction,
        "0o600 as crate::libc::mode_t,\n            )",
        "narrow config openat variadic argument",
    )

    transfer_open = region(
        sources["transfer"],
        "fn open_regular_child_no_follow(",
        "\n#[cfg(unix)]\nfn open_existing_regular_no_follow(",
        "portable file-transfer open helper",
    )
    require_all(
        transfer_open,
        (
            ("mode: crate::libc::mode_t", "fixed Rust mode input type"),
            (
                "mode as crate::libc::c_uint",
                "portable openat variadic mode promotion",
            ),
        ),
    )
    absent(
        transfer_open,
        "flags, mode as crate::libc::mode_t",
        "narrow portable openat variadic argument",
    )

    pid_file = region(
        sources["ipc_fs"],
        "fn write_pid_file(path: &Path) -> ResultType<()> {",
        "\n#[inline]\npub(crate) fn write_pid(",
        "macOS-reachable PID-file creation",
    )
    require(
        pid_file,
        "hbb_common::libc::open(path_c.as_ptr(), flags, 0o0600)",
        "already-promoted i32 PID-file mode",
    )
    absent(
        pid_file,
        "0o0600 as hbb_common::libc::mode_t",
        "narrow PID-file open variadic argument",
    )

    paste_create = region(
        sources["paste_task"],
        "fn open_relative_file_exclusive_no_follow(",
        "\nfn unlink_relative_file_no_follow(",
        "macOS paste target creation",
    )
    require_all(
        paste_create,
        (
            ("0o666 as libc::c_uint", "paste-target openat mode promotion"),
            ("libc::O_CREAT", "paste-target create flag"),
            ("libc::O_EXCL", "paste-target exclusive-create guard"),
            ("libc::O_NOFOLLOW", "paste-target no-follow guard"),
            ("libc::fstat", "paste-target descriptor type check"),
        ),
    )
    absent(
        paste_create,
        "0o666 as libc::mode_t",
        "narrow paste-target openat variadic argument",
    )
    require(
        sources["paste_task"],
        "libc::mkdirat(parent_fd, name.as_ptr(), 0o777 as libc::mode_t)",
        "fixed-prototype macOS mkdirat mode_t",
    )

    placeholder_create = region(
        sources["pasteboard"],
        "pub(super) fn create_placeholder_file(",
        "\nfn placeholder_file_name<'a>(",
        "macOS clipboard placeholder creation",
    )
    require_all(
        placeholder_create,
        (
            ("0o600 as libc::c_uint", "placeholder openat mode promotion"),
            ("libc::O_CREAT", "placeholder create flag"),
            ("libc::O_EXCL", "placeholder exclusive-create guard"),
            ("libc::O_NOFOLLOW", "placeholder no-follow guard"),
        ),
    )
    absent(
        placeholder_create,
        "0o600 as libc::mode_t",
        "narrow placeholder openat variadic argument",
    )
    require(
        sources["pasteboard"],
        "libc::fchmod(dir.as_raw_fd(), 0o700 as libc::mode_t)",
        "fixed-prototype macOS fchmod mode_t",
    )

    for source, needle, label in (
        (
            sources["requirements"],
            '<span class="id">R-S11av</span>',
            "R-S11av requirement",
        ),
        (
            sources["requirements"],
            "macOS file-creation modes obey the C variadic ABI",
            "R-S11av title",
        ),
        (sources["requirements"], "<tr><td>170</td>", "Appendix C #170"),
        (
            sources["hardening"],
            "R-S11e-62 — macOS variadic file-creation ABI",
            "R-S11e-62 ledger",
        ),
        (
            sources["verify"],
            'echo "== (3b-iii-d9cl) macOS variadic file-creation ABI (R-S11av/R-S11e-62) =="',
            "shared source gate",
        ),
        (
            sources["apple"],
            'echo "== (2b-iii-c5b) macOS variadic file-creation ABI (R-S11av/R-S11e-62) =="',
            "Apple source gate",
        ),
    ):
        require(source, needle, label)


Mutation = Tuple[str, str, str, str]


MUTATIONS: Tuple[Mutation, ...] = (
    (
        "config",
        "0o600 as crate::libc::c_uint,",
        "0o600 as crate::libc::mode_t,",
        "config openat promotion",
    ),
    (
        "transfer",
        "mode as crate::libc::c_uint",
        "mode as crate::libc::mode_t",
        "portable openat promotion",
    ),
    (
        "ipc_fs",
        "hbb_common::libc::open(path_c.as_ptr(), flags, 0o0600)",
        "hbb_common::libc::open(path_c.as_ptr(), flags, 0o0600 as hbb_common::libc::mode_t)",
        "PID-file promoted mode",
    ),
    (
        "paste_task",
        "0o666 as libc::c_uint",
        "0o666 as libc::mode_t",
        "paste-target openat promotion",
    ),
    (
        "pasteboard",
        "0o600 as libc::c_uint",
        "0o600 as libc::mode_t",
        "placeholder openat promotion",
    ),
    (
        "config",
        "crate::libc::fchmod(fd, 0o600 as crate::libc::mode_t)",
        "crate::libc::fchmod(fd, 0o600 as crate::libc::c_uint)",
        "fixed config fchmod type",
    ),
    (
        "paste_task",
        "libc::mkdirat(parent_fd, name.as_ptr(), 0o777 as libc::mode_t)",
        "libc::mkdirat(parent_fd, name.as_ptr(), 0o777 as libc::c_uint)",
        "fixed paste mkdirat type",
    ),
    (
        "pasteboard",
        "libc::fchmod(dir.as_raw_fd(), 0o700 as libc::mode_t)",
        "libc::fchmod(dir.as_raw_fd(), 0o700 as libc::c_uint)",
        "fixed placeholder fchmod type",
    ),
    (
        "requirements",
        '<span class="id">R-S11av</span>',
        '<span class="id">R-S11az</span>',
        "R-S11av requirement",
    ),
    ("requirements", "<tr><td>170</td>", "<tr><td>9170</td>", "Appendix C #170"),
    (
        "hardening",
        "R-S11e-62 — macOS variadic file-creation ABI",
        "R-S11e-62 — narrow variadic modes",
        "R-S11e-62 ledger",
    ),
    (
        "verify",
        'echo "== (3b-iii-d9cl) macOS variadic file-creation ABI (R-S11av/R-S11e-62) =="',
        'echo "== (3b-iii-d9cl) macOS narrow file-creation ABI (R-S11av/R-S11e-62) =="',
        "shared source gate",
    ),
    (
        "apple",
        'echo "== (2b-iii-c5b) macOS variadic file-creation ABI (R-S11av/R-S11e-62) =="',
        'echo "== (2b-iii-c5b) macOS narrow file-creation ABI (R-S11av/R-S11e-62) =="',
        "Apple source gate",
    ),
)


def run_mutations(sources: Dict[str, str]) -> None:
    for key, old, new, label in MUTATIONS:
        if sources[key].count(old) != 1:
            raise VerificationError(f"mutation anchor is not unique for {label}")
        mutated = dict(sources)
        mutated[key] = sources[key].replace(old, new, 1)
        try:
            validate(mutated)
        except VerificationError:
            continue
        raise VerificationError(f"mutation was not rejected: {label}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path("."))
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    sources = load_sources(args.repo.resolve())
    validate(sources)
    if args.self_test:
        run_mutations(sources)
    print(
        "macOS variadic file-creation ABI semantic validation: OK"
        + (f" ({len(MUTATIONS)} mutations)" if args.self_test else "")
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
