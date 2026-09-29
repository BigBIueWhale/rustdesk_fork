#!/usr/bin/env python3
"""Count a live Android process's descriptors from a streamed debuggerd tombstone."""

import argparse
import io
import re
import sys


MAX_INPUT_BYTES = 32 * 1024 * 1024
MAX_LINE_BYTES = 1024 * 1024
FD_LINE = re.compile(rb"^[ \t]+fd ([0-9]+): .*$")


class TombstoneError(ValueError):
    pass


def count_fds(stream, expected_pid: int, expected_package: str,
              max_input_bytes: int = MAX_INPUT_BYTES,
              max_line_bytes: int = MAX_LINE_BYTES) -> int:
    if expected_pid <= 0:
        raise TombstoneError("expected pid is not positive")
    try:
        package = expected_package.encode("ascii")
    except UnicodeEncodeError as error:
        raise TombstoneError("expected package is not ASCII") from error
    if not re.fullmatch(rb"[A-Za-z0-9_.]+", package):
        raise TombstoneError("expected package is malformed")

    header = re.compile(
        rb"^pid:[ \t]*" + str(expected_pid).encode("ascii")
        + rb",[ \t]*tid:[ \t]*[1-9][0-9]*,[ \t]*name:.*>>>[ \t]*"
        + re.escape(package) + rb"[ \t]*<<<[ \t]*$"
    )
    if max_input_bytes <= 0 or max_line_bytes <= 0:
        raise TombstoneError("input bounds are not positive")

    total = 0
    header_count = 0
    section_count = 0
    in_open_files = False
    descriptors = set()

    while True:
        raw_line = stream.readline(max_line_bytes + 1)
        if not raw_line:
            break
        if len(raw_line) > max_line_bytes:
            raise TombstoneError(
                f"tombstone line exceeds the {max_line_bytes}-byte bound"
            )
        total += len(raw_line)
        if total > max_input_bytes:
            raise TombstoneError(
                f"tombstone exceeds the {max_input_bytes}-byte input bound"
            )
        line = raw_line.rstrip(b"\r\n")
        if header.fullmatch(line):
            header_count += 1
        if line == b"open files:":
            section_count += 1
            in_open_files = True
            continue
        if not in_open_files:
            continue
        match = FD_LINE.fullmatch(line)
        if match is None:
            if re.match(rb"^[ \t]+fd(?:[ \t:]|$)", line):
                raise TombstoneError("malformed descriptor row")
            continue
        descriptor = int(match.group(1), 10)
        if descriptor in descriptors:
            raise TombstoneError("duplicate descriptor row")
        descriptors.add(descriptor)

    if header_count != 1:
        raise TombstoneError("exact target pid/package header is absent or duplicated")
    if section_count != 1:
        raise TombstoneError("open-files section is absent or duplicated")
    if not descriptors:
        raise TombstoneError("open-files section has no descriptor rows")
    return len(descriptors)


def expect_failure(payload: bytes, pid: int = 42,
                   package: str = "com.example.app") -> None:
    try:
        count_fds(io.BytesIO(payload), pid, package, max_input_bytes=4096)
    except TombstoneError:
        return
    raise AssertionError("invalid tombstone fixture was accepted")


def self_test() -> None:
    prefix = (
        b"*** *** *** ***\n"
        b"pid: 42, tid: 42, name: example  >>> com.example.app <<<\n"
        b"open files:\n"
    )
    assert count_fds(
        io.BytesIO(prefix + b" fd 0: /dev/null (unowned)\n"
                   + b"    fd 7: socket:[123] (unowned)\n"),
        42,
        "com.example.app",
        max_input_bytes=4096,
    ) == 2
    assert count_fds(
        io.BytesIO(prefix.replace(b"\n", b"\r\n")
                   + b"\tfd 3: /dev/binder (unowned)\r\n"),
        42,
        "com.example.app",
        max_input_bytes=4096,
    ) == 1
    expect_failure(prefix + b" fd 3: x (unowned)\n fd 3: y (unowned)\n")
    expect_failure(prefix + b" fd nope: x (unowned)\n")
    expect_failure(prefix.replace(b"pid: 42", b"pid: 43")
                   + b" fd 3: x (unowned)\n")
    expect_failure(prefix.replace(b"com.example.app", b"com.example.other")
                   + b" fd 3: x (unowned)\n")
    expect_failure(prefix.replace(b"open files:\n", b"")
                   + b" fd 3: x (unowned)\n")
    expect_failure(prefix)
    expect_failure(prefix + b" fd 3: x (unowned)\n" + b"x" * 4096)
    try:
        count_fds(
            io.BytesIO(prefix + b" fd 3: " + b"x" * 512),
            42,
            "com.example.app",
            max_input_bytes=8192,
            max_line_bytes=256,
        )
    except TombstoneError:
        pass
    else:
        raise AssertionError("overlong tombstone line was accepted")
    print(
        "ANDROID_TOMBSTONE_FD_PARSER_SELF_TEST=pass "
        "scenarios=10 max_input_bytes=33554432"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--pid", type=int)
    parser.add_argument("--package")
    arguments = parser.parse_args()
    if arguments.self_test:
        if arguments.pid is not None or arguments.package is not None:
            parser.error("--self-test does not accept a pid or package")
        self_test()
        return 0
    if arguments.pid is None or arguments.package is None:
        parser.error("--pid and --package are required")
    try:
        descriptors = count_fds(
            sys.stdin.buffer,
            arguments.pid,
            arguments.package,
        )
    except TombstoneError as error:
        print(f"Android tombstone descriptor parser: {error}", file=sys.stderr)
        return 1
    print(f"fds={descriptors}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
