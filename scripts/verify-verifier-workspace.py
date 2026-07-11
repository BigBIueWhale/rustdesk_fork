#!/usr/bin/env python3
import argparse
import re
import shlex
import sys
from pathlib import Path


WORKSPACE_BLOCKS = (
    (
        "workspace creation",
        (
            "VERIFY_TMP=$(umask 077 && mktemp -d /tmp/rustdesk-verify.XXXXXXXXXX)",
            "readonly VERIFY_TMP",
        ),
    ),
    (
        "workspace cleanup",
        (
            "cleanup_verify_tmp() {",
            "  local status=$?",
            "  trap - EXIT HUP INT TERM",
            '  if ! rm -rf -- "$VERIFY_TMP"; then',
            '    echo "verify: failed to remove private workspace: $VERIFY_TMP" >&2',
            "    status=1",
            "  fi",
            '  exit "$status"',
            "}",
        ),
    ),
    (
        "workspace signal handling",
        (
            "trap cleanup_verify_tmp EXIT",
            "trap 'exit 129' HUP",
            "trap 'exit 130' INT",
            "trap 'exit 143' TERM",
        ),
    ),
    (
        "workspace metadata proof",
        (
            'if ! python3 - "$VERIFY_TMP" <<\'PY\'',
            "import os",
            "import stat",
            "import sys",
            "",
            "metadata = os.lstat(sys.argv[1])",
            "if (",
            "    not stat.S_ISDIR(metadata.st_mode)",
            "    or metadata.st_uid != os.geteuid()",
            "    or stat.S_IMODE(metadata.st_mode) != 0o700",
            "):",
            '    raise SystemExit("verify: private workspace is not a current-UID mode-0700 directory")',
            "PY",
            "then",
            "  exit 1",
            "fi",
        ),
    ),
)

OLD_SCRATCH_PREFIX = re.compile(r"/tmp/(?:rd_verify|r_s11b3|r_s11c23)")
PUBLIC_TMP_REDIRECTION = re.compile(r"\d*(?:>>?|<<?)\s*['\"]?/tmp/")
SHELL_COMMAND_SEPARATORS = {"|", "||", "&", "&&", ";"}


class VerificationError(RuntimeError):
    pass


def find_unique_line(lines, expected, label):
    matches = [index for index, line in enumerate(lines) if line == expected]
    if len(matches) != 1:
        raise VerificationError(f"{label}: expected exactly one full-line match, found {len(matches)}")
    return matches[0]


def find_unique_block(lines, block, label):
    width = len(block)
    matches = [
        index
        for index in range(len(lines) - width + 1)
        if tuple(lines[index : index + width]) == block
    ]
    if len(matches) != 1:
        raise VerificationError(f"{label}: expected exactly one full-line block, found {len(matches)}")
    return matches[0]


def has_fixed_string_self_check(line):
    if "grep" not in line or "scripts/verify.sh" not in line:
        return False
    try:
        lexer = shlex.shlex(line, posix=True, punctuation_chars="|&;")
        lexer.whitespace_split = True
        lexer.commenters = ""
        tokens = list(lexer)
    except ValueError as exc:
        raise VerificationError(f"cannot parse potential verify.sh self-check: {exc}") from exc

    for index, token in enumerate(tokens):
        if token != "grep":
            continue
        command = []
        for argument in tokens[index + 1 :]:
            if argument in SHELL_COMMAND_SEPARATORS:
                break
            command.append(argument)
        fixed_strings = any(
            argument == "--fixed-strings"
            or argument.startswith("--fixed-strings=")
            or (argument.startswith("-") and not argument.startswith("--") and "F" in argument[1:])
            for argument in command
        )
        if fixed_strings and "scripts/verify.sh" in command:
            return True
    return False


def validate_source(source):
    lines = source.splitlines()
    cd_index = find_unique_line(lines, 'cd "$(dirname "$0")/.."', "repository-root selection")
    source_index = find_unique_line(
        lines,
        "source scripts/fork-version.sh",
        "fork-version loading",
    )

    positions = {}
    previous_end = cd_index
    for label, block in WORKSPACE_BLOCKS:
        start = find_unique_block(lines, block, label)
        if start <= previous_end:
            raise VerificationError(f"{label}: block is outside the ordered startup sequence")
        positions[label] = start
        previous_end = start + len(block) - 1
    if previous_end >= source_index:
        raise VerificationError("workspace setup must finish before fork-version loading")

    for line_number, line in enumerate(lines, 1):
        if OLD_SCRATCH_PREFIX.search(line):
            raise VerificationError(f"line {line_number}: predictable public scratch prefix is present")
        if PUBLIC_TMP_REDIRECTION.search(line):
            raise VerificationError(f"line {line_number}: direct public-/tmp redirection is present")
        if has_fixed_string_self_check(line):
            raise VerificationError(f"line {line_number}: fixed-string self-inspection is present")

    return lines, positions


def expect_rejection(lines, expected):
    try:
        validate_source("\n".join(lines) + "\n")
    except VerificationError as exc:
        if expected not in str(exc):
            raise VerificationError(
                f"negative test failed for {expected!r}: rejected for {exc!s}"
            ) from exc
        return
    raise VerificationError(f"negative test accepted mutation for {expected!r}")


def self_test(lines, positions):
    for label, block in WORKSPACE_BLOCKS:
        start = positions[label]
        for offset, line in enumerate(block):
            if not line:
                continue
            mutated = list(lines)
            del mutated[start + offset]
            expect_rejection(mutated, label)

    for injected in (
        "printf x >/tmp/verify-probe",
        "printf x >'/tmp/verify-probe'",
        'printf x >"/tmp/verify-probe"',
    ):
        expect_rejection(lines + [injected], "direct public-/tmp redirection")
    expect_rejection(
        lines + ["printf x >/tmp/rd_verify_probe.$$"],
        "predictable public scratch prefix",
    )
    for injected in (
        "grep -qF 'readonly VERIFY_TMP' scripts/verify.sh",
        "grep -Fq 'readonly VERIFY_TMP' scripts/verify.sh",
        "grep -F -q 'readonly VERIFY_TMP' scripts/verify.sh",
        "grep --fixed-strings --quiet 'readonly VERIFY_TMP' scripts/verify.sh",
        "if ! grep -qF 'readonly VERIFY_TMP' \"scripts/verify.sh\"; then exit 1; fi",
    ):
        expect_rejection(lines + [injected], "fixed-string self-inspection")


def main():
    parser = argparse.ArgumentParser(description="Verify verify.sh private-workspace source invariants.")
    parser.add_argument("--repo", default=".", help="repository root")
    parser.add_argument("--self-test", action="store_true", help="run mutation-negative checks")
    args = parser.parse_args()

    try:
        path = Path(args.repo).resolve() / "scripts/verify.sh"
        lines, positions = validate_source(path.read_text(encoding="utf-8"))
        if args.self_test:
            self_test(lines, positions)
    except (OSError, UnicodeError, VerificationError) as exc:
        print(f"verify-verifier-workspace: FAIL: {exc}", file=sys.stderr)
        return 1

    print("verify-verifier-workspace: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
