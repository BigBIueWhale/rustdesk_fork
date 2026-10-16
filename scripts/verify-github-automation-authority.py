#!/usr/bin/env python3
"""Require absent GitHub automation and dependency-rewrite configuration."""

import argparse
import stat
import sys
from pathlib import Path


class VerificationError(RuntimeError):
    pass


ABSENT_PATHS = (
    ".github/dependabot.yml",
    ".github/dependabot.yaml",
    ".github/dependabot.yml.disabled",
    ".github/dependabot.yaml.disabled",
    ".gitmodules",
    "scripts/verify-disabled-workflow-authority.py",
)


def check_repository(repo: Path) -> None:
    for relative in (".github", ".github/workflows"):
        if not stat.S_ISDIR((repo / relative).lstat().st_mode):
            raise VerificationError(f"required real directory: {relative}")
    for relative in ABSENT_PATHS:
        try:
            (repo / relative).lstat()
        except FileNotFoundError:
            continue
        raise VerificationError(f"forbidden automation path: {relative}")

    workflows = repo / ".github/workflows"
    if sorted(path.name for path in workflows.iterdir()) != ["DISABLED.md"]:
        raise VerificationError("workflow directory must contain only DISABLED.md")
    if not stat.S_ISREG((workflows / "DISABLED.md").lstat().st_mode):
        raise VerificationError("workflow policy must be a regular file")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path("."))
    args = parser.parse_args()
    check_repository(args.repo)
    print("GitHub automation authority: absent")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, VerificationError) as error:
        print(f"GitHub automation-authority verification failed: {error}", file=sys.stderr)
        raise SystemExit(1)
