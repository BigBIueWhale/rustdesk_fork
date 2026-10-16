#!/usr/bin/env python3
"""Exercise automation admission through the CLI and actual filesystem nodes."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile


scripts = Path(__file__).resolve().parent
subprocess.run(["/bin/bash", str(scripts / "verify-vm-entry-preflight.sh")],
               check=True, stdout=subprocess.DEVNULL)
checker = scripts / "verify-github-automation-authority.py"
cases = 0


def check(repo: Path, error: str = "") -> None:
    global cases
    result = subprocess.run(
        [sys.executable, "-B", "-I", "-S", str(checker), "--repo", str(repo)],
        capture_output=True, text=True, timeout=5,
    )
    if error:
        if (result.returncode != 1 or result.stdout or error not in result.stderr
                or not result.stderr.startswith("GitHub automation-authority verification failed:")):
            raise RuntimeError(f"wrong refusal for {error}: {result}")
    elif (result.returncode or result.stderr
          or result.stdout != "GitHub automation authority: absent\n"):
        raise RuntimeError(f"valid repository refused: {result}")
    cases += 1


def create_node(path: Path, kind: str) -> None:
    if kind == "regular":
        path.write_text("on: push\njobs: {}\n")
    elif kind == "symlink":
        path.symlink_to("absent-target")
    elif kind == "directory":
        path.mkdir()
    elif kind == "fifo":
        os.mkfifo(path)
    else:
        raise RuntimeError(f"unknown fixture kind: {kind}")


def remove_node(path: Path, kind: str) -> None:
    if kind == "directory":
        path.rmdir()
    else:
        path.unlink()


with tempfile.TemporaryDirectory(prefix="github-automation.") as temporary:
    repo = Path(temporary)
    workflows = repo / ".github/workflows"
    workflows.mkdir(parents=True)
    (repo / "scripts").mkdir()
    policy = workflows / "DISABLED.md"
    policy.write_text("Policy wording does not grant authority.\n")
    check(repo)
    for name in ("ci.yml", "ci.yaml", "ci.yml.disabled", "ci.yaml.disabled", "extra.md"):
        path = workflows / name
        for kind in ("regular", "symlink", "directory", "fifo"):
            create_node(path, kind)
            check(repo, "workflow directory must contain only DISABLED.md")
            remove_node(path, kind)
    policy.unlink()
    check(repo, "workflow directory must contain only DISABLED.md")
    for kind in ("symlink", "directory", "fifo"):
        create_node(policy, kind)
        check(repo, "workflow policy must be a regular file")
        remove_node(policy, kind)
    policy.write_text("")
    check(repo)

    for relative in (".github/workflows", ".github"):
        path = repo / relative
        retained = repo / "retained-directory"
        path.rename(retained)
        check(repo, "No such file or directory")
        for kind in ("regular", "symlink", "fifo"):
            create_node(path, kind)
            check(repo, "required real directory")
            remove_node(path, kind)
        retained.rename(path)

    for relative in (
        ".github/dependabot.yml", ".github/dependabot.yaml",
        ".github/dependabot.yml.disabled", ".github/dependabot.yaml.disabled",
        ".gitmodules", "scripts/verify-disabled-workflow-authority.py",
    ):
        path = repo / relative
        for kind in ("regular", "symlink", "directory", "fifo"):
            create_node(path, kind)
            check(repo, f"forbidden automation path: {relative}")
            remove_node(path, kind)
    check(repo)

print(f"GITHUB_AUTOMATION_FILESYSTEM=pass cases={cases} source=production-cli "
      "nodes=regular,symlink,directory,fifo schema=absent cleanup=joined")
