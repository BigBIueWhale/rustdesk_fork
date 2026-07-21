#!/usr/bin/env python3
"""R-R1a/R-R2/R-R2d GitHub-hosted automation-authority verifier."""

from __future__ import annotations

import argparse
import os
import re
import stat
from pathlib import Path
from typing import Dict, Tuple


class VerificationError(RuntimeError):
    pass


DISABLED_WORKFLOWS: Tuple[str, ...] = (
    "bridge.yml.disabled",
    "ci.yml.disabled",
    "flutter-build.yml.disabled",
    "flutter-ci.yml.disabled",
    "flutter-tag.yml.disabled",
    "third-party-RustDeskTempTopMostWindow.yml.disabled",
    "wf-cliprdr-ci.yml.disabled",
)

FORBIDDEN_DEPENDABOT_PATHS: Tuple[str, ...] = (
    ".github/dependabot.yml",
    ".github/dependabot.yaml",
    ".github/dependabot.yml.disabled",
    ".github/dependabot.yaml.disabled",
)

LEGACY_VERIFIER_PATH = "scripts/verify-disabled-workflow-authority.py"

EXPECTED_TOP_LEVEL_KEYS = {
    "bridge.yml.disabled": ("name", "historical_on", "env", "historical_jobs"),
    "ci.yml.disabled": ("name", "env", "historical_on", "historical_jobs"),
    "flutter-build.yml.disabled": ("name", "historical_on", "env", "historical_jobs"),
    "flutter-ci.yml.disabled": ("name", "historical_on", "historical_jobs"),
    "flutter-tag.yml.disabled": ("name", "historical_on", "historical_jobs"),
    "third-party-RustDeskTempTopMostWindow.yml.disabled": (
        "name",
        "historical_on",
        "env",
        "historical_jobs",
    ),
    "wf-cliprdr-ci.yml.disabled": (
        "name",
        "historical_on",
        "permissions",
        "concurrency",
        "historical_jobs",
    ),
}

EXPECTED_ENTRY_INVENTORY = "\n".join(
    f"regular:{name}" for name in ("DISABLED.md", *DISABLED_WORKFLOWS)
)


def require(source: str, needle: str, label: str) -> None:
    if needle not in source:
        raise VerificationError(f"missing {label}")


def regular_file_state(path: Path) -> str:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return "absent"
    if stat.S_ISREG(metadata.st_mode):
        return "regular"
    if stat.S_ISLNK(metadata.st_mode):
        return "symlink"
    return "wrong-type"


def entry_inventory(path: Path) -> str:
    try:
        directory = path.lstat()
    except OSError as error:
        raise VerificationError(f"cannot stat workflow directory: {error}") from error
    if stat.S_ISLNK(directory.st_mode) or not stat.S_ISDIR(directory.st_mode):
        raise VerificationError("workflow path is not a real directory")

    entries = []
    try:
        scanned = sorted(os.scandir(path), key=lambda entry: entry.name)
    except OSError as error:
        raise VerificationError(f"cannot scan workflow directory: {error}") from error
    for entry in scanned:
        try:
            mode = entry.stat(follow_symlinks=False).st_mode
        except OSError as error:
            raise VerificationError(f"cannot stat workflow entry {entry.name}: {error}") from error
        if stat.S_ISREG(mode):
            kind = "regular"
        elif stat.S_ISLNK(mode):
            kind = "symlink"
        else:
            kind = "wrong-type"
        entries.append(f"{kind}:{entry.name}")
    return "\n".join(entries)


def enabled_workflow_inventory(path: Path) -> str:
    names = []
    for entry in os.scandir(path):
        if entry.name.endswith((".yml", ".yaml")):
            names.append(entry.name)
    return "\n".join(sorted(names)) or "<none>"


def top_level_keys(source: str, name: str) -> Tuple[str, ...]:
    keys = []
    for line_number, line in enumerate(source.splitlines(), start=1):
        if not line.strip() or line.lstrip().startswith("#") or line[0].isspace():
            continue
        key, separator, _value = line.partition(":")
        if separator != ":" or re.fullmatch(r"[a-z_]+", key) is None:
            raise VerificationError(
                f"disabled reference has an unrecognized top-level form: {name}:{line_number}"
            )
        keys.append(key)
    return tuple(keys)


def load_sources(repo: Path) -> Dict[str, str]:
    workflows = repo / ".github/workflows"
    sources = {
        "entry_inventory": entry_inventory(workflows),
        "enabled_inventory": enabled_workflow_inventory(workflows),
        "documentation": (workflows / "DISABLED.md").read_text(encoding="utf-8"),
        "requirements": (repo / "requirements.html").read_text(encoding="utf-8"),
        "hardening": (repo / "HARDENING_STATUS.md").read_text(encoding="utf-8"),
        "verify": (repo / "scripts/verify.sh").read_text(encoding="utf-8"),
        "gitmodules_state": regular_file_state(repo / ".gitmodules"),
        "legacy_verifier_state": regular_file_state(repo / LEGACY_VERIFIER_PATH),
    }
    for relative in FORBIDDEN_DEPENDABOT_PATHS:
        sources[f"path:{relative}"] = regular_file_state(repo / relative)
    for name in DISABLED_WORKFLOWS:
        path = workflows / name
        sources[f"state:{name}"] = regular_file_state(path)
        sources[f"workflow:{name}"] = path.read_text(encoding="utf-8")
    return sources


def validate(sources: Dict[str, str]) -> None:
    if sources["gitmodules_state"] != "absent":
        raise VerificationError("absorbed hbb_common unexpectedly regained .gitmodules authority")
    if sources["legacy_verifier_state"] != "absent":
        raise VerificationError("legacy narrow workflow-authority verifier remains present")
    for relative in FORBIDDEN_DEPENDABOT_PATHS:
        if sources[f"path:{relative}"] != "absent":
            raise VerificationError(
                f"Dependabot dependency-update authority remains present: {relative}"
            )

    if sources["entry_inventory"] != EXPECTED_ENTRY_INVENTORY:
        raise VerificationError("workflow directory inventory differs from the closed reference set")
    if sources["enabled_inventory"] != "<none>":
        raise VerificationError(
            f"enabled GitHub Actions workflow authority is present: {sources['enabled_inventory']}"
        )

    for name in DISABLED_WORKFLOWS:
        if sources[f"state:{name}"] != "regular":
            raise VerificationError(f"disabled workflow reference is not a regular file: {name}")
        workflow = sources[f"workflow:{name}"]
        if re.search(r"(?m)^(?:on|jobs):", workflow):
            raise VerificationError(f"disabled reference retains active workflow schema keys: {name}")
        if top_level_keys(workflow, name) != EXPECTED_TOP_LEVEL_KEYS[name]:
            raise VerificationError(f"disabled reference top-level key inventory differs: {name}")
        if len(re.findall(r"(?m)^historical_on:", workflow)) != 1:
            raise VerificationError(f"disabled reference lacks one demoted trigger key: {name}")
        if len(re.findall(r"(?m)^historical_jobs:", workflow)) != 1:
            raise VerificationError(f"disabled reference lacks one demoted jobs key: {name}")
        require(
            workflow,
            "HISTORICAL INERT REFERENCE ONLY",
            f"inert-reference marker in {name}",
        )
        require(
            workflow,
            "schema-demoted so a rename cannot activate this file",
            f"rename-resistant marker in {name}",
        )

    for source, needle, label in (
        (
            sources["documentation"],
            "Renaming a reference alone cannot enable it",
            "rename-resistant workflow documentation",
        ),
        (
            sources["documentation"],
            "Restoring `on` and `jobs` is an explicit release-authority change",
            "explicit workflow reactivation ceremony",
        ),
        (
            sources["documentation"],
            "No Dependabot configuration or disabled copy is retained",
            "absent Dependabot authority documentation",
        ),
        (sources["requirements"], '<span class="id">R-R1a</span>', "R-R1a requirement"),
        (
            sources["requirements"],
            "No automated dependency rewrite authority",
            "R-R1a dependency-authority title",
        ),
        (sources["requirements"], '<span class="id">R-R2d</span>', "R-R2d requirement"),
        (
            sources["requirements"],
            "Semantic inertia for retained GitHub Actions references",
            "R-R2d semantic-inertia title",
        ),
        (sources["requirements"], "<tr><td>195</td>", "Appendix C #195"),
        (sources["requirements"], "<tr><td>196</td>", "Appendix C #196"),
        (
            sources["hardening"],
            "R-R1a — obsolete Dependabot submodule updater deleted",
            "R-R1a hardening ledger",
        ),
        (
            sources["hardening"],
            "R-R2d — retained GitHub Actions references made schema-inert",
            "R-R2d hardening ledger",
        ),
        (
            sources["verify"],
            'echo "== (6c-a4) absent/inert GitHub automation authority (R-R1a/R-R2/R-R2d) =="',
            "shared GitHub-automation gate",
        ),
        (
            sources["verify"],
            "python3 scripts/verify-github-automation-authority.py --repo . --self-test",
            "focused GitHub-automation mutation gate",
        ),
    ):
        require(source, needle, label)


Mutation = Tuple[str, str, str, str]


MUTATIONS: Tuple[Mutation, ...] = tuple(
    mutation
    for name in DISABLED_WORKFLOWS
    for mutation in (
        (
            f"workflow:{name}",
            "historical_on:",
            "on:",
            f"reactivated trigger schema in {name}",
        ),
        (
            f"workflow:{name}",
            "historical_jobs:",
            "jobs:",
            f"reactivated jobs schema in {name}",
        ),
    )
) + tuple(
    (
        f"path:{relative}",
        "absent",
        "regular",
        f"restored Dependabot path {relative}",
    )
    for relative in FORBIDDEN_DEPENDABOT_PATHS
) + (
    (
        "gitmodules_state",
        "absent",
        "regular",
        "restored absorbed submodule manifest",
    ),
    (
        "legacy_verifier_state",
        "absent",
        "regular",
        "retained narrow workflow-authority verifier",
    ),
    (
        "entry_inventory",
        EXPECTED_ENTRY_INVENTORY,
        EXPECTED_ENTRY_INVENTORY + "\nregular:unexpected.yml.disabled",
        "unexpected workflow reference",
    ),
    ("enabled_inventory", "<none>", "ci.yml", "enabled workflow definition"),
    (
        "workflow:bridge.yml.disabled",
        "historical_on:",
        '"on":',
        "quoted active trigger schema",
    ),
    (
        "workflow:bridge.yml.disabled",
        "historical_jobs:",
        "jobs :",
        "space-delimited active jobs schema",
    ),
    (
        "documentation",
        "Renaming a reference alone cannot enable it",
        "Renaming a reference enables it",
        "rename-resistant workflow documentation",
    ),
    (
        "requirements",
        '<span class="id">R-R1a</span>',
        '<span class="id">R-R1a-disabled</span>',
        "R-R1a requirement",
    ),
    (
        "requirements",
        '<span class="id">R-R2d</span>',
        '<span class="id">R-R2d-disabled</span>',
        "R-R2d requirement",
    ),
    (
        "requirements",
        "<tr><td>195</td>",
        "<tr><td>195-disabled</td>",
        "Appendix C #195",
    ),
    (
        "requirements",
        "<tr><td>196</td>",
        "<tr><td>196-disabled</td>",
        "Appendix C #196",
    ),
    (
        "hardening",
        "R-R1a — obsolete Dependabot submodule updater deleted",
        "R-R1a — obsolete Dependabot submodule updater retained",
        "R-R1a hardening ledger",
    ),
    (
        "hardening",
        "R-R2d — retained GitHub Actions references made schema-inert",
        "R-R2d — retained GitHub Actions references remain executable",
        "R-R2d hardening ledger",
    ),
    (
        "verify",
        "python3 scripts/verify-github-automation-authority.py --repo . --self-test",
        "true # GitHub-automation authority validator removed",
        "focused GitHub-automation mutation gate",
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
        "GitHub automation-authority semantic validation: OK"
        + (f" ({len(MUTATIONS)} mutations)" if args.self_test else "")
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, UnicodeError, VerificationError) as error:
        print(
            f"GitHub automation-authority verification failed: {error}",
            file=__import__("sys").stderr,
        )
        raise SystemExit(1)
