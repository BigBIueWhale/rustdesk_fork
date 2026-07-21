#!/usr/bin/env python3
"""R-R2/R-R2c/R-R2d exact mobile build-authority semantic verifier."""

from __future__ import annotations

import argparse
import os
import re
import stat
from pathlib import Path
from typing import Dict, Tuple


class VerificationError(RuntimeError):
    pass


FORBIDDEN_PATHS: Tuple[str, ...] = (
    "flutter/build_android.sh",
    "flutter/build_android_deps.sh",
    "flutter/build_fdroid.sh",
    "flutter/build_ios.sh",
    "flutter/ios_arm64.sh",
    "flutter/ios_x64.sh",
    "flutter/ndk_arm.sh",
    "flutter/ndk_x64.sh",
    "flutter/ndk_x86.sh",
    "flutter/run.sh",
)

EXPECTED_HELPER = """#!/usr/bin/env bash
cargo ndk --platform 21 --target aarch64-linux-android build --locked --release --features flutter
"""

EXPECTED_FLUTTER_COMMAND = (
    "cd flutter && flutter build apk --release "
    "--target-platform android-arm64 --split-per-abi"
)


def require(source: str, needle: str, label: str) -> None:
    if needle not in source:
        raise VerificationError(f"missing {label}")


def require_count(source: str, needle: str, count: int, label: str) -> None:
    observed = source.count(needle)
    if observed != count:
        raise VerificationError(
            f"{label}: expected {count} occurrence(s), observed {observed}"
        )


def path_state(path: Path) -> str:
    return "present" if os.path.lexists(path) else "absent"


def regular_executable_state(path: Path) -> str:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return "absent"
    if stat.S_ISREG(metadata.st_mode) and metadata.st_mode & 0o111:
        return "regular-executable"
    if stat.S_ISLNK(metadata.st_mode):
        return "symlink"
    return "wrong-type-or-mode"


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


def top_level_flutter_shells(repo: Path) -> str:
    flutter = repo / "flutter"
    names = []
    for entry in flutter.iterdir():
        if entry.name.endswith(".sh") and (
            entry.is_file() or entry.is_symlink()
        ):
            names.append(f"flutter/{entry.name}")
    return "\n".join(sorted(names))


def load_sources(repo: Path) -> Dict[str, str]:
    sources = {
        "helper": (repo / "flutter/ndk_arm64.sh").read_text(encoding="utf-8"),
        "helper_state": regular_executable_state(repo / "flutter/ndk_arm64.sh"),
        "flutter_shell_inventory": top_level_flutter_shells(repo),
        "android_inner": (repo / "scripts/android-apk-build.sh").read_text(
            encoding="utf-8"
        ),
        "android_outer": (repo / "scripts/build-android.sh").read_text(
            encoding="utf-8"
        ),
        "online_fetch": (repo / "scripts/online-fetch.sh").read_text(
            encoding="utf-8"
        ),
        "disabled_workflow": (
            repo / ".github/workflows/flutter-build.yml.disabled"
        ).read_text(encoding="utf-8"),
        "disabled_workflow_state": regular_file_state(
            repo / ".github/workflows/flutter-build.yml.disabled"
        ),
        "enabled_workflow_state": path_state(
            repo / ".github/workflows/flutter-build.yml"
        ),
        "toolchain": (repo / "rust-toolchain.toml").read_text(encoding="utf-8"),
        "requirements": (repo / "requirements.html").read_text(encoding="utf-8"),
        "hardening": (repo / "HARDENING_STATUS.md").read_text(encoding="utf-8"),
        "verify": (repo / "scripts/verify.sh").read_text(encoding="utf-8"),
    }
    for relative in FORBIDDEN_PATHS:
        sources[f"path:{relative}"] = path_state(repo / relative)
    return sources


def active_flutter_build_commands(source: str) -> Tuple[str, ...]:
    commands = []
    for line in source.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if re.search(r"\bflutter build (?:apk|appbundle)\b", stripped):
            commands.append(stripped)
    return tuple(commands)


def validate(sources: Dict[str, str]) -> None:
    for relative in FORBIDDEN_PATHS:
        if sources[f"path:{relative}"] != "absent":
            raise VerificationError(
                f"obsolete mobile build authority remains present: {relative}"
            )

    if sources["flutter_shell_inventory"] != "flutter/ndk_arm64.sh":
        raise VerificationError(
            "top-level Flutter shell inventory is not exactly flutter/ndk_arm64.sh"
        )
    if sources["helper_state"] != "regular-executable":
        raise VerificationError(
            "flutter/ndk_arm64.sh is not a regular executable file"
        )
    if sources["helper"] != EXPECTED_HELPER:
        raise VerificationError(
            "flutter/ndk_arm64.sh is not the exact locked aarch64 Android command"
        )

    inner = sources["android_inner"]
    require_count(
        inner,
        "bash ./flutter/ndk_arm64.sh",
        1,
        "sole Android NDK helper invocation",
    )
    commands = active_flutter_build_commands(inner)
    if commands != (EXPECTED_FLUTTER_COMMAND,):
        raise VerificationError(
            "Android inner harness does not contain exactly the arm64 split-APK command"
        )
    for forbidden in (
        "flutter build appbundle",
        "--target armv7-linux-androideabi",
        "--target i686-linux-android",
        "--target x86_64-linux-android",
        "--target-platform android-arm,",
        "--target-platform android-x64",
        "--target-platform android-x86",
    ):
        if forbidden in inner:
            raise VerificationError(
                f"Android inner harness retains alternate target authority: {forbidden}"
            )

    outer = sources["android_outer"]
    require(outer, "scripts/android-apk-build.sh", "container-owned Android inner harness")
    require(outer, "--network=none", "networkless Android container execution")
    require(outer, '--user "$BUILD_UID:$BUILD_GID"', "nonroot Android container execution")
    if "--network=host" in outer or "--privileged" in outer or "--user 0:0" in outer:
        raise VerificationError("Android outer harness retains forbidden container authority")

    online = sources["online_fetch"]
    require_count(
        online,
        "stage_vcpkg_natives_arm64() {",
        1,
        "arm64 vcpkg staging definition",
    )
    require_count(
        online,
        "    stage_vcpkg_natives_arm64\n",
        1,
        "arm64 vcpkg staging dispatch",
    )
    require(
        online,
        '"$VR"/vcpkg install --triplet arm64-android --overlay-ports=/overlay',
        "exact arm64 Android vcpkg triplet",
    )
    require(online, "stage_android_ndk", "pinned Android NDK staging")
    require(online, "stage_android_sdk", "pinned Android SDK staging")
    require(online, "stage_gradle", "pinned Gradle staging")
    if "flutter/build_android_deps.sh" in online:
        raise VerificationError(
            "online cache authority still delegates to the deleted Android dependency helper"
        )

    if sources["enabled_workflow_state"] != "absent":
        raise VerificationError("active flutter-build.yml workflow authority is present")
    if sources["disabled_workflow_state"] != "regular":
        raise VerificationError("historical disabled Flutter workflow is not a regular file")
    disabled = sources["disabled_workflow"]
    require(
        disabled,
        "HISTORICAL INERT REFERENCE ONLY (R-R2/R-R2c/R-R2d)",
        "inert workflow marker",
    )
    require(disabled, "It MUST NOT become a build authority.", "inert workflow prohibition")
    require(disabled, "historical_on:", "schema-demoted historical workflow trigger")
    require(disabled, "historical_jobs:", "schema-demoted historical workflow jobs")
    if re.search(r"(?m)^(?:on|jobs):", disabled):
        raise VerificationError("historical Flutter reference retains active workflow schema keys")
    require(
        disabled,
        './flutter/build_android_deps.sh "${ANDROID_TARGET}"',
        "intentional dangling historical helper command",
    )
    if ".github/workflows/flutter-build.yml\n" in sources["toolchain"]:
        raise VerificationError("toolchain documentation names a nonexistent active workflow")

    for source, needle, label in (
        (sources["requirements"], '<span class="id">R-R2c</span>', "R-R2c requirement"),
        (
            sources["requirements"],
            "One executable mobile build authority",
            "R-R2c single-authority title",
        ),
        (sources["requirements"], "<tr><td>194</td>", "Appendix C #194"),
        (
            sources["hardening"],
            "R-R2c — alternate mobile build authorities deleted",
            "R-R2c hardening ledger",
        ),
        (
            sources["verify"],
            'echo "== (6c-a3) exact mobile build authority (R-R2/R-R2c) =="',
            "shared mobile build-authority gate",
        ),
        (
            sources["verify"],
            "python3 scripts/verify-mobile-build-authority.py --repo . --self-test",
            "focused semantic mutation gate",
        ),
    ):
        require(source, needle, label)


Mutation = Tuple[str, str, str, str]


MUTATIONS: Tuple[Mutation, ...] = tuple(
    (
        f"path:{relative}",
        "absent",
        "present",
        f"restored obsolete path {relative}",
    )
    for relative in FORBIDDEN_PATHS
) + (
    (
        "flutter_shell_inventory",
        "flutter/ndk_arm64.sh",
        "flutter/ndk_arm64.sh\nflutter/new_mobile_builder.sh",
        "alternate top-level Flutter shell",
    ),
    (
        "helper_state",
        "regular-executable",
        "symlink",
        "symlinked arm64 helper",
    ),
    (
        "helper",
        "--target aarch64-linux-android",
        "--target x86_64-linux-android",
        "alternate NDK helper target",
    ),
    (
        "android_inner",
        "bash ./flutter/ndk_arm64.sh",
        "true # arm64 helper removed",
        "missing arm64 helper dispatch",
    ),
    (
        "android_inner",
        EXPECTED_FLUTTER_COMMAND,
        EXPECTED_FLUTTER_COMMAND.replace("android-arm64", "android-x64"),
        "alternate Flutter APK target",
    ),
    (
        "android_inner",
        "flutter build apk --release",
        "flutter build appbundle --release",
        "Android app-bundle authority",
    ),
    (
        "android_outer",
        "--name rustdesk-fork-harness-apk \\\n        --network=none",
        "--name rustdesk-fork-harness-apk \\\n        --network=host",
        "host-network Android container",
    ),
    (
        "android_outer",
        '--network=none \\\n        --user "$BUILD_UID:$BUILD_GID" \\\n        -e SOURCE_DATE_EPOCH',
        '--network=none \\\n        --user 0:0 \\\n        -e SOURCE_DATE_EPOCH',
        "root Android container",
    ),
    (
        "online_fetch",
        "    stage_vcpkg_natives_arm64\n",
        "    true # arm64 staging dispatch removed\n",
        "missing arm64 native staging dispatch",
    ),
    (
        "online_fetch",
        "--triplet arm64-android",
        "--triplet x64-android",
        "alternate vcpkg target triplet",
    ),
    (
        "online_fetch",
        "not manifest mode:",
        "delegated to flutter/build_android_deps.sh; not manifest mode:",
        "deleted dependency-helper delegation",
    ),
    (
        "enabled_workflow_state",
        "absent",
        "present",
        "enabled Flutter workflow",
    ),
    (
        "disabled_workflow_state",
        "regular",
        "symlink",
        "nonregular historical workflow",
    ),
    (
        "disabled_workflow",
        "HISTORICAL INERT REFERENCE ONLY (R-R2/R-R2c/R-R2d)",
        "HISTORICAL REFERENCE",
        "inert workflow marker",
    ),
    (
        "disabled_workflow",
        "historical_on:",
        "on:",
        "active workflow trigger schema",
    ),
    (
        "disabled_workflow",
        "historical_jobs:",
        "jobs:",
        "active workflow jobs schema",
    ),
    (
        "requirements",
        '<span class="id">R-R2c</span>',
        '<span class="id">R-R2c-disabled</span>',
        "R-R2c requirement",
    ),
    (
        "requirements",
        "<tr><td>194</td>",
        "<tr><td>194-disabled</td>",
        "Appendix C #194",
    ),
    (
        "hardening",
        "R-R2c — alternate mobile build authorities deleted",
        "R-R2c — alternate mobile build authorities retained",
        "R-R2c hardening ledger",
    ),
    (
        "verify",
        'echo "== (6c-a3) exact mobile build authority (R-R2/R-R2c) =="',
        'echo "== (6c-a3) mobile build helper inventory skipped =="',
        "shared mobile build-authority gate",
    ),
    (
        "verify",
        "python3 scripts/verify-mobile-build-authority.py --repo . --self-test",
        "true # focused mobile authority validator removed",
        "focused semantic mutation gate",
    ),
    (
        "toolchain",
        "That matrix survives here\n# only as a `.disabled` historical reference",
        "That matrix survives here as .github/workflows/flutter-build.yml\n# only as a historical reference",
        "active-workflow toolchain documentation",
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
        "mobile build-authority semantic validation: OK"
        + (f" ({len(MUTATIONS)} mutations)" if args.self_test else "")
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, UnicodeError, VerificationError) as error:
        print(f"mobile build-authority verification failed: {error}", file=__import__("sys").stderr)
        raise SystemExit(1)
