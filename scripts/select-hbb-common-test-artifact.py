#!/usr/bin/env python3
"""Select the exact shared-library libtest artifact from an isolated Cargo build."""

import json
import re
import sys


MAX_OUTPUT = 4 * 1024 * 1024


def select_artifact(output, package="hbb_common", source_root="/source"):
    if package not in ("hbb_common", "clipboard") or source_root not in (
            "/source", "/cargo-target/fuse-test-source"):
        raise ValueError("Unexpected library-test identity")
    if len(output) > MAX_OUTPUT:
        raise ValueError("Cargo artifact output exceeds 4 MiB")
    artifacts = []
    finished = []
    for line in output.splitlines():
        # Cargo cannot control output from procedural macros. It is not metadata.
        if not line.startswith(b"{"):
            continue
        message = json.loads(line)
        if not isinstance(message, dict):
            raise ValueError("Cargo message is not an object")
        if message.get("reason") == "build-finished":
            finished.append(message.get("success"))
        if message.get("reason") != "compiler-artifact":
            continue
        target = message.get("target")
        profile = message.get("profile")
        if (message.get("manifest_path") == f"{source_root}/libs/{package}/Cargo.toml"
                and isinstance(target, dict) and isinstance(profile, dict)
                and target.get("name") == package
                and target.get("kind") == ["lib"]
                and target.get("src_path") == f"{source_root}/libs/{package}/src/lib.rs"
                and profile.get("test") is True):
            artifacts.append(message.get("executable"))
    if len(finished) != 1 or finished[0] is not True:
        raise ValueError("Cargo build lacks one successful completion")
    if len(artifacts) != 1 or not isinstance(artifacts[0], str):
        raise ValueError(f"Cargo build lacks one exact {package} libtest artifact")
    executable = artifacts[0]
    if not re.fullmatch(rf"/cargo-target/debug/deps/{package}-[0-9a-f]{{16}}", executable):
        raise ValueError(f"{package} executable is outside the private test target")
    return executable


if __name__ == "__main__":
    try:
        with open(sys.argv[1], "rb") as stream:
            print(select_artifact(stream.read(MAX_OUTPUT + 1)))
    except (OSError, ValueError, IndexError) as error:
        sys.exit(f"hbb_common artifact selection failed: {error}")
