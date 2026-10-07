#!/usr/bin/env python3
"""Select the sole hbb_common libtest artifact from the isolated Cargo build."""

import json
import re
import sys


MAX_OUTPUT = 4 * 1024 * 1024


def select_artifact(output):
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
        if (message.get("manifest_path") == "/source/libs/hbb_common/Cargo.toml"
                and isinstance(target, dict) and isinstance(profile, dict)
                and target.get("name") == "hbb_common"
                and target.get("kind") == ["lib"]
                and target.get("src_path") == "/source/libs/hbb_common/src/lib.rs"
                and profile.get("test") is True):
            artifacts.append(message.get("executable"))
    if len(finished) != 1 or finished[0] is not True:
        raise ValueError("Cargo build lacks one successful completion")
    if len(artifacts) != 1 or not isinstance(artifacts[0], str):
        raise ValueError("Cargo build lacks one exact hbb_common libtest artifact")
    executable = artifacts[0]
    if not re.fullmatch(r"/cargo-target/debug/deps/hbb_common-[0-9a-f]{16}", executable):
        raise ValueError("hbb_common executable is outside the private test target")
    return executable


if __name__ == "__main__":
    try:
        with open(sys.argv[1], "rb") as stream:
            print(select_artifact(stream.read(MAX_OUTPUT + 1)))
    except (OSError, ValueError, IndexError) as error:
        sys.exit(f"hbb_common artifact selection failed: {error}")
