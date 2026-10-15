#!/usr/bin/env python3
"""Select an exact shared-library or CPace libtest artifact from an isolated Cargo build."""

import json
import re
import sys


MAX_OUTPUT = 4 * 1024 * 1024


def select_artifact(output, package="hbb_common", source_root="/source"):
    manifest_package, executable_dir = package, "/cargo-target/debug/deps"
    if package == "cpace_it" and source_root == "/source":
        name, kind, source = "handshake", ["test"], "tests/handshake.rs"
    elif package == "probe_client" and source_root == "/source":
        manifest_package = "hbb_common"
        name, kind, source = "probe_client", ["example"], "../../examples/probe_client.rs"
        executable_dir = "/cargo-target/debug/examples"
    elif package in ("hbb_common", "clipboard") and source_root in (
            "/source", "/cargo-target/fuse-test-source"):
        name, kind, source = package, ["lib"], "src/lib.rs"
    else:
        raise ValueError("Unexpected test identity")
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
        sources = (f"{source_root}/libs/{manifest_package}/{source}",)
        if package == "probe_client":
            sources += (f"{source_root}/examples/probe_client.rs",)
        if (message.get("manifest_path") == f"{source_root}/libs/{manifest_package}/Cargo.toml"
                and isinstance(target, dict) and isinstance(profile, dict)
                and target.get("name") == name
                and target.get("kind") == kind
                and target.get("src_path") in sources
                and profile.get("test") is True):
            artifacts.append(message.get("executable"))
    if len(finished) != 1 or finished[0] is not True:
        raise ValueError("Cargo build lacks one successful completion")
    if len(artifacts) != 1 or not isinstance(artifacts[0], str):
        raise ValueError(f"Cargo build lacks one exact {package} libtest artifact")
    executable = artifacts[0]
    if not re.fullmatch(rf"{executable_dir}/{name}-[0-9a-f]{{16}}", executable):
        raise ValueError(f"{package} executable is outside the private test target")
    return executable


if __name__ == "__main__":
    try:
        if len(sys.argv) not in (2, 3):
            raise ValueError("Expected Cargo output and optional closed package identity")
        with open(sys.argv[1], "rb") as stream:
            print(select_artifact(stream.read(MAX_OUTPUT + 1),
                                  sys.argv[2] if len(sys.argv) == 3 else "hbb_common"))
    except (OSError, ValueError, IndexError) as error:
        sys.exit(f"hbb_common artifact selection failed: {error}")
