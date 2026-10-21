#!/usr/bin/env python3
"""Run the exact controlled-egress implementation and its five existing Rust tests."""

import errno
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import time
import tomllib


PACKAGE = "rustdesk-control-egress"
INPUTS = (
    "Cargo.lock", "src/server/connection.rs", "libs/hbb_common/src/cpace.rs",
    "libs/hbb_common/build.rs", "libs/hbb_common/src/protos/mod.rs",
    "libs/hbb_common/protos/message.proto", "libs/hbb_common/protos/rendezvous.proto",
    "scripts/test-control-egress.rs", "scripts/run-control-egress-tests.py",
)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def run(arguments, directory, *, timeout=30):
    result = subprocess.run(arguments, cwd=directory, check=False, timeout=timeout,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if len(result.stdout) > 2 * 1024 * 1024:
        raise ValueError("controlled-egress output exceeds 2 MiB")
    print(result.stdout.decode("utf-8", errors="replace"), end="", flush=True)
    if result.returncode != 0:
        raise ValueError(f"controlled-egress command failed: {result.returncode}")
    return result.stdout


def between(source, start, end):
    if source.count(start) != 1 or source.count(end) != 1:
        raise ValueError("controlled-egress source boundary is missing or ambiguous")
    first = source.index(start)
    last = source.index(end)
    if first >= last:
        raise ValueError("controlled-egress source boundaries are reversed")
    return source[first:last]


def main():
    if (len(sys.argv) != 3 or (os.geteuid(), os.getegid()) != (1000, 1000)
            or Path.cwd() != Path("/source")
            or os.environ.get("CARGO_TARGET_DIR") != "/cargo-target"):
        raise ValueError("controlled-egress tests require their isolated guest entry")
    repo = Path(sys.argv[1]).resolve(strict=True)
    config_path = Path(sys.argv[2]).resolve(strict=True)
    if repo != Path("/source") or config_path != Path("/tmp/cargo-home/config.toml"):
        raise ValueError("controlled-egress source/config paths differ")
    config = ["--config", str(config_path)]
    inputs = {name: (repo / name).read_bytes() for name in INPUTS}
    packages = tomllib.loads(inputs["Cargo.lock"].decode("utf-8"))["package"]
    records = {(p["name"], p["version"], p["source"]): p
               for p in packages if "source" in p}
    connection = inputs["src/server/connection.rs"].decode("utf-8")
    snippets = {
        "queue.rs": between(connection, "const CONTROL_EGRESS_WAKE_CAPACITY:",
                            "#[derive(Default)]\nstruct AudioEgressState"),
        "tests.rs": between(connection, "#[cfg(test)]\nmod control_egress_tests {",
                            "#[cfg(test)]\nmod audio_egress_tests {"),
    }
    limits = re.findall(r"^pub const MAX_SESSION_PACKET: usize = [0-9 *]+;\n",
                        inputs["libs/hbb_common/src/cpace.rs"].decode("utf-8"), re.MULTILINE)
    if len(limits) != 1:
        raise ValueError("controlled-egress production packet limit is ambiguous")
    snippets["packet-limit.rs"] = limits[0]
    with socket.socket() as canary:
        try:
            canary.connect(("192.0.2.1", 9))
        except OSError as error:
            if error.errno != errno.ENETUNREACH:
                raise
        else:
            raise ValueError("controlled-egress offline canary connected")
    print("R-B10 canary: build confirmed network-isolated (offline compile stage).", flush=True)
    with tempfile.TemporaryDirectory(prefix="control-egress-", dir="/tmp") as temporary:
        fixture = Path(temporary)
        (fixture / "protos").mkdir()
        for name in ("message.proto", "rendezvous.proto"):
            (fixture / "protos" / name).write_bytes(inputs[f"libs/hbb_common/protos/{name}"])
        (fixture / "build.rs").write_bytes(inputs["libs/hbb_common/build.rs"])
        for name, body in snippets.items():
            (fixture / name).write_text(body)
            print(f"CONTROL_EGRESS_SOURCE=pass part={name} bytes={len(body.encode())} "
                  f"sha256={digest(body.encode())}", flush=True)
        os.environ["CONTROL_EGRESS_SOURCE"] = str(fixture / "queue.rs")
        os.environ["CONTROL_EGRESS_TESTS"] = str(fixture / "tests.rs")
        os.environ["CONTROL_EGRESS_LIMIT"] = str(fixture / "packet-limit.rs")

        def version(name):
            versions = {p["version"] for p in packages if p["name"] == name}
            if len(versions) != 1:
                raise ValueError(f"controlled-egress dependency version is ambiguous: {name}")
            return versions.pop()

        (fixture / "Cargo.toml").write_text(
            f'[package]\nname = "{PACKAGE}"\nversion = "0.0.0"\nedition = "2021"\n'
            '[dependencies]\n'
            f'bytes = "={version("bytes")}"\nlog = "={version("log")}"\n'
            f'sodiumoxide = "={version("sodiumoxide")}"\n'
            f'protobuf = {{ version = "={version("protobuf")}", features = ["with-bytes"] }}\n'
            f'tokio = {{ version = "={version("tokio")}", features = ["full"] }}\n'
            '[build-dependencies]\n'
            f'protobuf-codegen = "={version("protobuf-codegen")}"\n'
            '[[test]]\nname = "control_egress"\n'
            f'path = "{repo}/scripts/test-control-egress.rs"\n')
        (fixture / "Cargo.lock").write_bytes(inputs["Cargo.lock"])
        run(["cargo", "metadata", "--offline", "--format-version=1", *config], fixture)
        lock_bytes = (fixture / "Cargo.lock").read_bytes()
        dependencies = []
        for item in tomllib.loads(lock_bytes.decode("utf-8"))["package"]:
            if item["name"] == PACKAGE and "source" not in item:
                continue
            expected = records.get((item["name"], item["version"], item.get("source", "")))
            if expected is None or item.get("checksum") != expected.get("checksum"):
                raise ValueError(f"controlled-egress dependency differs from root lock: {item['name']}")
            dependencies.append({k: item[k] for k in ("name", "version", "source", "checksum")
                                 if k in item})
        print(f"CONTROL_EGRESS_DEPENDENCIES=pass lock_sha256={digest(lock_bytes)} "
              f"records_sha256={digest(json.dumps(dependencies, sort_keys=True).encode())}", flush=True)
        started = time.monotonic()
        output = run(["cargo", "test", "--offline", "--locked", "--test", "control_egress",
                      "--no-run", "--jobs", "1", "--message-format=json", *config],
                     fixture, timeout=180)
        messages = [json.loads(line) for line in output.splitlines() if line.startswith(b"{")]
        artifacts = [Path(m["executable"]) for m in messages
                     if m.get("reason") == "compiler-artifact" and m.get("executable")
                     and m.get("manifest_path") == str(fixture / "Cargo.toml")
                     and m.get("target", {}).get("name") == "control_egress"
                     and m.get("target", {}).get("src_path") == str(repo / "scripts/test-control-egress.rs")
                     and m.get("profile", {}).get("test") is True]
        if ([m.get("success") for m in messages if m.get("reason") == "build-finished"] != [True]
                or len(artifacts) != 1
                or not re.fullmatch(r"/cargo-target/debug/deps/control_egress-[0-9a-f]{16}",
                                    str(artifacts[0]))
                or not artifacts[0].is_file() or artifacts[0].is_symlink()):
            raise ValueError("controlled-egress lacks one completed exact test artifact")
        artifact = artifacts[0]
        artifact_sha = digest(artifact.read_bytes())
        print(f"CONTROL_EGRESS_BUILD=pass seconds={time.monotonic() - started:.3f} "
              f"sha256={artifact_sha}", flush=True)
        run([str(artifact), "--test-threads=1", "--color", "never", "--show-output"], fixture)
        if digest(artifact.read_bytes()) != artifact_sha or (fixture / "Cargo.lock").read_bytes() != lock_bytes:
            raise ValueError("controlled-egress artifact or dependencies changed")
        for name, body in snippets.items():
            if (fixture / name).read_bytes() != body.encode():
                raise ValueError("controlled-egress extracted source changed")
        for name, body in inputs.items():
            if (repo / name).read_bytes() != body:
                raise ValueError(f"controlled-egress source changed: {name}")
            print(f"CONTROL_EGRESS_INPUT=pass path={name} bytes={len(body)} sha256={digest(body)}")
        print(f"CONTROL_EGRESS_ARTIFACT=pass sha256={artifact_sha} tests=5 unchanged=before-after",
              flush=True)


if __name__ == "__main__":
    try:
        main()
    except (OSError, UnicodeError, ValueError, subprocess.TimeoutExpired) as error:
        raise SystemExit(f"Controlled-egress tests: FAIL: {error}") from error
