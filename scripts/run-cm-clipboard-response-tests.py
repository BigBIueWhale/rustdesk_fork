#!/usr/bin/env python3
"""Execute the production CM clipboard response assembly in isolation."""
import errno
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import tomllib

PACKAGE = "rustdesk-cm-clipboard-response"
INPUTS = ("Cargo.lock", "src/ipc.rs", "src/ipc/clipboard_non_file.rs",
          "src/server/clipboard_service.rs", "scripts/run-cm-clipboard-response-tests.py",
          "src/clipboard.rs", "src/clipboard/limits.rs", "src/ui_cm_interface.rs",
          "libs/hbb_common/src/bytes_codec.rs",
          "libs/hbb_common/build.rs", "libs/hbb_common/src/protos/mod.rs",
          "libs/hbb_common/protos/message.proto", "libs/hbb_common/protos/rendezvous.proto")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def run(arguments, directory, timeout):
    result = subprocess.run(arguments, cwd=directory, timeout=timeout,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            env={key: value for key, value in os.environ.items()
                                 if not key.startswith("RD_CLIPBOARD_PREPARE_ALLOC_")})
    if len(result.stdout) > 2 * 1024 * 1024:
        raise ValueError("CM clipboard response output exceeds 2 MiB")
    print(result.stdout.decode("utf-8", errors="replace"), end="", flush=True)
    if result.returncode:
        raise ValueError(f"CM clipboard response command failed: {result.returncode}")
    return result.stdout


def main():
    if len(sys.argv) != 3 or os.geteuid() == 0 or os.getegid() == 0:
        raise ValueError("CM clipboard response tests require a nonroot isolated container")
    repo = Path(sys.argv[1]).resolve(strict=True)
    config = ["--config", str(Path(sys.argv[2]).resolve(strict=True))]
    inputs = {name: (repo / name).read_bytes() for name in INPUTS}
    locked = {(item["name"], item["version"]): item
              for item in tomllib.loads(inputs["Cargo.lock"].decode())["package"] if "source" in item}
    with socket.socket() as canary:
        try:
            canary.connect(("192.0.2.1", 9))
        except OSError as error:
            if error.errno != errno.ENETUNREACH:
                raise
        else:
            raise ValueError("CM clipboard response offline canary connected")
    print("R-B10 canary: build confirmed network-isolated (offline compile stage).", flush=True)
    with tempfile.TemporaryDirectory(prefix="cm-clipboard-response-", dir="/tmp") as directory:
        fixture = Path(directory)
        (fixture / "protos").mkdir()
        for name in ("message.proto", "rendezvous.proto"):
            (fixture / "protos" / name).write_bytes(inputs[f"libs/hbb_common/protos/{name}"])
        (fixture / "build.rs").write_bytes(inputs["libs/hbb_common/build.rs"])
        (fixture / "Cargo.toml").write_text(
            f'[package]\nname = "{PACKAGE}"\nversion = "0.0.0"\nedition = "2021"\n'
            '[dependencies]\nbytes = { version = "=1.11.1", features = ["serde"] }\n'
            'serde = "=1.0.228"\nserde_derive = "=1.0.228"\n'
            'protobuf = { version = "=3.7.2", features = ["with-bytes"] }\n'
            'tokio-util = { version = "=0.7.15", features = ["codec"] }\n'
            'tokio = { version = "=1.44.2", features = ["rt", "macros", "net", "io-util", "time"] }\n'
            'futures = "=0.3.30"\n'
            '[build-dependencies]\nprotobuf-codegen = "=3.7.2"\n'
            '[dev-dependencies]\nserde_json = "=1.0.118"\n'
            '[lib]\nname = "rustdesk_cm_clipboard_response"\npath = "lib.rs"\n')
        (fixture / "lib.rs").write_text(
            'extern crate self as hbb_common;\npub use bytes;\npub use protobuf;\npub use tokio_util;\n'
            'mod clipboard {\n'
            f'#[path = "{repo}/src/clipboard/limits.rs"] pub(crate) mod limits;\n}}\n'
            f'#[path = "{repo}/libs/hbb_common/src/bytes_codec.rs"] pub mod bytes_codec;\n'
            f'#[path = "{repo}/libs/hbb_common/src/protos/mod.rs"] pub mod protos;\n'
            'pub use protos::message as message_proto;\n'
            f'#[path = "{repo}/src/ipc/clipboard_non_file.rs"] mod clipboard_non_file;\n')
        run(["cargo", "generate-lockfile", "--offline", *config], fixture, 30)
        lock_bytes = (fixture / "Cargo.lock").read_bytes()
        dependencies = []
        for item in tomllib.loads(lock_bytes.decode())["package"]:
            if item["name"] == PACKAGE and "source" not in item:
                continue
            expected = locked.get((item["name"], item["version"]))
            if expected is None or any(item.get(key) != expected.get(key) for key in ("source", "checksum")):
                raise ValueError("CM clipboard response dependency differs from root lock")
            dependencies.append({key: item[key] for key in ("name", "version", "source", "checksum")})
        print(f"CM_CLIPBOARD_RESPONSE_DEPENDENCIES=pass lock_sha256={digest(lock_bytes)} "
              f"records_sha256={digest(json.dumps(dependencies, sort_keys=True).encode())}", flush=True)
        output = run(["cargo", "test", "--offline", "--locked", "--lib", "--no-run", "--jobs", "1",
                      "--message-format=json", *config], fixture, 180)
        messages = [json.loads(line) for line in output.splitlines() if line.startswith(b"{")]
        candidates = [Path(item["executable"]) for item in messages
                      if item.get("reason") == "compiler-artifact" and item.get("executable")
                      and item.get("manifest_path") == str(fixture / "Cargo.toml")
                      and item.get("target", {}).get("name") == "rustdesk_cm_clipboard_response"
                      and item.get("target", {}).get("src_path") == str(fixture / "lib.rs")
                      and item.get("target", {}).get("kind") == ["lib"]
                      and item.get("profile", {}).get("test") is True]
        if len(candidates) != 1 or candidates[0].is_symlink() or not candidates[0].is_file():
            raise ValueError("CM clipboard response artifact is absent or ambiguous")
        artifact = candidates[0]
        artifact_sha = digest(artifact.read_bytes())
        print(f"CM_CLIPBOARD_RESPONSE_ARTIFACT_BEFORE=observed sha256={artifact_sha} tests=35", flush=True)
        try:
            run([str(artifact), "--test-threads=1", "--color", "never", "--show-output"], fixture, 20)
        finally:
            if digest(artifact.read_bytes()) != artifact_sha:
                raise ValueError("CM clipboard response artifact changed during execution")
            print(f"CM_CLIPBOARD_RESPONSE_ARTIFACT_AFTER=observed sha256={artifact_sha} tests=35 unchanged=before-after", flush=True)
        if digest(artifact.read_bytes()) != artifact_sha or (fixture / "Cargo.lock").read_bytes() != lock_bytes:
            raise ValueError("CM clipboard response artifact or lock changed")
        for name, data in inputs.items():
            if (repo / name).read_bytes() != data:
                raise ValueError(f"CM clipboard response source changed: {name}")
            print(f"CM_CLIPBOARD_RESPONSE_INPUT=pass path={name} bytes={len(data)} sha256={digest(data)}")
        print(f"CM_CLIPBOARD_RESPONSE_ARTIFACT=pass sha256={artifact_sha} tests=35 unchanged=before-after", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        raise SystemExit(f"CM clipboard response component tests: FAIL: {error}") from error
