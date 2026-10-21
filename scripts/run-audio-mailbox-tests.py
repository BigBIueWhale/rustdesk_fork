#!/usr/bin/env python3
"""Execute the production mailbox with the production generated protobuf types."""

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


PACKAGE = "rustdesk-audio-mailbox"
INPUTS = (
    "Cargo.lock", "src/client.rs", "src/client/audio_mailbox.rs", "src/client/audio_buffer.rs",
    "src/client/io_loop.rs", "src/server/connection.rs",
    "libs/hbb_common/build.rs", "libs/hbb_common/src/protos/mod.rs",
    "libs/hbb_common/protos/message.proto", "libs/hbb_common/protos/rendezvous.proto",
    "scripts/test-audio-mailbox.rs", "scripts/run-audio-mailbox-tests.py",
)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def run(arguments, directory, *, timeout=90):
    result = subprocess.run(arguments, cwd=directory, check=False, timeout=timeout,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if len(result.stdout) > 2 * 1024 * 1024:
        raise ValueError("mailbox test output exceeds 2 MiB")
    print(result.stdout.decode("utf-8", errors="replace"), end="", flush=True)
    if result.returncode != 0:
        raise ValueError(f"mailbox test command failed: {result.returncode}")
    return result.stdout


def main():
    if len(sys.argv) != 3 or os.geteuid() == 0 or os.getegid() == 0:
        raise ValueError("mailbox tests require source/config and a nonroot isolated container")
    repo = Path(sys.argv[1]).resolve(strict=True)
    config = ["--config", str(Path(sys.argv[2]).resolve(strict=True))]
    inputs = {name: (repo / name).read_bytes() for name in INPUTS}
    root_lock = tomllib.loads(inputs["Cargo.lock"].decode("utf-8"))
    records = {(p["name"], p["version"]): p for p in root_lock["package"] if "source" in p}
    with socket.socket() as canary:
        try:
            canary.connect(("192.0.2.1", 9))
        except OSError as error:
            if error.errno != errno.ENETUNREACH:
                raise
        else:
            raise ValueError("mailbox test offline canary connected")
    print("R-B10 canary: build confirmed network-isolated (offline compile stage).", flush=True)
    with tempfile.TemporaryDirectory(prefix="audio-mailbox-", dir="/tmp") as temporary:
        fixture = Path(temporary)
        (fixture / "protos").mkdir()
        for name in ("message.proto", "rendezvous.proto"):
            (fixture / "protos" / name).write_bytes(inputs[f"libs/hbb_common/protos/{name}"])
        (fixture / "build.rs").write_bytes(inputs["libs/hbb_common/build.rs"])
        client = inputs["src/client.rs"].decode("utf-8")
        start = client.index("    fn build_output_stream<T:")
        end = client.index("\n}\n\n/// Video handler", start)
        method = client[start:end]
        callback_start = method.index("        let err_fn = move |err| {")
        callback_end = method.index("\n        };", callback_start) + len("\n        };")
        callback = method[callback_start:callback_end]
        generated = (
            "impl AudioHandler {\n" + method + "\n}\n"
            "fn candidate_error_callback(failure: audio_mailbox::AudioOutputCallback) "
            "-> impl FnMut(cpal::StreamError) {\n" + callback + "\nerr_fn\n}\n"
        ).encode("utf-8")
        (fixture / "output-method.rs").write_bytes(generated)
        os.environ["AUDIO_OUTPUT_METHOD"] = str(fixture / "output-method.rs")
        print(f"AUDIO_MAILBOX_METHOD=compile-only method_sha256={digest(method.encode())} "
              f"callback_sha256={digest(callback.encode())} generated_sha256={digest(generated)}",
              flush=True)
        (fixture / "Cargo.toml").write_text(
            f'[package]\nname = "{PACKAGE}"\nversion = "0.0.0"\nedition = "2021"\n'
            '[dependencies]\nbytes = "=1.11.1"\n'
            'protobuf = { version = "=3.7.2", features = ["with-bytes"] }\n'
            'ringbuf = "=0.3.3"\nlog = "=0.4.22"\nanyhow = "1.0"\n'
            'cpal = { git = "https://github.com/rustdesk-org/cpal", branch = "osx-screencapturekit" }\n'
            '[build-dependencies]\nprotobuf-codegen = "=3.7.2"\n'
            '[[test]]\nname = "audio_mailbox"\n'
            f'path = "{repo}/scripts/test-audio-mailbox.rs"\n')
        # The root lock pins the vendored CPAL Git revision before offline resolution.
        (fixture / "Cargo.lock").write_bytes(inputs["Cargo.lock"])
        run(["cargo", "metadata", "--offline", "--format-version=1", *config],
            fixture, timeout=30)
        lock_bytes = (fixture / "Cargo.lock").read_bytes()
        dependencies = []
        for item in tomllib.loads(lock_bytes.decode("utf-8"))["package"]:
            if item["name"] == PACKAGE and "source" not in item:
                continue
            expected = records.get((item["name"], item["version"]))
            if expected is None or any(item.get(k) != expected.get(k) for k in ("source", "checksum")):
                raise ValueError(f"mailbox fixture dependency differs from the root lock: {item['name']} {item['version']}")
            dependencies.append({k: item[k] for k in ("name", "version", "source", "checksum") if k in item})
        print(f"AUDIO_MAILBOX_DEPENDENCIES=pass lock_sha256={digest(lock_bytes)} "
              f"records_sha256={digest(json.dumps(dependencies, sort_keys=True).encode())}", flush=True)
        output = run(["cargo", "test", "--offline", "--locked", "--test", "audio_mailbox",
                      "--no-run", "--jobs", "1", "--message-format=json", *config], fixture)
        messages = [json.loads(line) for line in output.splitlines() if line.startswith(b"{")]
        artifacts = [Path(m["executable"]) for m in messages
                     if m.get("reason") == "compiler-artifact" and m.get("executable")
                     and m.get("target", {}).get("name") == "audio_mailbox"]
        if len(artifacts) != 1 or not artifacts[0].is_file() or artifacts[0].is_symlink():
            raise ValueError("mailbox test executable is absent or ambiguous")
        artifact = artifacts[0]
        artifact_sha = digest(artifact.read_bytes())
        run([str(artifact), "--test-threads=1", "--color", "never", "--show-output"], fixture, timeout=30)
        if digest(artifact.read_bytes()) != artifact_sha or (fixture / "Cargo.lock").read_bytes() != lock_bytes:
            raise ValueError("mailbox test artifact or dependencies changed")
        for name, data in inputs.items():
            if (repo / name).read_bytes() != data:
                raise ValueError(f"mailbox test source changed: {name}")
            print(f"AUDIO_MAILBOX_INPUT=pass path={name} bytes={len(data)} sha256={digest(data)}")
        if (fixture / "output-method.rs").read_bytes() != generated:
            raise ValueError("extracted output method changed")
        print(f"AUDIO_MAILBOX_ARTIFACT=pass sha256={artifact_sha} tests=32 unchanged=before-after", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        raise SystemExit(f"Audio mailbox tests: FAIL: {error}") from error
