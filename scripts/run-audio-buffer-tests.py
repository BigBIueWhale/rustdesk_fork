#!/usr/bin/env python3
"""Execute the production portable PCM buffer with its locked ring implementation."""

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


PACKAGE = "rustdesk-audio-buffer"
INPUTS = ("Cargo.lock", "src/client.rs", "src/client/audio_buffer.rs",
          "scripts/test-audio-buffer.rs", "scripts/run-audio-buffer-tests.py")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def run(arguments, directory, *, timeout=90):
    result = subprocess.run(arguments, cwd=directory, check=False, timeout=timeout,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if len(result.stdout) > 2 * 1024 * 1024:
        raise ValueError("audio-buffer test output exceeds 2 MiB")
    print(result.stdout.decode("utf-8", errors="replace"), end="", flush=True)
    if result.returncode != 0:
        raise ValueError(f"audio-buffer command failed: {result.returncode}")
    return result.stdout


def main():
    if len(sys.argv) != 3 or os.geteuid() == 0 or os.getegid() == 0:
        raise ValueError("audio-buffer tests require source/config and a nonroot isolated container")
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
            raise ValueError("audio-buffer offline canary connected")
    print("R-B10 canary: build confirmed network-isolated (offline compile stage).", flush=True)
    with tempfile.TemporaryDirectory(prefix="audio-buffer-", dir="/tmp") as temporary:
        fixture = Path(temporary)
        (fixture / "Cargo.toml").write_text(
            f'[package]\nname = "{PACKAGE}"\nversion = "0.0.0"\nedition = "2021"\n'
            '[dependencies]\nringbuf = "=0.3.3"\nlog = "=0.4.22"\ndasp_sample = "=0.11.0"\n'
            '[[test]]\nname = "audio_buffer"\n'
            f'path = "{repo}/scripts/test-audio-buffer.rs"\n')
        run(["cargo", "generate-lockfile", "--offline", *config], fixture, timeout=30)
        lock_bytes = (fixture / "Cargo.lock").read_bytes()
        dependencies = []
        for item in tomllib.loads(lock_bytes.decode("utf-8"))["package"]:
            if item["name"] == PACKAGE and "source" not in item:
                continue
            expected = records.get((item["name"], item["version"]))
            if expected is None or any(item.get(k) != expected.get(k) for k in ("source", "checksum")):
                raise ValueError("audio-buffer dependency differs from the root lock")
            dependencies.append({k: item[k] for k in ("name", "version", "source", "checksum")})
        print(f"AUDIO_BUFFER_DEPENDENCIES=pass lock_sha256={digest(lock_bytes)} "
              f"records_sha256={digest(json.dumps(dependencies, sort_keys=True).encode())}", flush=True)
        output = run(["cargo", "test", "--offline", "--locked", "--test", "audio_buffer",
                      "--no-run", "--jobs", "1", "--message-format=json", *config], fixture)
        messages = [json.loads(line) for line in output.splitlines() if line.startswith(b"{")]
        artifacts = [Path(m["executable"]) for m in messages
                     if m.get("reason") == "compiler-artifact" and m.get("executable")
                     and m.get("target", {}).get("name") == "audio_buffer"]
        if len(artifacts) != 1 or not artifacts[0].is_file() or artifacts[0].is_symlink():
            raise ValueError("audio-buffer executable is absent or ambiguous")
        artifact = artifacts[0]
        artifact_sha = digest(artifact.read_bytes())
        run([str(artifact), "--test-threads=1", "--color", "never"], fixture, timeout=30)
        if digest(artifact.read_bytes()) != artifact_sha or (fixture / "Cargo.lock").read_bytes() != lock_bytes:
            raise ValueError("audio-buffer artifact or dependencies changed")
        for name, data in inputs.items():
            if (repo / name).read_bytes() != data:
                raise ValueError(f"audio-buffer source changed: {name}")
            print(f"AUDIO_BUFFER_INPUT=pass path={name} bytes={len(data)} sha256={digest(data)}")
        print(f"AUDIO_BUFFER_ARTIFACT=pass sha256={artifact_sha} tests=18 unchanged=before-after", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        raise SystemExit(f"Audio buffer tests: FAIL: {error}") from error
