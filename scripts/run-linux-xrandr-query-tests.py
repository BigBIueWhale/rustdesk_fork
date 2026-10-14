#!/usr/bin/env python3
"""Build and execute the production Linux query boundary in an isolated container."""

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


PACKAGE = "rustdesk-linux-xrandr-query"
INPUTS = ("Cargo.lock", "src/platform/linux.rs", "src/platform/linux/xrandr_query.rs",
          "libs/hbb_common/src/lib.rs", "scripts/test-linux-xrandr-query.rs",
          "scripts/run-linux-xrandr-query-tests.py")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def run(arguments, directory, *, timeout=90):
    result = subprocess.run(arguments, cwd=directory, check=False, timeout=timeout,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if len(result.stdout) > 2 * 1024 * 1024:
        raise ValueError("query test output exceeds 2 MiB")
    print(result.stdout.decode("utf-8", errors="replace"), end="", flush=True)
    if result.returncode != 0:
        raise ValueError(f"query test command failed: {result.returncode}")
    return result.stdout


def main():
    if os.geteuid() == 0 or os.getegid() == 0:
        raise ValueError("query tests require the nonroot isolated container")
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
            raise ValueError("query test offline canary connected")
    print("R-B10 canary: build confirmed network-isolated (offline compile stage).", flush=True)
    with tempfile.TemporaryDirectory(prefix="xrandr-query-", dir="/tmp") as temporary:
        fixture = Path(temporary)
        (fixture / "Cargo.toml").write_text(
            f'[package]\nname = "{PACKAGE}"\nversion = "0.0.0"\nedition = "2021"\n'
            '[dependencies]\nregex = "=1.11.1"\n[[test]]\nname = "xrandr_query"\n'
            f'path = "{repo}/scripts/test-linux-xrandr-query.rs"\n')
        run(["cargo", "generate-lockfile", "--offline", *config], fixture, timeout=30)
        lock_bytes = (fixture / "Cargo.lock").read_bytes()
        dependencies = []
        for item in tomllib.loads(lock_bytes.decode("utf-8"))["package"]:
            if item["name"] == PACKAGE and "source" not in item:
                continue
            expected = records.get((item["name"], item["version"]))
            if expected is None or any(item.get(k) != expected.get(k) for k in ("source", "checksum")):
                raise ValueError("query fixture dependency differs from the root lock")
            dependencies.append({k: item[k] for k in ("name", "version", "source", "checksum")})
        print(f"LINUX_XRANDR_QUERY_DEPENDENCIES=pass lock_sha256={digest(lock_bytes)} "
              f"records_sha256={digest(json.dumps(dependencies, sort_keys=True).encode())}", flush=True)
        output = run(["cargo", "test", "--offline", "--locked", "--test", "xrandr_query",
                      "--no-run", "--jobs", "1", "--message-format=json", *config], fixture)
        messages = [json.loads(line) for line in output.splitlines() if line.startswith(b"{")]
        artifacts = [Path(m["executable"]) for m in messages
                     if m.get("reason") == "compiler-artifact" and m.get("executable")
                     and m.get("target", {}).get("name") == "xrandr_query"]
        if len(artifacts) != 1 or not artifacts[0].is_file() or artifacts[0].is_symlink():
            raise ValueError("query test executable is absent or ambiguous")
        artifact = artifacts[0]
        artifact_sha = digest(artifact.read_bytes())
        run([str(artifact), "--test-threads=1", "--color", "never"], fixture, timeout=30)
        if digest(artifact.read_bytes()) != artifact_sha or (fixture / "Cargo.lock").read_bytes() != lock_bytes:
            raise ValueError("query test artifact or dependencies changed")
        for name, data in inputs.items():
            if (repo / name).read_bytes() != data:
                raise ValueError(f"query test source changed: {name}")
            print(f"LINUX_XRANDR_QUERY_INPUT=pass path={name} bytes={len(data)} sha256={digest(data)}")
        print(f"LINUX_XRANDR_QUERY_ARTIFACT=pass sha256={artifact_sha} tests=8 unchanged=before-after", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        raise SystemExit(f"Linux xrandr query tests: FAIL: {error}") from error
