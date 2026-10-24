#!/usr/bin/env python3
"""Compile the production fd initializer and exercise real Linux process limits."""

import errno
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import tomllib


PACKAGE = "rustdesk-linux-resource-limits"
INPUTS = (
    "Cargo.lock", "src/server.rs", "src/direct_service.rs",
    "src/direct_service/resource_limits.rs", "libs/hbb_common/src/lib.rs",
    "scripts/test-linux-resource-limits.rs",
    "scripts/fixtures/linux-resource-limits-before.rs",
    "scripts/run-linux-resource-limits-tests.py",
)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def run(arguments, directory, timeout):
    process = subprocess.Popen(arguments, cwd=directory, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, start_new_session=True)
    try:
        output, _ = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        # The unreaped group leader and all fixture descendants belong to this run.
        os.killpg(process.pid, signal.SIGKILL)
        output, _ = process.communicate(timeout=5)
        print(output[:2 * 1024 * 1024].decode("utf-8", errors="replace"), flush=True)
        raise
    if len(output) > 2 * 1024 * 1024:
        raise ValueError("resource-limit output exceeds its bound")
    print(output.decode("utf-8", errors="replace"), end="", flush=True)
    if process.returncode != 0:
        raise ValueError(f"resource-limit command failed: {process.returncode}")
    return output


def main():
    if len(sys.argv) != 3 or (os.getuid(), os.geteuid(), os.getgid(), os.getegid()) != (1000, 1000, 1000, 1000):
        raise ValueError("resource-limit tests require the isolated numeric test principal")
    repo = Path(sys.argv[1]).resolve(strict=True)
    config = ["--config", str(Path(sys.argv[2]).resolve(strict=True))]
    inputs = {name: (repo / name).read_bytes() for name in INPUTS}
    records = {(p["name"], p["version"]): p for p in tomllib.loads(inputs["Cargo.lock"].decode())["package"] if "source" in p}
    with socket.socket() as canary:
        try:
            canary.connect(("192.0.2.1", 9))
        except OSError as error:
            if error.errno != errno.ENETUNREACH:
                raise
        else:
            raise ValueError("resource-limit offline canary connected")
    print("R-B10 canary: build confirmed network-isolated (offline compile stage).", flush=True)
    with tempfile.TemporaryDirectory(prefix="linux-resource-limits-", dir="/tmp") as temporary:
        fixture = Path(temporary)
        (fixture / "Cargo.toml").write_text(
            f'[package]\nname = "{PACKAGE}"\nversion = "0.0.0"\nedition = "2021"\n'
            '[dependencies]\nlibc = "=0.2.171"\nlog = "=0.4.22"\n'
            '[[test]]\nname = "linux_resource_limits"\n'
            f'path = "{repo}/scripts/test-linux-resource-limits.rs"\n')
        run(["cargo", "generate-lockfile", "--offline", *config], fixture, 30)
        lock = (fixture / "Cargo.lock").read_bytes()
        dependencies = []
        for item in tomllib.loads(lock.decode())["package"]:
            if item["name"] == PACKAGE and "source" not in item:
                continue
            expected = records.get((item["name"], item["version"]))
            if expected is None or any(item.get(k) != expected.get(k) for k in ("source", "checksum")):
                raise ValueError("resource-limit dependency differs from root lock")
            dependencies.append({k: item[k] for k in ("name", "version", "source", "checksum")})
        print(f"LINUX_RESOURCE_LIMITS_DEPENDENCIES=pass lock_sha256={digest(lock)} records_sha256={digest(json.dumps(dependencies, sort_keys=True).encode())}", flush=True)
        output = run(["cargo", "test", "--offline", "--locked", "--test", "linux_resource_limits",
                      "--no-run", "--jobs", "1", "--message-format=json", *config], fixture, 90)
        messages = [json.loads(line) for line in output.splitlines() if line.startswith(b"{")]
        artifacts = [Path(m["executable"]) for m in messages if m.get("reason") == "compiler-artifact"
                     and m.get("executable") and m.get("target", {}).get("name") == "linux_resource_limits"]
        if len(artifacts) != 1 or not artifacts[0].is_file() or artifacts[0].is_symlink():
            raise ValueError("resource-limit artifact is absent or ambiguous")
        artifact = artifacts[0]
        artifact_sha = digest(artifact.read_bytes())
        output = run([str(artifact), "--exact", "tests::native_matrix", "--show-output",
                      "--test-threads=1", "--color", "never"], fixture, 45)
        lines = output.decode().splitlines()
        if sum("RESOURCE_LIMIT_CASE " in line for line in lines) != 16:
            raise ValueError("resource-limit native observation count differs")
        receipt = "LINUX_RESOURCE_LIMITS_NATIVE=pass cases=16 before_failed=5 before_controls=3 after_passed=8 child_raises=10 children=joined"
        if lines.count(receipt) != 1 or sum("test result: ok. 1 passed; 0 failed;" in line for line in lines) != 1:
            raise ValueError("resource-limit native matrix did not finish")
        if digest(artifact.read_bytes()) != artifact_sha or (fixture / "Cargo.lock").read_bytes() != lock:
            raise ValueError("resource-limit artifact or lock changed")
        for name, data in inputs.items():
            if (repo / name).read_bytes() != data:
                raise ValueError(f"resource-limit source changed: {name}")
            print(f"LINUX_RESOURCE_LIMITS_INPUT=pass path={name} bytes={len(data)} sha256={digest(data)}")
        print(f"LINUX_RESOURCE_LIMITS_ARTIFACT=pass sha256={artifact_sha} tests=1 cases=16 before_failed=5 before_controls=3 child_raises=10 unchanged=before-after", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        raise SystemExit(f"Linux resource-limit tests: FAIL: {error}") from error
