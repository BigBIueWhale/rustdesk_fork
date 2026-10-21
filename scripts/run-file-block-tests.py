#!/usr/bin/env python3
"""Compile and execute the production file-block decoder and compressor in isolation."""
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
import tomllib

PACKAGE = "rustdesk-file-block"
INPUTS = ("Cargo.lock", "libs/hbb_common/src/config.rs", "libs/hbb_common/src/compress.rs",
          "libs/hbb_common/src/fs.rs", "libs/hbb_common/src/fs/file_block.rs",
          "scripts/run-file-block-tests.py")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def run(arguments, directory, timeout):
    result = subprocess.run(arguments, cwd=directory, timeout=timeout,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if len(result.stdout) > 2 * 1024 * 1024:
        raise ValueError("file-block output exceeds 2 MiB")
    print(result.stdout.decode("utf-8", errors="replace"), end="", flush=True)
    if result.returncode:
        raise ValueError(f"file-block command failed: {result.returncode}")
    return result.stdout


def main():
    if len(sys.argv) != 3 or os.geteuid() == 0 or os.getegid() == 0:
        raise ValueError("file-block tests require a nonroot isolated container")
    repo = Path(sys.argv[1]).resolve(strict=True)
    config = ["--config", str(Path(sys.argv[2]).resolve(strict=True))]
    inputs = {name: (repo / name).read_bytes() for name in INPUTS}
    locked = {(item["name"], item["version"]): item
              for item in tomllib.loads(inputs["Cargo.lock"].decode())["package"] if "source" in item}
    level = re.findall(r"(?m)^pub const COMPRESS_LEVEL: i32 = [0-9]+;$",
                       inputs["libs/hbb_common/src/config.rs"].decode())
    if len(level) != 1:
        raise ValueError("production compression-level declaration is absent or ambiguous")
    with socket.socket() as canary:
        try:
            canary.connect(("192.0.2.1", 9))
        except OSError as error:
            if error.errno != errno.ENETUNREACH:
                raise
        else:
            raise ValueError("file-block offline canary connected")
    print("R-B10 canary: build confirmed network-isolated (offline compile stage).", flush=True)
    with tempfile.TemporaryDirectory(prefix="file-block-", dir="/tmp") as directory:
        fixture = Path(directory)
        (fixture / "Cargo.toml").write_text(
            f'[package]\nname = "{PACKAGE}"\nversion = "0.0.0"\nedition = "2021"\n'
            '[dependencies]\nzstd = "=0.13.1"\n'
            '[lib]\nname = "rustdesk_file_block"\npath = "lib.rs"\n')
        (fixture / "lib.rs").write_text(
            'mod config { ' + level[0] + ' }\n'
            f'#[path = "{repo}/libs/hbb_common/src/compress.rs"] mod compress;\n'
            f'#[path = "{repo}/libs/hbb_common/src/fs/file_block.rs"] mod file_block;\n')
        run(["cargo", "generate-lockfile", "--offline", *config], fixture, 30)
        lock_bytes = (fixture / "Cargo.lock").read_bytes()
        dependencies = []
        for item in tomllib.loads(lock_bytes.decode())["package"]:
            if item["name"] == PACKAGE and "source" not in item:
                continue
            expected = locked.get((item["name"], item["version"]))
            if expected is None or any(item.get(key) != expected.get(key) for key in ("source", "checksum")):
                raise ValueError("file-block dependency differs from root lock")
            dependencies.append({key: item[key] for key in ("name", "version", "source", "checksum")})
        print(f"FILE_BLOCK_DEPENDENCIES=pass lock_sha256={digest(lock_bytes)} "
              f"records_sha256={digest(json.dumps(dependencies, sort_keys=True).encode())}", flush=True)
        output = run(["cargo", "test", "--offline", "--locked", "--lib", "--no-run", "--jobs", "1",
                      "--message-format=json", *config], fixture, 180)
        messages = [json.loads(line) for line in output.splitlines() if line.startswith(b"{")]
        candidates = [Path(item["executable"]) for item in messages
                      if item.get("reason") == "compiler-artifact" and item.get("executable")
                      and item.get("manifest_path") == str(fixture / "Cargo.toml")
                      and item.get("target", {}).get("name") == "rustdesk_file_block"
                      and item.get("target", {}).get("src_path") == str(fixture / "lib.rs")
                      and item.get("target", {}).get("kind") == ["lib"]
                      and item.get("profile", {}).get("test") is True]
        if len(candidates) != 1 or candidates[0].is_symlink() or not candidates[0].is_file():
            raise ValueError("file-block artifact is absent or ambiguous")
        artifact = candidates[0]
        artifact_sha = digest(artifact.read_bytes())
        run([str(artifact), "--test-threads=1", "--color", "never"], fixture, 20)
        if digest(artifact.read_bytes()) != artifact_sha or (fixture / "Cargo.lock").read_bytes() != lock_bytes:
            raise ValueError("file-block artifact or lock changed")
        for name, data in inputs.items():
            if (repo / name).read_bytes() != data:
                raise ValueError(f"file-block source changed: {name}")
            print(f"FILE_BLOCK_INPUT=pass path={name} bytes={len(data)} sha256={digest(data)}")
        print(f"FILE_BLOCK_ARTIFACT=pass sha256={artifact_sha} tests=7 unchanged=before-after", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        raise SystemExit(f"file-block component tests: FAIL: {error}") from error
