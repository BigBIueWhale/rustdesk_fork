#!/usr/bin/env python3
"""Execute the actual FUSE helper IO loop and extracted production child owner."""

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


PACKAGE = "rustdesk-fusermount-process"
OWNER = "libs/hbb_common/src/platform/linux.rs"
BASE = "libs/clipboard/src/platform/unix/fuse/"
INPUTS = ("Cargo.lock", OWNER, BASE + "mod.rs", BASE + "fusermount_fd.rs",
          BASE + "fusermount_fd_tests.rs", BASE + "fusermount_process.rs",
          BASE + "fusermount_process_tests.rs", "scripts/run-fusermount-process-tests.py")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def run(arguments, directory, timeout=90):
    result = subprocess.run(arguments, cwd=directory, timeout=timeout,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            env={key: value for key, value in os.environ.items()
                                 if not key.startswith(("RD_FUSE_HELPER_", "RD_FUSE_FD_EXEC_"))})
    if len(result.stdout) > 2 * 1024 * 1024:
        raise ValueError("helper test output exceeds 2 MiB")
    print(result.stdout.decode("utf-8", errors="replace"), end="", flush=True)
    if result.returncode != 0:
        raise ValueError(f"helper command failed: {result.returncode}")
    return result.stdout


def main():
    if len(sys.argv) != 3 or os.geteuid() == 0 or os.getegid() == 0:
        raise ValueError("helper tests require source/config and a nonroot isolated container")
    repo = Path(sys.argv[1]).resolve(strict=True)
    config = ["--config", str(Path(sys.argv[2]).resolve(strict=True))]
    inputs = {name: (repo / name).read_bytes() for name in INPUTS}
    locked = {(item["name"], item["version"]): item
              for item in tomllib.loads(inputs["Cargo.lock"].decode())["package"] if "source" in item}
    owner_source = inputs[OWNER].decode()
    start = "pub struct OwnedAuthorizationChild {"
    end = "\npub const DISPLAY_SERVER_WAYLAND:"
    if owner_source.count(start) != 1 or owner_source.count(end) != 1:
        raise ValueError("production child-owner extraction differs")
    owner = owner_source[owner_source.index(start):owner_source.index(end)]
    with socket.socket() as canary:
        try:
            canary.connect(("192.0.2.1", 9))
        except OSError as error:
            if error.errno != errno.ENETUNREACH:
                raise
        else:
            raise ValueError("helper offline canary connected")
    print("R-B10 canary: build confirmed network-isolated (offline compile stage).", flush=True)
    with tempfile.TemporaryDirectory(prefix="fusermount-process-", dir="/tmp") as directory:
        fixture = Path(directory)
        (fixture / "Cargo.toml").write_text(
            f'[package]\nname = "{PACKAGE}"\nversion = "0.0.0"\nedition = "2021"\n'
            '[dependencies]\nlibc = "=0.2.171"\nlog = "=0.4.22"\n'
            '[lib]\nname = "rustdesk_fusermount_process"\npath = "lib.rs"\n')
        (fixture / "lib.rs").write_text(
            'extern crate self as hbb_common;\npub use libc;\npub use log;\n'
            'pub mod platform { pub mod linux {\n'
            'use std::{io, os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd}, '
            'process::{Child, ChildStdout, ChildStderr, Command, ExitStatus}};\n' + owner + '\n}}\n'
            f'#[path = "{repo / BASE}fusermount_fd.rs"] mod fusermount_fd;\n'
            f'#[path = "{repo / BASE}fusermount_process.rs"] mod fusermount_process;\n')
        run(["cargo", "generate-lockfile", "--offline", *config], fixture, 30)
        lock_bytes = (fixture / "Cargo.lock").read_bytes()
        dependencies = []
        for item in tomllib.loads(lock_bytes.decode())["package"]:
            if item["name"] == PACKAGE and "source" not in item:
                continue
            expected = locked.get((item["name"], item["version"]))
            if expected is None or any(item.get(key) != expected.get(key) for key in ("source", "checksum")):
                raise ValueError("helper dependency differs from root lock")
            dependencies.append({key: item[key] for key in ("name", "version", "source", "checksum")})
        print(f"FUSE_PROCESS_DEPENDENCIES=pass lock_sha256={digest(lock_bytes)} "
              f"records_sha256={digest(json.dumps(dependencies, sort_keys=True).encode())} "
              f"owner_source_sha256={digest(owner.encode())}", flush=True)
        output = run(["cargo", "test", "--offline", "--locked", "--lib", "--no-run", "--jobs", "1",
                      "--message-format=json", *config], fixture)
        messages = [json.loads(line) for line in output.splitlines() if line.startswith(b"{")]
        candidates = [Path(item["executable"]) for item in messages
                      if item.get("reason") == "compiler-artifact" and item.get("executable")
                      and item.get("manifest_path") == str(fixture / "Cargo.toml")
                      and item.get("target", {}).get("name") == "rustdesk_fusermount_process"
                      and item.get("target", {}).get("src_path") == str(fixture / "lib.rs")
                      and item.get("target", {}).get("kind") == ["lib"]
                      and item.get("profile", {}).get("test") is True]
        if len(candidates) != 1 or candidates[0].is_symlink() or not candidates[0].is_file():
            raise ValueError("helper artifact is absent or ambiguous")
        artifact = candidates[0]
        artifact_sha = digest(artifact.read_bytes())
        run([str(artifact), "--test-threads=1", "--color", "never"], fixture, 30)
        if digest(artifact.read_bytes()) != artifact_sha or (fixture / "Cargo.lock").read_bytes() != lock_bytes:
            raise ValueError("helper artifact or lock changed")
        for name, data in inputs.items():
            if (repo / name).read_bytes() != data:
                raise ValueError(f"helper source changed: {name}")
            print(f"FUSE_PROCESS_INPUT=pass path={name} bytes={len(data)} sha256={digest(data)}")
        print(f"FUSE_PROCESS_ARTIFACT=pass sha256={artifact_sha} tests=18 unchanged=before-after", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        raise SystemExit(f"FUSE helper component tests: FAIL: {error}") from error
