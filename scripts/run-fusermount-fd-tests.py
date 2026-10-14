#!/usr/bin/env python3
"""Run actual Unix descriptor transfers through the production FUSE receiver."""

import base64
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


PACKAGE = "rustdesk-fusermount-fd"
MODULE = "libs/clipboard/src/platform/unix/fuse/fusermount_fd.rs"
TESTS = "libs/clipboard/src/platform/unix/fuse/fusermount_fd_tests.rs"
BASELINE = "scripts/fixtures/fusermount-fd-before-owned-receive.rs"
INPUTS = ("Cargo.lock", "libs/clipboard/src/platform/unix/fuse/mod.rs", MODULE, TESTS,
          BASELINE, "scripts/run-fusermount-fd-tests.py")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def run(arguments, directory, *, expected=0, publish=True, timeout=90):
    result = subprocess.run(arguments, cwd=directory, check=False, timeout=timeout,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            env={key: value for key, value in os.environ.items()
                                 if not key.startswith("RD_FUSE_FD_EXEC_")})
    if len(result.stdout) > 2 * 1024 * 1024:
        raise ValueError("FUSE fd output exceeds 2 MiB")
    if publish or result.returncode != expected:
        print(result.stdout.decode("utf-8", errors="replace"), end="", flush=True)
    if result.returncode != expected:
        raise ValueError(f"FUSE fd command returned {result.returncode}, expected {expected}")
    return result.stdout


def build(fixture, config):
    output = run(["cargo", "test", "--offline", "--locked", "--lib", "--no-run",
                  "--jobs", "1", "--message-format=json", *config], fixture)
    messages = [json.loads(line) for line in output.splitlines() if line.startswith(b"{")]
    artifacts = [Path(item["executable"]) for item in messages
                 if item.get("reason") == "compiler-artifact" and item.get("executable")
                 and item.get("manifest_path") == str(fixture / "Cargo.toml")
                 and item.get("target", {}).get("name") == PACKAGE.replace("-", "_")
                 and item.get("target", {}).get("kind") == ["lib"]
                 and item.get("profile", {}).get("test") is True]
    if len(artifacts) != 1 or not artifacts[0].is_file() or artifacts[0].is_symlink():
        raise ValueError("FUSE fd executable is absent or ambiguous")
    return artifacts[0]


def main():
    if len(sys.argv) != 3 or os.geteuid() == 0 or os.getegid() == 0:
        raise ValueError("FUSE fd tests require source/config and a nonroot isolated container")
    repo = Path(sys.argv[1]).resolve(strict=True)
    config = ["--config", str(Path(sys.argv[2]).resolve(strict=True))]
    inputs = {name: (repo / name).read_bytes() for name in INPUTS}
    root_lock = tomllib.loads(inputs["Cargo.lock"].decode("utf-8"))
    records = {(item["name"], item["version"]): item for item in root_lock["package"] if "source" in item}
    with socket.socket() as canary:
        try:
            canary.connect(("192.0.2.1", 9))
        except OSError as error:
            if error.errno != errno.ENETUNREACH:
                raise
        else:
            raise ValueError("FUSE fd offline canary connected")
    print("R-B10 canary: build confirmed network-isolated (offline compile stage).", flush=True)
    with tempfile.TemporaryDirectory(prefix="fusermount-fd-", dir="/tmp") as temporary:
        fixture = Path(temporary)
        (fixture / "Cargo.toml").write_text(
            f'[package]\nname = "{PACKAGE}"\nversion = "0.0.0"\nedition = "2021"\n'
            '[dependencies]\nlibc = "=0.2.171"\n[lib]\npath = "lib.rs"\n')
        (fixture / "lib.rs").write_text(f'#[path = "{repo / MODULE}"] mod fusermount_fd;\n')
        run(["cargo", "generate-lockfile", "--offline", *config], fixture, timeout=30)
        lock_bytes = (fixture / "Cargo.lock").read_bytes()
        dependencies = []
        for item in tomllib.loads(lock_bytes.decode("utf-8"))["package"]:
            if item["name"] == PACKAGE and "source" not in item:
                continue
            expected = records.get((item["name"], item["version"]))
            if expected is None or any(item.get(key) != expected.get(key) for key in ("source", "checksum")):
                raise ValueError("FUSE fd dependency differs from the root lock")
            dependencies.append({key: item[key] for key in ("name", "version", "source", "checksum")})
        print(f"FUSE_FD_DEPENDENCIES=pass lock_sha256={digest(lock_bytes)} "
              f"records_sha256={digest(json.dumps(dependencies, sort_keys=True).encode())}", flush=True)

        # Only error construction is adapted; the prior recvmsg/dup code and the
        # current native scenarios are unchanged in the baseline comparison.
        (fixture / "lib.rs").write_text(
            'mod fusermount_fd {\nuse std::{io, mem, os::unix::{io::{AsRawFd, FromRawFd, OwnedFd, RawFd}, net::UnixStream}};\n'
            'type CliprdrError = io::Error;\n'
            'fn fuse_common_error(value: impl Into<String>) -> io::Error { io::Error::new(io::ErrorKind::Other, value.into()) }\n'
            f'include!("{repo / BASELINE}");\n#[cfg(test)] #[path = "{repo / TESTS}"] mod tests;\n}}\n')
        baseline = build(fixture, config)
        baseline_sha = digest(baseline.read_bytes())
        for case, expected in (
            ("receives_exact_native_object_and_closes_on_drop", 0),
            ("extra_descriptor_is_refused_and_all_handles_close", 101),
            ("truncated_rights_close_every_delivered_handle", 101),
            ("received_descriptor_is_cloexec", 101),
        ):
            name = f"fusermount_fd::tests::{case}"
            output = run([str(baseline), "--exact", name, "--color", "never"], fixture,
                         expected=expected, publish=False, timeout=5)
            outcome = "ok" if expected == 0 else "FAILED"
            if f"test {name} ... {outcome}".encode() not in output:
                raise ValueError("baseline did not execute the exact native scenario")
            if expected != 0:
                reason = (b"descriptor must already be close-on-exec" if case == "received_descriptor_is_cloexec"
                          else b"a refused descriptor must have no surviving reference")
                if reason not in output:
                    raise ValueError("baseline failed without the distinguishing native observation")
            if digest(baseline.read_bytes()) != baseline_sha:
                raise ValueError("baseline artifact changed")
            print("FUSE_FD_BASELINE=" + json.dumps({
                "case": name, "expected_exit": expected, "observed_exit": expected,
                "artifact_sha256": baseline_sha, "output_sha256": digest(output),
                "output_base64": base64.b64encode(output).decode("ascii"),
            }, sort_keys=True), flush=True)

        (fixture / "lib.rs").write_text(f'#[path = "{repo / MODULE}"] mod fusermount_fd;\n')
        artifact = build(fixture, config)
        artifact_sha = digest(artifact.read_bytes())
        run([str(artifact), "--test-threads=1", "--color", "never"], fixture, timeout=30)
        if digest(artifact.read_bytes()) != artifact_sha or (fixture / "Cargo.lock").read_bytes() != lock_bytes:
            raise ValueError("FUSE fd artifact or dependencies changed")
        for name, data in inputs.items():
            if (repo / name).read_bytes() != data:
                raise ValueError(f"FUSE fd source changed: {name}")
            print(f"FUSE_FD_INPUT=pass path={name} bytes={len(data)} sha256={digest(data)}")
        print(f"FUSE_FD_ARTIFACT=pass sha256={artifact_sha} tests=9 unchanged=before-after", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        raise SystemExit(f"FUSE descriptor tests: FAIL: {error}") from error
