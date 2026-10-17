#!/usr/bin/env python3
"""Run exact production C reader bodies with portable COM/RPC fixtures in the VM."""
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

CASES = (
    "full_read", "short_read", "end_of_file", "empty_response", "failed_hresult",
    "caller_capacity", "file_extent", "offset_overflow", "failed_win32_status",
    "zero_count_at_eof", "missing_payload", "zero_count_before_eof",
)
OLD_FAILURES = set(CASES[5:])
BODY_SHA = "a96b8f3b2c19eb99a1337f930ab905066784648130aa4c37d77b31cc9fdb52e9"
INPUTS = (
    "libs/clipboard/src/windows/wf_cliprdr.c", "scripts/test-windows-cliprdr-read.c",
    "scripts/fixtures/windows-cliprdr-read-before-capacity.c",
    "scripts/run-windows-cliprdr-read-tests.py",
)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def execute(command, cwd, prefix=""):
    result = subprocess.run(command, cwd=cwd, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=40)
    for name, raw in (("stdout", result.stdout), ("stderr", result.stderr)):
        if len(raw) > 2 * 1024 * 1024:
            raise ValueError("cliprdr component output exceeds its bound")
        for line in raw.decode("utf-8", errors="strict").splitlines():
            print(prefix + ("stderr: " if name == "stderr" else "") + line, flush=True)
    return result


def main():
    if len(sys.argv) != 2 or os.geteuid() == 0 or os.getegid() == 0:
        raise ValueError("cliprdr component tests require the nonroot isolated guest container")
    repo = Path(sys.argv[1]).resolve(strict=True)
    inputs = {name: (repo / name).read_bytes() for name in INPUTS}
    with socket.socket() as canary:
        try:
            canary.connect(("192.0.2.1", 9))
        except OSError as error:
            if error.errno != errno.ENETUNREACH:
                raise
        else:
            raise ValueError("cliprdr offline canary connected")
    print("R-B10 canary: build confirmed network-isolated (offline compile stage).", flush=True)
    source = inputs[INPUTS[0]].decode()
    start = "static HRESULT STDMETHODCALLTYPE CliprdrStream_Read("
    current = source[source.index(start):source.index(
        "static HRESULT STDMETHODCALLTYPE CliprdrStream_Write(", source.index(start))]
    before = inputs[INPUTS[2]].decode().split(start, 1)
    if len(before) != 2:
        raise ValueError("cliprdr baseline inventory differs")
    before = start + before[1].rstrip() + "\n\n"
    if sha(before.encode()) != BODY_SHA:
        raise ValueError("cliprdr baseline differs from its exact pre-correction body")
    helper_start = source.index("static void wf_cliprdr_clear_file_response(")
    helper = source[helper_start:source.index("#define WM_CLIPRDR_MESSAGE", helper_start)]
    driver = "mod cliprdr_stream_read {\nextern \"C\" { fn cliprdr_read_test(case: u32) -> i32; }\n"
    for index, name in enumerate(CASES):
        driver += (f"#[test] fn {name}() {{ assert_eq!(unsafe {{ cliprdr_read_test({index}) }}, 0); }}\n")
    driver += "}\n"
    artifacts = {}
    with tempfile.TemporaryDirectory(prefix="cliprdr-read-", dir="/tmp") as temporary:
        for version, body in (("before", before), ("current", current)):
            work = Path(temporary) / version
            work.mkdir()
            (work / "production_read.c").write_text(helper + body)
            (work / "fixture.c").write_bytes(inputs[INPUTS[1]])
            (work / "driver.rs").write_text(driver)
            for command in (
                ["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-c", "fixture.c", "-o", "fixture.o"],
                ["rustc", "--edition=2021", "--test", "driver.rs", "-C", "link-arg=fixture.o", "-o", "probe"],
            ):
                if execute(command, work).returncode:
                    raise ValueError(f"cliprdr {version} component compilation failed")
            artifact = work / "probe"
            digest = sha(artifact.read_bytes())
            result = execute([str(artifact), "--test-threads=1", "--color", "never"], work,
                             "BEFORE: " if version == "before" else "")
            output = result.stdout.decode()
            failed = set(re.findall(r"^test cliprdr_stream_read::(\w+) \.\.\. FAILED$", output, re.M))
            passed = set(re.findall(r"^test cliprdr_stream_read::(\w+) \.\.\. ok$", output, re.M))
            if version == "before":
                if result.returncode != 101 or failed != OLD_FAILURES or passed != set(CASES[:5]):
                    raise ValueError("cliprdr old reader did not reproduce the exact seven failures and five controls")
            elif result.returncode or failed or passed != set(CASES):
                raise ValueError("cliprdr corrected reader did not pass all twelve cases")
            if sha(artifact.read_bytes()) != digest:
                raise ValueError("cliprdr executable changed during execution")
            artifacts[version] = {"sha256": digest, "exit": result.returncode,
                                  "passed": sorted(passed), "failed": sorted(failed)}
    for name, data in inputs.items():
        if (repo / name).read_bytes() != data:
            raise ValueError(f"cliprdr input changed: {name}")
    record = {"tests": len(CASES), "artifacts": artifacts, "before_body_sha256": BODY_SHA,
              "current_body_sha256": sha(current.encode()), "helper_sha256": sha(helper.encode()),
              "inputs": {name: sha(data) for name, data in inputs.items()},
              "execution": "exact-C-reader-and-response-release-with-portable-COM-RPC-fixtures",
              "windows_native": False, "callback_concurrency": False}
    print("CLIPRDR_READ_ARTIFACT=pass " + json.dumps(record, sort_keys=True, separators=(",", ":")), flush=True)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        raise SystemExit(f"cliprdr reader component tests: FAIL: {error}") from error
