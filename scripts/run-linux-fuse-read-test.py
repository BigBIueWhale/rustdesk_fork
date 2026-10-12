#!/usr/bin/env python3
"""Run the production clipboard read tests and the earlier retry implementation in the VM."""

import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import shutil
import stat
import subprocess
import sys
import time


BEFORE_SHA = "3c7fad9d747cec3489ca6d4f09f41a81c59d1ae66d72b20c9f122d1c7cff6154"
MODULE = "platform::unix::fuse::cs::fuse_test"
REGRESSION = MODULE + "::read_node_keeps_failed_request_and_next_read_responses_separate"
SOURCE = Path("/cargo-target/fuse-test-source")
RELATIVE = Path("libs/clipboard/src/platform/unix/fuse/cs.rs")
MAX_OUTPUT = 4 * 1024 * 1024


def digest(data):
    return hashlib.sha256(data).hexdigest()


def file_digest(path):
    fingerprint = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            fingerprint.update(chunk)
    return fingerprint.hexdigest()


def read_bounded(path):
    with path.open("rb") as stream:
        data = stream.read(MAX_OUTPUT + 1)
    if len(data) > MAX_OUTPUT:
        raise ValueError("FUSE test input or output exceeds its bound")
    return data


def assert_role():
    if len(sys.argv) != 1 or os.getresuid() != (1000, 1000, 1000) or os.getresgid() != (1000, 1000, 1000):
        raise ValueError("FUSE component runner requires the ordinary VM compiler principal")
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    if (status["CapEff"].strip() != "0000000000000000" or status["NoNewPrivs"].strip() != "1"
            or status["Seccomp"].strip() != "2" or [p.name for p in Path("/sys/class/net").iterdir()] != ["lo"]
            or not os.statvfs("/source").f_flag & os.ST_RDONLY):
        raise ValueError("FUSE component runner authority differs")


def main():
    assert_role()
    deadline = time.monotonic() + 220
    current = read_bounded(Path("/source") / RELATIVE)
    before = read_bounded(Path("/inputs/fuse-before.rs"))
    if digest(before) != BEFORE_SHA or not before.endswith(b"}\n"):
        raise ValueError("Earlier production FUSE source identity differs")
    begin = b"    fn next_read_stream_id("
    end = b"    #[test]\n    fn read_node_refuses_invalid_flags_and_oversized_response()"
    if current.count(begin) != 1 or current.count(end) != 1:
        raise ValueError("Exact adversarial retry fixture is absent or ambiguous")
    fixture = current[current.index(begin):current.index(end)]
    earlier = before[:-2] + fixture + b"}\n"
    shutil.copytree("/source", SOURCE, symlinks=True)
    module = SOURCE / RELATIVE
    module_stat = module.lstat()
    if not stat.S_ISREG(module_stat.st_mode) or module_stat.st_uid != 1000 or module_stat.st_nlink != 1:
        raise ValueError("Private FUSE source is not an owned regular file")
    module.chmod(0o600)
    select_artifact = runpy.run_path("/source/scripts/select-hbb-common-test-artifact.py")["select_artifact"]
    environment = dict(os.environ, CARGO_BUILD_JOBS="2", CARGO_PROFILE_DEV_DEBUG="0", CARGO_PROFILE_TEST_DEBUG="0")

    def run(command, label):
        output = Path("/cargo-target") / (label + ".log")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError("FUSE component deadline expired")
        with output.open("xb") as stream:
            result = subprocess.run(command, cwd=SOURCE, env=environment, stdout=stream,
                                    stderr=subprocess.STDOUT, timeout=remaining, check=False)
        return result.returncode, read_bounded(output)

    def build(source, label):
        module.write_bytes(source)
        print("FUSE_READ_BUILD=" + label, flush=True)
        status, output = run(["cargo", "test", "--offline", "--locked", "-p", "clipboard",
                              "--features", "unix-file-copy-paste", "--lib", "--no-run",
                              "--message-format=json-render-diagnostics", "--color", "never"], label + "-build")
        if status != 0:
            sys.stdout.buffer.write(output)
            raise ValueError("FUSE library compilation failed")
        executable = Path(select_artifact(output, "clipboard", str(SOURCE)))
        st = executable.lstat()
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != 1000 or st.st_gid != 1000
                or st.st_nlink != 1 or not st.st_mode & 0o111 or read_bounded(module) != source):
            raise ValueError("FUSE compiler output or source changed")
        owned = Path("/cargo-target") / (label + "-libtest")
        with executable.open("rb") as source_stream, owned.open("xb") as destination:
            shutil.copyfileobj(source_stream, destination)
        owned.chmod(0o500)
        return owned, file_digest(owned)

    new_executable, new_sha = build(current, "fuse-current")
    status, output = run([str(new_executable), MODULE, "--color", "never", "--test-threads=1"], "fuse-current-tests")
    sys.stdout.buffer.write(output)
    sys.stdout.flush()
    summary = re.findall(rb"^test result: ok\. ([0-9]+) passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out; finished in .+s$", output, re.M)
    required = ("fuse_request_accepts_only_one_response", "overlapping_file_content_read_is_rejected",
                "file_content_response_requires_matching_connection_id", "read_node_routes_response_after_request",
                "read_node_keeps_failed_request_and_next_read_responses_separate",
                "read_node_refuses_invalid_flags_and_oversized_response",
                "fuse_stream_ids_preserve_unsigned_bits_and_refuse_exhaustion",
                "old_route_guard_does_not_remove_new_request")
    if (status != 0 or len(summary) != 1 or int(summary[0]) < len(required)
            or any(output.count(("test " + MODULE + "::" + name + " ... ok").encode()) != 1 for name in required)):
        raise ValueError("Corrected FUSE component cases did not complete")
    old_executable, old_sha = build(earlier, "fuse-before")
    status, old_output = run([str(old_executable), REGRESSION, "--exact", "--color", "never", "--test-threads=1"], "fuse-before-tests")
    sys.stdout.buffer.write(old_output)
    sys.stdout.flush()
    if (status != 101 or b"completed failed read was retried" not in old_output
            or old_output.count(("test " + REGRESSION + " ... FAILED").encode()) != 1
            or b"test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured;" not in old_output):
        raise ValueError("Earlier FUSE component did not exhibit the exact retry defect")
    for executable, expected in [(new_executable, new_sha), (old_executable, old_sha)]:
        if file_digest(executable) != expected:
            raise ValueError("Executed FUSE artifact changed")
    if read_bounded(module) != earlier or read_bounded(Path("/source") / RELATIVE) != current:
        raise ValueError("FUSE source changed during execution")
    module.write_bytes(current)
    print("FUSE_READ_COMPONENT_ARTIFACT=pass " + json.dumps({
        "before_source_sha256": BEFORE_SHA, "before_with_fixture_sha256": digest(earlier),
        "source_sha256": digest(current), "new_artifact_sha256": new_sha,
        "old_artifact_sha256": old_sha, "old_exit": status, "new_exit": 0,
        "tests": int(summary[0]), "fixture_sha256": digest(fixture),
        "mounted_fuse": False, "execution": "production-library-read-path",
    }, sort_keys=True), flush=True)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        sys.exit(f"FUSE read component test failed: {error}")
