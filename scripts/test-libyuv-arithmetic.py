#!/usr/bin/env python3
"""Reproduce known arithmetic failures in the authenticated 1857 source.

Run only through smoke-verifier-vm-authority.sh --libyuv-arithmetic-tests.
A successful reproduction is not a passing native-codec release gate.
"""

from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import signal
import subprocess
import tarfile
import tempfile


ARCHIVE_SHA512 = (
    "be6b343ab6c62e8f2d1571fedf25f5facbf7cd7fe8e1cc4949dab7549ad15f962c91ea"
    "43bf567785e54382d7689514f6b66d61bd56b3f38ba54ef51c5fd0da9b"
)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def checked(command):
    result = subprocess.run(command, capture_output=True, text=True, timeout=90)
    require(result.returncode == 0, f"command failed: {command!r}: {result.stderr[-4096:]}")
    require(len(result.stdout) + len(result.stderr) <= 16384, "compiler output exceeded its bound")


def main():
    require(os.getuid() == os.getgid() == 4000, "isolated native-test principal required")
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines()
                  if ":" in line)
    require(status["NoNewPrivs"].strip() == "1" and all(
        int(status[key].strip(), 16) == 0 for key in
        ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")), "native-test authority differs")
    archive = Path("/repo/inputs/libyuv.tar.gz")
    require(archive.stat().st_size == 566889 and
            hashlib.sha512(archive.read_bytes()).hexdigest() == ARCHIVE_SHA512,
            "pinned source archive differs")
    fixture = Path("/repo/scripts/test-libyuv-arithmetic.cc")
    records = {"archive_sha512": ARCHIVE_SHA512, "fixture_sha256": sha256(fixture),
               "compiler_sha256": sha256(Path("/usr/bin/g++").resolve()), "cases": {}}
    with tempfile.TemporaryDirectory(prefix="libyuv-", dir="/work") as directory:
        work = Path(directory)
        members = {}
        total = 0
        with tarfile.open(archive) as source:
            for member in source:
                name = PurePosixPath(member.name)
                if not ((name.parts[0] == "source" and name.suffix == ".cc") or
                        (name.parts[0] == "include" and name.suffix == ".h")):
                    continue
                require(member.isfile() and not name.is_absolute() and ".." not in name.parts
                        and member.name not in members and member.size <= 1048576,
                        "source archive member differs")
                total += member.size
                require(total <= 8388608, "source expansion exceeds its bound")
                data = source.extractfile(member).read()
                destination = work / member.name
                destination.parent.mkdir(parents=True, exist_ok=True)
                with destination.open("xb") as output:
                    output.write(data)
                members[member.name] = hashlib.sha256(data).hexdigest()
        records["source_members"] = members
        flags = ["/usr/bin/g++", "-std=c++11", "-O1", "-g0", "-fno-omit-frame-pointer",
                 "-fsanitize=undefined", "-fno-sanitize-recover=undefined",
                 "-I" + str(work / "include")]
        sources = sorted((work / "source").glob("*.cc"))
        require(len(sources) >= 20, "native source set incomplete")

        def compile_one(source):
            target = source.with_suffix(".o")
            checked([*flags, "-c", str(source), "-o", str(target)])
            return target

        # Leaving the executor joins every compiler even when one compilation fails.
        with ThreadPoolExecutor(max_workers=2) as compiler:
            objects = list(compiler.map(compile_one, sources))
        binary = work / "arithmetic"
        checked([*flags, str(fixture), *map(str, objects), "-o", str(binary)])
        records["binary_sha256"] = sha256(binary)
        records["compiler_flags"] = flags[1:-1] + ["-I<authenticated-source>/include"]
        controls = faults = 0
        scenarios = [(depth, case) for depth in ("8", "16", "12")
                     for case in ("copy", "downscale", "inverted", "boundary", "oversize")]
        scenarios += [("affine", "small"), ("affine", "large-stride")]
        for operation, case in scenarios:
            result = subprocess.run([str(binary), operation, case], capture_output=True,
                                    text=True, timeout=5,
                                    env={"PATH": "/usr/bin:/bin", "LC_ALL": "C",
                                         "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=0"})
            require(len(result.stdout) + len(result.stderr) <= 4096, "case output exceeds bound")
            if case in ("boundary", "oversize"):
                require(result.returncode == -signal.SIGFPE and not result.stdout
                        and not result.stderr, f"scaling reproduction differs: {operation}/{case}: {result}")
                faults += 1
            elif case == "large-stride":
                require(result.returncode == 1 and not result.stdout and
                        "source/row_common.cc:" in result.stderr and
                        "signed integer overflow: 2 * 1073741824" in result.stderr,
                        f"affine reproduction differs: {result}")
                faults += 1
            else:
                require(result.returncode == 0 and result.stdout == "pixels=exact\n"
                        and not result.stderr, f"valid control differs: {operation}/{case}: {result}")
                controls += 1
            records["cases"][operation + "/" + case] = {
                "returncode": result.returncode, "stdout": result.stdout,
                "stderr": result.stderr.replace(str(work), "<source>")}
        require(controls == 10 and faults == 7 and sha256(binary) == records["binary_sha256"],
                "case inventory or artifact changed")
    print("LIBYUV_ARITHMETIC_ARTIFACTS=" + json.dumps(records, sort_keys=True, separators=(",", ":")))
    print("LIBYUV_ARITHMETIC_BASELINE=confirmed cases=17 controls=10 sigfpe=6 "
          "ubsan_affine=1 boundary=32768 oversize=32769 source=1857 "
          "app_reachability=unproved release_gate=open children=joined")


if __name__ == "__main__":
    main()
