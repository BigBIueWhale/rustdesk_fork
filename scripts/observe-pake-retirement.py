#!/usr/bin/env python3
"""Observe only a freshly spawned, cooperating PAKE test child's fixture bytes."""
import os
from pathlib import Path
import re
import selectors
import subprocess
import sys
import time

FIXTURE = b"public-pake-erasure-fixture-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
CASES = (
    "control-plain", "control-tail", "control-unreleased",
    "drop-initiator", "drop-responder", "refuse-initiator", "refuse-responder",
    "advance-initiator", "advance-responder", "unwind-initiator", "unwind-responder",
)


def observe(executable, case):
    expected = bytes(63) + b"Z" if case == "control-tail" else FIXTURE
    environment = dict(os.environ, PAKE_ERASURE_CASE=case)
    child = subprocess.Popen(
        [executable, "--exact", "allocation_probe::credential_retirement_probe",
         "--ignored", "--test-threads=1", "--color", "never", "--nocapture"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=environment,
    )
    memory = None
    output = {"stdout": bytearray(), "stderr": bytearray()}
    pending = bytearray()
    phases = []
    address = length = capacity = None
    nonzero = None
    deadline = time.monotonic() + 10
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ, "stdout")
            selector.register(child.stderr, selectors.EVENT_READ, "stderr")
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RuntimeError(f"{case}: child observation timed out")
                for key, _ in selector.select(min(remaining, 1)):
                    chunk = os.read(key.fileobj.fileno(), 4096)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    output[key.data].extend(chunk)
                    if len(output[key.data]) > 65536:
                        raise RuntimeError(f"{case}: child output exceeds bound")
                    if key.data != "stderr":
                        continue
                    pending.extend(chunk)
                    while b"\n" in pending:
                        line, _, rest = pending.partition(b"\n")
                        pending = bytearray(rest)
                        if line.startswith(b"WATCH "):
                            match = re.fullmatch(
                                rb"WATCH address=([0-9a-f]{1,16}) length=([0-9]+) capacity=([0-9]+)",
                                line,
                            )
                            assert match and not phases and memory is None
                            address = int(match[1], 16)
                            length, capacity = int(match[2]), int(match[3])
                            assert address > 0 and length == len(expected) <= capacity <= 256
                            assert child.poll() is None
                            # Only our unreaped child, at its explicit barrier. No
                            # PID/address input from the operator or other process.
                            memory = os.open(f"/proc/{child.pid}/mem", os.O_RDONLY | os.O_CLOEXEC)
                            phases.append("watch")
                        elif line == b"LIVE":
                            assert phases == ["watch"] and memory is not None
                            assert os.pread(memory, length, address) == expected, "live fixture differs"
                            phases.append("live")
                            assert os.write(child.stdin.fileno(), b"+") == 1
                        elif line == b"RELEASE":
                            assert phases == ["watch", "live"] and memory is not None
                            # Physical bytes are observed by a separate process
                            # before System.dealloc. No Rust read of deinitialized
                            # storage and no use of memory after it is freed.
                            contents = os.pread(memory, length, address)
                            assert len(contents) == length
                            nonzero = sum(byte != 0 for byte in contents)
                            del contents
                            phases.append("release")
                            assert os.write(child.stdin.fileno(), b"+") == 1
                        elif line == b"DONE":
                            expected_phases = ["watch", "live"]
                            if case != "control-unreleased":
                                expected_phases.append("release")
                            assert phases == expected_phases
                            phases.append("done")
                        else:
                            raise RuntimeError(f"{case}: unexpected child diagnostic")
            assert not pending and phases[-1:] == ["done"]
            assert child.wait(timeout=max(0.01, deadline - time.monotonic())) == 0
            assert b"test result: ok. 1 passed; 0 failed; 0 ignored;" in output["stdout"]
            if case == "control-unreleased":
                assert nonzero is None
            elif case.startswith("control-"):
                assert nonzero == (1 if case == "control-tail" else len(expected))
            else:
                assert nonzero == 0, f"{case}: credential bytes were not erased"
            print(f"PAKE_ERASURE_CASE={case} live=matched released={nonzero is not None} "
                  f"nonzero={nonzero} child=joined", flush=True)
    except BaseException:
        print(f"PAKE_ERASURE_FAILURE={case} stdout={bytes(output['stdout'][-2048:])!r} "
              f"stderr={bytes(output['stderr'][-2048:])!r}", file=sys.stderr, flush=True)
        raise
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=5)
        for stream in (child.stdin, child.stdout, child.stderr):
            stream.close()
        if memory is not None:
            os.close(memory)


def main():
    assert len(sys.argv) == 2 and os.getuid() == os.getgid() == 1000
    assert Path.cwd() == Path("/source")
    executable = sys.argv[1]
    assert re.fullmatch(r"/cargo-target/release/deps/pake-[0-9a-f]{16}", executable)
    for case in CASES:
        observe(executable, case)
    print("PAKE_ERASURE=pass cases=11 production=8 controls=3 observer=owned-child-proc-mem "
          "scope=initialized-credential-bytes-before-system-free cleanup=joined")


if __name__ == "__main__":
    main()
