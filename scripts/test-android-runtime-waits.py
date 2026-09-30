#!/usr/bin/env python3
"""Execute runtime wait/deadline primitives against the guest kernel clock.

Scripted container states are unit fixtures, not Docker or Android evidence.
The replay separately exercises the authenticated real Docker inspection path.
"""

import os
from pathlib import Path
import subprocess
import sys
import time


sys.dont_write_bytecode = True
scripts = Path(__file__).resolve().parent
subprocess.run(["/bin/bash", str(scripts / "verify-vm-entry-preflight.sh")],
               check=True, stdout=subprocess.DEVNULL)
source = (scripts / "android-emulator-runtime-check.sh").read_text()
functions = []
for name in ("runtime_monotonic_millis", "runtime_deadline_command",
             "wait_runtime_container_terminal"):
    marker = name + "() {\n"
    if source.count(marker) != 1:
        raise RuntimeError("runtime primitive is absent or duplicated: " + name)
    functions.append(marker + source.split(marker, 1)[1].split("\n}\n", 1)[0] + "\n}\n")
prefix = "set -euo pipefail\n" + "\n".join(functions)


def run(body, expected_status, expected_output, *, limit=3.0):
    started = time.monotonic()
    result = subprocess.run(["/bin/bash", "--noprofile", "--norc", "-c", prefix + body],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=limit)
    elapsed = time.monotonic() - started
    if result.returncode != expected_status or result.stdout != expected_output:
        raise RuntimeError("runtime wait result differs: " + repr(result))
    if expected_status != 65 and result.stderr:
        raise RuntimeError("runtime wait produced unexpected diagnostics: " + repr(result.stderr))
    return elapsed


# A slow inspection consumes the same budget as polling, not an extra iteration allowance.
elapsed = run("runtime_container_state() { /usr/bin/sleep 0.08; printf 'running\\n'; }\n"
              "wait_runtime_container_terminal fixture 150\n", 124, b"")
if elapsed >= 1.0:
    raise RuntimeError("elapsed-time deadline did not stop the slow polling fixture")
run("runtime_container_state() { printf 'exited\\n'; }\n"
    "wait_runtime_container_terminal fixture 500\n", 0, b"exited\n")
run("runtime_container_state() { /usr/bin/sleep 0.15; printf 'exited\\n'; }\n"
    "wait_runtime_container_terminal fixture 50\n", 124, b"")
run("runtime_container_state() { printf 'unknown\\n'; }\n"
    "wait_runtime_container_terminal fixture 500\n", 65, b"")
run("runtime_container_state() { return 66; }\n"
    "wait_runtime_container_terminal fixture 500\n", 66, b"")
run("runtime_monotonic_millis() { return 1; }\n"
    "runtime_deadline_command 500 /usr/bin/printf forbidden\n", 125, b"")
run("now=$(runtime_monotonic_millis)\n"
    "runtime_deadline_command \"$now\" /usr/bin/printf forbidden\n", 124, b"")
run("now=$(runtime_monotonic_millis)\n"
    "runtime_deadline_command \"$((now + 500))\" /bin/bash -c 'exit 67'\n", 67, b"")

# Actual blocked command cancellation, and synchronous TERM cleanup, not a mocked timer.
for command in (
        'printf "%s\\n" "$$"; exec /usr/bin/sleep 5',
        'printf "%s\\n" "$$"; trap "/usr/bin/sleep 0.05; exit 0" TERM; /usr/bin/sleep 5'):
    body = ('now=$(runtime_monotonic_millis)\n'
            'runtime_deadline_command "$((now + 100))" /bin/bash -c "$1"\n')
    result = subprocess.run(["/bin/bash", "--noprofile", "--norc", "-c", prefix + body,
                             "deadline-fixture", command], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=3)
    if result.returncode != 124 or not result.stdout.strip().isdigit():
        raise RuntimeError("blocked command cancellation differs: " + repr(result))
    pid = int(result.stdout)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        pass
    else:
        raise RuntimeError("deadline command did not join its exact child")

print("ANDROID_RUNTIME_WAITS_TEST=pass cases=10 clock=guest-boottime "
      "polling=elapsed late=refused command=cancelled drain=joined states=unit-fixtures")
