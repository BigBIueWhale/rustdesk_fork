#!/usr/bin/env python3
"""Observe sparse progress before producer EOF, using the real guest filter."""

import os
from pathlib import Path
import select
import subprocess
import sys


sys.dont_write_bytecode = True
scripts = Path(__file__).resolve().parent
subprocess.run(["/bin/bash", str(scripts / "verify-vm-entry-preflight.sh")],
               check=True, stdout=subprocess.DEVNULL)
source = (scripts / "smoke-verifier-vm-authority-guest.sh").read_text()
marker = "forward_android_runtime_progress() {\n"
if source.count(marker) != 1:
    raise RuntimeError("progress filter source is absent or duplicated")
function = marker + source.split(marker, 1)[1].split("\n}\n", 1)[0] + "\n}\n"
probe = b"ignored diagnostic\nANDROID_PEER_ARTIFACT_ADMITTED=pass test=pipe\n"
expected = b"ANDROID_RUNTIME_PROGRESS event=peer-admitted build=absent\n"


def observe(arguments, immediate):
    process = subprocess.Popen(arguments, stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        process.stdin.write(probe)
        process.stdin.flush()
        readable = bool(select.select([process.stdout], [], [], 1.0)[0])
        if readable != immediate or process.poll() is not None:
            raise RuntimeError("progress ordering differs while producer remains open")
        prefix = os.read(process.stdout.fileno(), 256) if readable else b""
        if immediate and prefix != expected:
            raise RuntimeError("progress before EOF is absent or contains diagnostics")
        process.stdin.close()
        process.stdin = None
        output, errors = process.communicate(timeout=2)
        if process.returncode != 0 or errors or prefix + output != expected:
            raise RuntimeError("progress completion or cardinality differs")
    finally:
        if process.stdin is not None:
            process.stdin.close()
            process.stdin = None
        if process.poll() is None:
            process.kill()
        process.wait()
        process.stdout.close()
        process.stderr.close()


observe(["/usr/bin/awk", "/^ANDROID_PEER_ARTIFACT_ADMITTED=pass / "
         "{ print \"ANDROID_RUNTIME_PROGRESS event=peer-admitted build=absent\"; fflush() }"],
        immediate=False)
observe(["/bin/bash", "--noprofile", "--norc", "-euo", "pipefail", "-c",
         function + "forward_android_runtime_progress"], immediate=True)
print("ANDROID_RUNTIME_PROGRESS_TEST=pass old=buffered new=before-eof "
      "diagnostics=filtered cardinality=1 children=joined")
