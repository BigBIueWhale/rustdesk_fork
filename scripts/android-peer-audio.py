"""Observe native recording in the private Android replay's Linux peer."""

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def query(kind):
    result = subprocess.run(
        ["/tmp/pa-runtime/root/usr/bin/pactl", "--format=json", "list", kind],
        check=True, capture_output=True, timeout=2,
    )
    require(len(result.stdout) <= 1048576, "PulseAudio observation exceeds its bound")
    value = json.loads(result.stdout)
    require(isinstance(value, list), "PulseAudio inventory is not an array")
    return value


def process(pid):
    root = Path("/proc", str(pid))
    fields = (root / "stat").read_text().rsplit(")", 1)[1].split()
    return (int(fields[1]), fields[19], os.readlink(root / "exe"),
            (root / "cmdline").read_bytes().split(b"\0")[:-1])


def main():
    require(os.getuid() == os.getgid() == 1000, "audio observer requires the fixture user")
    require(len(sys.argv) in (2, 4), "audio observer arguments differ")
    phase = sys.argv[1]
    require(re.fullmatch(r"[a-z0-9-]+", phase), "audio phase is malformed")
    if len(sys.argv) == 2:
        require(phase in ("before-peer", "after-peer"), "unknown empty recording phase")
        require(query("source-outputs") == [], "recording survived outside the peer lifetime")
        print(f"ANDROID_PEER_AUDIO_EMPTY=pass phase={phase} recordings=0")
        return

    server_pid, server_start = int(sys.argv[2]), sys.argv[3]
    image = "/smoke-target/debug/rustdesk"
    server = process(server_pid)
    require(server[1:3] == (server_start, image), "owned server generation differs")
    deadline = time.monotonic() + 8
    observed = None
    consecutive = 0
    last = "no recording"
    while time.monotonic() < deadline:
        require(process(server_pid) == server, "owned server generation changed")
        sources = query("sources")
        monitors = [s for s in sources if s.get("name") == "rd_pa_test.monitor"]
        require(len(monitors) == 1, "private test monitor is absent or ambiguous")
        outputs = query("source-outputs")
        clients = query("clients")
        if len(outputs) == 1:
            stream = outputs[0]
            owners = [c for c in clients if str(c["index"]) == stream.get("client")]
            require(len(owners) == 1, "recording client is absent or ambiguous")
            pid = int(owners[0]["properties"]["application.process.id"])
            owner = process(pid)
            require(owner[0] == server_pid and owner[2] == image
                    and owner[3] == [os.fsencode(image), b"--cm"],
                    "recording is not owned by the production CM")
            require(stream.get("source") == monitors[0]["index"]
                    and stream.get("corked") is False and stream.get("mute") is False,
                    "production recording is inactive or attached to the wrong source")
            current = (pid, owner[1], stream["index"], stream["source"])
            consecutive = consecutive + 1 if current == observed else 1
            observed = current
            if consecutive == 3:
                require(process(pid) == owner and process(server_pid) == server,
                        "recording owner changed during observation")
                print(f"ANDROID_PEER_AUDIO_CAPTURE=pass phase={phase} cm_pid={pid} "
                      f"cm_start={owner[1]} recording={stream['index']} source={stream['source']} "
                      "monitor=rd_pa_test.monitor corked=false mute=false observations=3 "
                      "scope=native-stream")
                return
            last = "recording has not remained stable for three observations"
        else:
            observed = None
            consecutive = 0
            last = f"recordings={len(outputs)}"
        time.sleep(0.25)
    raise RuntimeError(f"production capture did not become ready: {last}")


if __name__ == "__main__":
    main()
