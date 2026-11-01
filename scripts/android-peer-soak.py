#!/usr/bin/env python3
"""Observe one uninterrupted Android peer session inside the disposable runtime."""

import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time


PACKAGE = "com.carriez.flutter_hbb"
DURATION_SECONDS = 7200
SERVER_LOG_LIMIT = 8 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def read_file(path, limit, *, replaceable=False):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        # Atomic publication may unlink the opened previous frame. Its retained
        # descriptor still owns immutable bytes; freshness decides usability.
        require(stat.S_ISREG(info.st_mode) and info.st_nlink in ((0, 1) if replaceable else (1,))
                and (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (os.getuid(), os.getgid(), 0o600)
                and 0 < info.st_size <= limit, "soak input metadata or size differs")
        value = stream.read(limit + 1)
        require(len(value) <= limit, "soak input grew past its bound")
        return value


def process_start(record, pid):
    require(record.startswith(f"{pid} (") and ") " in record, "process record identity differs")
    fields = record.rsplit(") ", 1)[1].split()
    require(len(fields) >= 20 and fields[0] not in ("Z", "X")
            and fields[19].isdigit() and int(fields[19]) > 0,
            "process is dead or lacks a start identity")
    return int(fields[19])


def main():
    require(os.getuid() == os.getgid() == 1000, "soak requires the disposable runtime principal")
    require(len(sys.argv) == 14, "soak argument count differs")
    (decoder_path, frame, source, server_log, observer_failure, adb, serial,
     app_pid, task_id, server_pid, server_start, source_pid, source_start) = sys.argv[1:]
    require(all(re.fullmatch(r"[1-9][0-9]*", value) for value in
                (app_pid, task_id, server_pid, server_start, source_pid, source_start)),
            "soak process/task identity is malformed")
    require(serial == "emulator-5554", "soak emulator serial differs")
    spec = importlib.util.spec_from_file_location("frame_decoder", decoder_path)
    decoder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(decoder)

    def local_identity():
        for pid, start in ((server_pid, server_start), (source_pid, source_start)):
            with open(f"/proc/{pid}/stat") as stream:
                require(process_start(stream.read(4097), pid) == int(start),
                        "owned peer/source process changed")
        with open("/proc/net/tcp") as stream:
            contents = stream.read(65537)
        require(len(contents) <= 65536, "peer socket inventory exceeds its bound")
        rows = [line.split() for line in contents.splitlines()[1:]]
        connections = [(row[1], row[2], row[9]) for row in rows
                       if row[1] == "0100007F:527E" and row[3] == "01"]
        require(len(connections) == 1, "soak requires one established peer connection")
        return connections[0]

    connection = local_identity()
    keyed_count = read_file(server_log, SERVER_LOG_LIMIT).count(b" Connection opened from ")
    require(keyed_count > 0, "soak has no authenticated peer session")
    # One bounded shell transaction avoids serial ADB startup costs. These IDs
    # are numeric and the package is fixed; no caller-controlled shell text enters.
    command = (
        f"printf 'SOAK_PID\\n'; pidof {PACKAGE}; "
        f"printf '\\nSOAK_STAT\\n'; head -c 4096 /proc/{app_pid}/stat; "
        f"printf '\\nSOAK_STATUS\\n'; head -c 65536 /proc/{app_pid}/status; "
        f"printf '\\nSOAK_SERVICE\\n'; dumpsys activity services {PACKAGE} | head -c 65536; "
        "printf '\\nSOAK_TASK\\n'; dumpsys activity recents | head -c 65536"
    )

    def resources():
        started = time.monotonic_ns()
        result = subprocess.run([adb, "-s", serial, "shell", command], check=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=1.5)
        require(not result.stderr and len(result.stdout) <= 262144,
                "Android resource observation failed or exceeded its output bound")
        output = result.stdout.decode("utf-8", errors="strict").replace("\r", "")
        sections = re.split(r"(?:^|\n)SOAK_(?:PID|STAT|STATUS|SERVICE|TASK)\n", output)
        require(len(sections) == 6 and not sections[0], "Android resource sections differ")
        _, pid, record, status, service, tasks = sections
        require(len(record) < 4096 and all(len(value) < 65536 for value in (status, service, tasks)),
                "Android resource observation was truncated")
        require(pid.strip() == app_pid, "Android application process changed")
        identity = process_start(record.strip(), app_pid)
        service_ids = set(re.findall(r"ServiceRecord\{[^}\n]* " + re.escape(PACKAGE)
                                     + r"/\.MainService\}", service))
        require(len(service_ids) == 1 and "isForeground=true" in service
                and "startRequested=true" in service, "Android foreground service changed")
        task_ids = set()
        for line in tasks.splitlines():
            if line.lstrip().startswith("* Recent #") and PACKAGE in line:
                match = re.search(r"Task\{[^}]* #([1-9][0-9]*)\b", line)
                require(match is not None, "Android recent task is malformed")
                task_ids.add(match[1])
        require(task_ids == {task_id}, "Android activity task changed")
        rss = re.findall(r"^VmRSS:\s+([1-9][0-9]*) kB$", status, re.M)
        threads = re.findall(r"^Threads:\s+([1-9][0-9]*)$", status, re.M)
        require(len(rss) == len(threads) == 1, "Android resource fields are unavailable")
        require(local_identity() == connection, "peer connection changed during resource observation")
        require(read_file(server_log, SERVER_LOG_LIMIT).count(b" Connection opened from ") == keyed_count,
                "soak acquired another authenticated peer session")
        return identity, service_ids, int(rss[0]), int(threads[0]), (time.monotonic_ns() - started) // 1000000

    app_start, service_ids, baseline_rss, baseline_threads, _ = resources()
    print(f"ANDROID_PEER_SOAK_WINDOW=started seconds={DURATION_SECONDS} "
          f"app_pid={app_pid} task_id={task_id} rss_baseline_kib={baseline_rss} "
          f"threads_baseline={baseline_threads}", flush=True)
    maximum_rss, maximum_threads = baseline_rss, baseline_threads
    windows = 0
    baseline_p95 = None
    maximum_drift = 0
    last_frame = None
    last_detail = {}

    def sample():
        nonlocal last_frame, last_detail
        require(not os.path.lexists(observer_failure), "emulator frame observer failed")
        require(local_identity() == connection, "soak peer connection was replaced")
        last_frame = read_file(frame, decoder.MAX_RECORD_BYTES, replaceable=True)
        last_detail = {}
        record = decoder.parse_record(last_frame)
        history = decoder.source_history(Path(source))
        analysis = decoder.analyze(record, history)
        last_detail = {key: value for key, value in record.items() if key != 'pixels'}
        last_detail.update(source_state=max(history), source_publication_us=history[max(history)],
                           candidates=analysis['candidates'])
        return record, analysis['chosen']

    def report(window):
        nonlocal windows, baseline_p95, maximum_drift, maximum_rss, maximum_threads
        identity, services, rss, threads, probe_ms = resources()
        require(identity == app_start and services == service_ids,
                "Android process or service generation changed")
        require(rss <= baseline_rss + 131072 and threads <= baseline_threads + 8,
                "Android soak exceeded its predeclared RSS/thread growth limit")
        maximum_rss, maximum_threads = max(maximum_rss, rss), max(maximum_threads, threads)
        if baseline_p95 is None:
            baseline_p95 = window['age_p95_ms']
        drift = max(0, window['age_p95_ms'] - baseline_p95)
        require(drift <= 250, "Android display age drift exceeded the first-minute envelope")
        maximum_drift = max(maximum_drift, drift)
        windows += 1
        detail = " ".join(f"{key}={value}" for key, value in window.items())
        print(f"ANDROID_PEER_SOAK_WINDOW=pass ordinal={windows} {detail} "
              f"baseline_p95_ms={baseline_p95} drift_ms={drift} rss_kib={rss} threads={threads} "
              f"resource_probe_ms={probe_ms}", flush=True)

    try:
        summary = decoder.observe_duration(sample, DURATION_SECONDS, report=report)
    except Exception:
        # Preserve the input that led to refusal, even if the display recovers
        # before the enclosing harness captures its UI diagnostic.
        print("ANDROID_PEER_FRAMEBUFFER_DIAGNOSTIC phase=soak last_observation="
              + json.dumps(last_detail, separators=(',', ':'), sort_keys=True), flush=True)
        if last_frame is not None:
            print("ANDROID_PEER_FRAMEBUFFER_RECORD_BEGIN "
                  f"bytes={len(last_frame)} sha256={hashlib.sha256(last_frame).hexdigest()} "
                  "encoding=base64 source=soak-last-observation", flush=True)
            sys.stdout.write(base64.encodebytes(last_frame).decode('ascii'))
            print("ANDROID_PEER_FRAMEBUFFER_RECORD_END", flush=True)
        raise
    require(windows == 120 and 7200 <= summary['samples'] <= 7201,
            "soak did not complete the required observation schedule")
    detail = " ".join(f"{key}={value}" for key, value in summary.items())
    print(f"ANDROID_PEER_SOAK_SUMMARY=pass {detail} windows={windows} "
          f"baseline_p95_ms={baseline_p95} maximum_drift_ms={maximum_drift} "
          f"resource_samples={windows + 1} rss_baseline_kib={baseline_rss} rss_max_kib={maximum_rss} "
          f"threads_baseline={baseline_threads} threads_max={maximum_threads} handles=unobserved "
          "input_to_visible=unobserved", flush=True)


if __name__ == "__main__":
    main()
