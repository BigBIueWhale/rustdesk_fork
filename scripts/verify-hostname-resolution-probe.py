#!/usr/bin/env python3
"""Read-only admission of the exact connector diagnostic, not a security pass."""
import hashlib
import json
from pathlib import Path
import re
import sys


def verify(log, source):
    raw = log.read_bytes()
    records = re.findall(rb'HOSTNAME_RESOLUTION_COMPONENT=(\{[^\r\n]*\})\r?(?:\n|$)', raw)
    if len(records) != 1 or raw.count(b"HOSTNAME_RESOLUTION_COMPONENT=") != 1:
        raise ValueError("Connector observation is absent or duplicated")
    record = json.loads(records[0])
    if (record.get("execution") != "production-connect_tcp_local"
            or record.get("product_correction") is not False or record.get("instrumented") is not True
            or record.get("private_executable_links") != 1
            or record.get("processes") != "exited-and-waited"
            or not re.fullmatch(r"[0-9a-f]{64}", record.get("artifact_sha256", ""))):
        raise ValueError("Connector observation scope differs")
    paths = ["libs/hbb_common/examples/hostname_resolution_probe.rs",
             "libs/hbb_common/src/tcp.rs", "libs/hbb_common/src/socket_client.rs",
             "scripts/run-hostname-resolution-probe.py", "scripts/verify-hostname-resolution-probe.py"]
    if record.get("sources") != {p: hashlib.sha256((source / p).read_bytes()).hexdigest() for p in paths}:
        raise ValueError("Connector observation source binding differs")
    observations = record.get("observations")
    cases = ["literal", "hosts-single", "hosts-multi", "hosts-multi-tcp", "dns-udp", "dns-tcp", "cancel", "dns-answer-tcp", "dns-cancel-tcp"]
    if not isinstance(observations, list) or [r.get("case") for r in observations] != cases:
        raise ValueError("Connector observation case inventory differs")
    for observation in observations:
        for key in ("ip_datagram_socket_attempts", "getaddrinfo_calls"):
            if type(observation.get(key)) is not int or not 0 <= observation[key] <= 128:
                raise ValueError("Connector observation counter differs")
        for key in ("connected", "gate_reached", "pending_after_connect_budget", "native_active_after_future_cancel"):
            if type(observation.get(key)) is not bool:
                raise ValueError("Connector observation outcome differs")
        if (observation.get("native_hook_drained") is not True
                or observation.get("trap_self_controls") != 2
                or observation.get("getaddrinfo_self_control") is not True
                or observation.get("datagram_action") != "kernel-trap-denied"
                or observation.get("cancellation_gate") != {
                    "dns-cancel-tcp": "real-tcp-dns-silent-peer",
                    "dns-answer-tcp": "real-tcp-dns-answer-peer",
                }.get(observation["case"], "controlled-before-real-getaddrinfo")):
            raise ValueError("Connector observation instrumentation/finality differs")
        if (observation.get("connect_timeout_ms") != (5 if observation["case"] in ("cancel", "dns-cancel-tcp") else 100)
                or type(observation.get("gate_observed_elapsed_ms")) is not int
                or not 0 <= observation["gate_observed_elapsed_ms"] <= 2500):
            raise ValueError("Connector observation deadline context differs")
        types = observation.get("dns_question_types")
        if (type(observation.get("dns_socket_retained_after_cancel")) is not bool
                or observation.get("dns_release") != (
                    "answer-and-server-half-close" if observation["case"] in ("dns-cancel-tcp", "dns-answer-tcp")
                    else "not-applicable")
                or not isinstance(types, list)
                or types != sorted(set(types)) or any(type(t) is not int or t not in (1, 28) for t in types)
                or (observation["case"] in ("dns-cancel-tcp", "dns-answer-tcp")
                    and (not types or not observation["gate_reached"]))
                or (observation["case"] not in ("dns-cancel-tcp", "dns-answer-tcp")
                    and (types or observation["dns_socket_retained_after_cancel"]))):
            raise ValueError("Connector observation actual TCP DNS context differs")
        late_datagrams = observation.get("ip_datagram_attempts_after_cancel")
        if (type(late_datagrams) is not int
                or not 0 <= late_datagrams <= observation["ip_datagram_socket_attempts"]
                or (observation["case"] != "dns-cancel-tcp" and late_datagrams != 0)):
            raise ValueError("Connector observation post-cancellation counter differs")
        if observation["case"] == "dns-answer-tcp" and not observation["connected"]:
            raise ValueError("Actual TCP DNS answer did not connect to the loopback control")
    literal = observations[0]
    if not literal["connected"] or literal["ip_datagram_socket_attempts"] or literal["getaddrinfo_calls"]:
        raise ValueError("Literal control did not exercise an ordinary TCP connection")
    # Counts describe the measured behavior. Never require the forbidden path to
    # remain present merely to keep a diagnostic green after the product changes.
    return record


if __name__ == "__main__":
    result = verify(Path(sys.argv[1]), Path(sys.argv[2]))
    print("HOSTNAME_RESOLUTION_COMPONENT=" + json.dumps(result, sort_keys=True, separators=(",", ":")))
