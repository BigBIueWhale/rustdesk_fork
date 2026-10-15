#!/usr/bin/env python3
"""Build and observe the production connector inside the confined Linux fixture."""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    if (os.getuid(), os.getgid()) != (1000, 1000):
        raise ValueError("Connector observation requires its confined nonroot principal")
    source = Path("/source")
    target = Path("/cargo-target")
    paths = ["libs/hbb_common/examples/hostname_resolution_probe.rs",
             "libs/hbb_common/src/tcp.rs", "libs/hbb_common/src/socket_client.rs",
             "scripts/run-hostname-resolution-probe.py", "scripts/verify-hostname-resolution-probe.py"]
    sources = {p: digest(source / p) for p in paths}
    hosts = Path("/etc/hosts").read_text().splitlines()
    for address, name in (("127.0.0.1", "single.resolver-audit.invalid"),
                          ("127.0.0.1", "multi.resolver-audit.invalid"),
                          ("127.0.0.2", "multi.resolver-audit.invalid")):
        if not any(line.split()[:2] == [address, name] for line in hosts):
            raise ValueError("The explicit hosts-file fixture differs")
    resolvers = [line.split()[1] for line in Path("/etc/resolv.conf").read_text().splitlines()
                 if line.split()[:1] == ["nameserver"]]
    if resolvers != ["127.0.0.1"]:
        raise ValueError("The diagnostic may use only its loopback DNS destination")
    build_log = target / "hostname-resolution-build.json"
    with build_log.open("wb") as output:
        build = subprocess.run(
            ["cargo", "build", "--offline", "--locked", "-p", "hbb_common",
             "--example", "hostname_resolution_probe", "--message-format=json-render-diagnostics",
             "--color", "never"], cwd=source, stdout=output, timeout=240)
    if build.returncode:
        for line in build_log.read_text().splitlines():
            record = json.loads(line)
            if record.get("reason") == "compiler-message":
                message = record.get("message", {}).get("rendered")
                if message:
                    print(message[:65536], flush=True)
        raise ValueError("Connector observation compilation failed")
    artifacts = [json.loads(line) for line in build_log.read_text().splitlines()]
    matches = [r for r in artifacts if r.get("reason") == "compiler-artifact"
               and r.get("target", {}).get("name") == "hostname_resolution_probe"
               and r.get("target", {}).get("kind") == ["example"]
               and r.get("target", {}).get("src_path") == str(source / paths[0])
               and r.get("profile", {}).get("test") is False and r.get("executable")]
    if len(matches) != 1:
        raise ValueError("Expected exactly one connector observation artifact")
    artifact = Path(matches[0]["executable"])
    metadata = artifact.lstat()
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
            or (metadata.st_uid, metadata.st_gid) != (1000, 1000)
            or artifact.resolve() != artifact
            or artifact != target / "debug/examples/hostname_resolution_probe"
            or not metadata.st_mode & 0o100):
        raise ValueError("Connector observation artifact authority differs")
    artifact_sha = digest(artifact)
    observations = []
    for case in ("literal", "hosts-single", "hosts-multi", "hosts-multi-tcp",
                 "dns-udp", "dns-tcp", "cancel"):
        result = subprocess.run([str(artifact), case], cwd=source, capture_output=True,
                                text=True, timeout=10)
        lines = result.stdout.splitlines()
        if (result.returncode or len(lines) != 1
                or not lines[0].startswith("HOSTNAME_RESOLUTION_OBSERVATION=")
                or result.stderr):
            raise ValueError(f"Connector observation {case} failed: {result.stdout[:4096]} {result.stderr[:4096]}")
        observation = json.loads(lines[0].split("=", 1)[1])
        if observation.get("case") != case or digest(artifact) != artifact_sha:
            raise ValueError("Connector observation or executable identity changed")
        observations.append(observation)
    if {p: digest(source / p) for p in paths} != sources:
        raise ValueError("Connector observation sources changed")
    print("HOSTNAME_RESOLUTION_COMPONENT=" + json.dumps({
        "artifact_sha256": artifact_sha, "sources": sources, "observations": observations,
        "product_correction": False, "instrumented": True,
        "execution": "production-FramedStream-new", "processes": "exited-and-waited"
    }, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
