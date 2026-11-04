#!/usr/bin/env python3
"""Build and execute the production Linux query boundary in an isolated container."""

import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import tomllib


PACKAGE = "rustdesk-linux-xrandr-query"
INPUTS = ("Cargo.lock", "src/platform/linux.rs", "src/platform/linux/xrandr_query.rs",
          "libs/hbb_common/src/lib.rs", "scripts/test-linux-xrandr-query.rs",
          "scripts/run-linux-xrandr-query-tests.py")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def run(arguments, directory, *, timeout=90):
    result = subprocess.run(arguments, cwd=directory, check=False, timeout=timeout,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if len(result.stdout) > 2 * 1024 * 1024:
        raise ValueError("query test output exceeds 2 MiB")
    print(result.stdout.decode("utf-8", errors="replace"), end="", flush=True)
    if result.returncode != 0:
        raise ValueError(f"query test command failed: {result.returncode}")
    return result.stdout


def main():
    if os.geteuid() == 0 or os.getegid() == 0:
        raise ValueError("query tests require the nonroot isolated container")
    repo = Path(sys.argv[1]).resolve(strict=True)
    config = ["--config", str(Path(sys.argv[2]).resolve(strict=True))]
    if len(sys.argv) not in (3, 4) or (len(sys.argv) == 4 and sys.argv[3] != "--lifetime"):
        raise ValueError("query fixture selection differs")
    lifetime = len(sys.argv) == 4
    test_file = "scripts/test-linux-resolution-lifetime.rs" if lifetime else "scripts/test-linux-xrandr-query.rs"
    input_names = INPUTS + (("src/server/connection.rs", "src/server/connection/resolution_work.rs",
                            "src/platform/linux/xrandr_command.rs", test_file) if lifetime else (
        "src/platform/mod.rs", "src/server/display_service/resolution_restore.rs",
        "scripts/test-linux-resolution-rotation.rs", "scripts/verify-linux-service-password-ipc.py"))
    inputs = {name: (repo / name).read_bytes() for name in input_names}
    receipt = "LINUX_RESOLUTION_LIFETIME" if lifetime else "LINUX_XRANDR_QUERY"
    tests = 24 if lifetime else 21
    root_lock = tomllib.loads(inputs["Cargo.lock"].decode("utf-8"))
    records = {(p["name"], p["version"]): p for p in root_lock["package"] if "source" in p}
    with socket.socket() as canary:
        try:
            canary.connect(("192.0.2.1", 9))
        except OSError as error:
            if error.errno != errno.ENETUNREACH:
                raise
        else:
            raise ValueError("query test offline canary connected")
    print("R-B10 canary: build confirmed network-isolated (offline compile stage).", flush=True)
    with tempfile.TemporaryDirectory(prefix="xrandr-query-", dir="/tmp") as temporary:
        fixture = Path(temporary)
        dependencies = ('libc = "=0.2.171"\nlog = "=0.4.22"\n'
                        'tokio = { version = "=1.44.2", features = ["rt", "sync", "time", "macros"] }\n'
                        if lifetime else 'anyhow = "=1.0.103"\nlog = "=0.4.22"\n')
        if not lifetime:
            spec = importlib.util.spec_from_file_location("query_parser", repo / "scripts/verify-linux-service-password-ipc.py")
            parser = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = parser
            spec.loader.exec_module(parser)
            extracted = []
            for path, names in (
                ("src/platform/linux.rs", ("get_width_height_from_captures", "resolutions", "current_resolution", "change_resolution_directly")),
                ("src/platform/mod.rs", ("change_resolution",)),
            ):
                source = parser.RustSource.parse(path, inputs[path].decode())
                for name in names:
                    starts = [i for i, token in enumerate(source.tokens[:-1])
                              if token.text == "fn" and source.tokens[i + 1].text == name
                              and source.brace_parent[i] is None]
                    bodies = source.functions(name, parent=None)
                    if len(starts) != 1 or len(bodies) != 1:
                        raise ValueError(f"ambiguous production query function: {name}")
                    extracted.append(source.text[source.tokens[starts[0]].offset:source.tokens[bodies[0].end].offset + 1])
            functions = fixture / "functions.rs"
            functions.write_text("\n".join(extracted))
            os.environ["RUSTDESK_XRANDR_FUNCTIONS"] = str(functions)
            os.environ["RUSTFLAGS"] = os.environ.get("RUSTFLAGS", "") + " --cfg xrandr_rotation_probe"
        (fixture / "Cargo.toml").write_text(
            f'[package]\nname = "{PACKAGE}"\nversion = "0.0.0"\nedition = "2021"\n'
            '[dependencies]\nregex = "=1.11.1"\n' + dependencies +
            '[[test]]\nname = "xrandr_query"\n' + f'path = "{repo}/{test_file}"\n')
        run(["cargo", "generate-lockfile", "--offline", *config], fixture, timeout=30)
        lock_bytes = (fixture / "Cargo.lock").read_bytes()
        dependencies = []
        for item in tomllib.loads(lock_bytes.decode("utf-8"))["package"]:
            if item["name"] == PACKAGE and "source" not in item:
                continue
            expected = records.get((item["name"], item["version"]))
            if expected is None or any(item.get(k) != expected.get(k) for k in ("source", "checksum")):
                raise ValueError("query fixture dependency differs from the root lock")
            dependencies.append({k: item[k] for k in ("name", "version", "source", "checksum")})
        print(f"{receipt}_DEPENDENCIES=pass lock_sha256={digest(lock_bytes)} "
              f"records_sha256={digest(json.dumps(dependencies, sort_keys=True).encode())}", flush=True)
        output = run(["cargo", "test", "--offline", "--locked", "--test", "xrandr_query",
                      "--no-run", "--jobs", "1", "--message-format=json", *config], fixture)
        messages = [json.loads(line) for line in output.splitlines() if line.startswith(b"{")]
        artifacts = [Path(m["executable"]) for m in messages
                     if m.get("reason") == "compiler-artifact" and m.get("executable")
                     and m.get("target", {}).get("name") == "xrandr_query"]
        if len(artifacts) != 1 or not artifacts[0].is_file() or artifacts[0].is_symlink():
            raise ValueError("query test executable is absent or ambiguous")
        artifact = artifacts[0]
        artifact_sha = digest(artifact.read_bytes())
        run([str(artifact), "--test-threads=1", "--color", "never"], fixture, timeout=30)
        if digest(artifact.read_bytes()) != artifact_sha or (fixture / "Cargo.lock").read_bytes() != lock_bytes:
            raise ValueError("query test artifact or dependencies changed")
        for name, data in inputs.items():
            if (repo / name).read_bytes() != data:
                raise ValueError(f"query test source changed: {name}")
            print(f"{receipt}_INPUT=pass path={name} bytes={len(data)} sha256={digest(data)}")
        print(f"{receipt}_ARTIFACT=pass sha256={artifact_sha} tests={tests} unchanged=before-after", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        raise SystemExit(f"Linux xrandr query tests: FAIL: {error}") from error
