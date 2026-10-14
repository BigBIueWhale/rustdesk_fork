#!/usr/bin/env python3
"""Compile production mode expressions against real Darwin libc; no OS execution."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import tomllib


REPO = Path("/work")
TARGETS = ("aarch64-apple-darwin", "x86_64-apple-darwin")
PACKAGE = "rustdesk-macos-file-mode-compile"
CASES = ("config", "transfer", "pid", "paste", "placeholder",
         "config_fixed", "paste_fixed", "placeholder_fixed")
INPUTS = ("libs/hbb_common/src/config.rs", "libs/hbb_common/src/fs.rs", "src/ipc/fs.rs",
          "libs/clipboard/src/platform/unix/macos/paste_task.rs",
          "libs/clipboard/src/platform/unix/macos/pasteboard_context.rs",
          "libs/hbb_common/src/lib.rs", "Cargo.lock", "scripts/macos-file-mode-fixture-build.rs")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def command(arguments, directory, *, negative=None, timeout=90):
    environment = os.environ.copy()
    environment.pop("MACOS_FILE_MODE_NEGATIVE", None)
    if negative is not None:
        environment["MACOS_FILE_MODE_NEGATIVE"] = negative
    result = subprocess.run(arguments, cwd=directory, env=environment, check=False,
                            timeout=timeout, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if len(result.stdout) > 2 * 1024 * 1024:
        raise ValueError("compiler output exceeds 2 MiB")
    return result.returncode, result.stdout


def compiler_messages(output):
    return [json.loads(line) for line in output.splitlines() if line.startswith(b"{")]


def main():
    if os.geteuid() == 0 or os.getegid() == 0:
        raise ValueError("file-mode compiler requires the nonroot Apple container")
    inputs = {name: (REPO / name).read_bytes() for name in INPUTS}
    root_lock = tomllib.loads(inputs["Cargo.lock"].decode("utf-8"))
    records = {(p["name"], p["version"]): p for p in root_lock["package"] if "source" in p}
    direct = {"libc": "0.2.171", "syn": "2.0.98", "quote": "1.0.36"}
    if any((name, version) not in records for name, version in direct.items()):
        raise ValueError("fixture dependency escaped the root lock")
    with tempfile.TemporaryDirectory(prefix="macos-file-mode-", dir="/tmp") as temporary:
        fixture = Path(temporary)
        (fixture / "src").mkdir()
        (fixture / "src/lib.rs").write_text('include!(concat!(env!("OUT_DIR"), "/modes.rs"));\n')
        (fixture / "build.rs").write_bytes(inputs["scripts/macos-file-mode-fixture-build.rs"])
        (fixture / "Cargo.toml").write_text(
            f'[package]\nname = "{PACKAGE}"\nversion = "0.0.0"\nedition = "2021"\n'
            '[dependencies]\nlibc = "=0.2.171"\n[build-dependencies]\n'
            'syn = { version = "=2.0.98", features = ["full", "visit"] }\nquote = "=1.0.36"\n')
        config = ["--config", "/tmp/cargo-config.toml"]
        status, output = command(["cargo", "generate-lockfile", "--offline", *config], fixture, timeout=30)
        if status != 0:
            print(output.decode("utf-8", errors="replace"), flush=True)
            raise ValueError("offline fixture lock generation failed")
        lock_bytes = (fixture / "Cargo.lock").read_bytes()
        dependencies = []
        for item in tomllib.loads(lock_bytes.decode("utf-8"))["package"]:
            if item["name"] == PACKAGE and "source" not in item:
                continue
            expected = records.get((item["name"], item["version"]))
            if expected is None or any(item.get(k) != expected.get(k) for k in ("source", "checksum")):
                raise ValueError("resolved fixture dependency differs from the root lock")
            dependencies.append({k: item[k] for k in ("name", "version", "source", "checksum")})
        dependency_sha = digest(json.dumps(dependencies, sort_keys=True).encode())
        for target in TARGETS:
            arguments = ["cargo", "check", "--locked", "--offline", "--lib", "--jobs", "2",
                         "--target", target, "--message-format=json", *config]
            print(f"MACOS_FILE_MODE_COMPILE_STAGE target={target} cases=8", flush=True)
            status, output = command(arguments, fixture)
            print(output.decode("utf-8", errors="replace"), end="", flush=True)
            messages = compiler_messages(output)
            if status != 0 or sum(m.get("reason") == "build-finished" and m.get("success") is True
                                  for m in messages) != 1:
                raise ValueError("positive compiler completion is absent")
            artifacts = [Path(p) for m in messages if m.get("reason") == "compiler-artifact"
                         and m.get("target", {}).get("name") == PACKAGE.replace("-", "_")
                         and m.get("target", {}).get("kind") == ["lib"]
                         for p in m["filenames"] if p.endswith(".rmeta")]
            if len(artifacts) != 1 or not artifacts[0].is_file() or artifacts[0].stat().st_size == 0:
                raise ValueError("positive compiler metadata is absent")
            generated = [Path(p) / "modes.rs" for m in messages
                         if m.get("reason") == "build-script-executed"
                         and PACKAGE in m.get("package_id", "") for p in [m["out_dir"]]]
            if len(generated) != 1:
                raise ValueError("source extractor output is absent or ambiguous")
            positive_source = generated[0].read_bytes()
            metadata = artifacts[0].read_bytes()
            for case in CASES:
                code = "E0308" if case.endswith("_fixed") else "E0617"
                status, negative_output = command(arguments, fixture, negative=case)
                print(negative_output.decode("utf-8", errors="replace"), end="", flush=True)
                negative_messages = compiler_messages(negative_output)
                errors = [m["message"] for m in negative_messages
                          if m.get("reason") == "compiler-message"
                          and m.get("target", {}).get("name") == PACKAGE.replace("-", "_")
                          and m["message"].get("level") == "error"
                          and any(s.get("is_primary") for s in m["message"].get("spans", []))]
                source = generated[0].read_text(encoding="utf-8")
                line = source.splitlines().index(f"unsafe fn mode_case_{case}(mode: libc::mode_t) {{") + 2
                if status != 101 or len(errors) != 1 or (errors[0].get("code") or {}).get("code") != code:
                    raise ValueError(f"negative compiler outcome differs: {target} {case}")
                if not any(s.get("is_primary") and s.get("line_start") == line
                           and Path(s["file_name"]).resolve() == generated[0].resolve()
                           for s in errors[0].get("spans", [])):
                    raise ValueError("negative diagnostic does not identify the admitted call")
                if sum(m.get("reason") == "build-finished" and m.get("success") is False
                       for m in negative_messages) != 1:
                    raise ValueError("negative compiler finality is absent")
                print(f"MACOS_FILE_MODE_NEGATIVE=pass target={target} case={case} code={code} "
                      f"status=101 source_sha256={digest(source.encode())} "
                      f"compiler_log_sha256={digest(negative_output)}", flush=True)
            if (fixture / "Cargo.lock").read_bytes() != lock_bytes:
                raise ValueError("locked compiler changed dependency records")
            print(f"MACOS_FILE_MODE_COMPILE_TARGET=pass target={target} cases=8 negatives=8 "
                  f"metadata_bytes={len(metadata)} metadata_sha256={digest(metadata)} "
                  f"fixture_sha256={digest(positive_source)} lock_sha256={digest(lock_bytes)} "
                  f"dependencies_sha256={dependency_sha} native=false", flush=True)
        for name, data in inputs.items():
            if (REPO / name).read_bytes() != data:
                raise ValueError(f"read-only production input changed: {name}")
            print(f"MACOS_FILE_MODE_COMPILE_INPUT path={name} bytes={len(data)} sha256={digest(data)}")
    print("MACOS_FILE_MODE_COMPONENT_COMPILE=pass targets=2 cases=8 negatives=16 libc=root-locked "
          "parser=syn sdk_shim=none linking=not-run native=false cleanup=joined", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        raise SystemExit(f"macOS file-mode component compile: FAIL: {error}") from error
