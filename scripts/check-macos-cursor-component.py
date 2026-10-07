#!/usr/bin/env python3
"""Compile the exact macOS cursor adapter; not a link or native AppKit test.

Run only in the Apple check's networkless, nonroot disposable container. The
fixture replaces unrelated app dependencies, never cursor or binding types.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import tomllib


REPO = Path("/work")
TARGETS = ("aarch64-apple-darwin", "x86_64-apple-darwin")
PACKAGE = "rustdesk-macos-cursor-compile"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def between(source: bytes, start: bytes, end: bytes) -> bytes:
    if source.count(start) != 1 or source.count(end) != 1:
        raise ValueError(f"ambiguous production extraction: {start!r}")
    begin = source.index(start)
    finish = source.index(end, begin + len(start))
    return source[begin:finish]


def run(arguments: list[str], directory: Path, timeout: int = 90) -> bytes:
    result = subprocess.run(
        arguments, cwd=directory, check=False, timeout=timeout,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if len(result.stdout) > 2 * 1024 * 1024:
        raise ValueError("compiler output exceeded 2 MiB")
    if result.returncode != 0:
        print(result.stdout.decode("utf-8", errors="replace"), flush=True)
        raise ValueError(f"compiler command failed: {arguments[1]} ({result.returncode})")
    return result.stdout


def main() -> None:
    if os.geteuid() == 0 or os.getegid() == 0:
        raise ValueError("cursor compiler requires the nonroot Apple container")
    inputs = {
        name: (REPO / name).read_bytes() for name in (
            "src/platform/macos.rs", "src/platform/mod.rs",
            "src/platform/macos/cursor_snapshot.rs", "libs/hbb_common/src/lib.rs",
            "libs/hbb_common/src/protos/mod.rs", "libs/hbb_common/build.rs",
            "libs/hbb_common/protos/message.proto",
            "libs/hbb_common/protos/rendezvous.proto", "Cargo.lock",
        )
    }
    macos = inputs["src/platform/macos.rs"]
    adapter = between(macos, b"pub fn get_cursor()", b"pub(crate) fn console_owner_uid()")
    tls = between(macos, b"thread_local! {", b"\n/// Global mutex")
    declaration = re.findall(rb"^    fn CGSCurrentCursorSeed\(\) -> i32;$", macos, re.M)
    alias = re.findall(rb"^pub type ResultType<[^\n]+;$", inputs["libs/hbb_common/src/lib.rs"], re.M)
    if len(declaration) != 1 or len(alias) != 1:
        raise ValueError("native declaration or shared error alias extraction differs")
    bounds = between(
        inputs["src/platform/mod.rs"], b"pub(crate) const MAX_CURSOR_RGBA_BYTES",
        b"#[cfg(all(test, not(any(target_os = \"android\", target_os = \"ios\"))))]",
    )
    root_lock = tomllib.loads(inputs["Cargo.lock"].decode("utf-8"))
    records = {
        (item["name"], item["version"]): item for item in root_lock["package"]
        if "source" in item
    }
    direct = {"anyhow": "1.0.103", "bytes": "1.11.1", "log": "0.4.22", "cocoa": "0.24.1",
              "objc": "0.2.7", "protobuf": "3.7.2", "protobuf-codegen": "3.7.2"}
    for name, version in direct.items():
        if (name, version) not in records:
            raise ValueError(f"component dependency is not root-locked: {name} {version}")

    with tempfile.TemporaryDirectory(prefix="macos-cursor-", dir="/tmp") as temporary:
        fixture = Path(temporary)
        (fixture / "src").mkdir()
        (fixture / "protos").mkdir()
        (fixture / "build.rs").write_bytes(inputs["libs/hbb_common/build.rs"])
        for name in ("message.proto", "rendezvous.proto"):
            (fixture / "protos" / name).write_bytes(inputs[f"libs/hbb_common/protos/{name}"])
        (fixture / "src/protos.rs").write_bytes(inputs["libs/hbb_common/src/protos/mod.rs"])
        manifest = f'[package]\nname = "{PACKAGE}"\nversion = "0.0.0"\nedition = "2021"\n'
        manifest += '[dependencies]\n'
        for name, version in direct.items():
            if name == "protobuf-codegen":
                continue
            extra = ', features = ["with-bytes"]' if name == "protobuf" else ""
            manifest += f'{name} = {{ version = "={version}"{extra} }}\n'
        manifest += '[build-dependencies]\nprotobuf-codegen = "=3.7.2"\n'
        (fixture / "Cargo.toml").write_text(manifest, encoding="utf-8")
        scaffold = b"""#![allow(dead_code, unexpected_cfgs)]
mod protos;
use protos::message::CursorData;
""" + alias[0] + b"\n" + bounds + b"""
mod macos {
use super::{CursorData, ResultType};
use cocoa::{base::{id, nil, BOOL, YES}, foundation::{NSPoint, NSSize}};
use anyhow::{anyhow, bail};
use objc::rc::autoreleasepool;
use objc::{class, msg_send, sel, sel_impl};
use std::cell::RefCell;
mod cursor_snapshot {
""" + inputs["src/platform/macos/cursor_snapshot.rs"] + b"\n}\nextern \"C\" {\n" \
            + declaration[0] + b"\n}\n" + tls + adapter + b"\n}\n"
        (fixture / "src/lib.rs").write_bytes(scaffold)
        cargo = ["cargo"]
        config = ["--config", "/tmp/cargo-config.toml"]
        run(cargo + ["generate-lockfile", "--offline"] + config, fixture, 30)
        lock_bytes = (fixture / "Cargo.lock").read_bytes()
        selected = tomllib.loads(lock_bytes.decode("utf-8"))["package"]
        dependencies = []
        for item in selected:
            if item["name"] == PACKAGE and "source" not in item:
                continue
            key = (item["name"], item["version"])
            expected = records.get(key)
            if expected is None or any(item.get(field) != expected.get(field)
                                       for field in ("source", "checksum")):
                raise ValueError(f"generated component lock escaped root lock: {key}")
            dependencies.append({field: item[field] for field in ("name", "version", "source", "checksum")})
        dependency_sha = digest(json.dumps(dependencies, sort_keys=True, separators=(",", ":")).encode())
        for target in TARGETS:
            print(f"MACOS_CURSOR_COMPILE_STAGE target={target} dependencies={len(dependencies)}", flush=True)
            output = run(cargo + ["check", "--locked", "--offline", "--lib", "--jobs", "2",
                                  "--target", target, "--message-format=json"] + config, fixture)
            print(output.decode("utf-8"), end="", flush=True)
            messages = []
            for line in output.splitlines():
                if line.startswith(b"{"):
                    messages.append(json.loads(line))
            if not any(item.get("reason") == "build-finished" and item.get("success") is True
                       for item in messages):
                raise ValueError("successful compiler completion is missing")
            artifacts = [Path(name) for item in messages
                         if item.get("reason") == "compiler-artifact"
                         and item.get("target", {}).get("name") == PACKAGE.replace("-", "_")
                         and item.get("target", {}).get("kind") == ["lib"]
                         for name in item["filenames"] if name.endswith(".rmeta")]
            if len(artifacts) != 1 or not artifacts[0].is_file() or artifacts[0].stat().st_size == 0:
                raise ValueError("exact cursor component compiler metadata is missing")
            if (fixture / "Cargo.lock").read_bytes() != lock_bytes:
                raise ValueError("locked compiler changed its dependency records")
            artifact = artifacts[0].read_bytes()
            print(f"MACOS_CURSOR_COMPILE_TARGET=pass target={target} metadata_bytes={len(artifact)} "
                  f"metadata_sha256={digest(artifact)} compiler_log_sha256={digest(output)} "
                  f"fixture_sha256={digest(scaffold)} lock_sha256={digest(lock_bytes)} "
                  f"dependencies_sha256={dependency_sha} native=false", flush=True)
        for name, data in inputs.items():
            if (REPO / name).read_bytes() != data:
                raise ValueError(f"read-only production input changed: {name}")
            print(f"MACOS_CURSOR_COMPILE_INPUT path={name} bytes={len(data)} sha256={digest(data)}")
    print("MACOS_CURSOR_COMPONENT_COMPILE=pass targets=2 bindings=real protobuf=generated "
          "sdk_shim=none linking=not-run native=false cleanup=joined", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        raise SystemExit(f"macOS cursor component compile: FAIL: {error}") from error
