#!/usr/bin/env python3
"""Execute the Android receiver's exact modifier rewrite, with real protobufs."""
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import tomllib

PACKAGE = "rustdesk-android-key-modifiers"
INPUTS = ("Cargo.lock", "src/server/connection.rs", "src/keyboard.rs", "src/common.rs",
          "libs/hbb_common/build.rs", "libs/hbb_common/src/protos/mod.rs",
          "libs/hbb_common/protos/message.proto", "libs/hbb_common/protos/rendezvous.proto",
          "scripts/test-android-key-modifiers.rs", "scripts/run-android-key-modifier-tests.py")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def between(source, start, end):
    if source.count(start) != 1 or source.count(end) != 1:
        raise ValueError("production boundary is absent or ambiguous")
    first, last = source.index(start), source.index(end)
    if first >= last:
        raise ValueError("production boundaries are reversed")
    return source[first:last]


def run(arguments, directory, timeout):
    result = subprocess.run(arguments, cwd=directory, timeout=timeout,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if len(result.stdout) > 2 * 1024 * 1024:
        raise ValueError("modifier test output exceeds 2 MiB")
    print(result.stdout.decode("utf-8", errors="replace"), end="", flush=True)
    if result.returncode:
        raise ValueError(f"modifier test command failed: {result.returncode}")
    return result.stdout


def main():
    if (len(sys.argv) != 3 or (os.geteuid(), os.getegid()) != (1000, 1000)
            or Path.cwd() != Path("/source")
            or os.environ.get("CARGO_TARGET_DIR") != "/cargo-target"):
        raise ValueError("modifier tests require their isolated guest entry")
    repo = Path(sys.argv[1]).resolve(strict=True)
    config_path = Path(sys.argv[2]).resolve(strict=True)
    if repo != Path("/source") or config_path != Path("/tmp/cargo-home/config.toml"):
        raise ValueError("modifier source/config paths differ")
    config = ["--config", str(config_path)]
    inputs = {name: (repo / name).read_bytes() for name in INPUTS}
    packages = tomllib.loads(inputs["Cargo.lock"].decode())["package"]
    locked = {(p["name"], p["version"], p["source"]): p for p in packages if "source" in p}

    def version(name):
        versions = {p["version"] for p in packages if p["name"] == name}
        if len(versions) != 1:
            raise ValueError(f"ambiguous locked dependency: {name}")
        return versions.pop()

    connection = inputs["src/server/connection.rs"].decode()
    branch = between(connection,
        '                #[cfg(any(target_os = "android"))]\n                Some(message::Union::KeyEvent(mut me)) => {',
        '                #[cfg(not(any(target_os = "android", target_os = "ios")))]\n                Some(message::Union::KeyEvent(me)) => {')
    start = '                    let key = match'
    end = '                    if let Err(err) = validate_key_input(&me) {'
    if branch.count(start) != 1 or branch.count(end) != 2:
        raise ValueError("Android rewrite/validation boundaries differ")
    rewrite = branch[branch.index(start):branch.rindex(end)]
    common = between(inputs["src/common.rs"].decode(), 'pub fn is_modifier(evt: &KeyEvent)',
                     '#[inline]\npub fn get_app_name()')
    fields = re.findall(r'(?m)^    pressed_modifiers: HashSet<ControlKey>,$', connection)
    if len(fields) != 1:
        raise ValueError("production connection modifier ownership differs")
    wrapper = ('use std::collections::HashSet;\nuse protobuf::{Message, Enum, EnumOrUnknown};\n'
               f'#[path = "{repo}/libs/hbb_common/src/protos/mod.rs"] mod protos;\n'
               'use protos::message::*;\n' + common +
               '#[derive(Default)] struct Connection {\n' + fields[0] + '\n}\n'
               'impl Connection { fn rewrite(&mut self, mut me: KeyEvent) -> KeyEvent {\n' + rewrite + '\nme\n} }\n'
               f'#[path = "{repo}/scripts/test-android-key-modifiers.rs"] mod tests;\n')
    with socket.socket() as canary:
        try:
            canary.connect(("192.0.2.1", 9))
        except OSError as error:
            if error.errno != errno.ENETUNREACH:
                raise
        else:
            raise ValueError("modifier offline canary connected")
    print("R-B10 canary: build confirmed network-isolated (offline compile stage).", flush=True)
    with tempfile.TemporaryDirectory(prefix="android-key-modifiers-", dir="/tmp") as directory:
        fixture = Path(directory)
        (fixture / "protos").mkdir()
        for name in ("message.proto", "rendezvous.proto"):
            (fixture / "protos" / name).write_bytes(inputs[f"libs/hbb_common/protos/{name}"])
        (fixture / "build.rs").write_bytes(inputs["libs/hbb_common/build.rs"])
        (fixture / "lib.rs").write_text(wrapper)
        (fixture / "Cargo.toml").write_text(
            f'[package]\nname = "{PACKAGE}"\nversion = "0.0.0"\nedition = "2021"\n'
            '[dependencies]\n'
            f'bytes = "={version("bytes")}"\n'
            f'protobuf = {{ version = "={version("protobuf")}", features = ["with-bytes"] }}\n'
            '[build-dependencies]\n'
            f'protobuf-codegen = "={version("protobuf-codegen")}"\n'
            '[lib]\nname = "android_key_modifiers"\npath = "lib.rs"\n')
        (fixture / "Cargo.lock").write_bytes(inputs["Cargo.lock"])
        run(["cargo", "metadata", "--offline", "--format-version=1", *config], fixture, 30)
        lock_bytes = (fixture / "Cargo.lock").read_bytes()
        for item in tomllib.loads(lock_bytes.decode())["package"]:
            if item["name"] == PACKAGE and "source" not in item:
                continue
            expected = locked.get((item["name"], item["version"], item.get("source", "")))
            if expected is None or item.get("checksum") != expected.get("checksum"):
                raise ValueError(f"modifier dependency differs from root lock: {item['name']}")
        print(f"ANDROID_KEY_MODIFIERS_DEPENDENCIES=pass lock_sha256={digest(lock_bytes)}", flush=True)
        output = run(["cargo", "test", "--offline", "--locked", "--lib", "--no-run", "--jobs", "1",
                      "--message-format=json", *config], fixture, 180)
        messages = [json.loads(line) for line in output.splitlines() if line.startswith(b"{")]
        candidates = [Path(item["executable"]) for item in messages
                      if item.get("reason") == "compiler-artifact" and item.get("executable")
                      and item.get("manifest_path") == str(fixture / "Cargo.toml")
                      and item.get("target", {}).get("name") == "android_key_modifiers"
                      and item.get("target", {}).get("src_path") == str(fixture / "lib.rs")
                      and item.get("target", {}).get("kind") == ["lib"]
                      and item.get("profile", {}).get("test") is True]
        if ([m.get("success") for m in messages if m.get("reason") == "build-finished"] != [True]
                or len(candidates) != 1 or candidates[0].is_symlink() or not candidates[0].is_file()
                or not re.fullmatch(r"/cargo-target/debug/deps/android_key_modifiers-[0-9a-f]{16}", str(candidates[0]))):
            raise ValueError("modifier artifact is absent or ambiguous")
        artifact = candidates[0]
        artifact_sha = digest(artifact.read_bytes())
        print(f"ANDROID_KEY_MODIFIERS_SOURCE=pass bytes={len(rewrite.encode())} sha256={digest(rewrite.encode())}", flush=True)
        print(f"ANDROID_KEY_MODIFIERS_ARTIFACT_BEFORE=observed sha256={artifact_sha} tests=8", flush=True)
        try:
            run([str(artifact), "--test-threads=1", "--color", "never", "--show-output"], fixture, 20)
        finally:
            if digest(artifact.read_bytes()) != artifact_sha:
                raise ValueError("modifier artifact changed during execution")
            print(f"ANDROID_KEY_MODIFIERS_ARTIFACT_AFTER=observed sha256={artifact_sha} tests=8 unchanged=before-after", flush=True)
        if (fixture / "Cargo.lock").read_bytes() != lock_bytes or (fixture / "lib.rs").read_text() != wrapper:
            raise ValueError("modifier artifact inputs changed")
        for name, data in inputs.items():
            if (repo / name).read_bytes() != data:
                raise ValueError(f"modifier source changed: {name}")
            print(f"ANDROID_KEY_MODIFIERS_INPUT=pass path={name} bytes={len(data)} sha256={digest(data)}")
        print(f"ANDROID_KEY_MODIFIERS_ARTIFACT=pass sha256={artifact_sha} tests=8 unchanged=before-after", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        raise SystemExit(f"Android key modifier tests: FAIL: {error}") from error
