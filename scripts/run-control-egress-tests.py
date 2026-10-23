#!/usr/bin/env python3
"""Run the production controlled-egress implementation and focused Rust tests."""

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
import time
import tomllib


PACKAGE = "rustdesk-control-egress"
INPUTS = (
    "Cargo.lock", "src/server/connection.rs", "libs/hbb_common/src/cpace.rs",
    "src/ui_cm_interface.rs", "src/ipc.rs", "libs/enigo/src/lib.rs",
    "libs/hbb_common/src/bytes_codec.rs",
    "libs/hbb_common/build.rs", "libs/hbb_common/src/protos/mod.rs",
    "libs/hbb_common/protos/message.proto", "libs/hbb_common/protos/rendezvous.proto",
    "scripts/test-control-egress.rs", "scripts/run-control-egress-tests.py",
    "libs/hbb_common/src/fs.rs",
)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def run(arguments, directory, *, timeout=30):
    result = subprocess.run(arguments, cwd=directory, check=False, timeout=timeout,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if len(result.stdout) > 2 * 1024 * 1024:
        raise ValueError("controlled-egress output exceeds 2 MiB")
    print(result.stdout.decode("utf-8", errors="replace"), end="", flush=True)
    if result.returncode != 0:
        raise ValueError(f"controlled-egress command failed: {result.returncode}")
    return result.stdout


def between(source, start, end):
    if source.count(start) != 1 or source.count(end) != 1:
        raise ValueError("controlled-egress source boundary is missing or ambiguous")
    first = source.index(start)
    last = source.index(end)
    if first >= last:
        raise ValueError("controlled-egress source boundaries are reversed")
    return source[first:last]


def enum_declaration(source, name):
    marker = f"\npub enum {name} {{"
    if source.count(marker) != 1:
        raise ValueError(f"egress enum declaration is absent or ambiguous: {name}")
    declaration = source.index(marker)
    first = source.rfind("\n\n", 0, declaration) + 2
    last = source.index("\n}", declaration) + 2
    return source[first:last] + "\n"


def main():
    if (len(sys.argv) != 3 or (os.geteuid(), os.getegid()) != (1000, 1000)
            or Path.cwd() != Path("/source")
            or os.environ.get("CARGO_TARGET_DIR") != "/cargo-target"):
        raise ValueError("controlled-egress tests require their isolated guest entry")
    repo = Path(sys.argv[1]).resolve(strict=True)
    config_path = Path(sys.argv[2]).resolve(strict=True)
    if repo != Path("/source") or config_path != Path("/tmp/cargo-home/config.toml"):
        raise ValueError("controlled-egress source/config paths differ")
    config = ["--config", str(config_path)]
    inputs = {name: (repo / name).read_bytes() for name in INPUTS}
    packages = tomllib.loads(inputs["Cargo.lock"].decode("utf-8"))["package"]
    records = {(p["name"], p["version"], p["source"]): p
               for p in packages if "source" in p}
    connection = inputs["src/server/connection.rs"].decode("utf-8")
    snippets = {
        "queue.rs": between(connection, "const CONTROL_EGRESS_WAKE_CAPACITY:",
                            "#[derive(Default)]\nstruct AudioEgressState"),
        "tests.rs": between(connection, "#[cfg(test)]\nmod control_egress_tests {",
                            "#[cfg(test)]\nmod audio_egress_tests {"),
    }
    limits = re.findall(r"^pub const MAX_SESSION_PACKET: usize = [0-9 *]+;\n",
                        inputs["libs/hbb_common/src/cpace.rs"].decode("utf-8"), re.MULTILINE)
    if len(limits) != 1:
        raise ValueError("controlled-egress production packet limit is ambiguous")
    snippets["packet-limit.rs"] = limits[0]
    cm = inputs["src/ui_cm_interface.rs"].decode("utf-8")
    ipc = inputs["src/ipc.rs"].decode("utf-8")
    enigo = inputs["libs/enigo/src/lib.rs"].decode("utf-8")
    snippets["cm-queue.rs"] = between(cm, "const CM_EGRESS_WAKE_CAPACITY:",
                                    "/// Default maximum number of files allowed per transfer request.")
    snippets["cm-directory.rs"] = between(
        cm, '#[cfg(not(any(target_os = "ios")))]\nfn cm_file_entry_type(',
        'lazy_static::lazy_static! {\n    static ref CLIENTS:')
    snippets["cm-directory-size.rs"] = (
        "fn cm_directory_size(directory: FileDirectory) -> Result<FileDirectory, String> {\n"
        + between(connection, "        let serialized_len = directory",
                  "\n    fn active_cm_write_generation("))
    enum_limits = re.findall(r"^pub const MAX_FILE_ENUM_SERIALIZED_BYTES: usize = [0-9 *]+;\n",
                             inputs["libs/hbb_common/src/fs.rs"].decode("utf-8"), re.MULTILINE)
    if len(enum_limits) != 1:
        raise ValueError("CM directory serialization limit is ambiguous")
    snippets["cm-directory-enum-limit.rs"] = enum_limits[0]
    snippets["cm-tests.rs"] = between(
        cm, '    #[tokio::test(flavor = "current_thread")]\n    async fn r_s11gy_cm_egress_is_fifo_and_releases_capacity_on_receive()',
        '    #[tokio::test(flavor = "current_thread")]\n    async fn r_s11ha_cm_file_job_log_is_returned_to_the_exact_command_owner()')
    snippets["cm-ipc.rs"] = between(
        ipc, "#[derive(Debug, Serialize, Deserialize, Clone, Copy, Eq, PartialEq)]\npub enum CmFileEntryType {",
        '#[derive(Debug, Serialize, Deserialize, Clone, Copy, Eq, PartialEq)]\n#[serde(tag = "t")]\npub enum CmAuthConnType {')
    snippets["cm-ipc.rs"] += enum_declaration(ipc, "CmAuthConnType") + enum_declaration(ipc, "Data")
    snippets["enigo-types.rs"] = enum_declaration(enigo, "MouseButton") + enum_declaration(enigo, "Key")
    cm_limits = re.findall(r"^pub\(crate\) const CM_(?:IPC|FILE_BLOCK)_MAX_FRAME_BYTES: usize = [0-9 *]+;\n",
                           ipc, re.MULTILINE)
    if len(cm_limits) != 2:
        raise ValueError("CM egress production frame limits are ambiguous")
    snippets["cm-limits.rs"] = "".join(cm_limits)
    with socket.socket() as canary:
        try:
            canary.connect(("192.0.2.1", 9))
        except OSError as error:
            if error.errno != errno.ENETUNREACH:
                raise
        else:
            raise ValueError("controlled-egress offline canary connected")
    print("R-B10 canary: build confirmed network-isolated (offline compile stage).", flush=True)
    with tempfile.TemporaryDirectory(prefix="control-egress-", dir="/tmp") as temporary:
        fixture = Path(temporary)
        (fixture / "protos").mkdir()
        for name in ("message.proto", "rendezvous.proto"):
            (fixture / "protos" / name).write_bytes(inputs[f"libs/hbb_common/protos/{name}"])
        (fixture / "build.rs").write_bytes(inputs["libs/hbb_common/build.rs"])
        for name, body in snippets.items():
            (fixture / name).write_text(body)
            print(f"CONTROL_EGRESS_SOURCE=pass part={name} bytes={len(body.encode())} "
                  f"sha256={digest(body.encode())}", flush=True)
        os.environ["CONTROL_EGRESS_SOURCE"] = str(fixture / "queue.rs")
        os.environ["CONTROL_EGRESS_TESTS"] = str(fixture / "tests.rs")
        os.environ["CONTROL_EGRESS_LIMIT"] = str(fixture / "packet-limit.rs")
        for variable, name in (("CM_EGRESS_SOURCE", "cm-queue.rs"), ("CM_EGRESS_TESTS", "cm-tests.rs"),
                               ("CM_IPC_TYPES", "cm-ipc.rs"), ("CM_ENIGO_TYPES", "enigo-types.rs"),
                               ("CM_EGRESS_LIMIT", "cm-limits.rs"),
                               ("CM_DIRECTORY_SOURCE", "cm-directory.rs"),
                               ("CM_DIRECTORY_SIZE_SOURCE", "cm-directory-size.rs"),
                               ("CM_DIRECTORY_ENUM_LIMIT", "cm-directory-enum-limit.rs")):
            os.environ[variable] = str(fixture / name)

        roots = [p for p in packages if p["name"] == "rustdesk" and "source" not in p]
        if len(roots) != 1:
            raise ValueError("controlled-egress root application is absent or ambiguous")

        def version(name):
            versions = {p["version"] for p in packages if p["name"] == name}
            qualified = {parts[1] for dependency in roots[0]["dependencies"]
                         if (parts := dependency.split())[0] == name and len(parts) > 1}
            if qualified:
                versions &= qualified
            if len(versions) != 1:
                raise ValueError(f"controlled-egress dependency version is ambiguous: {name}")
            return versions.pop()

        (fixture / "Cargo.toml").write_text(
            f'[package]\nname = "{PACKAGE}"\nversion = "0.0.0"\nedition = "2021"\n'
            '[features]\ndefault = ["with_serde"]\nwith_serde = []\n'
            '[dependencies]\n'
            f'bytes = {{ version = "={version("bytes")}", features = ["serde"] }}\nlog = "={version("log")}"\n'
            f'serde = "={version("serde")}"\nserde_derive = "={version("serde_derive")}"\n'
            f'serde_json = "={version("serde_json")}"\n'
            f'sodiumoxide = "={version("sodiumoxide")}"\n'
            f'protobuf = {{ version = "={version("protobuf")}", features = ["with-bytes"] }}\n'
            f'tokio = {{ version = "={version("tokio")}", features = ["full"] }}\n'
            f'tokio-util = {{ version = "={version("tokio-util")}", features = ["codec"] }}\n'
            f'futures = "={version("futures")}"\n'
            '[build-dependencies]\n'
            f'protobuf-codegen = "={version("protobuf-codegen")}"\n'
            '[[test]]\nname = "control_egress"\n'
            f'path = "{repo}/scripts/test-control-egress.rs"\n')
        (fixture / "Cargo.lock").write_bytes(inputs["Cargo.lock"])
        run(["cargo", "metadata", "--offline", "--format-version=1", *config], fixture)
        lock_bytes = (fixture / "Cargo.lock").read_bytes()
        dependencies = []
        for item in tomllib.loads(lock_bytes.decode("utf-8"))["package"]:
            if item["name"] == PACKAGE and "source" not in item:
                continue
            expected = records.get((item["name"], item["version"], item.get("source", "")))
            if expected is None or item.get("checksum") != expected.get("checksum"):
                raise ValueError(f"controlled-egress dependency differs from root lock: {item['name']}")
            dependencies.append({k: item[k] for k in ("name", "version", "source", "checksum")
                                 if k in item})
        print(f"CONTROL_EGRESS_DEPENDENCIES=pass lock_sha256={digest(lock_bytes)} "
              f"records_sha256={digest(json.dumps(dependencies, sort_keys=True).encode())}", flush=True)
        started = time.monotonic()
        output = run(["cargo", "test", "--offline", "--locked", "--test", "control_egress",
                      "--no-run", "--jobs", "1", "--message-format=json", *config],
                     fixture, timeout=180)
        messages = [json.loads(line) for line in output.splitlines() if line.startswith(b"{")]
        artifacts = [Path(m["executable"]) for m in messages
                     if m.get("reason") == "compiler-artifact" and m.get("executable")
                     and m.get("manifest_path") == str(fixture / "Cargo.toml")
                     and m.get("target", {}).get("name") == "control_egress"
                     and m.get("target", {}).get("src_path") == str(repo / "scripts/test-control-egress.rs")
                     and m.get("profile", {}).get("test") is True]
        if ([m.get("success") for m in messages if m.get("reason") == "build-finished"] != [True]
                or len(artifacts) != 1
                or not re.fullmatch(r"/cargo-target/debug/deps/control_egress-[0-9a-f]{16}",
                                    str(artifacts[0]))
                or not artifacts[0].is_file() or artifacts[0].is_symlink()):
            raise ValueError("controlled-egress lacks one completed exact test artifact")
        artifact = artifacts[0]
        artifact_sha = digest(artifact.read_bytes())
        print(f"CONTROL_EGRESS_BUILD=pass seconds={time.monotonic() - started:.3f} "
              f"sha256={artifact_sha}", flush=True)
        print(f"CONTROL_EGRESS_ARTIFACT_BEFORE=observed sha256={artifact_sha} tests=34", flush=True)
        try:
            run([str(artifact), "--test-threads=1", "--color", "never", "--show-output"], fixture)
        finally:
            if digest(artifact.read_bytes()) != artifact_sha:
                raise ValueError("controlled-egress artifact changed during execution")
            print(f"CONTROL_EGRESS_ARTIFACT_AFTER=observed sha256={artifact_sha} tests=34 unchanged=before-after", flush=True)
        if digest(artifact.read_bytes()) != artifact_sha or (fixture / "Cargo.lock").read_bytes() != lock_bytes:
            raise ValueError("controlled-egress artifact or dependencies changed")
        for name, body in snippets.items():
            if (fixture / name).read_bytes() != body.encode():
                raise ValueError("controlled-egress extracted source changed")
        for name, body in inputs.items():
            if (repo / name).read_bytes() != body:
                raise ValueError(f"controlled-egress source changed: {name}")
            print(f"CONTROL_EGRESS_INPUT=pass path={name} bytes={len(body)} sha256={digest(body)}")
        print(f"CONTROL_EGRESS_ARTIFACT=pass sha256={artifact_sha} tests=34 unchanged=before-after",
              flush=True)


if __name__ == "__main__":
    try:
        main()
    except (OSError, UnicodeError, ValueError, subprocess.TimeoutExpired) as error:
        raise SystemExit(f"Controlled-egress tests: FAIL: {error}") from error
