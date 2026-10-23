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
    "libs/hbb_common/src/config.rs", "libs/hbb_common/src/lib.rs", "src/common.rs",
    "libs/clipboard/src/lib.rs", "libs/clipboard/Cargo.toml",
    "src/ui_session_interface.rs",
    "src/server/input_service.rs", "scripts/test-cursor-echo.rs",
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
    file_clipboard = inputs["libs/clipboard/src/lib.rs"].decode("utf-8")
    file_clipboard_start = "pub struct ProgressPercent {"
    if file_clipboard.count(file_clipboard_start) != 1:
        raise ValueError("file-clipboard common implementation boundary is ambiguous")
    snippets = {
        "file-clipboard.rs": (
            "use std::{collections::VecDeque, fmt, sync::{Arc, Mutex, RwLock}};\n"
            "use hbb_common::{lazy_static, tokio::sync::mpsc};\n"
            "use serde_derive::{Deserialize, Serialize};\nuse thiserror::Error;\n"
            + file_clipboard[file_clipboard.index(file_clipboard_start):]),
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
    input_source = inputs["src/server/input_service.rs"].decode("utf-8")
    snippets["cursor-state.rs"] = between(
        input_source, "struct StatePos {", "#[derive(Default)]\nstruct StateWindowFocus {")
    snippets["cursor-input.rs"] = between(
        input_source, "#[derive(Default, Clone, Copy)]\nstruct Input {",
        "#[derive(Clone, Default)]\npub struct MouseCursorSub {")
    snippets["cursor-clock.rs"] = between(
        input_source, "#[inline]\npub fn update_latest_input_cursor_time(",
        "// check if mouse is moved by the controlled side user")
    snippets["cursor-sender.rs"] = between(input_source, "fn run_pos(", "fn run_cursor(")
    declarations = [re.findall(expression, input_source, re.MULTILINE) for expression in (
        r"^const INVALID_CURSOR_POS: i32 = [^;]+;\n",
        r"^    static ref LATEST_PEER_INPUT_CURSOR: [^;]+;\n",
        r"^    static ref LATEST_SYS_CURSOR_POS: [^;]+;\n",
    )]
    if any(len(matches) != 1 for matches in declarations):
        raise ValueError("cursor echo state declaration is absent or ambiguous")
    snippets["cursor-globals.rs"] = (
        declarations[0][0] + "lazy_static::lazy_static! {\n"
        + declarations[1][0] + declarations[2][0] + "}\n")
    writers = re.findall(
        r"\*LATEST_PEER_INPUT_CURSOR\.lock\(\)\.unwrap\(\) = Input \{[^}]+};",
        input_source)
    if len(writers) != 2 or "x: evt.x" not in writers[0] or "x: evt.x" in writers[1]:
        raise ValueError("cursor echo input assignment is absent or ambiguous")
    snippets["cursor-writers.rs"] = (
        "fn record_absolute(conn: i32, evt: &MouseEvent) {\n" + writers[0]
        + "\n}\nfn record_relative(conn: i32, x: i32, y: i32) {\n"
        + writers[1] + "\n}\n")
    session = inputs["src/ui_session_interface.rs"].decode("utf-8")
    legacy_marker = "            std::fs::File::create(&path).ok();\n"
    marker_start = "            let marker_ready = "
    marker_end = "            if marker_ready {"
    if session.count(legacy_marker) == 1 and marker_start not in session:
        marker_body = legacy_marker + "    true\n"
        marker_shape = "legacy-create-before-shell"
    elif session.count(marker_start) == 1 and legacy_marker not in session:
        marker_body = between(session, marker_start, marker_end)[len(marker_start):].strip()
        if not marker_body.endswith(";"):
            raise ValueError("recent-document marker expression is incomplete")
        marker_body = marker_body[:-1] + "\n"
        marker_shape = "production-create-only-match"
    else:
        raise ValueError("recent-document marker source is absent or ambiguous")
    snippets["recent-document-marker.rs"] = (
        "fn recent_document_marker(path: &std::path::Path) -> bool {\n"
        + marker_body + "}\n")
    print(f"RECENT_DOCUMENT_EXTRACTION=pass shape={marker_shape} "
          "scope=portable-file-operation shell=unexecuted", flush=True)
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
    snippets["cm-read-block.rs"] = (
        "fn cm_read_block_to_proto(id: i32, file_num: i32, data: bytes::Bytes, compressed: bool) -> FileTransferBlock {\n"
        + between(connection, "                let mut block = FileTransferBlock::new();\n",
                  "                self.send(fs::new_block(block)).await;")
        + "    block\n}\n")
    fs_source = inputs["libs/hbb_common/src/fs.rs"].decode("utf-8")
    config_source = inputs["libs/hbb_common/src/config.rs"].decode("utf-8")
    common = inputs["src/common.rs"].decode("utf-8")
    shared = inputs["libs/hbb_common/src/lib.rs"].decode("utf-8")
    def declaration(source, expression):
        matches = re.findall(expression, source, re.MULTILINE)
        if len(matches) != 1:
            raise ValueError("CM directory helper declaration is absent or ambiguous")
        return matches[0] + "\n"
    snippets["cm-proto-fs.rs"] = (
        declaration(fs_source, r"^pub const DEFAULT_FILE_TRANSFER_MAX_FILES: usize = [0-9_]+;$")
        + between(fs_source, "pub fn validate_file_name_no_traversal(",
                  "#[inline]\nfn validate_fs_path_argument(")
        + between(fs_source, "fn is_symlink_or_reparse_point(", "fn join_validated_path("))
    snippets["cm-proto-config.rs"] = (
        "lazy_static::lazy_static! {\n"
        + declaration(config_source, r"^    pub static ref BUILTIN_SETTINGS: RwLock<HashMap<String, String>> = Default::default\(\);$")
        + "}\npub mod keys {\n"
        + declaration(config_source, r'^    pub const OPTION_FILE_TRANSFER_MAX_FILES: &str = "file-transfer-max-files";$')
        + "}\n")
    snippets["cm-proto-count.rs"] = (
        declaration(cm, r"^const DEFAULT_MAX_VALIDATED_FILES: usize = fs::DEFAULT_FILE_TRANSFER_MAX_FILES;$")
        + declaration(cm, r"^static MAX_VALIDATED_FILES: std::sync::OnceLock<usize> = std::sync::OnceLock::new\(\);$")
        + between(cm, "pub fn get_max_validated_files()", '#[cfg(not(any(target_os = "ios")))]\npub fn file_transfer_enumeration_budget(')
        + between(cm, "pub fn check_file_count_limit(", "#[derive(Serialize, Clone)]\npub struct Client {"))
    snippets["cm-proto-getter.rs"] = (
        declaration(shared, r"^pub type ResultType<F, E = anyhow::Error> = anyhow::Result<F, E>;$")
        + between(common, "pub fn get_builtin_option(", "#[inline]\npub fn is_custom_client("))
    snippets["cm-proto-conversion.rs"] = (
        "struct DirectoryConnection;\nimpl DirectoryConnection {\n"
        + between(connection, "    fn cm_file_directory_to_proto(", "    fn active_cm_write_generation(")
        + "    fn cm_directories_to_proto(directories: Vec<ipc::CmFileDirectory>) -> Result<Vec<FileDirectory>, String> {\n"
        + between(connection, "                match result.and_then(|directories| {\n",
                  "                }) {\n                    Ok(empty_dirs) => {").split("\n", 1)[1]
        + "    }\n}\n")
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
        os.environ["FILE_CLIPBOARD_SOURCE"] = str(fixture / "file-clipboard.rs")
        os.environ["RECENT_DOCUMENT_MARKER_SOURCE"] = str(fixture / "recent-document-marker.rs")
        for variable, name in (("CM_EGRESS_SOURCE", "cm-queue.rs"), ("CM_EGRESS_TESTS", "cm-tests.rs"),
                               ("CM_IPC_TYPES", "cm-ipc.rs"), ("CM_ENIGO_TYPES", "enigo-types.rs"),
                               ("CM_EGRESS_LIMIT", "cm-limits.rs"),
                               ("CM_DIRECTORY_SOURCE", "cm-directory.rs"),
                               ("CM_DIRECTORY_SIZE_SOURCE", "cm-directory-size.rs"),
                               ("CM_DIRECTORY_ENUM_LIMIT", "cm-directory-enum-limit.rs"),
                               ("CM_READ_BLOCK_SOURCE", "cm-read-block.rs"),
                               ("CM_PROTO_FS", "cm-proto-fs.rs"),
                               ("CM_PROTO_CONFIG", "cm-proto-config.rs"),
                               ("CM_PROTO_COUNT", "cm-proto-count.rs"),
                               ("CM_PROTO_GETTER", "cm-proto-getter.rs"),
                               ("CM_PROTO_CONVERSION", "cm-proto-conversion.rs"),
                               ("CURSOR_ECHO_STATE", "cursor-state.rs"),
                               ("CURSOR_ECHO_INPUT", "cursor-input.rs"),
                               ("CURSOR_ECHO_CLOCK", "cursor-clock.rs"),
                               ("CURSOR_ECHO_SENDER", "cursor-sender.rs"),
                               ("CURSOR_ECHO_GLOBALS", "cursor-globals.rs"),
                               ("CURSOR_ECHO_WRITERS", "cursor-writers.rs")):
            os.environ[variable] = str(fixture / name)

        roots = [p for p in packages if p["name"] == "rustdesk" and "source" not in p]
        if len(roots) != 1:
            raise ValueError("controlled-egress root application is absent or ambiguous")

        def version(name, consumer=roots[0]):
            versions = {p["version"] for p in packages if p["name"] == name}
            qualified = {parts[1] for dependency in consumer["dependencies"]
                         if (parts := dependency.split())[0] == name and len(parts) > 1}
            if qualified:
                versions &= qualified
            if len(versions) != 1:
                raise ValueError(f"controlled-egress dependency version is ambiguous: {name}")
            return versions.pop()

        clipboard_roots = [p for p in packages if p["name"] == "clipboard" and "source" not in p]
        if len(clipboard_roots) != 1:
            raise ValueError("file-clipboard package lock authority is ambiguous")
        (fixture / "Cargo.toml").write_text(
            f'[package]\nname = "{PACKAGE}"\nversion = "0.0.0"\nedition = "2021"\n'
            '[features]\ndefault = ["with_serde"]\nwith_serde = []\n'
            '[dependencies]\n'
            f'bytes = {{ version = "={version("bytes")}", features = ["serde"] }}\nlog = "={version("log")}"\n'
            f'serde = "={version("serde")}"\nserde_derive = "={version("serde_derive")}"\n'
            f'serde_json = "={version("serde_json")}"\n'
            f'thiserror = "={version("thiserror", clipboard_roots[0])}"\n'
            f'sodiumoxide = "={version("sodiumoxide")}"\n'
            f'anyhow = "={version("anyhow")}"\nfiletime = "={version("filetime")}"\n'
            f'libc = "={version("libc")}"\nlazy_static = "={version("lazy_static")}"\n'
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
        for name, body in inputs.items():
            if (repo / name).read_bytes() != body:
                raise ValueError(f"controlled-egress source changed before execution: {name}")
            print(f"CONTROL_EGRESS_INPUT=pass path={name} bytes={len(body)} sha256={digest(body)}")
        print(f"CONTROL_EGRESS_BUILD=pass seconds={time.monotonic() - started:.3f} "
              f"sha256={artifact_sha}", flush=True)
        print(f"CONTROL_EGRESS_ARTIFACT_BEFORE=observed sha256={artifact_sha} tests=48", flush=True)
        try:
            run([str(artifact), "--test-threads=1", "--color", "never", "--show-output"], fixture)
        finally:
            if digest(artifact.read_bytes()) != artifact_sha:
                raise ValueError("controlled-egress artifact changed during execution")
            print(f"CONTROL_EGRESS_ARTIFACT_AFTER=observed sha256={artifact_sha} tests=48 unchanged=before-after", flush=True)
        if digest(artifact.read_bytes()) != artifact_sha or (fixture / "Cargo.lock").read_bytes() != lock_bytes:
            raise ValueError("controlled-egress artifact or dependencies changed")
        for name, body in snippets.items():
            if (fixture / name).read_bytes() != body.encode():
                raise ValueError("controlled-egress extracted source changed")
        for name, body in inputs.items():
            if (repo / name).read_bytes() != body:
                raise ValueError(f"controlled-egress source changed: {name}")
        print(f"CONTROL_EGRESS_ARTIFACT=pass sha256={artifact_sha} tests=48 unchanged=before-after",
              flush=True)


if __name__ == "__main__":
    try:
        main()
    except (OSError, UnicodeError, ValueError, subprocess.TimeoutExpired) as error:
        raise SystemExit(f"Controlled-egress tests: FAIL: {error}") from error
