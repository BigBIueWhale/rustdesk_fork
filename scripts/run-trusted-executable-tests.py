#!/usr/bin/env python3
"""Compile the exact Unix helper selectors and execute native path-admission cases."""

import hashlib
import os
from pathlib import Path
import subprocess
import sys


REGIONS = (
    ("shared", "libs/hbb_common/src/platform/linux.rs", "trusted_fixed_executable_path",
     ("linux_helper_path_is_clean_absolute", "trusted_command_file_metadata",
      "trusted_command_parent_metadata", "trusted_command_file", "trusted_command_parent")),
    ("system", "src/platform/linux.rs", "trusted_fixed_executable_path",
     ("linux_helper_path_is_clean_absolute", "trusted_command_file_metadata",
      "trusted_command_parent_metadata", "trusted_command_file", "trusted_command_parent")),
    ("authorization", "src/ipc.rs", "linux_trusted_authority_command_path",
     ("linux_path_is_clean_absolute", "linux_trusted_command_file_metadata",
      "linux_trusted_command_parent_metadata", "linux_trusted_command_file", "linux_trusted_command_parent")),
    ("terminal", "src/server/terminal_service.rs", "trusted_unix_terminal_shell_path",
     ("unix_path_is_clean_absolute", "trusted_unix_shell_file", "trusted_unix_shell_parent")),
)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def function(source, name, required=True):
    marker = "fn " + name + "("
    if marker not in source:
        if required:
            raise ValueError(f"missing selector function: {name}")
        return ""
    start = source.index(marker)
    opening = source.index("{", start)
    depth = 1
    end = opening + 1
    # These selected functions have no brace-bearing literals. Rust compilation is mandatory.
    while depth and end < len(source):
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    if depth:
        raise ValueError(f"unclosed selector function: {name}")
    return source[start:end] + "\n"


def main():
    if len(sys.argv) != 2 or os.getuid() != 1000 or not Path("/.dockerenv").is_file():
        raise ValueError("selector tests require the isolated ordinary verifier container")
    repo = Path(sys.argv[1]).resolve(strict=True)
    inputs = {}
    generated = "extern crate self as hbb_common;\n"
    historical = "scripts/fixtures/trusted-executable-before.rs"
    inputs[historical] = (repo / historical).read_bytes()
    before = inputs[historical].decode("utf-8")
    fragment = "".join(function(before, name) for name in REGIONS[0][3])
    fragment += function(before, REGIONS[0][2])
    if digest(fragment.encode()) != "e360862fdace60bb6323769dd149244e4fcd1c702ad5f713d7caf2b2b06cc285":
        raise ValueError("historical selector differs from exact b3f8206a production")
    generated += f'#[path = "{repo / historical}"] mod before;\n'
    print(f"TRUSTED_EXECUTABLE_HISTORICAL=source commit=b3f8206a path={historical} "
          f"fragment_sha256={digest(fragment.encode())}", flush=True)
    policy = repo / "libs/hbb_common/src/platform/trusted_executable.rs"
    if policy.exists():
        inputs[str(policy.relative_to(repo))] = policy.read_bytes()
        generated += f'pub mod platform {{ #[path = "{policy}"] pub mod trusted_executable; }}\n'
    for module, path, selector, helpers in REGIONS:
        data = (repo / path).read_bytes()
        inputs[path] = data
        source = data.decode("utf-8")
        body = "".join(function(source, name, False) for name in helpers)
        body += function(source, selector)
        generated += (f"mod {module} {{ use std::{{fs, path::{{Component, Path, PathBuf}}}}; "
                      "use std::os::unix::fs::MetadataExt;\n" + body +
                      f"pub fn select(path: &Path) -> Option<PathBuf> {{ {selector}(path) }}\n}}\n")
        print(f"TRUSTED_EXECUTABLE_SELECTOR=source module={module} path={path} sha256={digest(data)} "
              f"fragment_sha256={digest(body.encode())}", flush=True)
    for path in ("scripts/test-linux-service-uid-policy.rs", "scripts/test-trusted-executable.rs",
                 "scripts/run-trusted-executable-tests.py", "src/ipc/uid_policy.rs",
                 "scripts/test-linux-process-identity.rs", "src/ipc/auth.rs"):
        inputs[path] = (repo / path).read_bytes()
    identity_source = inputs["src/ipc/auth.rs"].decode("utf-8")
    structure_start = identity_source.index("pub struct LinuxProcessIdentity {")
    structure_end = identity_source.index("\n}", structure_start) + 2
    identity_body = identity_source[structure_start:structure_end] + "\n"
    for name in ("linux_proc_stat_start_time", "linux_proc_start_time", "linux_proc_uid",
                 "linux_proc_live_stat_start_time", "linux_proc_status_uid",
                 "linux_kernel_process_identity_by_pid", "linux_process_identity_is_live"):
        identity_body += function(identity_source, name)
    # The exact metadata bodies use only std operations. Serialization and anyhow's
    # error representation are outside this component; Result/refusal behavior is retained.
    generated += ('use std::{fs, os::unix::fs::MetadataExt};\n'
                  'type ResultType<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;\n'
                  'macro_rules! bail { ($($arg:tt)*) => { return Err(format!($($arg)*).into()) }; }\n'
                  '#[derive(Clone, Debug, Eq, PartialEq)]\n' + identity_body)
    print(f"LINUX_KERNEL_IDENTITY_SOURCE=sha256={digest(inputs['src/ipc/auth.rs'])} "
          f"fragment_sha256={digest(identity_body.encode())} error_context=std-boxed serialization=unexecuted", flush=True)
    generated += f'include!("{repo}/scripts/test-linux-service-uid-policy.rs");\n'
    generated += f'include!("{repo}/scripts/test-trusted-executable.rs");\n'
    generated += f'include!("{repo}/scripts/test-linux-process-identity.rs");\n'
    source = Path("/cargo-target/trusted-executable-tests.rs")
    source.write_text(generated)
    artifact = Path("/cargo-target/uid-policy-tests")
    subprocess.run(["rustc", "--edition=2021", "--test", str(source), "-o", str(artifact)],
                   check=True, timeout=30)
    identity = digest(artifact.read_bytes())
    print(f"TRUSTED_EXECUTABLE_BUILD=sha256={identity} tests=14", flush=True)
    result = subprocess.run([str(artifact), "--test-threads=1", "--color", "never", "--show-output"],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=20,
                            env={key: value for key, value in os.environ.items()
                                 if not key.startswith("LINUX_IDENTITY_")})
    if len(result.stdout) > 65536:
        raise ValueError("selector test output exceeds 64 KiB")
    print(result.stdout.decode("utf-8"), end="", flush=True)
    if digest(artifact.read_bytes()) != identity or source.read_text() != generated:
        raise ValueError("selector fixture changed during execution")
    for path, data in inputs.items():
        if (repo / path).read_bytes() != data:
            raise ValueError(f"selector input changed: {path}")
        print(f"TRUSTED_EXECUTABLE_INPUT=path={path} bytes={len(data)} sha256={digest(data)}", flush=True)
    print(f"TRUSTED_EXECUTABLE_ARTIFACT=status={result.returncode} sha256={identity} unchanged=before-after", flush=True)
    if result.returncode != 0:
        raise ValueError(f"native selector tests failed: {result.returncode}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        raise SystemExit(f"Trusted executable tests: FAIL: {error}") from error
