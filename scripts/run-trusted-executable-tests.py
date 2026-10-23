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
                 "scripts/test-linux-process-identity.rs", "scripts/test-linux-process-peer.c",
                 "src/ipc/auth.rs", "src/common.rs"):
        inputs[path] = (repo / path).read_bytes()
    identity_source = inputs["src/ipc/auth.rs"].decode("utf-8")
    structure_start = identity_source.index("pub struct LinuxProcessIdentity {")
    structure_end = identity_source.index("\n}", structure_start) + 2
    identity_body = identity_source[structure_start:structure_end] + "\n"
    peer_start = identity_source.index("pub struct PeerProcessIdentity {")
    peer_end = identity_source.index("\n}", peer_start) + 2
    debug_start = identity_source.index("impl fmt::Debug for PeerProcessIdentity {")
    debug_end = identity_source.index("\n}", debug_start) + 2
    identity_body += ("#[derive(Clone, Eq, PartialEq)]\n" +
                      identity_source[peer_start:peer_end] + "\n" +
                      identity_source[debug_start:debug_end] + "\n")
    for name in ("linux_proc_stat_start_time", "linux_proc_start_time", "linux_proc_uid",
                 "linux_kernel_process_identity_by_pid", "linux_process_identity_is_live",
                 "linux_proc_cmdline_args", "user_owned_main_server_argv_is_expected",
                 "linux_service_owned_server_argv_is_expected", "process_argv_is_exact",
                 "linux_service_owned_password_client_argv_is_expected",
                 "cm_process_argv_is_expected", "helper_server_argv_is_expected",
                 "main_server_cmdline_args", "linux_proc_environ_value",
                 "linux_proc_u32_env", "linux_process_identity_fields_by_pid"):
        identity_body += function(identity_source, name)
    common = inputs["src/common.rs"].decode("utf-8")
    constants = [next(line for line in common.splitlines()
                      if line.startswith("pub const " + name + ": &str = "))
                 for name in ("SERVICE_OWNED_SERVER_ARG", "CM_LAUNCH_TOKEN_ENV", "CM_LAUNCH_PARENT_ENV",
                              "SERVICE_OWNED_SERVER_GENERATION_ENV")]
    generated += "mod common { " + "\n".join(constants) + " }\n"
    # The exact metadata bodies use the error and kernel ABI adapters below. Serialization and anyhow's
    # error representation are outside this component; Result/refusal behavior is retained.
    generated += ('use std::{fmt, fs, os::unix::fs::MetadataExt};\n'
                  'type ResultType<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;\n'
                  'macro_rules! bail { ($($arg:tt)*) => { return Err(format!($($arg)*).into()) }; }\n'
                  'extern crate self as anyhow;\n'
                  '#[macro_export] macro_rules! anyhow { ($($arg:tt)*) => { '
                  'Box::<dyn std::error::Error + Send + Sync>::from(format!($($arg)*)) }; }\n'
                  'mod libc { pub const SYS_pidfd_open: i64 = 434; pub const POLLIN: i16 = 1;\n'
                  '#[repr(C)] pub struct pollfd { pub fd: i32, pub events: i16, pub revents: i16 }\n'
                  'extern "C" { pub fn syscall(number: i64, ...) -> i64; '
                  'pub fn poll(fds: *mut pollfd, count: usize, timeout: i32) -> i32; } }\n'
                  '#[derive(Clone, Debug, Eq, PartialEq)]\n' + identity_body)
    print(f"LINUX_KERNEL_IDENTITY_SOURCE=sha256={digest(inputs['src/ipc/auth.rs'])} "
          f"fragment_sha256={digest(identity_body.encode())} error_context=std-boxed libc_abi=linux-x86_64 serialization=unexecuted", flush=True)
    child_role = function(inputs["src/platform/linux.rs"].decode("utf-8"), "service_child_cmdline_has_exact_role")
    generated += child_role
    print(f"LINUX_KERNEL_CHILD_ROLE_SOURCE=sha256={digest(inputs['src/platform/linux.rs'])} "
          f"fragment_sha256={digest(child_role.encode())}", flush=True)
    child_environment = function(inputs["src/platform/linux.rs"].decode("utf-8"), "service_child_environment_has_generation")
    generated += child_environment
    print(f"LINUX_KERNEL_CHILD_ENV_SOURCE=sha256={digest(inputs['src/platform/linux.rs'])} "
          f"fragment_sha256={digest(child_environment.encode())}", flush=True)
    generated += f'include!("{repo}/scripts/test-linux-service-uid-policy.rs");\n'
    generated += f'include!("{repo}/scripts/test-trusted-executable.rs");\n'
    generated += f'include!("{repo}/scripts/test-linux-process-identity.rs");\n'
    source = Path("/cargo-target/trusted-executable-tests.rs")
    source.write_text(generated)
    peer = Path("/cargo-target/linux-process-peer")
    subprocess.run(["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-pthread",
                    str(repo / "scripts/test-linux-process-peer.c"), "-o", str(peer)],
                   check=True, timeout=20)
    peer_identity = digest(peer.read_bytes())
    print(f"LINUX_KERNEL_PEER_BUILD=sha256={peer_identity} abi=linux-x86_64", flush=True)
    artifact = Path("/cargo-target/uid-policy-tests")
    subprocess.run(["rustc", "--edition=2021", "--test", str(source), "-o", str(artifact)],
                   check=True, timeout=30)
    identity = digest(artifact.read_bytes())
    print(f"TRUSTED_EXECUTABLE_BUILD=sha256={identity} tests=18", flush=True)
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith("LINUX_IDENTITY_")}
    environment["LINUX_IDENTITY_PEER_PROBE"] = str(peer)
    result = subprocess.run([str(artifact), "--test-threads=1", "--color", "never", "--show-output"],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=20,
                            env=environment)
    if len(result.stdout) > 65536:
        raise ValueError("selector test output exceeds 64 KiB")
    print(result.stdout.decode("utf-8"), end="", flush=True)
    if (digest(artifact.read_bytes()) != identity or source.read_text() != generated
            or digest(peer.read_bytes()) != peer_identity):
        raise ValueError("selector fixture changed during execution")
    for path, data in inputs.items():
        if (repo / path).read_bytes() != data:
            raise ValueError(f"selector input changed: {path}")
        print(f"TRUSTED_EXECUTABLE_INPUT=path={path} bytes={len(data)} sha256={digest(data)}", flush=True)
    print(f"TRUSTED_EXECUTABLE_ARTIFACT=status={result.returncode} sha256={identity} unchanged=before-after", flush=True)
    print(f"LINUX_KERNEL_PEER_ARTIFACT=status={result.returncode} sha256={peer_identity} unchanged=before-after", flush=True)
    if result.returncode != 0:
        raise ValueError(f"native selector tests failed: {result.returncode}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        raise SystemExit(f"Trusted executable tests: FAIL: {error}") from error
