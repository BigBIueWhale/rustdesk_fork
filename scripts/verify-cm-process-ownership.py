#!/usr/bin/env python3
"""Verify exact macOS/Windows connection-manager process ownership (R-S11gi)."""

from __future__ import annotations

import argparse
import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping


class VerificationError(RuntimeError):
    pass


FILES = (
    "src/common.rs",
    "src/ipc.rs",
    "src/ipc/auth.rs",
    "src/platform/windows.cc",
    "src/platform/windows.rs",
    "src/privacy_mode.rs",
    "src/server/clipboard_service.rs",
    "src/server/connection.rs",
    "requirements.html",
    "HARDENING_STATUS.md",
    "scripts/verify.sh",
    "scripts/apple-conform-check.sh",
    "scripts/build-windows.ps1",
)


@dataclass(frozen=True)
class Mutation:
    path: str
    old: str
    new: str
    label: str


def read_regular(root: Path, relative: str) -> str:
    path = root / relative
    metadata = os.lstat(path)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise VerificationError(f"{relative} is not a single-link regular file")
    return path.read_text(encoding="utf-8")


def require(text: str, needle: str, label: str) -> None:
    if needle not in text:
        raise VerificationError(f"missing {label}: {needle!r}")


def forbid(text: str, needle: str, label: str) -> None:
    if needle in text:
        raise VerificationError(f"forbidden {label}: {needle!r}")


def function_block(text: str, signature: str) -> str:
    start = text.find(signature)
    if start < 0:
        raise VerificationError(f"missing function signature {signature!r}")
    brace = text.find("{", start)
    if brace < 0:
        raise VerificationError(f"missing function body for {signature!r}")
    depth = 0
    for index in range(brace, len(text)):
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[start : index + 1]
    raise VerificationError(f"unterminated function body for {signature!r}")


def ordered(block: str, needles: tuple[str, ...], label: str) -> None:
    cursor = -1
    for needle in needles:
        position = block.find(needle, cursor + 1)
        if position < 0:
            raise VerificationError(f"{label} is missing ordered edge {needle!r}")
        cursor = position


def verify(files: Mapping[str, str]) -> None:
    common = files["src/common.rs"]
    ipc = files["src/ipc.rs"]
    auth = files["src/ipc/auth.rs"]
    windows_native = files["src/platform/windows.cc"]
    windows = files["src/platform/windows.rs"]
    privacy = files["src/privacy_mode.rs"]
    clipboard = files["src/server/clipboard_service.rs"]
    connection = files["src/server/connection.rs"]
    requirements = files["requirements.html"]
    ledger = files["HARDENING_STATUS.md"]
    shared_gate = files["scripts/verify.sh"]
    apple_gate = files["scripts/apple-conform-check.sh"]
    windows_build = files["scripts/build-windows.ps1"]

    require(
        common,
        'pub const CM_LAUNCH_PARENT_CREATION_ENV: &str = "RUSTDESK_CM_LAUNCH_PARENT_CREATION";',
        "Windows parent-generation environment name",
    )

    require(connection, "trait CmOwnedProcess: Send", "thread-transferable CM process owner")
    generation = function_block(connection, "fn lease_or_launch_cm_process")
    forbid(generation, ".await", "lock-across-await CM launch")
    ordered(
        generation,
        (
            ".lock()",
            "Arc::strong_count(generation) == 1",
            ".try_reap_exited()?",
            "let launch_token = crate::encode64",
            "let process = launch(&launch_token)?;",
            "identity: process.identity(),",
            "*state = Some(generation.clone());",
        ),
        "CM launch state machine",
    )
    retirement = function_block(connection, "fn retire_failed_cm_process_if_exited")
    forbid(retirement, ".await", "lock-across-await CM retirement")
    ordered(
        retirement,
        (
            "Arc::ptr_eq(current, failed)",
            "Arc::strong_count(current) != 2",
            ".try_reap_exited()?",
            "state.take();",
        ),
        "failed CM authentication retirement",
    )
    require(connection, "struct MacosCmProcess(std::process::Child);", "retained macOS child")
    require(connection, "static ref OWNED_CM_PROCESS", "process-global exact CM owner")
    require(
        connection,
        "active_authentication_lease_prevents_reap_and_generation_replacement",
        "active-lease regression",
    )
    require(
        connection,
        "failed_authentication_retires_only_the_unshared_exited_generation",
        "failed-authentication retirement regression",
    )
    require(
        connection,
        "concurrent_selection_launches_one_generation",
        "concurrent launch-selection regression",
    )
    require(
        connection,
        "uncertain_liveness_preserves_the_exact_generation",
        "uncertain-liveness fail-closed regression",
    )
    require(
        connection,
        '#[cfg(target_os = "linux")]\nlazy_static::lazy_static! {\n    static ref CM_LAUNCH_TOKEN',
        "Linux-only process-lifetime CM token",
    )
    forbid(
        connection,
        '#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]\nlazy_static::lazy_static! {\n    static ref CM_LAUNCH_TOKEN',
        "macOS/Windows process-lifetime bearer token",
    )

    mac_launch = function_block(
        connection,
        '#[cfg(target_os = "macos")]\nfn lease_or_launch_platform_cm',
    )
    ordered(
        mac_launch,
        (
            "lease_or_launch_cm_process(&OWNED_CM_PROCESS, expected_role",
            "crate::run_me_with_env(vec![expected_role], cm_launch_env(launch_token))?",
            "Ok(MacosCmProcess(child))",
        ),
        "macOS retained-child CM launch",
    )
    win_platform_launch = function_block(
        connection,
        '#[cfg(target_os = "windows")]\nfn lease_or_launch_platform_cm',
    )
    ordered(
        win_platform_launch,
        (
            'if expected_role != "--cm"',
            "lease_or_launch_cm_process(&OWNED_CM_PROCESS, expected_role",
            "crate::platform::run_connection_manager_user_helper(launch_token)",
        ),
        "Windows dedicated exact-process CM launch",
    )

    mac_connect = function_block(
        connection,
        '#[cfg(target_os = "macos")]\nasync fn connect_authenticated_cm_inner',
    )
    ordered(
        mac_connect,
        (
            "lease_existing_cm_process(&OWNED_CM_PROCESS, expected_arg)?",
            'crate::ipc::connect(ms_timeout, "_cm").await?',
            "authenticate_macos_cm_endpoint(&stream, expected_arg, generation.identity)?",
            "&generation.launch_token",
            ".await?;",
        ),
        "macOS exact-process authentication",
    )
    win_generation_connect = function_block(
        connection,
        '#[cfg(target_os = "windows")]\nasync fn connect_authenticated_cm_inner',
    )
    ordered(
        win_generation_connect,
        (
            "lease_existing_cm_process(&OWNED_CM_PROCESS, expected_arg)?",
            "crate::ipc::connect_authenticated_windows_cm(",
            "&generation.launch_token",
            "generation.identity",
            ".await",
        ),
        "Windows exact-generation connection facade",
    )
    public_connect = function_block(connection, "pub(crate) async fn connect_authenticated_cm")
    ordered(
        public_connect,
        (
            "lease_existing_cm_process(&OWNED_CM_PROCESS, expected_arg)?",
            "connect_authenticated_cm_inner(ms_timeout, expected_arg).await",
            "retire_failed_cm_process_if_exited(&OWNED_CM_PROCESS, &generation)",
        ),
        "shared exact-process connection facade",
    )
    require(
        connection,
        'lease_or_launch_platform_cm("--cm")',
        "serialized platform CM launch",
    )
    forbid(
        connection,
        "WindowsUserHelperLaunch::ConnectionManager",
        "generic Windows CM launch",
    )
    forbid(
        connection,
        "CHILD_PROCESS.lock().unwrap().push(task)",
        "unlabelled Windows privileged CM child ownership",
    )

    mac_auth = function_block(auth, "pub(crate) fn authenticate_macos_cm_endpoint")
    ordered(
        mac_auth,
        (
            "expected_pid: u32",
            "peer_pid != expected_pid",
            "ensure_peer_executable_matches_current_by_pid",
            "cm_process_argv_is_expected",
            "stream.peer_pid() != Some(expected_pid)",
        ),
        "macOS CM endpoint identity",
    )
    win_auth = function_block(auth, "pub(crate) fn authenticate_windows_cm_endpoint")
    ordered(
        win_auth,
        (
            "expected_identity: WindowsProcessIdentityKey",
            "peer_pid != expected_identity.pid",
            "process.key != expected_identity",
            'process.require_running("connection-manager endpoint")?',
            "ensure_windows_identity_matches_current",
            "windows_identity_has_exact_role",
            "windows_named_pipe_server_pid",
            'process.require_running("connection-manager endpoint")?',
        ),
        "Windows CM endpoint identity",
    )
    listener = function_block(auth, "pub(crate) fn authorize_cm_ipc_connection")
    for needle, label in (
        ("cm_launch_parent_pid_from_env()", "macOS launch-parent PID"),
        ("libc::getppid()", "macOS live parent"),
        (
            "actual_parent_pid as u32 != expected_parent_pid",
            "macOS current launch-parent equality",
        ),
        ("peer_pid != Some(expected_parent_pid)", "macOS exact server peer"),
        ("windows_cm_launch_parent_identity_from_env()", "Windows launch-parent generation"),
        ("process.key != expected_parent", "Windows exact server generation"),
        ('process.require_running("connection-manager launch parent")', "Windows parent liveness"),
        ("stream.peer_pid() != Some(expected_parent.pid)", "Windows stable named-pipe client PID"),
    ):
        require(listener, needle, label)

    win_connect = function_block(ipc, "pub(crate) async fn connect_authenticated_windows_cm")
    ordered(
        win_connect,
        (
            "expected_identity: ipc_auth::WindowsProcessIdentityKey",
            'connect(ms_timeout, "_cm").await?',
            "authenticate_windows_cm_endpoint(&stream, expected_arg, expected_identity)?",
            "authenticate_cm_endpoint_launch_proof",
        ),
        "Windows exact-generation authenticated connect",
    )

    require(
        windows,
        "pub(crate) struct WindowsConnectionManagerProcess",
        "owned Windows CM process",
    )
    require(
        windows,
        "unsafe impl Send for ServiceOwnedWindowsHandle {}",
        "retained Windows CM handle Send ownership",
    )
    require(
        windows,
        "limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;",
        "Windows CM kill-on-close job policy",
    )
    native_launch = function_block(windows_native, "HANDLE LaunchProcessWin(")
    ordered(
        native_launch,
        (
            "HANDLE jobList[] = {hJob};",
            "if (hJob != NULL)",
            "PROC_THREAD_ATTRIBUTE_JOB_LIST",
            "dwCreationFlags |= EXTENDED_STARTUPINFO_PRESENT;",
            "CreateProcessAsUserW(",
        ),
        "Windows job-at-process-creation launch",
    )
    require(
        windows,
        "Session {\n        job: ServiceOwnedWindowsHandle,\n        process: ServiceOwnedWindowsHandle,",
        "kill-on-close Windows session CM job",
    )
    launch = function_block(windows, "pub(crate) fn run_connection_manager_user_helper")
    ordered(
        launch,
        (
            "current_windows_process_identity_key()?",
            "windows_connection_manager_launch_environment",
            "create_windows_service_process_job()?",
            "launch_process_in_session_with_env",
            "job.raw()",
            "windows_process_identity(launched.process_id, process.raw())?",
            "WindowsConnectionManagerProcessHandle::Session { job, process }",
        ),
        "privileged Windows CM launch ownership",
    )
    require(launch, "child.kill().err()", "same-user identity-failure kill")
    require(launch, "child.wait()", "same-user identity-failure reap")
    generic_launch = function_block(windows, "pub(crate) fn run_user_helper")
    forbid(generic_launch, "connection-manager", "generic Windows helper CM authority")
    forbid(
        windows,
        "WindowsUserHelperLaunch::ConnectionManager",
        "retired generic Windows CM variant",
    )

    require(
        privacy,
        'crate::server::connect_authenticated_cm(ms_timeout, "--cm").await?',
        "privacy exact-owner CM facade",
    )
    require(
        clipboard,
        'crate::server::connect_authenticated_cm(100, "--cm")',
        "clipboard exact-owner CM facade",
    )
    for secondary, label in ((privacy, "privacy"), (clipboard, "clipboard")):
        forbid(secondary, "cm_launch_token()", f"{label} bearer-token access")
        forbid(
            secondary,
            "ipc::connect_authenticated_windows_cm",
            f"{label} direct Windows CM connector",
        )

    require(requirements, '<span class="id">R-S11gi</span>', "R-S11gi requirement")
    require(requirements, "Appendix C #344", "R-S11gi Appendix binding")
    require(
        ledger,
        "- **R-S11gi/R-S11e-221 — macOS/Windows exact connection-manager process ownership",
        "R-S11gi hardening record",
    )
    require(
        shared_gate,
        'python3 scripts/verify-cm-process-ownership.py --self-test',
        "shared verifier self-test",
    )
    require(
        shared_gate,
        'python3 scripts/verify-cm-process-ownership.py .',
        "shared verifier normal path",
    )
    require(
        apple_gate,
        'python3 "$REPO/scripts/verify-cm-process-ownership.py" --self-test',
        "Apple verifier self-test",
    )
    require(
        apple_gate,
        'python3 "$REPO/scripts/verify-cm-process-ownership.py" "$REPO"',
        "Apple verifier normal path",
    )
    require(
        windows_build,
        "cargo test --offline --locked --lib --features flutter --color never process_launch_tests",
        "native Windows helper-launch tests",
    )
    require(
        windows_build,
        "cargo test --offline --locked --lib --features flutter --color never cm_process_generation_tests",
        "native Windows CM generation tests",
    )


MUTATIONS = (
    Mutation(
        "src/server/connection.rs",
        "Arc::strong_count(generation) == 1",
        "true",
        "reap despite active authentication lease",
    ),
    Mutation(
        "src/server/connection.rs",
        "trait CmOwnedProcess: Send",
        "trait CmOwnedProcess",
        "CM process-owner Send bound removal",
    ),
    Mutation(
        "src/server/connection.rs",
        "identity: process.identity(),",
        "identity: Default::default(),",
        "discard launched process identity",
    ),
    Mutation(
        "src/server/connection.rs",
        "crate::platform::run_connection_manager_user_helper(launch_token)",
        "crate::platform::run_user_helper(crate::platform::WindowsUserHelperLaunch::Tray)",
        "bypass dedicated Windows CM launcher",
    ),
    Mutation(
        "src/ipc/auth.rs",
        "peer_pid != expected_pid",
        "false",
        "macOS endpoint PID bypass",
    ),
    Mutation(
        "src/ipc/auth.rs",
        'if process.key != expected_identity {\n        bail!(\n            "_cm endpoint process generation mismatch',
        'if false {\n        bail!(\n            "_cm endpoint process generation mismatch',
        "Windows endpoint generation bypass",
    ),
    Mutation(
        "src/ipc/auth.rs",
        "actual_parent_pid as u32 != expected_parent_pid",
        "false",
        "macOS current-parent bypass",
    ),
    Mutation(
        "src/ipc/auth.rs",
        "process.key != expected_parent",
        "false",
        "Windows server-generation bypass",
    ),
    Mutation(
        "src/platform/windows.rs",
        "let job = create_windows_service_process_job()?;\n        let launched = "
        "launch_process_in_session_with_env(\n            &exe,\n            &[\"--cm\"],",
        "let job = ServiceOwnedWindowsHandle::new(NULL, \"disabled\")?;\n        let launched = "
        "launch_process_in_session_with_env(\n            &exe,\n            &[\"--cm\"],",
        "Windows kill-on-close job removal",
    ),
    Mutation(
        "src/platform/windows.cc",
        "if (hJob != NULL)",
        "if (false)",
        "Windows job-at-creation bypass",
    ),
    Mutation(
        "src/platform/windows.rs",
        "limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;",
        "limits.BasicLimitInformation.LimitFlags = 0;",
        "Windows kill-on-close policy bypass",
    ),
    Mutation(
        "src/platform/windows.rs",
        "unsafe impl Send for ServiceOwnedWindowsHandle {}",
        "// retained handle is not transferable across the CM owner",
        "Windows retained-handle Send ownership removal",
    ),
    Mutation(
        "src/privacy_mode.rs",
        'crate::server::connect_authenticated_cm(ms_timeout, "--cm").await?',
        'crate::ipc::connect(ms_timeout, "_cm").await?',
        "privacy direct fixed-endpoint fallback",
    ),
    Mutation(
        "src/server/clipboard_service.rs",
        'crate::server::connect_authenticated_cm(100, "--cm")',
        'crate::ipc::connect(100, "_cm")',
        "clipboard direct fixed-endpoint fallback",
    ),
    Mutation(
        "scripts/build-windows.ps1",
        "cargo test --offline --locked --lib --features flutter --color never process_launch_tests",
        "Write-Host 'native Windows CM launch test disabled'",
        "native Windows CM launch gate removal",
    ),
    Mutation(
        "requirements.html",
        '<span class="id">R-S11gi</span>',
        '<span class="id">R-S11gi-disabled</span>',
        "requirement removal",
    ),
    Mutation(
        "HARDENING_STATUS.md",
        "- **R-S11gi/R-S11e-221 — macOS/Windows exact connection-manager process ownership",
        "- **R-S11gi-disabled/R-S11e-221 — macOS/Windows exact connection-manager process ownership",
        "ledger removal",
    ),
)


def run_self_test(files: Mapping[str, str]) -> None:
    verify(files)
    for mutation in MUTATIONS:
        original = files[mutation.path]
        if original.count(mutation.old) != 1:
            raise VerificationError(
                f"self-test target {mutation.label!r} is not unique in {mutation.path}"
            )
        mutated = dict(files)
        mutated[mutation.path] = original.replace(mutation.old, mutation.new, 1)
        try:
            verify(mutated)
        except VerificationError:
            continue
        raise VerificationError(f"self-test accepted mutation: {mutation.label}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    root = Path(args.root).resolve()
    files = {relative: read_regular(root, relative) for relative in FILES}
    if args.self_test:
        run_self_test(files)
        print("verify-cm-process-ownership self-test: ok")
    else:
        verify(files)
        print("verify-cm-process-ownership: ok")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, UnicodeError, VerificationError) as error:
        print(f"verify-cm-process-ownership: {error}", file=sys.stderr)
        raise SystemExit(1)
