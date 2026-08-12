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
    "Cargo.toml",
    "build.py",
    "examples/probe_client.rs",
    "examples/windows_cm_lifecycle_probe.rs",
    "flutter/lib/desktop/pages/server_page.dart",
    "flutter/lib/models/server_model.dart",
    "src/common.rs",
    "src/core_main.rs",
    "src/ipc.rs",
    "src/ipc/auth.rs",
    "src/lib.rs",
    "src/platform/windows.cc",
    "src/platform/windows.rs",
    "src/privacy_mode.rs",
    "src/server/clipboard_service.rs",
    "src/server/connection.rs",
    "src/ui_cm_interface.rs",
    "src/windows_cm_lifecycle_probe.rs",
    "requirements.html",
    "HARDENING_STATUS.md",
    "scripts/verify.sh",
    "scripts/apple-conform-check.sh",
    "scripts/build-windows.ps1",
    "scripts/verify-windows-installed-service-result.py",
    "scripts/windows-installed-service-probe.ps1",
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
    cargo = files["Cargo.toml"]
    build_py = files["build.py"]
    probe_client = files["examples/probe_client.rs"]
    probe_example = files["examples/windows_cm_lifecycle_probe.rs"]
    desktop_server_page = files["flutter/lib/desktop/pages/server_page.dart"]
    server_model = files["flutter/lib/models/server_model.dart"]
    common = files["src/common.rs"]
    core_main = files["src/core_main.rs"]
    ipc = files["src/ipc.rs"]
    auth = files["src/ipc/auth.rs"]
    lib = files["src/lib.rs"]
    windows_native = files["src/platform/windows.cc"]
    windows = files["src/platform/windows.rs"]
    privacy = files["src/privacy_mode.rs"]
    clipboard = files["src/server/clipboard_service.rs"]
    connection = files["src/server/connection.rs"]
    ui_cm = files["src/ui_cm_interface.rs"]
    lifecycle_probe = files["src/windows_cm_lifecycle_probe.rs"]
    requirements = files["requirements.html"]
    ledger = files["HARDENING_STATUS.md"]
    shared_gate = files["scripts/verify.sh"]
    apple_gate = files["scripts/apple-conform-check.sh"]
    windows_build = files["scripts/build-windows.ps1"]
    installed_result = files["scripts/verify-windows-installed-service-result.py"]
    installed_probe = files["scripts/windows-installed-service-probe.ps1"]

    forbid(
        server_model,
        "_zeroClientLengthCounter",
        "timer-driven graphical CM process retirement",
    )
    timer_callback = function_block(server_model, "timerCallback() async")
    idle_timer_branch = function_block(timer_callback, "if (_clients.isEmpty)")
    require(
        idle_timer_branch,
        "hideCmWindow();",
        "idle graphical CM window hiding",
    )
    forbid(
        idle_timer_branch,
        "windowManager.close();",
        "idle graphical CM process close",
    )
    client_removal = function_block(server_model, "void onClientRemove")
    require(
        client_removal,
        "if (desktopType == DesktopType.cm && _clients.isEmpty) {\n        hideCmWindow();",
        "backend CM last-client window hiding",
    )
    forbid(
        desktop_server_page,
        "tabController.onRemoved =",
        "CM backend-tab-removal window callback",
    )
    forbid(
        desktop_server_page,
        "void onRemoveId(String id)",
        "CM last-tab process-close handler",
    )

    require(
        common,
        'pub const CM_LAUNCH_PARENT_CREATION_ENV: &str = "RUSTDESK_CM_LAUNCH_PARENT_CREATION";',
        "Windows parent-generation environment name",
    )
    require(
        common,
        'pub const CM_LAUNCH_PARENT_HANDLE_ENV: &str = "RUSTDESK_CM_LAUNCH_PARENT_HANDLE";',
        "Windows inherited parent-process capability environment name",
    )
    require(
        common,
        'pub const CM_LAUNCH_PARENT_HANDLE_NONE: &str = "none";',
        "Windows explicit same-user parent-handle sentinel",
    )
    require(
        ipc,
        "pub(crate) use ipc_auth::seal_windows_cm_launch_parent_handle;",
        "Windows early CM parent-capability sealing export",
    )
    if core_main.count("crate::ipc::seal_windows_cm_launch_parent_handle()") != 2:
        raise VerificationError(
            "Windows CM launch roles must each seal the inherited parent capability exactly once"
        )
    core_dispatch = function_block(core_main, "pub fn core_main()")
    ordered(
        core_dispatch,
        (
            'args[0] == "--cm"',
            "crate::ipc::seal_windows_cm_launch_parent_handle()",
            "crate::ui_interface::start_main_status_sync();",
            'args[0] == "--cm-no-ui"',
            "crate::ipc::seal_windows_cm_launch_parent_handle()",
            "crate::ui_interface::start_main_status_sync();",
        ),
        "Windows CM capability sealing before UI or headless startup",
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
    win_main_auth = function_block(
        auth, "pub(crate) fn authenticate_windows_cm_main_server"
    )
    ordered(
        win_main_auth,
        (
            "windows_cm_launch_parent_identity_from_env()?",
            "windows_named_pipe_server_pid(client)?",
            "server_pid != expected_parent.pid",
            "windows_cm_launch_parent_handle_from_env()?",
            "WindowsPeerProcess::from_inherited_handle(server_pid, handle)?",
            "process.key != expected_parent",
            'process.require_running("connection-manager main IPC server")?',
            "ensure_windows_identity_matches_current",
            "windows_identity_is_main_server",
            "windows_named_pipe_server_pid(client)? != expected_parent.pid",
            'process.require_running("connection-manager main IPC server")?',
        ),
        "Windows CM main-IPC exact launch-parent authentication",
    )
    inherited_parent = function_block(auth, "fn from_inherited_handle")
    ordered(
        inherited_parent,
        (
            "duplicate_windows_handle(handle",
            "GetProcessId(handle.0)",
            "handle_pid != pid",
            "windows_process_creation_time(handle.0)?",
            "WindowsProcessIdentityKey { pid, creation_time }",
        ),
        "Windows inherited launch-parent process capability",
    )
    inherited_parent_env = function_block(
        auth, "fn windows_cm_launch_parent_handle_from_env"
    )
    ordered(
        inherited_parent_env,
        (
            "CM_LAUNCH_PARENT_HANDLE_ENV",
            "CM_LAUNCH_PARENT_HANDLE_NONE",
            "return Ok(None)",
            "handle.is_invalid()",
            "SetHandleInformation(handle, HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0))",
        ),
        "Windows inherited launch-parent capability parsing and sealing",
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
        (
            "windows_cm_launch_parent_handle_from_env()",
            "Windows optional inherited parent process capability",
        ),
        (
            "WindowsPeerProcess::from_inherited_handle(expected_parent.pid, handle)",
            "Windows inherited parent process inspection",
        ),
        ("process.key != expected_parent", "Windows exact server generation"),
        ('process.require_running("connection-manager launch parent")', "Windows parent liveness"),
        ("stream.peer_pid() != Some(expected_parent.pid)", "Windows stable named-pipe client PID"),
    ):
        require(listener, needle, label)
    cm_listener = function_block(ui_cm, "pub async fn start_ipc<T: InvokeUiCM>")
    require(
        cm_listener,
        "if !ipc::authorize_cm_ipc_connection(&stream) {",
        "CM listener fail-closed parent admission",
    )
    ordered(
        cm_listener,
        (
            "authorize_cm_ipc_connection(&stream)",
            "answer_cm_endpoint_challenge(&mut stream).await",
            "tokio::spawn(IpcTaskRunner::<T>::ipc_task(stream, cm.clone()))",
        ),
        "CM parent admission before mandatory launch-secret proof and task dispatch",
    )

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
    win_main_connect = function_block(ipc, "async fn connect_windows_cm_main")
    ordered(
        win_main_connect,
        (
            'Config::ipc_path("")',
            "connect_windows_named_pipe(&path)",
            "authenticate_windows_cm_main_server(&client)?",
            "ConnectionTmpl::new_main(client)",
        ),
        "Windows CM dedicated main-IPC connector",
    )
    cm_validation = function_block(ipc, "pub(crate) async fn validate_cm_connection_authority")
    require(
        cm_validation,
        "let stream = connect_windows_cm_main(1_000).await?;",
        "Windows CM authority validation through exact-parent connector",
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
    parent_proof = function_block(windows, "fn create_inheritable_current_process_proof")
    ordered(
        parent_proof,
        (
            "PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE",
            "GetCurrentProcessId()",
            'ServiceOwnedWindowsHandle::new(raw, "connection-manager parent proof")?',
            "SetHandleInformation(process.raw(), HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)",
        ),
        "least-right inheritable current-process proof",
    )
    job_attributes = function_block(windows_native, "class ProcessCreationJobAttributes")
    ordered(
        job_attributes,
        (
            "job_ = job;",
            "inheritedHandle_ = inheritedHandle;",
            "attributeCount = inheritedHandle_ == NULL ? 1 : 2",
            "InitializeProcThreadAttributeList(NULL, attributeCount, 0, &size)",
            "InitializeProcThreadAttributeList(list_, attributeCount, 0, &size)",
            "PROC_THREAD_ATTRIBUTE_JOB_LIST",
            "&job_, sizeof job_",
            "PROC_THREAD_ATTRIBUTE_HANDLE_LIST",
            "&inheritedHandle_, sizeof inheritedHandle_",
        ),
        "persistent Windows job and explicit inherited-handle attributes",
    )
    require(job_attributes, "HANDLE job_;", "retained job-list attribute value")
    require(
        job_attributes,
        "HANDLE inheritedHandle_;",
        "retained inherited-handle-list attribute value",
    )
    require(
        job_attributes,
        "DeleteProcThreadAttributeList(list_);",
        "process-creation attribute cleanup",
    )

    native_launch = function_block(windows_native, "HANDLE LaunchProcessWin(")
    ordered(
        native_launch,
        (
            "ProcessCreationJobAttributes jobAttributes;",
            "if (hJob != NULL)",
            "jobAttributes.initialize(hJob, hInheritedHandle)",
            "si.lpAttributeList = jobAttributes.get();",
            "dwCreationFlags |= EXTENDED_STARTUPINFO_PRESENT;",
            "CreateProcessAsUserW(",
            "hInheritedHandle != NULL",
        ),
        "Windows token-switched job and explicit-handle-at-process-creation launch",
    )
    current_native_launch = function_block(windows_native, "HANDLE LaunchProcessCurrentWin(")
    ordered(
        current_native_launch,
        (
            "hJob == NULL || pProcessId == NULL",
            "GetEnvironmentStringsW()",
            "merge_environment_blocks(currentEnvironment, extraEnvironment)",
            "ProcessCreationJobAttributes jobAttributes;",
            "jobAttributes.initialize(hJob, NULL)",
            "si.lpAttributeList = jobAttributes.get();",
            "EXTENDED_STARTUPINFO_PRESENT",
            "CreateProcessW(",
        ),
        "Windows current-token job-at-process-creation launch",
    )
    require(
        current_native_launch,
        "CreateProcessW(application, commandLine.data(), NULL, NULL, FALSE,",
        "same-user launch disables handle inheritance",
    )
    require(
        windows,
        "struct WindowsConnectionManagerProcessHandle {\n    _job: ServiceOwnedWindowsHandle,\n    process: ServiceOwnedWindowsHandle,",
        "unified retained Windows CM process job",
    )
    forbid(
        windows,
        "enum WindowsConnectionManagerProcessHandle",
        "branch-specific Windows CM ownership",
    )
    current_launch = function_block(windows, "fn launch_current_process_with_env_and_job")
    ordered(
        current_launch,
        (
            "current-token Windows launch requires an owned process job",
            "windows_command_line(exe, arg)?",
            "windows_env_block(envs)?",
            "LaunchProcessCurrentWin(",
            "job,",
        ),
        "same-user Windows atomic-job launch wrapper",
    )
    cm_launch_environment = function_block(
        windows, "fn windows_connection_manager_launch_environment"
    )
    ordered(
        cm_launch_environment,
        (
            "parent_handle: Option<HANDLE>",
            "CM_LAUNCH_PARENT_CREATION_ENV",
            "let parent_handle = match parent_handle",
            "parent_handle as usize",
            "CM_LAUNCH_PARENT_HANDLE_NONE",
            "CM_LAUNCH_PARENT_HANDLE_ENV",
            "parent_handle,",
        ),
        "Windows optional inherited parent capability environment",
    )
    if windows.count("windows_connection_manager_launch_environment(") != 5:
        raise VerificationError(
            "Windows CM launch-environment function/call inventory is not exactly five"
        )
    require(
        windows,
        'windows_connection_manager_launch_environment("", parent_identity, None).is_err()',
        "Windows invalid CM token regression uses the explicit same-user handle sentinel",
    )
    launch = function_block(windows, "pub(crate) fn run_connection_manager_user_helper")
    ordered(
        launch,
        (
            "current_windows_process_identity_key()",
            "create_inheritable_current_process_proof()",
            "windows_connection_manager_launch_environment",
            "create_windows_service_process_job()?",
            "if is_root()",
            "launch_process_in_session_with_env",
            "job.raw()",
            "ServiceOwnedWindowsHandle::raw",
            "drop(inherited_parent);",
            "let launched = launch_result?;",
            "launch_current_process_with_env_and_job(",
            "job.raw()",
            "windows_process_identity(launched.process_id, process.raw())?",
            "WindowsConnectionManagerProcessHandle { _job: job, process }",
        ),
        "unified Windows CM launch ownership",
    )
    forbid(launch, "std::process::Command", "jobless same-user CM launch")
    forbid(launch, "WindowsConnectionManagerProcessHandle::Direct", "direct CM child ownership")
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

    if cargo.count("windows-cm-lifecycle-probe") != 2:
        raise VerificationError(
            "Windows CM lifecycle feature must appear only in its declaration and example requirement"
        )
    require(
        cargo,
        'required-features = ["windows-cm-lifecycle-probe"]',
        "Windows CM lifecycle example feature gate",
    )
    require(
        cargo,
        "artifact compilation never enables it",
        "Windows CM lifecycle non-artifact intent",
    )
    forbid(
        build_py,
        "windows-cm-lifecycle-probe",
        "Windows CM lifecycle probe in artifact compiler",
    )
    require(
        lib,
        '#[cfg(all(target_os = "windows", feature = "windows-cm-lifecycle-probe"))]',
        "Windows-only lifecycle probe module",
    )
    require(
        connection,
        "pub fn windows_cm_lifecycle_probe_lease(",
        "feature-confined production CM lease probe edge",
    )
    require(
        probe_example,
        "librustdesk::windows_cm_lifecycle_probe::run()",
        "Windows lifecycle probe example entrypoint",
    )
    for token, label in (
        ("TcpListener", "TCP listener"),
        ("TcpStream", "TCP stream"),
        ("UdpSocket", "UDP socket"),
        ("0.0.0.0", "wildcard listener"),
    ):
        forbid(lifecycle_probe, token, f"Windows CM lifecycle probe {label}")
    probe_server = function_block(lifecycle_probe, "fn run_server_worker()")
    ordered(
        probe_server,
        (
            "windows_cm_lifecycle_probe_lease()",
            "windows_cm_lifecycle_probe_lease()",
            "first_identity != second_identity || first_token != second_token",
            "connect_exact_cm_pipe_until_ready(&runtime, first_identity)?",
            "authenticate_cm_endpoint_launch_proof(",
            "&wrong_token",
            "if wrong.is_ok()",
            "drop(wrong_stream)",
            "for attempt in 1..=2",
            "connect_authenticated_cm_until_ready(&runtime, attempt)?",
            "close_authenticated_cm(stream)",
            "READY_PREFIX",
        ),
        "native CM lease, wrong-token, and authenticated reconnect probe",
    )
    probe_pipe_ready = function_block(
        lifecycle_probe, "fn connect_exact_cm_pipe_until_ready"
    )
    ordered(
        probe_pipe_ready,
        (
            'runtime.block_on(ipc::connect(',
            '"_cm"',
            'authenticate_windows_cm_endpoint(&stream, "--cm", expected_identity)',
            "return Ok(stream)",
        ),
        "native exact CM pipe readiness probe",
    )
    probe_child = function_block(lifecycle_probe, "fn run_cm_child()")
    require(
        probe_child,
        "crate::ui_cm_interface::start_ipc(cm);",
        "production named-pipe CM listener probe edge",
    )
    probe_launch = function_block(lifecycle_probe, "fn launch_worker()")
    ordered(
        probe_launch,
        (
            "std::env::current_exe()",
            '.arg("--server")',
            "parse_ready(&receipt)",
            "OwnedProcessHandle::open(cm_identity)",
            "cm_process.require_running()",
        ),
        "exact same-image CM owner probe",
    )
    probe_parent_death = function_block(
        lifecycle_probe, "fn terminate_owner_and_require_cm_exit"
    )
    ordered(
        probe_parent_death,
        (
            "cm_process.require_running()",
            "stop_worker(&mut worker.child)",
            "cm_process.wait_for_exit()",
            "cm_process.force_terminate_and_wait()",
        ),
        "CM owner-death and stale-child cleanup probe",
    )
    probe_controller = function_block(lifecycle_probe, "fn run_controller()")
    ordered(
        probe_controller,
        (
            "let mut first = launch_worker()?;",
            "terminate_owner_and_require_cm_exit(&mut first)?;",
            "let mut replacement = launch_worker()?;",
            "replacement.cm_identity == first.cm_identity",
            "terminate_owner_and_require_cm_exit(&mut replacement)?;",
        ),
        "CM fresh-generation replacement probe",
    )
    probe_dispatch = function_block(lifecycle_probe, "pub fn run()")
    ordered(
        probe_dispatch,
        (
            "[] => run_controller()",
            '[role] if role == "--server" => run_server_worker()',
            '[role] if role == "--cm" => run_cm_child()',
        ),
        "closed Windows lifecycle probe role inventory",
    )

    require(requirements, '<span class="id">R-S11gi</span>', "R-S11gi requirement")
    require(requirements, "Appendix C #344", "R-S11gi Appendix binding")
    require(
        requirements,
        "both same-user and LocalSystem launches",
        "both Windows CM launch branches in the normative job contract",
    )
    require(
        requirements,
        "Closing the final server-owned job handle",
        "abrupt Windows CM owner-death contract",
    )
    require(
        requirements,
        "atomically allowlist that one inheritable capability",
        "LocalSystem CM exact parent-process capability contract",
    )
    require(
        requirements,
        '<span class="id">R-S11gib</span>',
        "Windows CM main-IPC capability-reuse requirement",
    )
    require(
        requirements,
        '<span class="id">R-S11gic</span>',
        "graphical CM retained-idle requirement",
    )
    require(
        requirements,
        "Backend-driven last-session removal and periodic zero-client checks",
        "graphical CM automatic-exit prohibition",
    )
    require(
        requirements,
        "reuse that same sealed process capability when it connects to the launching server's main IPC",
        "LocalSystem CM main-IPC exact parent-process capability contract",
    )
    require(
        requirements,
        "MUST NOT</span> depend on granting the desktop user <code>SeImpersonatePrivilege</code>",
        "LocalSystem CM privilege-independent parent proof",
    )
    require(
        ledger,
        "- **R-S11gi/R-S11e-221 — macOS/Windows exact connection-manager process ownership",
        "R-S11gi hardening record",
    )
    require(
        ledger,
        "Both the LocalSystem token-switched launch and the same-user current-token",
        "both Windows CM job-owned launch branches in the ledger",
    )
    require(
        ledger,
        "that dedicated connector requires the pipe server PID to equal the",
        "Windows CM main-IPC exact-parent connector in the ledger",
    )
    require(
        ledger,
        "The first inherited-main-IPC native retry proves both authenticated directory round trips",
        "native graphical CM idle-exit finding in the ledger",
    )
    require(
        requirements,
        "Appendix C #344 installed lifecycle pass (2026-08-12)",
        "installed graphical CM lifecycle pass in requirements",
    )
    require(
        ledger,
        "Exact installed LocalSystem lifecycle evidence is now green for the correction commit",
        "installed graphical CM lifecycle pass in the ledger",
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
    require(
        windows_build,
        'cargo run --offline --locked --example windows_cm_lifecycle_probe --features "flutter,windows-cm-lifecycle-probe" --color never',
        "native Windows CM lifecycle probe",
    )
    for needle, label in (
        ('mode == "cmfiletransfer" && !received_directory', "strict CM directory-response probe"),
        ("$arguments.Count -ne 2", "installed CM complete role arity"),
        ("$arguments[1] -cne '--cm'", "installed CM exact role"),
        ("$process.UserSid -cne $InteractiveToken.UserSid", "installed CM interactive principal"),
        ("$process.SessionId -ne $InteractiveToken.SessionId", "installed CM interactive session"),
        (
            "TerminateExactProcessGeneration(\n        [uint32]$Generation.ProcessId",
            "installed exact CM termination",
        ),
        ("if (wait == WAIT_OBJECT_0) { return false; }", "installed signaled-process liveness refusal"),
        ("Wait-ExactProcessGenerationGone $cmAfterStaleRecovery", "installed abrupt-owner CM retirement"),
        ("Wait-ExactProcessGenerationGone $cmPreRestart", "installed SCM-stop CM retirement"),
        ("rustdesk-windows-installed-service-probe-v2", "installed CM lifecycle receipt"),
    ):
        require(
            probe_client if needle.startswith('mode ==') else installed_probe,
            needle,
            label,
        )
    for needle, label in (
        ('result["cm_roundtrip_count"] != 6', "installed six-CM-round-trip result"),
        ("stale CM recovery did not change the CM generation", "installed stale-CM result relation"),
        ("abrupt owner recovery did not change the CM generation", "installed owner-death result relation"),
        ("retained CM generation was not reused before SCM restart", "installed retained-CM result relation"),
        ("SCM restart did not change the CM generation", "installed SCM-restart result relation"),
    ):
        require(installed_result, needle, label)


MUTATIONS = (
    Mutation(
        "flutter/lib/models/server_model.dart",
        "defeats exact reuse.\n            hideCmWindow();",
        "defeats exact reuse.\n            windowManager.close();",
        "graphical CM timer idle-process close restoration",
    ),
    Mutation(
        "flutter/lib/desktop/pages/server_page.dart",
        "Get.put<DesktopTabController>(tabController);",
        "Get.put<DesktopTabController>(tabController);\n    tabController.onRemoved = (_, __) {\n      windowManager.close();\n    };",
        "graphical CM last-tab process close restoration",
    ),
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
        'if process.key != expected_parent {\n            log::warn!(\n                "Rejected _cm IPC launch-parent generation',
        'if false {\n            log::warn!(\n                "Rejected _cm IPC launch-parent generation',
        "Windows server-generation bypass",
    ),
    Mutation(
        "src/ipc/auth.rs",
        "WindowsPeerProcess::from_inherited_handle(expected_parent.pid, handle)",
        "WindowsPeerProcess::open(expected_parent.pid)",
        "Windows inherited launch-parent capability bypass",
    ),
    Mutation(
        "src/ipc/auth.rs",
        "WindowsPeerProcess::from_inherited_handle(server_pid, handle)?",
        "WindowsPeerProcess::open(server_pid)?",
        "Windows CM main-IPC inherited capability bypass",
    ),
    Mutation(
        "src/ipc/auth.rs",
        "if server_pid != expected_parent.pid {\n        bail!(\n            \"connection-manager main IPC server mismatch",
        "if false {\n        bail!(\n            \"connection-manager main IPC server mismatch",
        "Windows CM main-IPC launch-parent PID bypass",
    ),
    Mutation(
        "src/ipc/auth.rs",
        'if process.key != expected_parent {\n        bail!(\n            "connection-manager main IPC server generation mismatch',
        'if false {\n        bail!(\n            "connection-manager main IPC server generation mismatch',
        "Windows CM main-IPC launch-parent generation bypass",
    ),
    Mutation(
        "src/ipc.rs",
        "let stream = connect_windows_cm_main(1_000).await?;",
        'let stream = connect(1_000, "").await?;',
        "Windows CM main-IPC dedicated connector bypass",
    ),
    Mutation(
        "src/ipc/auth.rs",
        "SetHandleInformation(handle, HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0))",
        "Ok(())",
        "Windows inherited parent handle resealing removal",
    ),
    Mutation(
        "src/platform/windows.rs",
        "None => OsString::from(crate::common::CM_LAUNCH_PARENT_HANDLE_NONE)",
        "None => OsString::new()",
        "Windows same-user parent-handle ambient override removal",
    ),
    Mutation(
        "src/platform/windows.rs",
        'windows_connection_manager_launch_environment("", parent_identity, None).is_err()',
        'windows_connection_manager_launch_environment("", parent_identity).is_err()',
        "Windows CM launch-environment regression signature rollback",
    ),
    Mutation(
        "src/ui_cm_interface.rs",
        "if !ipc::authorize_cm_ipc_connection(&stream) {",
        "if false && !ipc::authorize_cm_ipc_connection(&stream) {",
        "CM listener parent-admission bypass",
    ),
    Mutation(
        "src/platform/windows.rs",
        "let job = create_windows_service_process_job()?;\n    let launched = if is_root() {",
        "let job = ServiceOwnedWindowsHandle::new(NULL, \"disabled\")?;\n    let launched = if is_root() {",
        "Windows kill-on-close job removal",
    ),
    Mutation(
        "src/platform/windows.cc",
        "if (hJob != NULL)",
        "if (false)",
        "Windows token-switched job-at-creation bypass",
    ),
    Mutation(
        "src/platform/windows.cc",
        "CreateProcessW(application, commandLine.data(), NULL, NULL, FALSE,",
        "CreateProcessW(application, commandLine.data(), NULL, NULL, TRUE,",
        "Windows same-user handle-inheritance bypass",
    ),
    Mutation(
        "src/platform/windows.cc",
        "PROC_THREAD_ATTRIBUTE_JOB_LIST",
        "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS",
        "Windows atomic process-job attribute removal",
    ),
    Mutation(
        "src/platform/windows.cc",
        "PROC_THREAD_ATTRIBUTE_HANDLE_LIST",
        "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS",
        "Windows explicit parent-handle inheritance removal",
    ),
    Mutation(
        "src/platform/windows.cc",
        "hInheritedHandle != NULL,\n                                     dwCreationFlags",
        "FALSE,\n                                     dwCreationFlags",
        "Windows explicit handle inheritance disablement",
    ),
    Mutation(
        "src/platform/windows.rs",
        "PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE",
        "PROCESS_QUERY_LIMITED_INFORMATION",
        "Windows parent-proof liveness right removal",
    ),
    Mutation(
        "src/platform/windows.rs",
        "drop(inherited_parent);",
        "// inherited parent proof retained until CM owner teardown",
        "Windows parent-proof prompt-close removal",
    ),
    Mutation(
        "src/core_main.rs",
        '} else if args[0] == "--cm-no-ui" {\n            #[cfg(target_os = "windows")]\n            if let Err(err) = crate::ipc::seal_windows_cm_launch_parent_handle() {',
        '} else if args[0] == "--cm-no-ui" {\n            #[cfg(target_os = "windows")]\n            if let Err(err) = Ok::<(), &str>(()) {',
        "Windows headless-CM early parent-handle sealing removal",
    ),
    Mutation(
        "src/platform/windows.rs",
        "WindowsConnectionManagerProcessHandle { _job: job, process }",
        "WindowsConnectionManagerProcessHandle { process }",
        "Windows retained CM ownership-job removal",
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
        "scripts/build-windows.ps1",
        'cargo run --offline --locked --example windows_cm_lifecycle_probe --features "flutter,windows-cm-lifecycle-probe" --color never',
        "Write-Host 'native Windows CM lifecycle probe disabled'",
        "native Windows CM lifecycle probe removal",
    ),
    Mutation(
        "examples/probe_client.rs",
        'mode == "cmfiletransfer" && !received_directory',
        'mode == "cmfiletransfer" && false',
        "installed CM directory-response requirement removal",
    ),
    Mutation(
        "scripts/windows-installed-service-probe.ps1",
        "$process.SessionId -ne $InteractiveToken.SessionId",
        "$process.SessionId -eq $InteractiveToken.SessionId",
        "installed CM interactive-session proof bypass",
    ),
    Mutation(
        "scripts/windows-installed-service-probe.ps1",
        "TerminateExactProcessGeneration(\n        [uint32]$Generation.ProcessId",
        "TerminateExactProcessGeneration(\n        [uint32]0",
        "installed exact-generation termination bypass",
    ),
    Mutation(
        "scripts/windows-installed-service-probe.ps1",
        "if (wait == WAIT_OBJECT_0) { return false; }",
        "if (wait == WAIT_OBJECT_0) { return true; }",
        "installed signaled-process liveness bypass",
    ),
    Mutation(
        "scripts/windows-installed-service-probe.ps1",
        "Wait-ExactProcessGenerationGone $cmAfterStaleRecovery 'CM generation owned by the abruptly terminated server'",
        "Write-Host 'CM owner retirement skipped'",
        "installed abrupt-owner CM retirement removal",
    ),
    Mutation(
        "scripts/verify-windows-installed-service-result.py",
        'result["cm_roundtrip_count"] != 6',
        'result["cm_roundtrip_count"] < 0',
        "installed CM round-trip result bypass",
    ),
    Mutation(
        "src/windows_cm_lifecycle_probe.rs",
        "worker.cm_process.wait_for_exit()",
        "Ok(())",
        "Windows CM parent-death observation removal",
    ),
    Mutation(
        "src/windows_cm_lifecycle_probe.rs",
        "if wrong.is_ok()",
        "if false",
        "Windows CM wrong-token rejection bypass",
    ),
    Mutation(
        "src/windows_cm_lifecycle_probe.rs",
        'ipc::authenticate_windows_cm_endpoint(&stream, "--cm", expected_identity)',
        'ipc::authenticate_windows_cm_endpoint_bypassed(&stream, "--cm", expected_identity)',
        "Windows CM wrong-token endpoint-identity bypass",
    ),
    Mutation(
        "Cargo.toml",
        'default = ["use_dasp"]',
        'default = ["use_dasp", "windows-cm-lifecycle-probe"]',
        "Windows CM lifecycle probe enabled in default artifacts",
    ),
    Mutation(
        "requirements.html",
        '<span class="id">R-S11gi</span>',
        '<span class="id">R-S11gi-disabled</span>',
        "requirement removal",
    ),
    Mutation(
        "requirements.html",
        "both same-user and LocalSystem launches",
        "only LocalSystem launches",
        "same-user Windows CM job requirement removal",
    ),
    Mutation(
        "requirements.html",
        "atomically allowlist that one inheritable capability",
        "optionally pass one inheritable capability",
        "LocalSystem Windows CM parent-capability requirement weakening",
    ),
    Mutation(
        "requirements.html",
        "reuse that same sealed process capability when it connects to the launching server's main IPC",
        "use generic process discovery when it connects to the launching server's main IPC",
        "LocalSystem Windows CM main-IPC capability-reuse requirement weakening",
    ),
    Mutation(
        "requirements.html",
        '<span class="id">R-S11gic</span>',
        '<span class="id">R-S11gic-disabled</span>',
        "graphical CM retained-idle requirement removal",
    ),
    Mutation(
        "HARDENING_STATUS.md",
        "The first inherited-main-IPC native retry proves both authenticated directory round trips",
        "The undocumented native retry proves both authenticated directory round trips",
        "graphical CM retained-idle ledger removal",
    ),
    Mutation(
        "requirements.html",
        "Appendix C #344 installed lifecycle pass (2026-08-12)",
        "Appendix C #344 installed lifecycle pending (2026-08-12)",
        "installed graphical CM lifecycle requirements evidence removal",
    ),
    Mutation(
        "HARDENING_STATUS.md",
        "Exact installed LocalSystem lifecycle evidence is now green for the correction commit",
        "Exact installed LocalSystem lifecycle evidence is still pending for the correction commit",
        "installed graphical CM lifecycle ledger evidence removal",
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
