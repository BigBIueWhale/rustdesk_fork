#!/usr/bin/env python3
"""Validate the macOS service-owned runtime PRS raw IPC authority boundary."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Tuple


class VerificationError(RuntimeError):
    pass


@dataclass(frozen=True)
class Mutation:
    source: str
    old: str
    new: str
    label: str


def require(source: str, token: str, label: str) -> None:
    if token not in source:
        raise VerificationError("missing {}: {!r}".format(label, token))


def forbid(source: str, token: str, label: str) -> None:
    if token in source:
        raise VerificationError("forbidden {} remains: {!r}".format(label, token))


def require_exact_count(source: str, token: str, count: int, label: str) -> None:
    actual = source.count(token)
    if actual != count:
        raise VerificationError(
            "{} count differs: expected {}, got {}".format(label, count, actual)
        )


def require_order(source: str, tokens: Tuple[str, ...], label: str) -> None:
    position = -1
    for token in tokens:
        position = source.find(token, position + 1)
        if position < 0:
            raise VerificationError(
                "{} is missing ordered token {!r}".format(label, token)
            )


def extract(source: str, start: str, end: str, label: str) -> str:
    if source.count(start) != 1:
        raise VerificationError("{} start cardinality differs".format(label))
    begin = source.index(start)
    finish = source.find(end, begin + len(start))
    if finish < 0:
        raise VerificationError("{} end is absent".format(label))
    return source[begin:finish]


def validate(sources: Dict[str, str]) -> None:
    ipc = sources["ipc"]
    password = sources["password"]
    auth = sources["auth"]
    config = sources["config"]
    verify = sources["verify"]
    apple = sources["apple"]
    requirements = sources["requirements"]
    hardening = sources["hardening"]
    native_watch = sources["native_watch"]
    workspace = sources["workspace"]

    for token, label in (
        (
            '#[cfg(any(target_os = "linux", target_os = "macos"))]\n'
            'pub(crate) const SERVICE_CREDENTIAL_IPC_POSTFIX: &str = '
            '"_service_credential";',
            "macOS raw credential endpoint",
        ),
        ("CredentialSnapshotRequest = 3", "bodyless snapshot request kind"),
        ("CredentialReplica = 4", "credential replica response kind"),
        ("const CREDENTIAL_REPLICA_BYTES: usize = 44;", "canonical PRS length"),
        (
            "pub(crate) async fn send_credential_snapshot_request_unix",
            "raw request writer",
        ),
        (
            "pub(crate) async fn receive_credential_snapshot_request_unix",
            "raw request reader",
        ),
        (
            "pub(crate) async fn send_credential_replica_unix",
            "raw replica writer",
        ),
        (
            "pub(crate) async fn receive_credential_replica_unix",
            "raw replica reader",
        ),
    ):
        require(password, token, label)
    snapshot_writer = extract(
        password,
        "pub(crate) async fn send_credential_snapshot_request_unix",
        "\n}\n\n#[cfg(any(target_os = \"linux\", target_os = \"macos\"))]\n"
        "pub(crate) async fn send_credential_replica_unix",
        "raw credential request writer",
    )
    require_order(
        snapshot_writer,
        (
            "SensitivePayloadKind::CredentialSnapshotRequest",
            "0,\n        0,",
            "stream.write_all(&header)",
            "stream.shutdown()",
        ),
        "bodyless operation-bound credential request",
    )
    replica_writer = extract(
        password,
        "pub(crate) async fn send_credential_replica_unix",
        "\n}\n\n#[cfg(any(target_os = \"linux\", target_os = \"macos\"))]\n"
        "pub(crate) async fn receive_request_unix",
        "raw credential replica writer",
    )
    require_order(
        replica_writer,
        (
            "SensitivePayloadKind::CredentialReplica",
            "replica.as_bytes().len()",
            "stream.write_all(&header)",
            "stream.write_all(replica.as_bytes())",
            "stream.shutdown()",
        ),
        "canonical operation-bound credential response",
    )
    replica_reader = extract(
        password,
        "pub(crate) async fn receive_credential_replica_unix",
        "\n}\n\n#[cfg(any(target_os = \"linux\", target_os = \"macos\"))]\n"
        "pub(crate) async fn send_status_unix",
        "raw credential replica reader",
    )
    require_order(
        replica_reader,
        (
            "SensitivePayloadKind::CredentialReplica",
            "request.operation_id() != expected_operation_id",
            "request.into_password()",
        ),
        "operation-bound sensitive replica receive",
    )
    for region, label in (
        (snapshot_writer, "raw request writer"),
        (replica_writer, "raw replica writer"),
        (replica_reader, "raw replica reader"),
    ):
        for token in ("serde", "Bytes", "Framed", "send_json", "next_timeout"):
            forbid(region, token, "{} generic framing".format(label))

    config_classifier = extract(
        config,
        "pub fn is_service_ipc_postfix(postfix: &str) -> bool {",
        "\n}",
        "service-scoped IPC endpoint classifier",
    )
    require_order(
        config_classifier,
        (
            'matches!(postfix, "_service" | "_service_password")',
            'cfg!(any(target_os = "linux", target_os = "macos"))',
            'postfix == "_service_credential"',
        ),
        "macOS root-scoped credential path selection",
    )

    request_enum = extract(
        ipc,
        "pub(crate) enum ServiceIpcRequest {",
        "\n}",
        "generic service request protocol",
    )
    response_enum = extract(
        ipc,
        "pub(crate) enum ServiceIpcResponse {",
        "\n}",
        "generic service response protocol",
    )
    for region, label in (
        (request_enum, "generic service request"),
        (response_enum, "generic service response"),
    ):
        forbid(region, "PermanentPasswordSnapshot", "{} credential variant".format(label))
        forbid(region, "storage: String", "{} storage field".format(label))
        forbid(region, "salt: String", "{} salt field".format(label))
    forbid(
        ipc,
        "handle_macos_service_owned_permanent_password_snapshot_request",
        "retired generic macOS snapshot handler",
    )
    forbid(
        ipc,
        "get_local_permanent_password_storage_and_salt()",
        "persistent storage/salt crossing IPC",
    )

    prepared = extract(
        ipc,
        "struct PreparedServiceIpc {",
        "\n}",
        "Unix service listener ownership",
    )
    require(
        prepared,
        "credential_incoming: Incoming",
        "mandatory Unix credential listener",
    )
    forbid(
        prepared,
        "credential_incoming: Option<Incoming>",
        "optional macOS credential listener",
    )
    prepare = extract(
        ipc,
        "async fn prepare_service_ipc(postfix: &str)",
        "\n}\n\n#[cfg(any(target_os = \"linux\", target_os = \"macos\"))]\n"
        "async fn start_service_ipc",
        "Unix service listener preparation",
    )
    require_order(
        prepare,
        (
            "new_listener(postfix).await?",
            "new_listener(password::SERVICE_PASSWORD_IPC_POSTFIX).await?",
            "new_listener(password::SERVICE_CREDENTIAL_IPC_POSTFIX).await?",
            "PreparedServiceIpc {",
        ),
        "independent service listener creation",
    )

    for token, label in (
        (
            "const SERVICE_CREDENTIAL_IPC_TRANSACTION_BUDGET: usize = 2;",
            "credential transaction budget",
        ),
        (
            "const MACOS_SERVICE_CREDENTIAL_IPC_AUTHORIZATION_BUDGET: usize = 2;",
            "macOS credential proof budget",
        ),
        (
            "fn try_acquire_service_credential_ipc_transaction_slot()",
            "credential transaction admission",
        ),
        (
            "fn try_acquire_macos_service_credential_ipc_authorization_slot()",
            "credential proof admission",
        ),
    ):
        require(ipc, token, label)
    service_loop = extract(
        ipc,
        "async fn run_service_ipc(postfix: &str, listeners: PreparedServiceIpc)",
        "\n\n#[cfg(target_os = \"linux\")]\n"
        "async fn handle_linux_service_credential_snapshot_transaction",
        "Unix service accept loop",
    )
    credential_accept = extract(
        service_loop,
        "result = credential_incoming.next() => {",
        "\n            result = password_incoming.next() => {",
        "macOS credential accept branch",
    )
    require_order(
        credential_accept,
        (
            "try_acquire_service_credential_ipc_transaction_slot()",
            "try_acquire_macos_service_credential_ipc_authorization_slot()",
            "service_scoped_ipc_authorization_snapshot_from_stream(",
            "password::SERVICE_CREDENTIAL_IPC_POSTFIX",
            "transactions.spawn(async move",
            "let Some(authorization)",
            "authorize_macos_service_scoped_credential_stream_for_task(",
            "handle_macos_service_credential_snapshot_transaction(",
            "stream,\n                            authorization,\n                            permit,",
        ),
        "bounded retained proof-before-request macOS credential admission",
    )
    forbid(
        credential_accept,
        "receive_credential_snapshot_request_unix",
        "raw request read before admission proof",
    )

    credential_handler = extract(
        ipc,
        "async fn handle_macos_service_credential_snapshot_transaction(",
        "\n}\n\n#[cfg(target_os = \"macos\")]\n"
        "async fn handle_sensitive_macos_service_ipc_transaction(",
        "macOS raw credential handler",
    )
    require_order(
        credential_handler,
        (
            "receive_credential_snapshot_request_unix(&mut stream, deadline)",
            "authenticate_macos_service_owned_credential_requester(authorization, deadline).await",
            "service_scoped_ipc_authorization_snapshot(",
            "password::SERVICE_CREDENTIAL_IPC_POSTFIX",
            "macos_service_owned_credential_requester_matches_post_request_authorization(",
            "&requester.identity,\n        post_request_authorization,",
            'service_owned_runtime_prs_replica("macOS")',
            "password::send_credential_replica_unix(",
        ),
        "bodyless request, retained exact LaunchAgent proof, post-request equality, and secret response",
    )
    for token, label in (
        ("get_local_permanent_password_storage_and_salt", "persistent envelope read"),
        ("send_service_response_timeout", "generic typed response"),
        ("ServiceIpcResponse", "serde response"),
        ("storage", "persistent storage field"),
        ("salt", "persistent salt field"),
    ):
        forbid(credential_handler, token, label)

    exact_peer = extract(
        ipc,
        "async fn authenticate_macos_service_owned_credential_requester(",
        "\n}\n\n#[cfg(any(target_os = \"macos\", test))]\n"
        "fn macos_service_owned_server_live_argv_is_expected",
        "macOS exact LaunchAgent peer proof admission",
    )
    require_order(
        exact_peer,
        (
            "try_acquire_macos_service_credential_ipc_authorization_slot()",
            "let proof_deadline = deadline.into_std();",
            'run_bounded_macos_security_proof(deadline, "macos-credential-snapshot-proof"',
            "authenticate_macos_service_owned_credential_requester_blocking(\n"
            "            authorization,\n"
            "            proof_deadline,\n"
            "        )",
        ),
        "retained audit-token and exactly owned blocking peer proof admission",
    )
    forbid(
        exact_peer,
        "try_acquire_macos_service_password_ipc_authorization_slot",
        "shared password proof capacity",
    )
    blocking_peer = extract(
        ipc,
        "fn authenticate_macos_service_owned_credential_requester_blocking(",
        "\n}\n\n#[cfg(target_os = \"macos\")]\n"
        "fn macos_service_owned_credential_requester_is_live",
        "macOS exact LaunchAgent blocking peer proof",
    )
    require_order(
        blocking_peer,
        (
            "authenticate_macos_service_owned_credential_requester_identity(authorization)?",
            "let argv = process.cmd().to_vec();",
            "macos_service_owned_server_live_argv_is_expected(&argv)",
            "if !macos_launch_agent_owns_service_owned_server_pid(peer_uid, peer_pid, proof_deadline)",
            "MacosServiceOwnedCredentialRequester { identity, argv }",
            "macos_service_owned_credential_requester_is_live(&requester).then_some(requester)",
        ),
        "retained installed-app identity, exact argv, exact launchd, and final requester replay",
    )
    final_requester = extract(
        ipc,
        "fn macos_service_owned_credential_requester_is_live(",
        "\n}\n\n#[cfg(target_os = \"macos\")]\n"
        "fn macos_service_owned_server_launch_agent_label",
        "macOS credential requester final replay",
    )
    require_order(
        final_requester,
        (
            "macos_service_owned_credential_requester_identity_is_live(&requester.identity)",
            "process.pid().as_u32() == requester.identity.pid()",
            "process.name().eq_ignore_ascii_case(&app_name)",
            "process.cmd() == requester.argv",
            "macos_service_owned_server_live_argv_is_expected(process.cmd())",
        ),
        "final installed generation and exact argv replay",
    )
    forbid(
        ipc,
        "macos_peer_is_service_owned_server(",
        "obsolete Boolean credential peer check",
    )
    forbid(
        ipc,
        "macos_peer_is_service_owned_server_blocking(",
        "obsolete Boolean blocking credential peer check",
    )

    retained_admission = extract(
        ipc,
        "async fn authorize_macos_service_scoped_credential_stream_for_task(",
        "\n}\n\n#[cfg(target_os = \"macos\")]\n"
        "async fn authorize_macos_service_server_snapshot_for_task",
        "macOS retained credential admission proof",
    )
    require_order(
        retained_admission,
        (
            "let retained_authorization = authorization.clone();",
            "authorize_service_scoped_ipc_authorization_snapshot(authorization)",
            "Ok((retained_authorization, authorized))",
            "Ok((authorization, true)) => Some(authorization)",
        ),
        "generic proof returns the exact accepted credential authorization snapshot",
    )

    service_server_task_proof = extract(
        ipc,
        "async fn authorize_macos_service_server_snapshot_for_task(",
        "\n}\n\n#[inline]\n"
        "pub async fn connect_service",
        "macOS service-server task proof",
    )
    require_order(
        service_server_task_proof,
        (
            ") -> ResultType<ipc_auth::MacosServiceServerAuthorization>",
            'run_bounded_macos_security_proof(deadline, "macos-service-server-proof"',
            "ipc_auth::authorize_macos_service_server_snapshot(authorization)",
        ),
        "typed exactly owned macOS service-server proof",
    )

    requester_identity = extract(
        auth,
        "pub(crate) fn authenticate_macos_service_owned_credential_requester_identity(",
        "\n}\n\n#[cfg(target_os = \"macos\")]\n"
        "pub(crate) fn macos_service_owned_credential_requester_identity_is_live",
        "macOS credential requester identity admission",
    )
    require_order(
        requester_identity,
        (
            "authorization.postfix != super::password::SERVICE_CREDENTIAL_IPC_POSTFIX",
            "!authorization.uid_authorized",
            "authorization.macos_peer_identity",
            "macos_service_owned_password_requester_identity_is_live(&identity)",
            "Ok(identity)",
        ),
        "credential endpoint, UID authority, and installed-app audit generation",
    )
    requester_generation = extract(
        auth,
        "pub(crate) fn macos_service_owned_credential_requester_identity_is_live(",
        "\n}\n\n#[cfg(target_os = \"macos\")]\n"
        "pub(crate) fn macos_service_owned_credential_requester_matches_post_request_authorization",
        "macOS credential requester generation replay",
    )
    require_order(
        requester_generation,
        (
            "macos_service_owned_password_requester_identity_is_live(identity)",
            "macos_service_owned_password_requester_generation_is_live(identity)",
        ),
        "final exact installed-app audit generation replay",
    )
    requester_post = extract(
        auth,
        "pub(crate) fn macos_service_owned_credential_requester_matches_post_request_authorization(",
        "\n}\n\n#[cfg(target_os = \"macos\")]\n"
        "fn macos_service_owned_password_requester_identity_is_live",
        "macOS credential requester post-request authorization equality",
    )
    require_order(
        requester_post,
        (
            "authorization.postfix != super::password::SERVICE_CREDENTIAL_IPC_POSTFIX",
            "!authorization.uid_authorized",
            "post_request_identity.uid == requester.uid",
            "post_request_identity.pid == requester.pid",
            "post_request_identity.audit_token == requester.audit_token",
        ),
        "post-request endpoint, UID, PID, and full audit-token equality",
    )
    launchctl_parser = extract(
        ipc,
        "fn macos_launchctl_service_identity<'a>(",
        '\n}\n\n#[cfg(any(target_os = "macos", all(target_os = "linux", test)))]\n'
        "#[derive(Debug)]\nstruct MacosBoundedChildOutput",
        "macOS launchctl service identity parser",
    )
    require_order(
        launchctl_parser,
        (
            "std::str::from_utf8(output).ok()?",
            'let expected_header = format!("{expected_target} = {{");',
            "lines.next()?.trim() != expected_header",
            "let mut depth = 1usize;",
            'if line == "}"',
            "depth = depth.checked_sub(1)?;",
            'line.ends_with(" = {") || line.ends_with(" => {")',
            "depth = depth.checked_add(1)?;",
            "if depth != 1",
            'match key {\n            "pid" => {',
            "if pid.is_some()",
            "parsed.to_string() != value",
            '            "path" => {',
            "if path.is_some()",
            "if !closed || lines.any(|line| !line.trim().is_empty())",
            "Some((pid?, path?))",
        ),
        "strict top-level launchctl identity parsing",
    )
    bounded_child = extract(
        ipc,
        "fn run_macos_bounded_child_stdout(",
        '\n}\n\n#[cfg(target_os = "macos")]\n'
        "fn macos_launch_agent_owns_service_owned_server_pid",
        "bounded macOS launchctl child owner",
    )
    require_order(
        bounded_child,
        (
            "if stdout_limit == 0",
            "std::time::Instant::now() >= deadline",
            ".stdin(std::process::Stdio::null())",
            ".stdout(std::process::Stdio::piped())",
            ".stderr(std::process::Stdio::null())",
            ".spawn()",
            "child.stdout.take()",
            "set_macos_bounded_child_stdout_nonblocking(&stdout)",
            "let mut captured = Vec::with_capacity(stdout_limit.min(16 * 1024));",
            "let mut buffer = [0u8; 8 * 1024];",
            "stdout.read(&mut buffer)",
            "count > stdout_limit.saturating_sub(captured.len())",
            "captured.extend_from_slice(&buffer[..count]);",
            "child.try_wait()",
            "if stdout_closed",
            "if let Some(status) = status.take()",
            "if now >= deadline",
            "std::thread::sleep(",
            "MACOS_LAUNCHCTL_POLL_INTERVAL.min(deadline.saturating_duration_since(now))",
        ),
        "byte- and deadline-bounded launchctl capture",
    )
    for token, label in (
        (
            "const MACOS_LAUNCHCTL_STDOUT_MAX_BYTES: usize = 256 * 1024;",
            "launchctl stdout ceiling",
        ),
        (
            "std::time::Duration::from_millis(50);",
            "launchctl cleanup reserve",
        ),
        (
            "flags | hbb_common::libc::O_NONBLOCK",
            "launchctl nonblocking pipe",
        ),
        (
            "fn terminate_and_reap_macos_bounded_child(",
            "launchctl child cleanup owner",
        ),
        (
            "child.kill().err()",
            "launchctl child termination",
        ),
        (
            "child.wait()",
            "launchctl child reap",
        ),
    ):
        require(ipc, token, label)
    require_exact_count(
        bounded_child,
        "macos_bounded_child_failure(",
        6,
        "bounded child cleanup failure edges",
    )
    launchctl_owner = extract(
        ipc,
        "fn macos_launch_agent_owns_service_owned_server_pid(",
        '\n}\n\n#[cfg(target_os = "macos")]\n'
        "async fn permanent_password_is_set_for_current_process",
        "macOS launchctl ownership query",
    )
    require_order(
        launchctl_owner,
        (
            "proof_deadline.checked_sub(MACOS_LAUNCHCTL_REAP_RESERVE)",
            'format!("gui/{peer_uid}/{label}")',
            "std::process::Command::new(MACOS_LAUNCHCTL)",
            '.current_dir("/")',
            ".env_clear()",
            '.env("LC_ALL", "C")',
            "configure_command_close_nonstdio_on_exec(&mut command)",
            "run_macos_bounded_child_stdout(",
            "child_deadline",
            "MACOS_LAUNCHCTL_STDOUT_MAX_BYTES",
            "macos_launchctl_service_identity(&output.stdout, &target)",
            "reported_identity != Some((peer_pid, expected_plist.as_str()))",
        ),
        "closed-environment exact launchctl ownership query",
    )
    forbid(
        ipc,
        "macos_launchctl_print_value",
        "depthless first-match launchctl parser",
    )
    forbid(
        launchctl_owner,
        "from_utf8_lossy",
        "lossy launchctl authority decoding",
    )
    forbid(
        launchctl_owner,
        "command.output()",
        "unbounded launchctl whole-output capture",
    )
    for test_name in (
        "macos_launchctl_service_identity_accepts_exact_top_level_record",
        "macos_launchctl_service_identity_rejects_nested_substitution",
        "macos_launchctl_service_identity_rejects_duplicate_top_level_authority",
        "macos_launchctl_service_identity_rejects_wrong_target_or_trailing_record",
        "macos_launchctl_service_identity_rejects_non_utf8_or_noncanonical_pid",
        "macos_bounded_child_stdout_accepts_exact_output",
        "macos_bounded_child_stdout_terminates_on_overflow",
        "macos_bounded_child_stdout_terminates_on_deadline",
    ):
        require(ipc, test_name, "launchctl regression {}".format(test_name))

    peer_snapshot = extract(
        auth,
        "pub(crate) fn macos_peer_process_identity_from_stream<T>(",
        "\n}\n\n#[cfg(target_os = \"macos\")]\n"
        "pub(crate) fn macos_service_server_authorization_snapshot",
        "raw-stream macOS peer identity snapshot",
    )
    require_order(
        peer_snapshot,
        (
            "let fd = stream.as_raw_fd();",
            "peer_uid_from_fd(fd)",
            "peer_pid_from_fd(fd)",
            "peer_audit_token_from_fd(fd)",
        ),
        "immediate kernel peer identity snapshot",
    )
    server_authorization = extract(
        auth,
        "pub(crate) struct MacosServiceServerAuthorization {",
        "\n}\n\n#[cfg(target_os = \"macos\")]\n"
        "pub(crate) fn macos_peer_process_identity_from_stream",
        "retained macOS privileged-helper authorization",
    )
    require_order(
        server_authorization,
        (
            "identity: MacosPeerProcessIdentity",
            "context: &'static str",
        ),
        "complete retained macOS privileged-helper authorization",
    )
    for token, label in (
        ("#[derive(Clone)]", "cloneable authorization"),
        ("#[derive(Copy)]", "copyable authorization"),
        ("pub identity:", "public authorization identity"),
        ("pub(crate) identity:", "crate-visible authorization identity"),
    ):
        forbid(server_authorization, token, label)
    for derive in ("Clone", "Copy"):
        forbid(
            auth,
            "#[derive({})]\npub(crate) struct MacosServiceServerAuthorization".format(
                derive
            ),
            "{} macOS privileged-helper authorization".format(
                derive.lower()
            ),
        )
    server_verify = extract(
        auth,
        "pub(crate) fn authorize_macos_service_server_snapshot(",
        "\n}\n\n#[cfg(target_os = \"macos\")]\n#[inline]\n"
        "pub(crate) fn macos_service_server_authorizations_match",
        "macOS privileged-helper authorization proof",
    )
    require_order(
        server_verify,
        (
            ") -> ResultType<MacosServiceServerAuthorization>",
            "authorization.identity.uid != 0",
            "macos_peer_is_trusted_privileged_helper(&authorization.identity)",
            "Ok(authorization)",
        ),
        "typed root and trusted-helper authorization return",
    )
    server_match = extract(
        auth,
        "pub(crate) fn macos_service_server_authorizations_match(",
        "\n}\n\n#[cfg(windows)]",
        "macOS privileged-helper identity continuity",
    )
    require_order(
        server_match,
        (
            "accepted: &MacosServiceServerAuthorization",
            "refreshed: &MacosServiceServerAuthorization",
            "accepted.identity.uid == refreshed.identity.uid",
            "accepted.identity.pid == refreshed.identity.pid",
            "accepted.identity.audit_token == refreshed.identity.audit_token",
        ),
        "exact UID, PID, and full audit-token helper continuity",
    )
    service_snapshot = extract(
        auth,
        "pub(crate) fn service_scoped_ipc_authorization_snapshot_from_stream<T>(",
        "\n}\n\n#[cfg(any(target_os = \"linux\", target_os = \"macos\"))]\n"
        "pub(crate) fn authorize_service_scoped_ipc_authorization_snapshot",
        "service-scoped accepted-socket authorization snapshot",
    )
    require_order(
        service_snapshot,
        (
            "let peer_uid = peer_uid_from_fd(fd);",
            "match (peer_uid, peer_pid_from_fd(fd), peer_audit_token_from_fd(fd))",
            "macos_peer_process_identity_from_socket_components(uid, pid, audit_token)",
            "uid_authorized",
            "ServiceScopedIpcAuthorization {",
        ),
        "credential socket UID, PID, full audit-token, and UID authority snapshot",
    )

    replica_receiver = extract(
        ipc,
        "struct MacosServiceOwnedCredentialReplicaReceiver {",
        "\n}\n\n#[cfg(target_os = \"macos\")]\n"
        "struct MacosServiceOwnedRuntimePrsAdmission",
        "macOS credential-replica receiver capability",
    )
    require_order(
        replica_receiver,
        (
            "stream: ConnClient",
            "server: ipc_auth::MacosServiceServerAuthorization",
        ),
        "receiver-owned stream and exact helper authorization",
    )
    replica_admission = extract(
        ipc,
        "struct MacosServiceOwnedRuntimePrsAdmission {",
        "\n}\n\n#[cfg(any(target_os = \"linux\", target_os = \"macos\"))]\n"
        "enum SensitiveMainPasswordAuthority",
        "macOS runtime-PRS admission capability",
    )
    require_order(
        replica_admission,
        (
            "_receiver: MacosServiceOwnedCredentialReplicaReceiver",
            "replica: ServiceOwnedRuntimePrsReplica",
        ),
        "admission retains receiver and typed runtime PRS",
    )
    for region, label in (
        (replica_receiver, "macOS credential-replica receiver"),
        (replica_admission, "macOS runtime-PRS admission"),
    ):
        for token, detail in (
            ("#[derive(Clone)]", "cloneable"),
            ("#[derive(Copy)]", "copyable"),
            ("pub struct", "public"),
            ("pub(crate) struct", "crate-visible"),
        ):
            forbid(region, token, "{} {} capability".format(label, detail))
    for type_name, label in (
        (
            "MacosServiceOwnedCredentialReplicaReceiver",
            "macOS credential-replica receiver",
        ),
        (
            "MacosServiceOwnedRuntimePrsAdmission",
            "macOS runtime-PRS admission",
        ),
    ):
        for visibility in ("pub ", "pub(crate) "):
            forbid(
                ipc,
                "{}struct {}".format(visibility, type_name),
                "{} capability visibility".format(label),
            )
        for derive in ("Clone", "Copy"):
            forbid(
                ipc,
                "#[derive({})]\nstruct {}".format(derive, type_name),
                "{} {} capability".format(derive.lower(), label),
            )

    receiver_impl = extract(
        ipc,
        "impl MacosServiceOwnedCredentialReplicaReceiver {",
        "\n}\n\n#[cfg(target_os = \"macos\")]\n"
        "impl MacosServiceOwnedRuntimePrsAdmission",
        "macOS credential-replica receiver transaction",
    )
    require_order(
        receiver_impl,
        (
            "async fn connect(deadline: tokio::time::Instant) -> ResultType<Self>",
            "!crate::common::is_service_owned_server_process()",
            "Config::ipc_path_for_uid(0, password::SERVICE_CREDENTIAL_IPC_POSTFIX)",
            "Endpoint::connect(path)",
            "ipc_auth::macos_service_server_authorization_snapshot(",
            "let server =\n"
            "            authorize_macos_service_server_snapshot_for_task(authorization, deadline).await?",
            "MacosServiceOwnedCredentialReplicaReceiver { stream, server }",
            "async fn receive_and_admit(",
            "mut self,",
            ") -> ResultType<MacosServiceOwnedRuntimePrsAdmission>",
            "!crate::common::is_service_owned_server_process()",
            "hbb_common::uuid::Uuid::new_v4()",
            "password::send_credential_snapshot_request_unix(",
            "&mut self.stream",
            "operation_id",
            "deadline",
            "password::receive_credential_replica_unix(",
            "&mut self.stream",
            "operation_id",
            "deadline",
            "ipc_auth::macos_service_server_authorization_snapshot(",
            "authorize_macos_service_server_snapshot_for_task(refreshed, deadline).await?",
            "ipc_auth::macos_service_server_authorizations_match(&self.server, &refreshed)",
            "MacosServiceOwnedRuntimePrsAdmission {",
            "_receiver: self",
            "replica: ServiceOwnedRuntimePrsReplica { value }",
        ),
        "fixed endpoint, consuming response, final helper replay, and typed admission",
    )
    for token, label in (
        ("connect_sensitive_unix(", "postfix-selectable sensitive connector"),
        ("connect_service(", "generic service connector"),
        ("Config::set_permanent_password_prs_for_runtime", "direct runtime sink"),
        ("if false", "detached receiver authority bypass"),
        ("&mut self,", "borrowed rather than consuming receiver admission"),
    ):
        forbid(receiver_impl, token, label)
    admission_impl = extract(
        ipc,
        "impl MacosServiceOwnedRuntimePrsAdmission {",
        "\n}\n\n#[cfg(target_os = \"linux\")]\n"
        "impl LinuxServiceOwnedPasswordReplicaWriter",
        "macOS runtime-PRS admitted action",
    )
    require_order(
        admission_impl,
        (
            "fn install(self) -> ResultType<bool>",
            "self.replica.install_for_runtime()",
        ),
        "consuming typed runtime-only install",
    )

    runtime_replica_impl = extract(
        ipc,
        "impl ServiceOwnedRuntimePrsReplica {",
        "\n}\n\n#[cfg(not(any(target_os = \"android\", target_os = \"ios\")))]\n"
        "enum MainPasswordMutationRequest",
        "typed service-owned runtime PRS",
    )
    require_order(
        runtime_replica_impl,
        (
            'as_sensitive_password(&self) -> &SensitivePassword',
            "fn install_for_runtime(self) -> ResultType<bool>",
            "Config::set_permanent_password_prs_for_runtime(self.value.as_str())",
        ),
        "borrow-only PRS access and consuming runtime-only sink",
    )
    forbid(
        runtime_replica_impl,
        '#[cfg(target_os = "linux")]\n    fn install_for_runtime',
        "Linux-only runtime PRS sink",
    )

    snapshot_client = extract(
        ipc,
        "pub async fn refresh_macos_service_owned_permanent_password_snapshot(",
        "\n}\n\n#[cfg(target_os = \"linux\")]\n"
        "pub async fn refresh_linux_service_owned_permanent_password_snapshot(",
        "macOS raw credential client",
    )
    require_order(
        snapshot_client,
        (
            "let receiver = MacosServiceOwnedCredentialReplicaReceiver::connect(deadline).await?",
            "let admission = receiver.receive_and_admit(deadline).await?",
            "admission.install()",
        ),
        "typed macOS credential-replica receive and admitted runtime install",
    )
    for token, label in (
        ("Endpoint::connect(", "direct untyped endpoint connection"),
        ("macos_service_server_authorization_snapshot(", "direct helper snapshot"),
        ("authorize_macos_service_server_snapshot_for_task(", "direct helper proof"),
        ("send_credential_snapshot_request_unix(", "direct raw request writer"),
        ("receive_credential_replica_unix(", "direct raw replica reader"),
        ("Config::set_permanent_password_prs_for_runtime", "direct runtime PRS sink"),
        ("connect_service(", "generic service connector"),
        ("ServiceIpcRequest::", "serde request"),
        ("ServiceIpcResponse::", "serde response"),
        ("send_service_request_timeout(", "generic request writer"),
        ("next_service_response_timeout(", "generic response reader"),
        ("storage", "persistent storage"),
        ("salt", "persistent salt"),
        ("set_permanent_password_storage_for_runtime", "storage-envelope runtime install"),
    ):
        forbid(snapshot_client, token, label)

    status_refresh = extract(
        ipc,
        "async fn refresh_macos_service_owned_permanent_password_snapshot_for_status()",
        "\n}\n\n#[cfg(not(target_os = \"macos\"))]\n"
        "async fn permanent_password_is_set_for_current_process()",
        "macOS service-owned status snapshot refresh",
    )
    require_order(
        status_refresh,
        (
            "refresh_macos_service_owned_permanent_password_snapshot(1_000).await",
            'Config::set_permanent_password_prs_for_runtime("")',
        ),
        "nonpersistent runtime-PRS failure clear",
    )
    forbid(
        status_refresh,
        "set_permanent_password_storage_for_runtime",
        "storage-envelope status failure clear",
    )

    for function_name in ("connect_with_path", "connect"):
        function = extract(
            ipc,
            "async fn {}(".format(function_name)
            if function_name == "connect_with_path"
            else "pub async fn connect(",
            "\n}",
            "{} raw endpoint guard".format(function_name),
        )
        require_order(
            function,
            (
                "password::SERVICE_CREDENTIAL_IPC_POSTFIX",
                'bail!("the service credential endpoint requires the raw transport")',
            ),
            "{} rejects generic credential framing".format(function_name),
        )

    regression = extract(
        ipc,
        "fn service_channel_uses_closed_directional_protocol()",
        "\n    }\n\n    #[test]\n"
        "    fn windows_service_sas_channel_uses_closed_directional_protocol()",
        "generic service protocol regression",
    )
    require_order(
        regression,
        (
            'br#"{"t":"PermanentPasswordSnapshot"}"#',
            "serde_json::from_slice::<ServiceIpcRequest>(retired_credential_request).is_err()",
            "serde_json::from_slice::<ServiceIpcResponse>(retired_credential_request).is_err()",
        ),
        "retired generic credential tag rejection",
    )

    for gate, label in ((verify, "shared gate"), (apple, "Apple gate")):
        require(
            gate,
            "verify-macos-service-credential-ipc.py",
            "{} focused verifier wiring".format(label),
        )
        for token in (
            "R-S11ep",
            "R-S11e-177",
            "R-S11fd",
            "R-S11e-191",
            "R-S11fe",
            "R-S11e-192",
            '<span class="id">R-S11ia</span>',
            "<tr><td>386</td>",
            "R-S11ia/R-S11e-264 — exact macOS service-owned credential requester generation and response finality",
            "The same identity additionally binds R-S11ia and Appendix C #386.",
            '<span class="id">R-S11ij</span>',
            "<tr><td>395</td>",
            "R-S11ij/R-S11e-273 — typed macOS child-side runtime PRS receiver authority",
            "The same identity additionally binds R-S11ij and Appendix C #395.",
        ):
            require(gate, token, "{} documentation binding".format(label))
    for token, label in (
        ('<span class="id">R-S11ep</span>', "R-S11ep requirement"),
        ("<tr><td>298</td>", "Appendix C #298"),
        ("raw <code>_service_credential</code>", "raw macOS endpoint contract"),
        ('<span class="id">R-S11fd</span>', "R-S11fd requirement"),
        ("<tr><td>312</td>", "Appendix C #312"),
        ('<span class="id">R-S11fe</span>', "R-S11fe requirement"),
        ("<tr><td>313</td>", "Appendix C #313"),
        ('<span class="id">R-S11ia</span>', "R-S11ia requirement"),
        ("<tr><td>386</td>", "Appendix C #386"),
        (
            "macOS service-owned credential replication responds only to one retained exact LaunchAgent requester generation",
            "exact credential response requirement",
        ),
        ('<span class="id">R-S11ij</span>', "R-S11ij requirement"),
        ("<tr><td>395</td>", "Appendix C #395"),
        (
            "non-<code>Clone</code>, non-<code>Copy</code> <code>MacosServiceOwnedCredentialReplicaReceiver</code>",
            "private non-cloneable macOS replica receiver requirement",
        ),
        (
            "consume itself, freshly require the exact service-owned-server role",
            "consuming final receiver requirement",
        ),
        (
            "Only the admission&#39;s consuming <code>install</code> action may reach the shared Unix typed replica",
            "typed admitted runtime-only install requirement",
        ),
    ):
        require(requirements, token, label)
    require(
        hardening,
        "R-S11ep/R-S11e-177 macOS runtime PRS raw credential authority",
        "hardening ledger",
    )
    require(
        hardening,
        "R-S11fd/R-S11e-191 exact macOS launchd service-record authority",
        "launchctl parser hardening ledger",
    )
    require(
        hardening,
        "R-S11fe/R-S11e-192 bounded macOS launchd proof-child resources",
        "launchctl bounded-child hardening ledger",
    )
    require(
        hardening,
        "R-S11ia/R-S11e-264 — exact macOS service-owned credential requester generation and response finality",
        "exact credential response hardening ledger",
    )
    require(
        hardening,
        "R-S11ij/R-S11e-273 — typed macOS child-side runtime PRS receiver authority",
        "typed macOS runtime-PRS receiver hardening ledger",
    )
    require(
        native_watch,
        "The same identity additionally binds R-S11ia and Appendix C #386.",
        "native-watch exact credential response binding",
    )
    require(
        native_watch,
        "The same identity additionally binds R-S11ij and Appendix C #395.",
        "native-watch typed runtime-PRS receiver binding",
    )
    for token, label in (
        (
            '"macos_service_credential_ipc_verifier": (\n'
            '                repo / "scripts/verify-macos-service-credential-ipc.py"',
            "independent focused-verifier source",
        ),
        (
            "validate_service_ipc_protocol_authority_contract(sources)",
            "independent contract dispatch",
        ),
        (
            '"struct MacosServiceOwnedCredentialReplicaReceiver {",\n'
            '            "#[derive(Clone)]\\nstruct MacosServiceOwnedCredentialReplicaReceiver {",',
            "independent typed-receiver mutation",
        ),
        (
            '"let output = std::str::from_utf8(output).ok()?;",\n'
            '            "let output = String::from_utf8_lossy(output);\\n"',
            "independent strict launchctl UTF-8 mutation",
        ),
        (
            '"R-S11fd/R-S11e-191 exact macOS launchd service-record authority",\n'
            '            "R-S11fd/R-S11e-191 depthless macOS launchd service-record authority",',
            "independent launchctl ledger mutation",
        ),
        (
            '"const MACOS_LAUNCHCTL_STDOUT_MAX_BYTES: usize = 256 * 1024;",\n'
            '            "const MACOS_LAUNCHCTL_STDOUT_MAX_BYTES: usize = usize::MAX;",',
            "independent launchctl output-limit mutation",
        ),
        (
            '"R-S11fe/R-S11e-192 bounded macOS launchd proof-child resources",\n'
            '            "R-S11fe/R-S11e-192 unbounded macOS launchd proof-child resources",',
            "independent launchctl bounded-child ledger mutation",
        ),
        (
            '"exact accepted credential snapshot return",',
            "independent retained credential snapshot validation",
        ),
        (
            '"macOS final installed generation and argv replay",',
            "independent final credential requester replay validation",
        ),
        (
            '"macOS credential endpoint, UID, PID, and full-token finality",',
            "independent credential post-request equality validation",
        ),
        (
            '"focused macOS credential final argv mutation",',
            "independent focused-verifier mutation binding",
        ),
        (
            '"shared macOS credential response finality proof",',
            "independent shared-gate mutation binding",
        ),
        (
            '"exact macOS credential requester finality identity binding",',
            "independent requirement-ledger-digest mutation binding",
        ),
        (
            '"macOS child-side runtime PRS receiver final-action authority",',
            "independent typed receiver validation",
        ),
        (
            '"focused macOS runtime PRS receiver mutation",',
            "independent focused-verifier typed receiver mutation binding",
        ),
        (
            '"shared macOS runtime PRS receiver mutation",',
            "independent shared-gate typed receiver mutation binding",
        ),
        (
            '"Apple macOS runtime PRS receiver mutation",',
            "independent Apple-gate typed receiver mutation binding",
        ),
        (
            '"macOS runtime PRS receiver requirement-ledger-digest binding",',
            "independent requirement-ledger-digest typed receiver binding",
        ),
    ):
        require(workspace, token, label)


MUTATIONS = (
    Mutation(
        "password",
        "CredentialSnapshotRequest = 3",
        "CredentialSnapshotRequest = 7",
        "snapshot wire-kind binding",
    ),
    Mutation(
        "password",
        "const CREDENTIAL_REPLICA_BYTES: usize = 44;",
        "const CREDENTIAL_REPLICA_BYTES: usize = 45;",
        "canonical replica length",
    ),
    Mutation(
        "password",
        "with_deadline(deadline, stream.write_all(&header)).await?;\n"
        "    with_deadline(deadline, stream.shutdown()).await",
        "with_deadline(deadline, stream.shutdown()).await?;\n"
        "    with_deadline(deadline, stream.write_all(&header)).await",
        "raw request header-first order",
    ),
    Mutation(
        "config",
        'cfg!(any(target_os = "linux", target_os = "macos"))',
        'cfg!(target_os = "linux")',
        "macOS root-scoped credential endpoint",
    ),
    Mutation(
        "ipc",
        "    #[cfg(target_os = \"macos\")]\n    EnsurePasswordRightReady {},",
        "    #[cfg(target_os = \"macos\")]\n"
        "    EnsurePasswordRightReady {},\n"
        "    #[cfg(target_os = \"macos\")]\n"
        "    PermanentPasswordSnapshot {},",
        "generic credential request absence",
    ),
    Mutation(
        "ipc",
        "    credential_incoming: Incoming,\n"
        "    listener_guard: LocalIpcListenerGuard,",
        "    credential_incoming: Option<Incoming>,\n"
        "    listener_guard: LocalIpcListenerGuard,",
        "mandatory macOS credential listener",
    ),
    Mutation(
        "ipc",
        "const MACOS_SERVICE_CREDENTIAL_IPC_AUTHORIZATION_BUDGET: usize = 2;",
        "const MACOS_SERVICE_CREDENTIAL_IPC_AUTHORIZATION_BUDGET: usize = usize::MAX;",
        "bounded credential proof capacity",
    ),
    Mutation(
        "ipc",
        "fn try_acquire_macos_service_credential_ipc_authorization_slot() "
        "-> Option<OwnedSemaphorePermit> {",
        "fn try_acquire_macos_service_password_ipc_authorization_slot() "
        "-> Option<OwnedSemaphorePermit> {",
        "independent credential proof capacity",
    ),
    Mutation(
        "ipc",
        "ipc_auth::service_scoped_ipc_authorization_snapshot_from_stream(\n"
        "                            &stream,\n"
        "                            password::SERVICE_CREDENTIAL_IPC_POSTFIX,",
        "ipc_auth::service_scoped_ipc_authorization_snapshot_from_stream(\n"
        "                            &stream,\n"
        "                            crate::POSTFIX_SERVICE,",
        "credential endpoint-bound admission proof",
    ),
    Mutation(
        "ipc",
        "authenticate_macos_service_owned_credential_requester(authorization, deadline).await",
        "None /* exact LaunchAgent proof bypassed */",
        "exact LaunchAgent proof before replica",
    ),
    Mutation(
        "ipc",
        'match run_bounded_macos_security_proof(deadline, "macos-credential-ipc-proof", move || {\n'
        "        let retained_authorization = authorization.clone();",
        'match run_bounded_macos_security_proof(deadline, "macos-credential-ipc-proof", move || {\n'
        "        let retained_authorization = ();",
        "retained accepted credential authorization snapshot",
    ),
    Mutation(
        "ipc",
        "stream,\n                            authorization,\n                            permit,",
        "stream,\n                            (),\n                            permit,",
        "retained credential authorization dispatch",
    ),
    Mutation(
        "auth",
        "if authorization.postfix != super::password::SERVICE_CREDENTIAL_IPC_POSTFIX {\n"
        "        bail!(\"macOS service-owned credential requester used the wrong endpoint\");",
        "if false {\n"
        "        bail!(\"macOS service-owned credential requester used the wrong endpoint\");",
        "credential requester endpoint authority",
    ),
    Mutation(
        "auth",
        "if !authorization.uid_authorized {\n"
        "        bail!(\"macOS service-owned credential requester is not root or the active console user\");",
        "if false {\n"
        "        bail!(\"macOS service-owned credential requester is not root or the active console user\");",
        "credential requester UID authority",
    ),
    Mutation(
        "ipc",
        "if !macos_service_owned_server_live_argv_is_expected(&argv) {",
        "if false {",
        "credential requester exact initial argv role",
    ),
    Mutation(
        "ipc",
        "if !macos_launch_agent_owns_service_owned_server_pid(peer_uid, peer_pid, proof_deadline) {",
        "if false && !macos_launch_agent_owns_service_owned_server_pid(peer_uid, peer_pid, proof_deadline) {",
        "exact launchd ownership proof",
    ),
    Mutation(
        "ipc",
        "macos_service_owned_credential_requester_is_live(&requester).then_some(requester)",
        "Some(requester)",
        "final credential requester replay",
    ),
    Mutation(
        "auth",
        "&& macos_service_owned_password_requester_generation_is_live(identity)",
        "&& true",
        "final credential requester installed-app generation",
    ),
    Mutation(
        "ipc",
        "&& process.cmd() == requester.argv",
        "&& true",
        "final credential requester complete argv equality",
    ),
    Mutation(
        "ipc",
        "let post_request_authorization = ipc_auth::service_scoped_ipc_authorization_snapshot(\n"
        "        &stream,\n"
        "        password::SERVICE_CREDENTIAL_IPC_POSTFIX,\n"
        "    );",
        "let post_request_authorization = authorization; /* post-request snapshot omitted */",
        "post-request credential stream snapshot",
    ),
    Mutation(
        "auth",
        "authorization.postfix != super::password::SERVICE_CREDENTIAL_IPC_POSTFIX\n"
        "        || !authorization.uid_authorized",
        "false",
        "post-request credential endpoint and UID authority",
    ),
    Mutation(
        "auth",
        "&& post_request_identity.pid == requester.pid",
        "&& true",
        "post-request credential PID equality",
    ),
    Mutation(
        "auth",
        "&& post_request_identity.audit_token == requester.audit_token",
        "&& true",
        "post-request credential full audit-token equality",
    ),
    Mutation(
        "ipc",
        'service_owned_runtime_prs_replica("macOS")',
        "SensitivePassword::new(String::new())",
        "canonical service-owned runtime PRS source",
    ),
    Mutation(
        "ipc",
        "password::send_credential_replica_unix(\n"
        "        &mut stream,\n"
        "        operation_id,\n"
        "        replica.as_sensitive_password(),\n"
        "        deadline,\n"
        "    )\n"
        "    .await\n"
        "    {\n"
        "        log::trace!(\"macOS service credential snapshot could not be returned: {err}\");",
        "stream.send_service_response_timeout(&replica, 1000).await\n"
        "    {\n"
        "        log::trace!(\"macOS service credential snapshot could not be returned: {err}\");",
        "raw credential response writer",
    ),
    Mutation(
        "auth",
        "if !macos_service_owned_password_requester_identity_is_live(&identity) {\n"
        "        bail!(\"macOS service-owned credential requester is not the live trusted installed app\");",
        "if false {\n"
        "        bail!(\"macOS service-owned credential requester is not the live trusted installed app\");",
        "installed-app code proof",
    ),
    Mutation(
        "ipc",
        "let proof_deadline = deadline.into_std();",
        "let proof_deadline = std::time::Instant::now();",
        "outer proof deadline transfer",
    ),
    Mutation(
        "ipc",
        "const MACOS_LAUNCHCTL_STDOUT_MAX_BYTES: usize = 256 * 1024;",
        "const MACOS_LAUNCHCTL_STDOUT_MAX_BYTES: usize = usize::MAX;",
        "bounded launchctl stdout ceiling",
    ),
    Mutation(
        "ipc",
        "const MACOS_LAUNCHCTL_REAP_RESERVE: std::time::Duration = "
        "std::time::Duration::from_millis(50);",
        "const MACOS_LAUNCHCTL_REAP_RESERVE: std::time::Duration = "
        "std::time::Duration::ZERO;",
        "launchctl cleanup deadline reserve",
    ),
    Mutation(
        "ipc",
        ".stdout(std::process::Stdio::piped())\n"
        "        .stderr(std::process::Stdio::null());",
        ".stdout(std::process::Stdio::piped())\n"
        "        .stderr(std::process::Stdio::piped());",
        "unused launchctl stderr discard",
    ),
    Mutation(
        "ipc",
        "flags | hbb_common::libc::O_NONBLOCK,",
        "flags,",
        "nonblocking launchctl stdout",
    ),
    Mutation(
        "ipc",
        "if count > stdout_limit.saturating_sub(captured.len()) {",
        "if false {",
        "launchctl stdout overflow rejection",
    ),
    Mutation(
        "ipc",
        "        if now >= deadline {\n"
        "            return Err(macos_bounded_child_failure(",
        "        if false {\n"
        "            return Err(macos_bounded_child_failure(",
        "launchctl child deadline enforcement",
    ),
    Mutation(
        "ipc",
        "proof_deadline.checked_sub(MACOS_LAUNCHCTL_REAP_RESERVE)",
        "Some(proof_deadline)",
        "launchctl inner cleanup deadline",
    ),
    Mutation(
        "ipc",
        "let output = match run_macos_bounded_child_stdout(\n"
        "        &mut command,\n"
        "        child_deadline,\n"
        "        MACOS_LAUNCHCTL_STDOUT_MAX_BYTES,\n"
        "    ) {",
        "let output = match command.output() {",
        "bounded launchctl child execution",
    ),
    Mutation(
        "ipc",
        "fn macos_bounded_child_stdout_terminates_on_overflow()",
        "fn macos_bounded_child_stdout_accepts_overflow()",
        "launchctl overflow behavior regression",
    ),
    Mutation(
        "ipc",
        "fn macos_bounded_child_stdout_terminates_on_deadline()",
        "fn macos_bounded_child_stdout_ignores_deadline()",
        "launchctl deadline behavior regression",
    ),
    Mutation(
        "ipc",
        "let output = std::str::from_utf8(output).ok()?;",
        "let output = String::from_utf8_lossy(output);\n"
        "    let output = output.as_ref();",
        "strict launchctl UTF-8 authority",
    ),
    Mutation(
        "ipc",
        "if lines.next()?.trim() != expected_header {",
        "if false {",
        "exact launchctl target header",
    ),
    Mutation(
        "ipc",
        "        if depth != 1 {\n            continue;\n        }",
        "        if false {\n            continue;\n        }",
        "top-level-only launchctl authority fields",
    ),
    Mutation(
        "ipc",
        "                if pid.is_some() {\n                    return None;\n                }",
        "                if false {\n                    return None;\n                }",
        "duplicate launchctl pid rejection",
    ),
    Mutation(
        "ipc",
        "                if path.is_some() {\n                    return None;\n                }",
        "                if false {\n                    return None;\n                }",
        "duplicate launchctl path rejection",
    ),
    Mutation(
        "ipc",
        "if !closed || lines.any(|line| !line.trim().is_empty()) {",
        "if false {",
        "complete launchctl record finality",
    ),
    Mutation(
        "ipc",
        '.current_dir("/")\n        .env_clear()\n        .env("LC_ALL", "C");',
        '.current_dir("/");',
        "closed launchctl query environment",
    ),
    Mutation(
        "ipc",
        "reported_identity != Some((peer_pid, expected_plist.as_str()))",
        "reported_identity.map(|identity| identity.0) != Some(peer_pid)",
        "exact launchctl pid and plist decision",
    ),
    Mutation(
        "auth",
        "(Some(uid), Some(pid), Some(audit_token)) => {\n"
        "            macos_peer_process_identity_from_socket_components(uid, pid, audit_token)\n"
        "        }",
        "(Some(uid), Some(pid), Some(audit_token)) => {\n"
        "            Some(MacosPeerProcessIdentity { uid, pid, audit_token })\n"
        "        }",
        "socket audit-token snapshot",
    ),
    Mutation(
        "auth",
        "pub(crate) struct MacosServiceServerAuthorization {",
        "#[derive(Clone)]\n"
        "pub(crate) struct MacosServiceServerAuthorization {",
        "non-cloneable privileged-helper authorization",
    ),
    Mutation(
        "auth",
        "    identity: MacosPeerProcessIdentity,\n"
        "    context: &'static str,\n"
        "}\n\n#[cfg(target_os = \"macos\")]\n"
        "pub(crate) fn macos_peer_process_identity_from_stream",
        "    pub(crate) identity: MacosPeerProcessIdentity,\n"
        "    context: &'static str,\n"
        "}\n\n#[cfg(target_os = \"macos\")]\n"
        "pub(crate) fn macos_peer_process_identity_from_stream",
        "private privileged-helper identity",
    ),
    Mutation(
        "auth",
        ") -> ResultType<MacosServiceServerAuthorization> {\n"
        "    if authorization.identity.uid != 0 {",
        ") -> ResultType<()> {\n"
        "    if authorization.identity.uid != 0 {",
        "typed privileged-helper authorization return",
    ),
    Mutation(
        "auth",
        "    Ok(authorization)\n}\n\n#[cfg(target_os = \"macos\")]\n#[inline]\n"
        "pub(crate) fn macos_service_server_authorizations_match",
        "    Ok(authorization)\n}\n\n#[cfg(target_os = \"macos\")]\n#[inline]\n"
        "pub(crate) fn macos_service_server_authorizations_differ",
        "helper continuity API identity",
    ),
    Mutation(
        "auth",
        "accepted.identity.uid == refreshed.identity.uid",
        "true",
        "helper continuity UID equality",
    ),
    Mutation(
        "auth",
        "&& accepted.identity.pid == refreshed.identity.pid",
        "&& true",
        "helper continuity PID equality",
    ),
    Mutation(
        "auth",
        "&& accepted.identity.audit_token == refreshed.identity.audit_token",
        "&& true",
        "helper continuity full audit-token equality",
    ),
    Mutation(
        "ipc",
        "struct MacosServiceOwnedCredentialReplicaReceiver {",
        "#[derive(Clone)]\nstruct MacosServiceOwnedCredentialReplicaReceiver {",
        "non-cloneable macOS credential-replica receiver",
    ),
    Mutation(
        "ipc",
        "struct MacosServiceOwnedCredentialReplicaReceiver {\n"
        "    stream: ConnClient,",
        "pub struct MacosServiceOwnedCredentialReplicaReceiver {\n"
        "    stream: ConnClient,",
        "private macOS credential-replica receiver",
    ),
    Mutation(
        "ipc",
        "    server: ipc_auth::MacosServiceServerAuthorization,\n"
        "}\n\n#[cfg(target_os = \"macos\")]\n"
        "struct MacosServiceOwnedRuntimePrsAdmission",
        "    server_authorized: bool,\n"
        "}\n\n#[cfg(target_os = \"macos\")]\n"
        "struct MacosServiceOwnedRuntimePrsAdmission",
        "receiver retains exact helper authorization",
    ),
    Mutation(
        "ipc",
        "struct MacosServiceOwnedRuntimePrsAdmission {",
        "#[derive(Clone)]\nstruct MacosServiceOwnedRuntimePrsAdmission {",
        "non-cloneable macOS runtime-PRS admission",
    ),
    Mutation(
        "ipc",
        "    _receiver: MacosServiceOwnedCredentialReplicaReceiver,",
        "    helper_authorized: bool,",
        "admission retains exact receiver authority",
    ),
    Mutation(
        "ipc",
        "    replica: ServiceOwnedRuntimePrsReplica,\n"
        "}\n\n#[cfg(any(target_os = \"linux\", target_os = \"macos\"))]",
        "    replica: SensitivePassword,\n"
        "}\n\n#[cfg(any(target_os = \"linux\", target_os = \"macos\"))]",
        "admission retains typed runtime PRS",
    ),
    Mutation(
        "ipc",
        "        if !crate::common::is_service_owned_server_process() {\n"
        "            bail!(\"macOS service credential snapshots require the exact service-owned server role\");",
        "        if false && !crate::common::is_service_owned_server_process() {\n"
        "            bail!(\"macOS service credential snapshots require the exact service-owned server role\");",
        "initial exact service-owned receiver role",
    ),
    Mutation(
        "ipc",
        "            bail!(\"macOS service credential snapshots require the exact service-owned server role\");\n"
        "        }\n"
        "        let path = Config::ipc_path_for_uid(0, password::SERVICE_CREDENTIAL_IPC_POSTFIX);",
        "            bail!(\"macOS service credential snapshots require the exact service-owned server role\");\n"
        "        }\n"
        "        let path = Config::ipc_path_for_uid(0, password::USER_PASSWORD_IPC_POSTFIX);",
        "fixed root credential-replica endpoint",
    ),
    Mutation(
        "ipc",
        "        let server =\n"
        "            authorize_macos_service_server_snapshot_for_task(authorization, deadline).await?;",
        "        let _server =\n"
        "            authorize_macos_service_server_snapshot_for_task(authorization, deadline).await?;",
        "typed initial helper proof retention",
    ),
    Mutation(
        "ipc",
        "    async fn receive_and_admit(\n"
        "        mut self,\n"
        "        deadline: tokio::time::Instant,\n"
        "    ) -> ResultType<MacosServiceOwnedRuntimePrsAdmission>",
        "    async fn receive_and_admit(\n"
        "        &mut self,\n"
        "        deadline: tokio::time::Instant,\n"
        "    ) -> ResultType<MacosServiceOwnedRuntimePrsAdmission>",
        "consuming credential-replica receiver",
    ),
    Mutation(
        "ipc",
        "        if !crate::common::is_service_owned_server_process() {\n"
        "            bail!(\"macOS service credential receiver lost the exact service-owned server role\");",
        "        if false && !crate::common::is_service_owned_server_process() {\n"
        "            bail!(\"macOS service credential receiver lost the exact service-owned server role\");",
        "final exact service-owned receiver role",
    ),
    Mutation(
        "ipc",
        "        let value =\n"
        "            password::receive_credential_replica_unix(&mut self.stream, operation_id, deadline)\n"
        "                .await?;\n"
        "        let refreshed = ipc_auth::macos_service_server_authorization_snapshot(",
        "        let value = SensitivePassword::new(String::new());\n"
        "        let refreshed = ipc_auth::macos_service_server_authorization_snapshot(",
        "operation-bound raw replica receive",
    ),
    Mutation(
        "ipc",
        "        let refreshed = ipc_auth::macos_service_server_authorization_snapshot(\n"
        "            &self.stream,\n"
        "            \"macOS service credential server\",\n"
        "        )?;",
        "        let refreshed = self.server;",
        "post-response helper socket snapshot",
    ),
    Mutation(
        "ipc",
        "        let refreshed =\n"
        "            authorize_macos_service_server_snapshot_for_task(refreshed, deadline).await?;",
        "        let refreshed = refreshed;",
        "post-response trusted-helper proof",
    ),
    Mutation(
        "ipc",
        "if !ipc_auth::macos_service_server_authorizations_match(&self.server, &refreshed) {",
        "if false {",
        "post-response exact helper continuity",
    ),
    Mutation(
        "ipc",
        "        Ok(MacosServiceOwnedRuntimePrsAdmission {\n"
        "            _receiver: self,\n"
        "            replica: ServiceOwnedRuntimePrsReplica { value },",
        "        Ok(MacosServiceOwnedRuntimePrsAdmissionDisabled {\n"
        "            _receiver: self,\n"
        "            replica: ServiceOwnedRuntimePrsReplica { value },",
        "sole typed runtime-PRS admission construction",
    ),
    Mutation(
        "ipc",
        "impl MacosServiceOwnedRuntimePrsAdmission {\n"
        "    fn install(self) -> ResultType<bool> {\n"
        "        self.replica.install_for_runtime()",
        "impl MacosServiceOwnedRuntimePrsAdmission {\n"
        "    fn install(&self) -> ResultType<bool> {\n"
        "        self.replica.install_for_runtime()",
        "consuming admitted runtime-PRS install",
    ),
    Mutation(
        "ipc",
        "impl MacosServiceOwnedRuntimePrsAdmission {\n"
        "    fn install(self) -> ResultType<bool> {\n"
        "        self.replica.install_for_runtime()",
        "impl MacosServiceOwnedRuntimePrsAdmission {\n"
        "    fn install(self) -> ResultType<bool> {\n"
        "        Config::set_permanent_password_prs_for_runtime(\n"
        "            self.replica.as_sensitive_password().as_str(),\n"
        "        )",
        "typed runtime-PRS sink ownership",
    ),
    Mutation(
        "ipc",
        "    fn install_for_runtime(self) -> ResultType<bool> {",
        "    #[cfg(target_os = \"linux\")]\n"
        "    fn install_for_runtime(self) -> ResultType<bool> {",
        "cross-Unix typed runtime-PRS sink",
    ),
    Mutation(
        "ipc",
        "    let receiver = MacosServiceOwnedCredentialReplicaReceiver::connect(deadline).await?;\n"
        "    let admission = receiver.receive_and_admit(deadline).await?;\n"
        "    admission.install()",
        "    Config::set_permanent_password_prs_for_runtime(\"\")\n"
        "        .map(|_| false)",
        "typed snapshot-client sole call graph",
    ),
    Mutation(
        "ipc",
        '            if let Err(clear_err) = Config::set_permanent_password_prs_for_runtime("") {\n'
        "                log::warn!(\n"
        '                    "Failed to clear macOS service-owned runtime PRS after snapshot refresh failure: {clear_err}"',
        '            if let Err(clear_err) = Config::set_permanent_password_storage_for_runtime("", "") {\n'
        "                log::warn!(\n"
        '                    "Failed to clear macOS service-owned runtime PRS after snapshot refresh failure: {clear_err}"',
        "nonpersistent runtime-PRS failure clear",
    ),
    Mutation(
        "verify",
        "verify-macos-service-credential-ipc.py",
        "verify-macos-service-credential-ipc-disabled.py",
        "shared focused-verifier wiring",
    ),
    Mutation(
        "apple",
        "verify-macos-service-credential-ipc.py",
        "verify-macos-service-credential-ipc-disabled.py",
        "Apple focused-verifier wiring",
    ),
    Mutation(
        "requirements",
        '<span class="id">R-S11ep</span>',
        '<span class="id">R-S11ep-disabled</span>',
        "normative raw macOS credential requirement",
    ),
    Mutation(
        "requirements",
        "<tr><td>298</td>",
        "<tr><td>298-disabled</td>",
        "Appendix C raw macOS credential disposition",
    ),
    Mutation(
        "requirements",
        '<span class="id">R-S11fd</span>',
        '<span class="id">R-S11fd-disabled</span>',
        "normative launchctl record authority requirement",
    ),
    Mutation(
        "requirements",
        "<tr><td>312</td>",
        "<tr><td>312-disabled</td>",
        "Appendix C launchctl record authority disposition",
    ),
    Mutation(
        "requirements",
        '<span class="id">R-S11fe</span>',
        '<span class="id">R-S11fe-disabled</span>',
        "normative bounded launchctl child requirement",
    ),
    Mutation(
        "requirements",
        "<tr><td>313</td>",
        "<tr><td>313-disabled</td>",
        "Appendix C bounded launchctl child disposition",
    ),
    Mutation(
        "hardening",
        "R-S11ep/R-S11e-177 macOS runtime PRS raw credential authority",
        "R-S11ep/R-S11e-177 macOS runtime PRS generic serde authority",
        "hardening ledger",
    ),
    Mutation(
        "hardening",
        "R-S11fd/R-S11e-191 exact macOS launchd service-record authority",
        "R-S11fd/R-S11e-191 depthless macOS launchd service-record authority",
        "launchctl parser hardening ledger",
    ),
    Mutation(
        "hardening",
        "R-S11fe/R-S11e-192 bounded macOS launchd proof-child resources",
        "R-S11fe/R-S11e-192 unbounded macOS launchd proof-child resources",
        "launchctl bounded-child hardening ledger",
    ),
    Mutation(
        "verify",
        'grep -Fq \'<span class="id">R-S11ia</span>\' requirements.html',
        "true # exact credential response requirement binding disabled",
        "shared exact credential response documentation binding",
    ),
    Mutation(
        "apple",
        'grep -Fq \'<span class="id">R-S11ia</span>\' "$REPO/requirements.html"',
        "true # Apple exact credential response requirement binding disabled",
        "Apple exact credential response documentation binding",
    ),
    Mutation(
        "requirements",
        '<span class="id">R-S11ia</span>',
        '<span class="id">R-S11ia-disabled</span>',
        "normative exact credential response requirement",
    ),
    Mutation(
        "requirements",
        "<tr><td>386</td>",
        "<tr><td>386-disabled</td>",
        "Appendix C exact credential response disposition",
    ),
    Mutation(
        "hardening",
        "R-S11ia/R-S11e-264 — exact macOS service-owned credential requester generation and response finality",
        "R-S11ia-disabled/R-S11e-264 — exact macOS service-owned credential requester generation and response finality",
        "exact credential response hardening ledger",
    ),
    Mutation(
        "native_watch",
        "The same identity additionally binds R-S11ia and Appendix C #386.",
        "The same identity no longer binds R-S11ia and Appendix C #386.",
        "native-watch exact credential response binding",
    ),
    Mutation(
        "verify",
        'grep -Fq \'<span class="id">R-S11ij</span>\' requirements.html',
        "true # typed macOS runtime PRS receiver requirement binding disabled",
        "shared typed runtime-PRS receiver documentation binding",
    ),
    Mutation(
        "apple",
        'grep -Fq \'<span class="id">R-S11ij</span>\' "$REPO/requirements.html"',
        "true # Apple typed macOS runtime PRS receiver requirement binding disabled",
        "Apple typed runtime-PRS receiver documentation binding",
    ),
    Mutation(
        "requirements",
        '<span class="id">R-S11ij</span>',
        '<span class="id">R-S11ij-disabled</span>',
        "normative typed macOS runtime-PRS receiver requirement",
    ),
    Mutation(
        "requirements",
        "<tr><td>395</td>",
        "<tr><td>395-disabled</td>",
        "Appendix C typed macOS runtime-PRS receiver disposition",
    ),
    Mutation(
        "requirements",
        "non-<code>Clone</code>, non-<code>Copy</code> <code>MacosServiceOwnedCredentialReplicaReceiver</code>",
        "cloneable <code>MacosServiceOwnedCredentialReplicaReceiver</code>",
        "normative non-cloneable macOS credential-replica receiver",
    ),
    Mutation(
        "requirements",
        "consume itself, freshly require the exact service-owned-server role",
        "borrow itself without rechecking the service-owned-server role",
        "normative consuming final receiver proof",
    ),
    Mutation(
        "requirements",
        "Only the admission&#39;s consuming <code>install</code> action may reach the shared Unix typed replica",
        "Any caller may reach the shared Unix typed replica",
        "normative admitted runtime-only install",
    ),
    Mutation(
        "hardening",
        "R-S11ij/R-S11e-273 — typed macOS child-side runtime PRS receiver authority",
        "R-S11ij-disabled/R-S11e-273 — typed macOS child-side runtime PRS receiver authority",
        "typed macOS runtime-PRS receiver hardening ledger",
    ),
    Mutation(
        "native_watch",
        "The same identity additionally binds R-S11ij and Appendix C #395.",
        "The same identity no longer binds R-S11ij and Appendix C #395.",
        "native-watch typed macOS runtime-PRS receiver binding",
    ),
    Mutation(
        "workspace",
        '"struct MacosServiceOwnedCredentialReplicaReceiver {",\n'
        '            "#[derive(Clone)]\\nstruct MacosServiceOwnedCredentialReplicaReceiver {",',
        '"struct MacosServiceOwnedCredentialReplicaReceiverDisabled {",\n'
        '            "#[derive(Clone)]\\nstruct MacosServiceOwnedCredentialReplicaReceiver {",',
        "independent typed-receiver mutation",
    ),
    Mutation(
        "workspace",
        '"let output = std::str::from_utf8(output).ok()?;",\n'
        '            "let output = String::from_utf8_lossy(output);\\n"',
        '"let output = String::from_utf8_lossy(output);",\n'
        '            "let output = String::from_utf8_lossy(output);\\n"',
        "independent strict launchctl UTF-8 mutation binding",
    ),
    Mutation(
        "workspace",
        '"R-S11fd/R-S11e-191 exact macOS launchd service-record authority",\n'
        '            "R-S11fd/R-S11e-191 depthless macOS launchd service-record authority",',
        '"R-S11fd/R-S11e-191 depthless macOS launchd service-record authority",\n'
        '            "R-S11fd/R-S11e-191 depthless macOS launchd service-record authority",',
        "independent launchctl ledger mutation binding",
    ),
)


def load_sources(repo: Path) -> Dict[str, str]:
    paths = {
        "ipc": "src/ipc.rs",
        "password": "src/ipc/password.rs",
        "auth": "src/ipc/auth.rs",
        "config": "libs/hbb_common/src/config.rs",
        "verify": "scripts/verify.sh",
        "apple": "scripts/apple-conform-check.sh",
        "requirements": "requirements.html",
        "hardening": "HARDENING_STATUS.md",
        "native_watch": "docs/NATIVE-CODEC-WATCH.md",
        "workspace": "scripts/verify-verifier-workspace.py",
    }
    return {
        name: (repo / relative).read_text(encoding="utf-8")
        for name, relative in paths.items()
    }


def run_mutations(sources: Dict[str, str]) -> None:
    seen = set()
    for mutation in MUTATIONS:
        if mutation.label in seen:
            raise VerificationError(
                "duplicate mutation label: {}".format(mutation.label)
            )
        seen.add(mutation.label)
        source = sources[mutation.source]
        count = source.count(mutation.old)
        if count != 1:
            raise VerificationError(
                "mutation {!r} expected one source match, got {}".format(
                    mutation.label, count
                )
            )
        mutated = dict(sources)
        mutated[mutation.source] = source.replace(
            mutation.old, mutation.new, 1
        )
        try:
            validate(mutated)
        except VerificationError:
            continue
        raise VerificationError(
            "mutation escaped verification: {}".format(mutation.label)
        )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify macOS service-owned runtime PRS raw IPC."
    )
    parser.add_argument("--repo", default=".", help="repository root")
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="run the deliberate source-mutation catalog",
    )
    args = parser.parse_args()
    sources = load_sources(Path(args.repo).resolve())
    validate(sources)
    if args.self_test:
        run_mutations(sources)
        print(
            "verify-macos-service-credential-ipc: "
            "{} deliberate mutations rejected".format(len(MUTATIONS))
        )
    else:
        print("verify-macos-service-credential-ipc: ok")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, VerificationError) as error:
        print(
            "verify-macos-service-credential-ipc: FAIL: {}".format(error),
            file=__import__("sys").stderr,
        )
        raise SystemExit(1)
