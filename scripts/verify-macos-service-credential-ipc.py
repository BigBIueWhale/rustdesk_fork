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
            "authorize_macos_service_scoped_credential_stream_for_task(",
            "handle_macos_service_credential_snapshot_transaction(",
        ),
        "bounded proof-before-request macOS credential admission",
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
            "macos_peer_is_service_owned_server(&stream, deadline).await",
            'service_owned_runtime_prs_replica("macOS")',
            "send_credential_replica_unix(&mut stream, operation_id, &replica, deadline)",
        ),
        "bodyless request, exact LaunchAgent proof, and secret response",
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
        "async fn macos_peer_is_service_owned_server<T>(",
        "\n}\n\n#[cfg(any(target_os = \"macos\", test))]\n"
        "fn macos_service_owned_server_live_argv_is_expected",
        "macOS exact LaunchAgent peer proof admission",
    )
    require_order(
        exact_peer,
        (
            "macos_peer_process_identity_from_stream(",
            "try_acquire_macos_service_credential_ipc_authorization_slot()",
            'run_bounded_macos_security_proof(deadline, "macos-credential-snapshot-proof"',
            "macos_peer_is_service_owned_server_blocking(identity)",
        ),
        "audit-token and exactly owned blocking peer proof admission",
    )
    forbid(
        exact_peer,
        "try_acquire_macos_service_password_ipc_authorization_slot",
        "shared password proof capacity",
    )
    blocking_peer = extract(
        ipc,
        "fn macos_peer_is_service_owned_server_blocking(",
        "\n}\n\n#[cfg(target_os = \"macos\")]\n"
        "fn macos_service_owned_server_launch_agent_label",
        "macOS exact LaunchAgent blocking peer proof",
    )
    require_order(
        blocking_peer,
        (
            "macos_peer_is_trusted_installed_app(&identity)",
            "macos_service_owned_server_live_argv_is_expected(process.cmd())",
            "macos_launch_agent_owns_service_owned_server_pid(peer_uid, peer_pid)",
            "ipc_auth::macos_peer_is_trusted_installed_app(&identity)",
        ),
        "installed-app, exact argv, exact launchd, and final code proof",
    )

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
            "!crate::common::is_service_owned_server_process()",
            "Config::ipc_path_for_uid(0, password::SERVICE_CREDENTIAL_IPC_POSTFIX)",
            "Endpoint::connect(path)",
            "macos_service_server_authorization_snapshot(",
            "authorize_macos_service_server_snapshot_for_task(authorization, deadline).await?",
            "password::remaining_millis(deadline)?",
            "hbb_common::uuid::Uuid::new_v4()",
            "send_credential_snapshot_request_unix(&mut stream, operation_id, deadline)",
            "receive_credential_replica_unix(&mut stream, operation_id, deadline)",
            "Config::set_permanent_password_prs_for_runtime(replica.as_str())?",
        ),
        "root-helper-proof-before-request and nonpersistent PRS install",
    )
    for token, label in (
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
        for token in ("R-S11ep", "R-S11e-177"):
            require(gate, token, "{} documentation binding".format(label))
    for token, label in (
        ('<span class="id">R-S11ep</span>', "R-S11ep requirement"),
        ("<tr><td>298</td>", "Appendix C #298"),
        ("raw <code>_service_credential</code>", "raw macOS endpoint contract"),
    ):
        require(requirements, token, label)
    require(
        hardening,
        "R-S11ep/R-S11e-177 macOS runtime PRS raw credential authority",
        "hardening ledger",
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
            '"    c.send_service_request_timeout(&ServiceIpcRequest::LivenessProbe {}, 1000)",\n'
            '            "raw macOS credential request writer",',
            "independent raw-client mutation",
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
        "if !macos_peer_is_service_owned_server(&stream, deadline).await",
        "if false",
        "exact LaunchAgent proof before replica",
    ),
    Mutation(
        "ipc",
        'service_owned_runtime_prs_replica("macOS")',
        "SensitivePassword::new(String::new())",
        "canonical service-owned runtime PRS source",
    ),
    Mutation(
        "ipc",
        "password::send_credential_replica_unix(&mut stream, operation_id, &replica, deadline).await\n"
        "    {\n"
        "        log::trace!(\"macOS service credential snapshot could not be returned: {err}\");",
        "stream.send_service_response_timeout(&replica, 1000).await\n"
        "    {\n"
        "        log::trace!(\"macOS service credential snapshot could not be returned: {err}\");",
        "raw credential response writer",
    ),
    Mutation(
        "ipc",
        "ipc_auth::macos_peer_process_identity_from_stream(",
        "stream.macos_peer_process_identity(",
        "raw-stream audit-token peer snapshot",
    ),
    Mutation(
        "ipc",
        "if !ipc_auth::macos_peer_is_trusted_installed_app(&identity) {",
        "if false {",
        "installed-app code proof",
    ),
    Mutation(
        "ipc",
        "macos_launch_agent_owns_service_owned_server_pid(peer_uid, peer_pid)\n"
        "        && ipc_auth::macos_peer_is_trusted_installed_app(&identity)",
        "true",
        "exact launchd ownership proof",
    ),
    Mutation(
        "auth",
        "audit_token: peer_audit_token_from_fd(fd)\n"
        "            .ok_or_else(|| anyhow::anyhow!(\"Failed to resolve {description} audit token\"))?,",
        "audit_token: [0; 8],",
        "socket audit-token snapshot",
    ),
    Mutation(
        "ipc",
        "authorize_macos_service_server_snapshot_for_task(authorization, deadline).await?;\n"
        "    password::remaining_millis(deadline)?;\n"
        "    let operation_id = hbb_common::uuid::Uuid::new_v4();\n"
        "    password::send_credential_snapshot_request_unix(&mut stream, operation_id, deadline)",
        "authorize_macos_service_server_snapshot_for_task(authorization, deadline).await?;\n"
        "    password::remaining_millis(deadline)?;\n"
        "    let operation_id = hbb_common::uuid::Uuid::new_v4();\n"
        "    c.send_service_request_timeout(&ServiceIpcRequest::LivenessProbe {}, 1000)",
        "macOS raw credential client request writer",
    ),
    Mutation(
        "ipc",
        "authorize_macos_service_server_snapshot_for_task(authorization, deadline).await?;\n"
        "    password::remaining_millis(deadline)?;\n"
        "    let operation_id = hbb_common::uuid::Uuid::new_v4();",
        "let _ = authorization;\n"
        "    password::remaining_millis(deadline)?;\n"
        "    let operation_id = hbb_common::uuid::Uuid::new_v4();",
        "client-side root-helper proof",
    ),
    Mutation(
        "ipc",
        "Config::set_permanent_password_prs_for_runtime(replica.as_str())?;\n"
        "    Ok(!replica.as_str().is_empty())\n"
        "}\n\n#[cfg(target_os = \"linux\")]",
        "Config::set_permanent_password_storage_for_runtime(replica.as_str(), \"\")?;\n"
        "    Ok(!replica.as_str().is_empty())\n"
        "}\n\n#[cfg(target_os = \"linux\")]",
        "nonpersistent PRS-only installation",
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
        "hardening",
        "R-S11ep/R-S11e-177 macOS runtime PRS raw credential authority",
        "R-S11ep/R-S11e-177 macOS runtime PRS generic serde authority",
        "hardening ledger",
    ),
    Mutation(
        "workspace",
        '"    c.send_service_request_timeout(&ServiceIpcRequest::LivenessProbe {}, 1000)",\n'
        '            "raw macOS credential request writer",',
        '"    c.send_service_request_timeout(&ServiceIpcRequest::LivenessProbe {}, 1000)",\n'
        '            "generic macOS credential request writer",',
        "independent raw-client mutation binding",
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
