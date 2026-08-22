#!/usr/bin/env python3
"""Verify closed directional Windows service credential/control IPC protocols."""

from __future__ import annotations

import argparse
import ast
import hashlib
import re
from pathlib import Path
from typing import Dict, Tuple


class VerificationError(RuntimeError):
    pass


def require(source: str, needle: str, label: str) -> None:
    if needle not in source:
        raise VerificationError(f"missing {label}: {needle!r}")


def forbid(source: str, needle: str, label: str) -> None:
    if needle in source:
        raise VerificationError(f"forbidden {label} remains: {needle!r}")


def require_order(source: str, needles: Tuple[str, ...], label: str) -> None:
    position = -1
    for needle in needles:
        position = source.find(needle, position + 1)
        if position < 0:
            raise VerificationError(f"{label}: missing or misordered {needle!r}")


def extract_braced(source: str, signature: str, label: str) -> str:
    start = source.find(signature)
    if start < 0:
        raise VerificationError(f"missing {label}")
    open_brace = source.find("{", start + len(signature))
    if open_brace < 0:
        raise VerificationError(f"missing body for {label}")
    depth = 0
    for offset in range(open_brace, len(source)):
        character = source[offset]
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                return source[start : offset + 1]
    raise VerificationError(f"unterminated {label}")


def enum_variants(source: str, declaration: str, label: str) -> Tuple[str, ...]:
    item = extract_braced(source, declaration, label)
    return tuple(re.findall(r"^    ([A-Z][A-Za-z0-9_]*)\b", item, re.MULTILINE))


def load_sources(repo: Path) -> Dict[str, str]:
    paths = {
        "ipc": "src/ipc.rs",
        "verify": "scripts/verify.sh",
        "apple": "scripts/apple-conform-check.sh",
        "requirements": "requirements.html",
        "hardening": "HARDENING_STATUS.md",
        "native_watch": "docs/NATIVE-CODEC-WATCH.md",
        "workspace": "scripts/verify-verifier-workspace.py",
    }
    return {
        key: (repo / relative).read_text(encoding="utf-8")
        for key, relative in paths.items()
    }


def validate(sources: Dict[str, str]) -> None:
    ipc = sources["ipc"]
    expected = (
        (
            "enum WindowsServiceCredentialRequest",
            (
                "QuiesceCredentialReplica",
                "ApplyCredentialReplica",
                "QueryCredentialReplica",
                "ResumeCredentialReplica",
            ),
            "credential request protocol",
        ),
        (
            "enum WindowsServiceCredentialResponse",
            ("State", "Rejected"),
            "credential response protocol",
        ),
        (
            "enum WindowsServiceControlRequest",
            ("PortForwardSessionCount", "Shutdown"),
            "control request protocol",
        ),
        (
            "enum WindowsServiceControlResponse",
            ("PortForwardSessionCount", "ShutdownAccepted"),
            "control response protocol",
        ),
    )
    variant_sets = []
    for declaration, variants, label in expected:
        actual = enum_variants(ipc, declaration, label)
        if actual != variants:
            raise VerificationError(
                f"{label}: expected exact variants {variants!r}, found {actual!r}"
            )
        variant_sets.append(set(actual))
        require(
            ipc,
            '#[serde(tag = "t", content = "c", deny_unknown_fields)]\n'
            + declaration,
            f"closed {label} envelope",
        )

    request_overlap = variant_sets[0] & variant_sets[2]
    response_overlap = variant_sets[1] & variant_sets[3]
    if request_overlap or response_overlap:
        raise VerificationError(
            "Windows credential/control protocols reuse directional operation tags"
        )
    for retired in (
        "WindowsServiceMainEndpoint",
        "WindowsServiceMainRequest",
        "WindowsServiceMainResponse",
        "WindowsCredentialReplicaResponse",
        "send_windows_service_main_request_timeout",
        "next_windows_service_main_request_timeout",
        "next_windows_service_main_response_timeout",
        "handle_windows_service_main_transaction",
        "try_acquire_windows_service_main_transaction_slot",
    ):
        forbid(ipc, retired, "shared Windows service-main protocol authority")
    require(
        ipc,
        "#[serde(deny_unknown_fields)]\n"
        "pub(crate) struct WindowsCredentialReplicaState",
        "closed credential state payload",
    )

    for needle, label in (
        (
            "fn try_acquire_windows_service_credential_transaction_slot()",
            "credential transaction budget owner",
        ),
        (
            "fn try_acquire_windows_service_control_transaction_slot()",
            "control transaction budget owner",
        ),
        (
            "async fn handle_windows_service_credential_transaction(",
            "credential-only receiver",
        ),
        (
            "async fn handle_windows_service_control_transaction(",
            "control-only receiver",
        ),
        (
            "async fn send_windows_service_credential_request_timeout(",
            "credential request writer",
        ),
        (
            "async fn next_windows_service_credential_request_timeout(",
            "credential request reader",
        ),
        (
            "async fn send_windows_service_credential_response_timeout(",
            "credential response writer",
        ),
        (
            "async fn next_windows_service_credential_response_timeout(",
            "credential response reader",
        ),
        (
            "async fn send_windows_service_control_request_timeout(",
            "control request writer",
        ),
        (
            "async fn next_windows_service_control_request_timeout(",
            "control request reader",
        ),
        (
            "async fn send_windows_service_control_response_timeout(",
            "control response writer",
        ),
        (
            "async fn next_windows_service_control_response_timeout(",
            "control response reader",
        ),
    ):
        require(ipc, needle, label)

    run = extract_braced(
        ipc,
        "async fn run_windows_service_main_ipc(",
        "Windows service listener owner",
    )
    require_order(
        run,
        (
            "result = control_incoming.next()",
            "try_acquire_windows_service_control_transaction_slot()",
            "handle_windows_service_control_transaction(stream, permit)",
            "result = credential_incoming.next()",
            "try_acquire_windows_service_credential_transaction_slot()",
            "handle_windows_service_credential_transaction(stream, permit)",
        ),
        "endpoint-specific listener dispatch",
    )

    credential_handler = extract_braced(
        ipc,
        "async fn handle_windows_service_credential_transaction(",
        "credential transaction receiver",
    )
    require_order(
        credential_handler,
        (
            ".next_windows_service_credential_request_timeout(",
            "authorize_windows_service_main_ipc_connection(&stream)",
            "match request",
            "WindowsServiceCredentialRequest::QuiesceCredentialReplica",
            "WindowsServiceCredentialRequest::ApplyCredentialReplica",
            "WindowsServiceCredentialRequest::QueryCredentialReplica",
            "WindowsServiceCredentialRequest::ResumeCredentialReplica",
        ),
        "credential parse, reauthorization, and dispatch",
    )
    require(
        credential_handler,
        "write_windows_service_credential_response_with_deadline(",
        "credential-only response writer",
    )
    for forbidden in (
        "WindowsServiceControlRequest",
        "WindowsServiceControlResponse",
        "next_windows_service_control_request_timeout",
        "write_windows_service_control_response_with_deadline",
        "write_response_with_deadline(",
    ):
        forbid(credential_handler, forbidden, "control vocabulary in credential receiver")

    control_handler = extract_braced(
        ipc,
        "async fn handle_windows_service_control_transaction(",
        "control transaction receiver",
    )
    require_order(
        control_handler,
        (
            ".next_windows_service_control_request_timeout(",
            "authorize_windows_service_main_ipc_connection(&stream)",
            "match request",
            "WindowsServiceControlRequest::PortForwardSessionCount",
            "WindowsServiceControlRequest::Shutdown",
        ),
        "control parse, reauthorization, and dispatch",
    )
    require(
        control_handler,
        "write_windows_service_control_response_with_deadline(",
        "control-only response writer",
    )
    for forbidden in (
        "WindowsServiceCredentialRequest",
        "WindowsServiceCredentialResponse",
        "next_windows_service_credential_request_timeout",
        "write_windows_service_credential_response_with_deadline",
        "write_response_with_deadline(",
    ):
        forbid(control_handler, forbidden, "credential vocabulary in control receiver")

    credential_client = extract_braced(
        ipc,
        "async fn windows_service_credential_request(",
        "credential endpoint client",
    )
    require_order(
        credential_client,
        (
            "WINDOWS_SERVICE_CREDENTIAL_IPC_POSTFIX",
            "ensure_windows_service_main_server_pid(&stream, expected_identity)?;",
            ".send_windows_service_credential_request_timeout(",
            ".next_windows_service_credential_response_timeout(",
        ),
        "exact-server credential exchange",
    )
    control_client = extract_braced(
        ipc,
        "async fn windows_service_control_request(",
        "control endpoint client",
    )
    require_order(
        control_client,
        (
            "WINDOWS_SERVICE_MAIN_CONTROL_IPC_POSTFIX",
            "ensure_windows_service_main_server_pid(&stream, expected_identity)?;",
            ".send_windows_service_control_request_timeout(",
            ".next_windows_service_control_response_timeout(",
        ),
        "exact-server control exchange",
    )

    regression = extract_braced(
        ipc,
        "fn windows_service_credential_and_control_channels_use_closed_directional_protocols()",
        "credential/control wire regression",
    )
    for needle, label in (
        ('br#"{\"t\":\"QuiesceCredentialReplica\"', "credential request wire"),
        ('br#"{\"t\":\"Shutdown\"}"#', "control request wire"),
        ('br#"{\"t\":\"Rejected\"}"#', "credential response wire"),
        ('br#"{\"t\":\"ShutdownAccepted\"}"#', "control response wire"),
        (
            "serde_json::from_slice::<WindowsServiceControlRequest>(&credential_request).is_err()",
            "credential-to-control rejection",
        ),
        (
            "serde_json::from_slice::<WindowsServiceCredentialRequest>(&control_request).is_err()",
            "control-to-credential rejection",
        ),
        ('"extra":true', "unknown-field rejection fixture"),
        ("state_with_unknown_field", "nested credential-state unknown-field fixture"),
        (
            "serde_json::from_value::<WindowsServiceCredentialResponse>(",
            "nested credential-state unknown-field rejection",
        ),
        ("serde_json::to_vec(&Data::Close)", "generic Data rejection fixture"),
    ):
        require(regression, needle, label)

    gate = (
        "python3 scripts/verify-windows-service-channel-protocols.py --repo . --self-test"
    )
    for key, needle, label in (
        ("verify", gate, "shared focused gate"),
        ("apple", gate, "Apple/shared focused gate"),
        (
            "requirements",
            '<div class="req"><span class="id">R-S11hg</span>',
            "normative requirement",
        ),
        ("requirements", "<tr><td>368</td>", "Appendix C row"),
        (
            "hardening",
            "### R-S11hg/R-S11e-245 — endpoint-specific Windows service credential/control protocols",
            "hardening ledger",
        ),
        (
            "workspace",
            "def validate_windows_service_channel_protocol_contract(sources):",
            "independent workspace contract",
        ),
    ):
        require(sources[key], needle, label)

    workspace_module = ast.parse(sources["workspace"])
    main_function = next(
        (
            node
            for node in workspace_module.body
            if isinstance(node, ast.FunctionDef) and node.name == "main"
        ),
        None,
    )
    if main_function is None:
        raise VerificationError("independent verifier main function is absent")
    source_maps = [
        node.value
        for node in ast.walk(main_function)
        if isinstance(node, ast.Assign)
        and isinstance(node.value, ast.Dict)
        and any(
            isinstance(target, ast.Name) and target.id == "sources"
            for target in node.targets
        )
    ]
    if len(source_maps) != 1:
        raise VerificationError("independent verifier source map is not singular")
    source_map_keys = [
        key.value
        for key in source_maps[0].keys
        if isinstance(key, ast.Constant) and isinstance(key.value, str)
    ]
    if source_map_keys.count("windows_service_channel_protocol_verifier") != 1:
        raise VerificationError("independent focused-verifier source binding is absent")

    validate_sources = next(
        (
            node
            for node in workspace_module.body
            if isinstance(node, ast.FunctionDef) and node.name == "validate_sources"
        ),
        None,
    )
    if validate_sources is None:
        raise VerificationError("independent verifier dispatch owner is absent")
    dispatches = [
        node
        for node in validate_sources.body
        if isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Name)
        and node.value.func.id == "validate_windows_service_channel_protocol_contract"
    ]
    if len(dispatches) != 1:
        raise VerificationError("independent protocol validation must dispatch exactly once")

    requirements_digest = hashlib.sha256(
        sources["requirements"].encode("utf-8")
    ).hexdigest()
    require(
        sources["hardening"],
        f"{requirements_digest}  requirements.html",
        "exact hardening requirements digest",
    )
    require(
        sources["native_watch"],
        f"Requirements hash: {requirements_digest}",
        "exact native-watch requirements digest",
    )


Mutation = Tuple[str, str, str, str]

MUTATIONS: Tuple[Mutation, ...] = (
    ("ipc", "enum WindowsServiceCredentialRequest", "enum WindowsServiceMainRequest", "credential request type identity"),
    ("ipc", "    ApplyCredentialReplica {", "    ApplyCredentialReplicaDisabled {", "credential request exact variants"),
    ("ipc", "enum WindowsServiceCredentialResponse", "enum WindowsServiceMainResponse", "credential response type identity"),
    ("ipc", "    Rejected,\n}\n\n#[cfg(any(target_os = \"windows\", test))]", "    RejectedDisabled,\n}\n\n#[cfg(any(target_os = \"windows\", test))]", "credential response exact variants"),
    ("ipc", "enum WindowsServiceControlRequest", "enum WindowsServiceEndpointControlRequest", "control request type identity"),
    ("ipc", "    PortForwardSessionCount,\n    Shutdown,\n}\n\n#[cfg(any(target_os = \"windows\", test))]", "    PortForwardSessionCount,\n    ShutdownDisabled,\n}\n\n#[cfg(any(target_os = \"windows\", test))]", "control request exact variants"),
    ("ipc", "enum WindowsServiceControlResponse", "enum WindowsServiceEndpointControlResponse", "control response type identity"),
    ("ipc", "    ShutdownAccepted,\n}", "    ShutdownAcceptedDisabled,\n}", "control response exact variants"),
    ("ipc", '#[serde(tag = "t", content = "c", deny_unknown_fields)]\nenum WindowsServiceCredentialRequest', '#[serde(tag = "t", content = "c")]\nenum WindowsServiceCredentialRequest', "closed credential request envelope"),
    ("ipc", '#[serde(tag = "t", content = "c", deny_unknown_fields)]\nenum WindowsServiceControlResponse', '#[serde(tag = "t", content = "c")]\nenum WindowsServiceControlResponse', "closed control response envelope"),
    ("ipc", "#[serde(deny_unknown_fields)]\npub(crate) struct WindowsCredentialReplicaState", "pub(crate) struct WindowsCredentialReplicaState", "closed credential state payload"),
    ("ipc", "let Some(permit) = try_acquire_windows_service_control_transaction_slot()", "let Some(permit) = try_acquire_windows_service_credential_transaction_slot()", "endpoint-specific transaction budget dispatch"),
    ("ipc", "handle_windows_service_control_transaction(stream, permit)", "handle_windows_service_credential_transaction(stream, permit)", "endpoint-specific receiver dispatch"),
    ("ipc", ".next_windows_service_credential_request_timeout(SERVICE_IPC_REQUEST_TIMEOUT_MS)", ".next_windows_service_control_request_timeout(SERVICE_IPC_REQUEST_TIMEOUT_MS)", "credential-only request parsing"),
    ("ipc", ".next_windows_service_control_request_timeout(SERVICE_IPC_REQUEST_TIMEOUT_MS)", ".next_windows_service_credential_request_timeout(SERVICE_IPC_REQUEST_TIMEOUT_MS)", "control-only request parsing"),
    ("ipc", "write_windows_service_credential_response_with_deadline(\n                &mut stream,\n                &response,\n                \"Windows credential replica quiesce\",", "write_response_with_deadline(\n                &mut stream,\n                &response,\n                \"Windows credential replica quiesce\",", "credential-only response writer"),
    ("ipc", "write_windows_service_control_response_with_deadline(\n                &mut stream,\n                &response,\n                \"Windows service-main session count\",", "write_response_with_deadline(\n                &mut stream,\n                &response,\n                \"Windows service-main session count\",", "control-only response writer"),
    ("ipc", "connect(ms_timeout, WINDOWS_SERVICE_CREDENTIAL_IPC_POSTFIX).await?", "connect(ms_timeout, WINDOWS_SERVICE_MAIN_CONTROL_IPC_POSTFIX).await?", "credential endpoint selection"),
    ("ipc", "connect(ms_timeout, WINDOWS_SERVICE_MAIN_CONTROL_IPC_POSTFIX).await?", "connect(ms_timeout, WINDOWS_SERVICE_CREDENTIAL_IPC_POSTFIX).await?", "control endpoint selection"),
    ("ipc", "let mut stream = connect(ms_timeout, WINDOWS_SERVICE_CREDENTIAL_IPC_POSTFIX).await?;\n    ensure_windows_service_main_server_pid(&stream, expected_identity)?;", "let mut stream = connect(ms_timeout, WINDOWS_SERVICE_CREDENTIAL_IPC_POSTFIX).await?;\n    let _ = expected_identity;", "exact child-generation client proof"),
    ("ipc", "fn windows_service_credential_and_control_channels_use_closed_directional_protocols()", "fn windows_service_credential_and_control_channels_share_protocols()", "credential/control wire regression"),
    ("ipc", "serde_json::from_slice::<WindowsServiceControlRequest>(&credential_request).is_err()", "serde_json::from_slice::<WindowsServiceControlRequest>(&credential_request).is_ok()", "credential-to-control rejection"),
    ("ipc", 'br#"{\"t\":\"QuiesceCredentialReplica\",\"c\":{\"transition_id\":\"transition\"},\"extra\":true}"#', 'br#"{\"t\":\"QuiesceCredentialReplica\",\"c\":{\"transition_id\":\"transition\"}}"#', "unknown-field rejection fixture"),
    ("verify", "python3 scripts/verify-windows-service-channel-protocols.py --repo . --self-test", "true # Windows service protocol gate disabled", "shared focused gate"),
    ("apple", "python3 scripts/verify-windows-service-channel-protocols.py --repo . --self-test", "true # Windows service protocol gate disabled", "Apple/shared focused gate"),
    ("requirements", '<div class="req"><span class="id">R-S11hg</span>', '<div class="req"><span class="id">R-S11hg-disabled</span>', "normative requirement"),
    ("requirements", "<tr><td>368</td>", "<tr><td>368-disabled</td>", "Appendix C row"),
    ("hardening", "### R-S11hg/R-S11e-245 — endpoint-specific Windows service credential/control protocols", "### R-S11hg-disabled/R-S11e-245 — endpoint-specific Windows service credential/control protocols", "hardening ledger"),
    ("workspace", '            "windows_service_channel_protocol_verifier": (\n                repo / "scripts/verify-windows-service-channel-protocols.py"\n            ).read_text(encoding="utf-8"),', '            "windows_service_channel_protocol_verifier_disabled": (\n                repo / "scripts/verify-windows-service-channel-protocols.py"\n            ).read_text(encoding="utf-8"),', "independent focused-verifier source binding"),
    ("workspace", "    validate_windows_service_channel_protocol_contract(sources)\n", "    validate_windows_service_channel_protocol_contract_disabled(sources)\n", "independent protocol validation dispatch"),
)


def run_mutations(sources: Dict[str, str]) -> None:
    labels = set()
    for source_name, old, new, label in MUTATIONS:
        if label in labels:
            raise VerificationError(f"duplicate mutation label: {label}")
        labels.add(label)
        source = sources[source_name]
        count = source.count(old)
        if count != 1:
            raise VerificationError(
                f"mutation {label!r} expected one source match, found {count}"
            )
        mutated = dict(sources)
        mutated[source_name] = source.replace(old, new, 1)
        try:
            validate(mutated)
        except VerificationError:
            continue
        raise VerificationError(f"mutation escaped verification: {label}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify directional Windows service credential/control protocols."
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
            "verify-windows-service-channel-protocols: "
            f"{len(MUTATIONS)} deliberate mutations rejected"
        )
    else:
        print("verify-windows-service-channel-protocols: ok")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, SyntaxError, VerificationError) as error:
        print(
            f"verify-windows-service-channel-protocols: FAIL: {error}",
            file=__import__("sys").stderr,
        )
        raise SystemExit(1)
