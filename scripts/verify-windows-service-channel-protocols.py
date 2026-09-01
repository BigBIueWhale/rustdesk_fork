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
        "auth": "src/ipc/auth.rs",
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
    auth = sources["auth"]
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

    share_rdp_handler = extract_braced(
        ipc,
        "pub(crate) async fn handle_windows_service_owned_share_rdp_request(",
        "Windows service-owned RDP policy receiver",
    )
    require_order(
        share_rdp_handler,
        (
            "authorize_windows_service_owned_share_rdp_requester(stream)",
            "requester.commit_share_rdp_change(stream, enable)",
            "ServiceIpcResponse::ShareRdpSet { accepted }",
        ),
        "retained exact requester capability before the RDP policy result",
    )
    forbid(
        share_rdp_handler,
        "crate::platform::windows::set_service_owned_share_rdp(enable)",
        "RDP policy mutation outside the retained requester capability",
    )
    for retired in (
        "windows_peer_is_authorized_for_service_owned_share_rdp_change",
        "windows_peer_is_authorized_for_service_owned_request",
    ):
        forbid(ipc, retired, "token-only Windows service policy authorization")
    forbid(
        auth,
        "windows_pipe_client_token_is_elevated",
        "detached Boolean Windows pipe-elevation authority",
    )

    pipe_token_proof = extract_braced(
        auth,
        "fn windows_pipe_client_token_proof(",
        "Windows named-pipe client token proof",
    )
    require(
        pipe_token_proof,
        "windows_live_token_proof(token)",
        "complete named-pipe token identity proof",
    )

    share_rdp_authority = extract_braced(
        auth,
        "pub(crate) fn authorize_windows_service_owned_share_rdp_requester(",
        "Windows service-owned RDP policy requester authority",
    )
    require(
        share_rdp_authority,
        ") -> Option<WindowsServiceOwnedShareRdpRequester>",
        "authority-bearing Windows RDP-policy requester result",
    )
    require_order(
        share_rdp_authority,
        (
            "let Some(peer_pid) = stream.peer_pid()",
            "WindowsPeerProcess::open(peer_pid)",
            "stream.windows_pipe_client_token_proof()",
            "process.live_token_proof()",
            "if pipe_token != process_token",
            "if !pipe_token.authority.is_elevated",
            "process.fresh_identity()",
            "ensure_windows_identity_matches_current(&identity, crate::POSTFIX_SERVICE)",
            "windows_identity_is_service_owned_share_rdp_client(&identity)",
            'process.require_running("Windows service-owned RDP policy requester")',
            "if stream.peer_pid() != Some(peer_pid)",
            "Some(WindowsServiceOwnedShareRdpRequester",
            "process,",
            "identity,",
            "token: pipe_token,",
        ),
        "elevated exact-role retained requester admission",
    )
    require(
        share_rdp_authority,
        "let identity = match process.fresh_identity() {",
        "fresh identity inspection through the retained requester generation",
    )
    forbid(
        share_rdp_authority,
        "-> bool",
        "detached Boolean Windows RDP-policy requester result",
    )

    share_rdp_requester = extract_braced(
        auth,
        "pub(crate) struct WindowsServiceOwnedShareRdpRequester",
        "Windows service-owned RDP policy requester capability",
    )
    require_order(
        share_rdp_requester,
        (
            "process: WindowsPeerProcess",
            "identity: WindowsProcessImmutableIdentity",
            "token: WindowsLiveTokenProof",
        ),
        "retained Windows RDP-policy requester capability state",
    )

    share_rdp_commit = extract_braced(
        auth,
        "pub(crate) fn commit_share_rdp_change(",
        "Windows service-owned RDP policy capability commit",
    )
    require_order(
        share_rdp_commit,
        (
            "let peer_pid = stream.peer_pid().ok_or_else",
            "if peer_pid != self.process.key.pid",
            'require_running("Windows service-owned RDP policy requester before commit")',
            "windows_process_creation_time(self.process.handle.0)?",
            "self.process.key.creation_time",
            "self.process.fresh_identity()?",
            "if identity != self.identity",
            "ensure_windows_identity_matches_current(&identity, crate::POSTFIX_SERVICE)?",
            "if !windows_identity_is_service_owned_share_rdp_client(&identity)",
            "stream.windows_pipe_client_token_proof()?",
            "self.process.live_token_proof()?",
            "if pipe_token != self.token || process_token != self.token",
            "if !pipe_token.authority.is_elevated",
            "if stream.peer_pid() != Some(peer_pid)",
            'require_running("Windows service-owned RDP policy requester at commit")',
            "crate::platform::windows::set_service_owned_share_rdp(enable)",
        ),
        "final retained Windows RDP-policy requester proof and mutation",
    )
    require(
        share_rdp_commit,
        "if windows_process_creation_time(self.process.handle.0)? != self.process.key.creation_time {",
        "final retained requester creation-time equality",
    )
    if not share_rdp_commit.rstrip().endswith(
        "crate::platform::windows::set_service_owned_share_rdp(enable)\n    }"
    ):
        raise VerificationError(
            "Windows service-owned RDP policy writer is not the capability commit's final action"
        )
    share_rdp_role = extract_braced(
        auth,
        "fn windows_identity_is_service_owned_share_rdp_client(",
        "Windows service-owned RDP policy requester role",
    )
    require(
        share_rdp_role,
        "windows_identity_has_exact_role(identity, &[])",
        "exact no-argument interactive UI role",
    )
    share_rdp_regression = extract_braced(
        auth,
        "fn windows_service_owned_share_rdp_client_role_is_exact_interactive_ui()",
        "Windows service-owned RDP policy role regression",
    )
    for needle, label in (
        ("windows_identity_for_test(1, 10, &[])", "interactive UI admission"),
        ('&["--server"][..]', "server-role refusal"),
        ('&["--service"][..]', "service-role refusal"),
        ('&["--tray"][..]', "tray-role refusal"),
        ('&["--cm"][..]', "CM-role refusal"),
        ('&["--password"][..]', "password-role refusal"),
        ('&["--unexpected"][..]', "arbitrary-role refusal"),
    ):
        require(share_rdp_regression, needle, label)
    require(
        ipc,
        "#[serde(deny_unknown_fields)]\n"
        "pub(crate) struct WindowsCredentialReplicaState",
        "closed credential state payload",
    )

    service_main_requester = extract_braced(
        auth,
        "struct WindowsServiceMainRequester",
        "retained Windows service-main requester capability",
    )
    require_order(
        service_main_requester,
        (
            "process: WindowsPeerProcess",
            "identity: WindowsProcessImmutableIdentity",
            "token: WindowsLiveTokenProof",
        ),
        "retained Windows service-main requester state",
    )
    for declaration, label in (
        (
            "pub(crate) struct WindowsServiceCredentialRequester",
            "credential requester capability",
        ),
        (
            "pub(crate) struct WindowsServiceControlRequester",
            "control requester capability",
        ),
    ):
        capability = extract_braced(auth, declaration, label)
        require(
            capability,
            "requester: WindowsServiceMainRequester",
            f"exact retained state in {label}",
        )
    shutdown_requester = extract_braced(
        auth,
        "pub(crate) struct WindowsServiceShutdownRequester",
        "prepared shutdown requester capability",
    )
    require(
        shutdown_requester,
        "requester: WindowsServiceControlRequester",
        "control requester retained across shutdown acknowledgement",
    )

    service_main_auth = extract_braced(
        auth,
        "fn authenticate_windows_service_main_requester(",
        "Windows service-main requester authentication",
    )
    require(
        service_main_auth,
        ") -> Option<WindowsServiceMainRequester>",
        "authority-bearing Windows service-main authentication result",
    )
    require_order(
        service_main_auth,
        (
            "let Some(peer_pid) = stream.peer_pid()",
            "WindowsPeerProcess::open(peer_pid)",
            "stream.windows_pipe_client_token_proof()",
            "process.live_token_proof()",
            "if pipe_token != process_token",
            "if !pipe_token.authority.is_local_system",
            "process.fresh_identity()",
            "WINDOWS_SERVICE_SUPERVISOR_PID_ENV",
            "WINDOWS_SERVICE_SUPERVISOR_CREATION_ENV",
            "if identity.key != expected_parent",
            "ensure_windows_identity_matches_fixed_service(",
            'windows_identity_has_exact_role(&identity, &["--service"])',
            'process.require_running("Windows service-main requester")',
            "if stream.peer_pid() != Some(peer_pid)",
            "Some(WindowsServiceMainRequester",
            "process,",
            "identity,",
            "token: pipe_token,",
        ),
        "retained exact LocalSystem supervisor admission",
    )
    require(
        service_main_auth,
        "let identity = match process.fresh_identity() {",
        "fresh service-main requester identity",
    )
    require(
        service_main_auth,
        'if !windows_identity_has_exact_role(&identity, &["--service"]) {',
        "exact service-main requester role",
    )
    forbid(
        service_main_auth,
        "immutable_identity()",
        "cached service-main requester identity",
    )
    forbid(
        service_main_auth,
        "-> bool",
        "detached Boolean Windows service-main requester authority",
    )

    for signature, result, construction, label in (
        (
            "pub(crate) fn authorize_windows_service_credential_requester(",
            ") -> Option<WindowsServiceCredentialRequester>",
            "WindowsServiceCredentialRequester { requester }",
            "credential requester wrapper",
        ),
        (
            "pub(crate) fn authorize_windows_service_control_requester(",
            ") -> Option<WindowsServiceControlRequester>",
            "WindowsServiceControlRequester { requester }",
            "control requester wrapper",
        ),
    ):
        wrapper = extract_braced(auth, signature, label)
        require_order(
            wrapper,
            (
                result,
                "authenticate_windows_service_main_requester(stream)",
                construction,
            ),
            f"exact {label}",
        )

    service_main_revalidation = extract_braced(
        auth,
        "fn revalidate(&self, stream: &Connection, context: &str)",
        "Windows service-main final requester revalidation",
    )
    require_order(
        service_main_revalidation,
        (
            "let peer_pid = stream",
            ".peer_pid()",
            "if peer_pid != self.process.key.pid",
            "self.process.require_running(context)?",
            "windows_process_creation_time(self.process.handle.0)?",
            "self.process.key.creation_time",
            "self.process.fresh_identity()?",
            "if identity != self.identity",
            "ensure_windows_identity_matches_fixed_service(",
            'windows_identity_has_exact_role(&identity, &["--service"])',
            "stream.windows_pipe_client_token_proof()?",
            "self.process.live_token_proof()?",
            "if pipe_token != self.token || process_token != self.token",
            "if !pipe_token.authority.is_local_system",
            "if stream.peer_pid() != Some(peer_pid)",
            "self.process.require_running(context)",
        ),
        "fresh exact LocalSystem supervisor proof immediately before action",
    )
    require(
        service_main_revalidation,
        "if windows_process_creation_time(self.process.handle.0)? != self.process.key.creation_time {",
        "retained service-main process-generation equality",
    )
    require(
        service_main_revalidation,
        'if !windows_identity_has_exact_role(&identity, &["--service"]) {',
        "final exact service-main requester role",
    )

    for method, action, label in (
        (
            "pub(crate) fn quiesce_replica(",
            "crate::server::quiesce_windows_credential_replica(transition_id)",
            "credential quiesce capability",
        ),
        (
            "pub(crate) fn apply_replica(",
            "crate::server::apply_windows_credential_replica(transition_id, storage, salt, replica_tag)",
            "credential apply capability",
        ),
        (
            "pub(crate) fn query_replica(",
            "Ok(crate::server::query_windows_credential_replica())",
            "credential query capability",
        ),
        (
            "pub(crate) fn resume_replica(",
            "crate::server::resume_windows_credential_replica(transition_id)",
            "credential resume capability",
        ),
    ):
        capability_method = extract_braced(auth, method, label)
        require_order(
            capability_method,
            ("self.requester", ".revalidate(", action),
            f"final revalidation and action in {label}",
        )
        if not capability_method.rstrip().endswith(action + "\n    }"):
            raise VerificationError(f"{label} action is not the method's final expression")

    count_sessions = extract_braced(
        auth,
        "pub(crate) fn count_port_forward_sessions(",
        "service session-count capability",
    )
    require_order(
        count_sessions,
        (
            "self.requester",
            ".revalidate(",
            "Ok(crate::server::AUTHED_CONNS",
            "crate::server::AuthConnType::PortForward",
            ".count())",
        ),
        "final revalidation and action in service session-count capability",
    )
    if not count_sessions.rstrip().endswith(".count())\n    }"):
        raise VerificationError(
            "service session-count action is not the capability method's final expression"
        )

    prepare_shutdown = extract_braced(
        auth,
        "pub(crate) fn prepare_shutdown(",
        "prepared Windows service shutdown authority",
    )
    require_order(
        prepare_shutdown,
        (
            "self.requester.revalidate(",
            '"Windows service shutdown requester before acknowledgement"',
            "Ok(WindowsServiceShutdownRequester { requester: self })",
        ),
        "shutdown authority retained after pre-acknowledgement revalidation",
    )
    shutdown_commit = extract_braced(
        auth,
        "pub(crate) fn commit(self, stream: &Connection)",
        "Windows service shutdown capability commit",
    )
    require_order(
        shutdown_commit,
        (
            "self.requester",
            ".requester",
            ".revalidate(",
            '"Windows service shutdown requester at commit"',
            "crate::server::request_graceful_shutdown();",
            "Ok(())",
        ),
        "post-acknowledgement shutdown revalidation and commit",
    )
    for retired in (
        "authorize_windows_service_main_ipc_connection",
        "windows_pipe_client_token_is_local_system",
        "WindowsPipeClientTokenRequirement",
    ):
        forbid(auth + ipc, retired, "detached Windows service-main authority")

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
            "authorize_windows_service_control_requester(&stream)",
            "try_acquire_windows_service_control_transaction_slot()",
            "handle_windows_service_control_transaction(stream, requester, permit)",
            "result = credential_incoming.next()",
            "authorize_windows_service_credential_requester(&stream)",
            "try_acquire_windows_service_credential_transaction_slot()",
            "handle_windows_service_credential_transaction(stream, requester, permit)",
        ),
        "endpoint-specific retained-requester listener dispatch",
    )

    credential_handler = extract_braced(
        ipc,
        "async fn handle_windows_service_credential_transaction(",
        "credential transaction receiver",
    )
    require_order(
        credential_handler,
        (
            "requester: WindowsServiceCredentialRequester",
            ".next_windows_service_credential_request_timeout(",
            "match request",
            "WindowsServiceCredentialRequest::QuiesceCredentialReplica",
            "requester.quiesce_replica(&stream, &transition_id)",
            "WindowsServiceCredentialRequest::ApplyCredentialReplica",
            "requester.apply_replica(",
            "WindowsServiceCredentialRequest::QueryCredentialReplica",
            "requester.query_replica(&stream)",
            "WindowsServiceCredentialRequest::ResumeCredentialReplica",
            "requester.resume_replica(&stream, &transition_id)",
        ),
        "credential parse and exact retained-capability dispatch",
    )
    require(
        credential_handler,
        "write_windows_service_credential_response_with_deadline(",
        "credential-only response writer",
    )
    for forbidden in (
        "crate::server::quiesce_windows_credential_replica",
        "crate::server::apply_windows_credential_replica",
        "crate::server::query_windows_credential_replica",
        "crate::server::resume_windows_credential_replica",
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
            "requester: WindowsServiceControlRequester",
            ".next_windows_service_control_request_timeout(",
            "match request",
            "WindowsServiceControlRequest::PortForwardSessionCount",
            "requester.count_port_forward_sessions(&stream)",
            "WindowsServiceControlRequest::Shutdown",
            "requester.prepare_shutdown(&stream)",
            "WindowsServiceControlResponse::ShutdownAccepted",
            '"Windows service-main shutdown acknowledgement"',
            "requester.commit(&stream)",
        ),
        "control parse, exact retained-capability dispatch, and acknowledgement-before-latch",
    )
    require(
        control_handler,
        "write_windows_service_control_response_with_deadline(",
        "control-only response writer",
    )
    for forbidden in (
        "crate::server::AUTHED_CONNS",
        "crate::server::request_graceful_shutdown()",
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
        (
            "requirements",
            '<div class="req"><span class="id">R-S11hw</span>',
            "exact Windows service RDP-policy requester requirement",
        ),
        ("requirements", "<tr><td>368</td>", "Appendix C row"),
        ("requirements", "<tr><td>382</td>", "exact requester Appendix C row"),
        (
            "hardening",
            "### R-S11hg/R-S11e-245 — endpoint-specific Windows service credential/control protocols",
            "hardening ledger",
        ),
        (
            "hardening",
            "### R-S11hw/R-S11e-260 — exact Windows service-owned RDP-policy requester role",
            "exact requester hardening ledger",
        ),
        (
            "requirements",
            '<div class="req"><span class="id">R-S11ib</span>',
            "retained Windows RDP-policy capability requirement",
        ),
        (
            "requirements",
            "<tr><td>387</td>",
            "retained Windows RDP-policy capability Appendix C row",
        ),
        (
            "hardening",
            "### R-S11ib/R-S11e-265 — retained Windows RDP-policy requester through final mutation",
            "retained Windows RDP-policy capability hardening ledger",
        ),
        (
            "native_watch",
            "The same identity additionally binds R-S11ib and Appendix C #387.",
            "retained Windows RDP-policy capability identity binding",
        ),
        (
            "requirements",
            '<div class="req"><span class="id">R-S11ic</span>',
            "retained Windows service-main requester requirement",
        ),
        (
            "requirements",
            "<tr><td>388</td>",
            "retained Windows service-main requester Appendix C row",
        ),
        (
            "hardening",
            "### R-S11ic/R-S11e-266 — retained Windows service-main supervisor authority through exact actions",
            "retained Windows service-main requester hardening ledger",
        ),
        (
            "native_watch",
            "The same identity additionally binds R-S11ic and Appendix C #388.",
            "retained Windows service-main requester identity binding",
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
    ("ipc", "requester.commit_share_rdp_change(stream, enable)", "crate::platform::windows::set_service_owned_share_rdp(enable)", "retained requester capability before RDP policy mutation"),
    ("auth", "let _token_guard = WindowsHandle(token);\n            windows_live_token_proof(token)\n        })\n    }\n\n    fn windows_pipe_client_authority", "let _token_guard = WindowsHandle(token);\n            windows_token_authority(token)\n        })\n    }\n\n    fn windows_pipe_client_authority", "complete named-pipe token identity proof"),
    ("auth", "fn windows_pipe_client_authority(&self)", "fn windows_pipe_client_token_is_elevated(&self)", "detached Boolean pipe-elevation helper absence"),
    ("auth", ") -> Option<WindowsServiceOwnedShareRdpRequester> {", ") -> bool {", "authority-bearing requester result"),
    ("auth", "pub(crate) struct WindowsServiceOwnedShareRdpRequester", "struct DetachedWindowsServiceOwnedShareRdpRequester", "action-specific requester capability"),
    ("auth", "pub(crate) struct WindowsServiceOwnedShareRdpRequester {\n    process: WindowsPeerProcess,\n    identity: WindowsProcessImmutableIdentity,\n    token: WindowsLiveTokenProof,\n}", "pub(crate) struct WindowsServiceOwnedShareRdpRequester {\n    identity: WindowsProcessImmutableIdentity,\n    token: WindowsLiveTokenProof,\n}", "retained requester process handle"),
    ("auth", "pub(crate) struct WindowsServiceOwnedShareRdpRequester {\n    process: WindowsPeerProcess,\n    identity: WindowsProcessImmutableIdentity,\n    token: WindowsLiveTokenProof,\n}", "pub(crate) struct WindowsServiceOwnedShareRdpRequester {\n    process: WindowsPeerProcess,\n    token: WindowsLiveTokenProof,\n}", "retained requester identity"),
    ("auth", "pub(crate) struct WindowsServiceOwnedShareRdpRequester {\n    process: WindowsPeerProcess,\n    identity: WindowsProcessImmutableIdentity,\n    token: WindowsLiveTokenProof,\n}", "pub(crate) struct WindowsServiceOwnedShareRdpRequester {\n    process: WindowsPeerProcess,\n    identity: WindowsProcessImmutableIdentity,\n}", "retained requester token"),
    ("auth", "let pipe_token = match stream.windows_pipe_client_token_proof() {\n        Ok(proof) => proof,\n        Err(err) => {\n            log::warn!(\n                \"Rejected Windows service-owned RDP policy requester token", "let pipe_token = match process.live_token_proof() {\n        Ok(proof) => proof,\n        Err(err) => {\n            log::warn!(\n                \"Rejected Windows service-owned RDP policy requester token", "named-pipe requester token proof"),
    ("auth", "let process_token = match process.live_token_proof() {\n        Ok(proof) => proof,\n        Err(err) => {\n            log::warn!(\n                \"Rejected Windows service-owned RDP policy requester process token", "let process_token = match stream.windows_pipe_client_token_proof() {\n        Ok(proof) => proof,\n        Err(err) => {\n            log::warn!(\n                \"Rejected Windows service-owned RDP policy requester process token", "same-generation process token proof"),
    ("auth", "if pipe_token != process_token {\n        log::warn!(\n            \"Rejected Windows service-owned RDP policy requester whose pipe and process token identities differ", "if pipe_token == process_token {\n        log::warn!(\n            \"Rejected Windows service-owned RDP policy requester whose pipe and process token identities differ", "pipe/process token identity equality"),
    ("auth", "if !pipe_token.authority.is_elevated {\n        log::warn!(", "if pipe_token.authority.is_elevated {\n        log::warn!(", "receiver-observed elevation proof"),
    ("auth", "let identity = match process.fresh_identity() {\n        Ok(identity) => identity,\n        Err(err) => {\n            log::warn!(\n                \"Rejected Windows service-owned RDP policy requester identity", "let identity = match process.immutable_identity() {\n        Ok(identity) => identity.as_ref().clone(),\n        Err(err) => {\n            log::warn!(\n                \"Rejected Windows service-owned RDP policy requester identity", "fresh admitted requester identity"),
    ("auth", "if let Err(err) = ensure_windows_identity_matches_current(&identity, crate::POSTFIX_SERVICE) {", "if let Err(err) = Ok(()) {", "current executable requester proof"),
    ("auth", "windows_identity_has_exact_role(identity, &[])", "windows_identity_has_exact_role(identity, &[\"--server\"])", "exact interactive UI role"),
    ("auth", "process.require_running(\"Windows service-owned RDP policy requester\")", "Ok(())", "live requester generation at admission"),
    ("auth", "if stream.peer_pid() != Some(peer_pid) {\n        log::warn!(\n            \"Rejected Windows service-owned RDP policy requester after named-pipe peer pid changed", "if stream.peer_pid() == Some(peer_pid) {\n        log::warn!(\n            \"Rejected Windows service-owned RDP policy requester after named-pipe peer pid changed", "stable named-pipe requester pid"),
    ("auth", "Some(WindowsServiceOwnedShareRdpRequester {\n        process,\n        identity,\n        token: pipe_token,\n    })", "None", "retained requester construction"),
    ("auth", "if peer_pid != self.process.key.pid {\n            bail!(\n                \"Windows service-owned RDP policy requester changed before commit", "if peer_pid == self.process.key.pid {\n            bail!(\n                \"Windows service-owned RDP policy requester changed before commit", "final requester pid equality"),
    ("auth", "self.process\n            .require_running(\"Windows service-owned RDP policy requester before commit\")?;", "", "final requester pre-commit liveness"),
    ("auth", "if windows_process_creation_time(self.process.handle.0)? != self.process.key.creation_time {\n            bail!(\"Windows service-owned RDP policy requester generation changed before commit\");", "if windows_process_creation_time(self.process.handle.0)? == self.process.key.creation_time {\n            bail!(\"Windows service-owned RDP policy requester generation changed before commit\");", "final requester generation equality"),
    ("auth", "let identity = self.process.fresh_identity()?;\n        if identity != self.identity {\n            bail!(\"Windows service-owned RDP policy requester identity changed before commit\");", "let identity = self.identity.clone();\n        if identity != self.identity {\n            bail!(\"Windows service-owned RDP policy requester identity changed before commit\");", "final fresh requester identity"),
    ("auth", "if identity != self.identity {\n            bail!(\"Windows service-owned RDP policy requester identity changed before commit\");", "if identity == self.identity {\n            bail!(\"Windows service-owned RDP policy requester identity changed before commit\");", "final requester identity equality"),
    ("auth", "ensure_windows_identity_matches_current(&identity, crate::POSTFIX_SERVICE)?;", "", "final current executable requester proof"),
    ("auth", "if !windows_identity_is_service_owned_share_rdp_client(&identity) {\n            bail!(\"Windows service-owned RDP policy requester role changed before commit\");", "if windows_identity_is_service_owned_share_rdp_client(&identity) {\n            bail!(\"Windows service-owned RDP policy requester role changed before commit\");", "final exact requester role"),
    ("auth", "let pipe_token = stream.windows_pipe_client_token_proof()?;\n        let process_token = self.process.live_token_proof()?;\n        if pipe_token != self.token || process_token != self.token {\n            bail!(\"Windows service-owned RDP policy requester token changed before commit\");", "let pipe_token = self.token.clone();\n        let process_token = self.process.live_token_proof()?;\n        if pipe_token != self.token || process_token != self.token {\n            bail!(\"Windows service-owned RDP policy requester token changed before commit\");", "final named-pipe token proof"),
    ("auth", "let process_token = self.process.live_token_proof()?;\n        if pipe_token != self.token || process_token != self.token {\n            bail!(\"Windows service-owned RDP policy requester token changed before commit\");", "let process_token = self.token.clone();\n        if pipe_token != self.token || process_token != self.token {\n            bail!(\"Windows service-owned RDP policy requester token changed before commit\");", "final process token proof"),
    ("auth", "if pipe_token != self.token || process_token != self.token {\n            bail!(\"Windows service-owned RDP policy requester token changed before commit\");", "if pipe_token == self.token || process_token == self.token {\n            bail!(\"Windows service-owned RDP policy requester token changed before commit\");", "final accepted-token equality"),
    ("auth", "if !pipe_token.authority.is_elevated {\n            bail!(\"Windows service-owned RDP policy requester is no longer elevated\");", "if pipe_token.authority.is_elevated {\n            bail!(\"Windows service-owned RDP policy requester is no longer elevated\");", "final requester elevation"),
    ("auth", "if stream.peer_pid() != Some(peer_pid) {\n            bail!(\"Windows service-owned RDP policy requester pipe changed before commit\");", "if stream.peer_pid() == Some(peer_pid) {\n            bail!(\"Windows service-owned RDP policy requester pipe changed before commit\");", "final stable pipe requester"),
    ("auth", "self.process\n            .require_running(\"Windows service-owned RDP policy requester at commit\")?;", "", "retained requester liveness at mutation"),
    ("auth", "crate::platform::windows::set_service_owned_share_rdp(enable)\n    }", "Ok(())\n    }", "policy writer inside retained capability"),
    ("auth", "fn windows_service_owned_share_rdp_client_role_is_exact_interactive_ui()", "fn windows_service_owned_share_rdp_client_role_is_broad()", "exact requester role regression"),
    ("ipc", "let Some(requester) = authorize_windows_service_control_requester(&stream) else {", "let Some(requester) = authorize_windows_service_credential_requester(&stream) else {", "endpoint-specific control requester admission"),
    ("ipc", "let Some(requester) = authorize_windows_service_credential_requester(&stream) else {", "let Some(requester) = authorize_windows_service_control_requester(&stream) else {", "endpoint-specific credential requester admission"),
    ("ipc", "handle_windows_service_control_transaction(stream, requester, permit)", "handle_windows_service_control_transaction(stream, permit)", "retained control requester transaction dispatch"),
    ("ipc", "handle_windows_service_credential_transaction(stream, requester, permit)", "handle_windows_service_credential_transaction(stream, permit)", "retained credential requester transaction dispatch"),
    ("ipc", "    requester: WindowsServiceCredentialRequester,\n    _permit: OwnedSemaphorePermit,", "    _permit: OwnedSemaphorePermit,", "credential requester retained across request read"),
    ("ipc", "    requester: WindowsServiceControlRequester,\n    _permit: OwnedSemaphorePermit,", "    _permit: OwnedSemaphorePermit,", "control requester retained across request read"),
    ("ipc", "requester.quiesce_replica(&stream, &transition_id)", "crate::server::quiesce_windows_credential_replica(&transition_id)", "capability-owned credential quiesce"),
    ("ipc", "requester.apply_replica(&stream, &transition_id, &storage, &salt, replica_tag)", "crate::server::apply_windows_credential_replica(&transition_id, &storage, &salt, replica_tag)", "capability-owned credential apply"),
    ("ipc", "requester.query_replica(&stream)", "Ok(crate::server::query_windows_credential_replica())", "capability-owned credential query"),
    ("ipc", "requester.resume_replica(&stream, &transition_id)", "crate::server::resume_windows_credential_replica(&transition_id)", "capability-owned credential resume"),
    ("ipc", "requester.count_port_forward_sessions(&stream)", "Ok(crate::server::AUTHED_CONNS.lock().unwrap().len())", "capability-owned service session count"),
    ("ipc", "let requester = match requester.prepare_shutdown(&stream) {", "let requester = match Ok(requester) {", "prepared shutdown authority before acknowledgement"),
    ("ipc", "if let Err(err) = requester.commit(&stream) {", "if let Err(err) = { crate::server::request_graceful_shutdown(); Ok::<(), hbb_common::anyhow::Error>(()) } {", "capability-owned shutdown commit"),
    ("auth", "struct WindowsServiceMainRequester {", "struct DetachedWindowsServiceMainRequester {", "retained common service-main requester capability"),
    ("auth", "struct WindowsServiceMainRequester {\n    process: WindowsPeerProcess,\n    identity: WindowsProcessImmutableIdentity,\n    token: WindowsLiveTokenProof,\n}", "struct WindowsServiceMainRequester {\n    identity: WindowsProcessImmutableIdentity,\n    token: WindowsLiveTokenProof,\n}", "retained service-main requester process handle"),
    ("auth", "struct WindowsServiceMainRequester {\n    process: WindowsPeerProcess,\n    identity: WindowsProcessImmutableIdentity,\n    token: WindowsLiveTokenProof,\n}", "struct WindowsServiceMainRequester {\n    process: WindowsPeerProcess,\n    token: WindowsLiveTokenProof,\n}", "retained service-main requester identity"),
    ("auth", "struct WindowsServiceMainRequester {\n    process: WindowsPeerProcess,\n    identity: WindowsProcessImmutableIdentity,\n    token: WindowsLiveTokenProof,\n}", "struct WindowsServiceMainRequester {\n    process: WindowsPeerProcess,\n    identity: WindowsProcessImmutableIdentity,\n}", "retained service-main requester token"),
    ("auth", "pub(crate) struct WindowsServiceCredentialRequester {\n    requester: WindowsServiceMainRequester,\n}", "pub(crate) struct WindowsServiceCredentialRequester {\n    requester: WindowsServiceControlRequester,\n}", "endpoint-specific credential requester capability"),
    ("auth", "pub(crate) struct WindowsServiceControlRequester {\n    requester: WindowsServiceMainRequester,\n}", "pub(crate) struct WindowsServiceControlRequester {\n    requester: WindowsServiceCredentialRequester,\n}", "endpoint-specific control requester capability"),
    ("auth", "pub(crate) struct WindowsServiceShutdownRequester {\n    requester: WindowsServiceControlRequester,\n}", "pub(crate) struct WindowsServiceShutdownRequester {\n    requester: WindowsServiceCredentialRequester,\n}", "prepared shutdown retains control authority"),
    ("auth", ") -> Option<WindowsServiceMainRequester> {", ") -> bool {", "authority-bearing service-main requester result"),
    ("auth", "let process = match WindowsPeerProcess::open(peer_pid) {\n        Ok(process) => process,\n        Err(err) => {\n            log::warn!(\"Rejected Windows service-main requester process", "let process = match WindowsPeerProcess::open(peer_pid.saturating_add(1)) {\n        Ok(process) => process,\n        Err(err) => {\n            log::warn!(\"Rejected Windows service-main requester process", "opened service-main requester process"),
    ("auth", "let pipe_token = match stream.windows_pipe_client_token_proof() {\n        Ok(proof) => proof,\n        Err(err) => {\n            log::warn!(\"Rejected Windows service-main requester pipe token", "let pipe_token = match process.live_token_proof() {\n        Ok(proof) => proof,\n        Err(err) => {\n            log::warn!(\"Rejected Windows service-main requester pipe token", "service-main named-pipe token proof"),
    ("auth", "let process_token = match process.live_token_proof() {\n        Ok(proof) => proof,\n        Err(err) => {\n            log::warn!(\"Rejected Windows service-main requester process token", "let process_token = match stream.windows_pipe_client_token_proof() {\n        Ok(proof) => proof,\n        Err(err) => {\n            log::warn!(\"Rejected Windows service-main requester process token", "service-main retained-process token proof"),
    ("auth", "if pipe_token != process_token {\n        log::warn!(\"Rejected Windows service-main requester whose pipe and process token identities differ\");", "if pipe_token == process_token {\n        log::warn!(\"Rejected Windows service-main requester whose pipe and process token identities differ\");", "service-main pipe/process token equality"),
    ("auth", "if !pipe_token.authority.is_local_system {\n        log::warn!(\"Rejected non-LocalSystem Windows service-main requester\");", "if pipe_token.authority.is_local_system {\n        log::warn!(\"Rejected non-LocalSystem Windows service-main requester\");", "service-main LocalSystem authority"),
    ("auth", "let identity = match process.fresh_identity() {\n        Ok(identity) => identity,\n        Err(err) => {\n            log::warn!(\"Rejected Windows service-main requester identity", "let identity = match process.immutable_identity() {\n        Ok(identity) => identity.as_ref().clone(),\n        Err(err) => {\n            log::warn!(\"Rejected Windows service-main requester identity", "fresh service-main requester identity"),
    ("auth", "if identity.key != expected_parent {\n        log::warn!(\n            \"Rejected Windows service-main requester identity", "if identity.key == expected_parent {\n        log::warn!(\n            \"Rejected Windows service-main requester identity", "launch-bound supervisor generation equality"),
    ("auth", "if let Err(err) = ensure_windows_identity_matches_fixed_service(\n        &identity,\n        super::WINDOWS_SERVICE_CREDENTIAL_IPC_POSTFIX,\n    ) {\n        log::warn!(\"Rejected Windows service-main requester executable", "if let Err(err) = Ok(()) {\n        log::warn!(\"Rejected Windows service-main requester executable", "fixed service-main requester image"),
    ("auth", "if !windows_identity_has_exact_role(&identity, &[\"--service\"]) {\n        log::warn!(\"Rejected Windows service-main requester with the wrong process role\");", "if windows_identity_has_exact_role(&identity, &[\"--service\"]) {\n        log::warn!(\"Rejected Windows service-main requester with the wrong process role\");", "exact service-main requester role"),
    ("auth", "if let Err(err) = process.require_running(\"Windows service-main requester\") {", "if let Err(err) = Ok(()) {", "live service-main requester at admission"),
    ("auth", "if stream.peer_pid() != Some(peer_pid) {\n        log::warn!(\"Rejected Windows service-main requester after named-pipe peer pid changed\");", "if stream.peer_pid() == Some(peer_pid) {\n        log::warn!(\"Rejected Windows service-main requester after named-pipe peer pid changed\");", "stable service-main pipe pid at admission"),
    ("auth", "Some(WindowsServiceMainRequester {\n        process,\n        identity,\n        token: pipe_token,\n    })", "None", "retained service-main requester construction"),
    ("auth", "WindowsServiceCredentialRequester { requester }", "WindowsServiceCredentialRequester { requester: unreachable!() }", "credential requester wrapper construction"),
    ("auth", "WindowsServiceControlRequester { requester }", "WindowsServiceControlRequester { requester: unreachable!() }", "control requester wrapper construction"),
    ("auth", "if peer_pid != self.process.key.pid {\n            bail!(\n                \"{context} process changed before action", "if peer_pid == self.process.key.pid {\n            bail!(\n                \"{context} process changed before action", "final service-main requester pid equality"),
    ("auth", "self.process.require_running(context)?;\n        if windows_process_creation_time(self.process.handle.0)?", "if windows_process_creation_time(self.process.handle.0)?", "final service-main pre-action liveness"),
    ("auth", "if windows_process_creation_time(self.process.handle.0)? != self.process.key.creation_time {\n            bail!(\"{context} process generation changed before action\");", "if windows_process_creation_time(self.process.handle.0)? == self.process.key.creation_time {\n            bail!(\"{context} process generation changed before action\");", "final service-main generation equality"),
    ("auth", "let identity = self.process.fresh_identity()?;\n        if identity != self.identity {\n            bail!(\"{context} process identity changed before action\");", "let identity = self.identity.clone();\n        if identity != self.identity {\n            bail!(\"{context} process identity changed before action\");", "final fresh service-main identity"),
    ("auth", "if identity != self.identity {\n            bail!(\"{context} process identity changed before action\");", "if identity == self.identity {\n            bail!(\"{context} process identity changed before action\");", "final service-main identity equality"),
    ("auth", "ensure_windows_identity_matches_fixed_service(\n            &identity,\n            super::WINDOWS_SERVICE_CREDENTIAL_IPC_POSTFIX,\n        )?;", "Ok::<(), hbb_common::anyhow::Error>(())?;", "final fixed service-main image"),
    ("auth", "if !windows_identity_has_exact_role(&identity, &[\"--service\"]) {\n            bail!(\"{context} process role changed before action\");", "if windows_identity_has_exact_role(&identity, &[\"--service\"]) {\n            bail!(\"{context} process role changed before action\");", "final exact service-main role"),
    ("auth", "let pipe_token = stream.windows_pipe_client_token_proof()?;\n        let process_token = self.process.live_token_proof()?;\n        if pipe_token != self.token || process_token != self.token {\n            bail!(\"{context} token changed before action\");", "let pipe_token = self.token.clone();\n        let process_token = self.token.clone();\n        if pipe_token != self.token || process_token != self.token {\n            bail!(\"{context} token changed before action\");", "final service-main pipe/process token proofs"),
    ("auth", "if pipe_token != self.token || process_token != self.token {\n            bail!(\"{context} token changed before action\");", "if pipe_token == self.token || process_token == self.token {\n            bail!(\"{context} token changed before action\");", "final accepted service-main token equality"),
    ("auth", "if !pipe_token.authority.is_local_system {\n            bail!(\"{context} is no longer LocalSystem\");", "if pipe_token.authority.is_local_system {\n            bail!(\"{context} is no longer LocalSystem\");", "final service-main LocalSystem authority"),
    ("auth", "if stream.peer_pid() != Some(peer_pid) {\n            bail!(\"{context} named-pipe process changed at action\");", "if stream.peer_pid() == Some(peer_pid) {\n            bail!(\"{context} named-pipe process changed at action\");", "final stable service-main pipe pid"),
    ("auth", "self.process.require_running(context)\n    }\n}", "Ok(())\n    }\n}", "final service-main requester liveness at action"),
    ("auth", "crate::server::quiesce_windows_credential_replica(transition_id)\n    }", "bail!(\"disabled\")\n    }", "credential quiesce final action"),
    ("auth", "crate::server::apply_windows_credential_replica(transition_id, storage, salt, replica_tag)\n    }", "bail!(\"disabled\")\n    }", "credential apply final action"),
    ("auth", "Ok(crate::server::query_windows_credential_replica())\n    }", "bail!(\"disabled\")\n    }", "credential query final action"),
    ("auth", "crate::server::resume_windows_credential_replica(transition_id)\n    }", "bail!(\"disabled\")\n    }", "credential resume final action"),
    ("auth", "Ok(crate::server::AUTHED_CONNS\n            .lock()", "Ok(0usize /* detached */)\n            /* .lock()", "service session-count final action"),
    ("auth", "self.requester.revalidate(\n            stream,\n            \"Windows service shutdown requester before acknowledgement\",\n        )?;", "", "shutdown revalidation before acknowledgement"),
    ("auth", "Ok(WindowsServiceShutdownRequester { requester: self })", "bail!(\"detached shutdown requester\")", "prepared shutdown requester construction"),
    ("auth", "self.requester\n            .requester\n            .revalidate(stream, \"Windows service shutdown requester at commit\")?;", "", "shutdown revalidation after acknowledgement"),
    ("auth", "crate::server::request_graceful_shutdown();\n        Ok(())", "Ok(())", "shutdown latch inside retained capability"),
    ("auth", "fn windows_pipe_client_authority(&self)", "fn windows_pipe_client_token_is_local_system(&self)", "detached LocalSystem token helper absence"),
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
    ("ipc", "handle_windows_service_control_transaction(stream, requester, permit)", "handle_windows_service_credential_transaction(stream, requester, permit)", "endpoint-specific receiver dispatch"),
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
    ("requirements", '<div class="req"><span class="id">R-S11hw</span>', '<div class="req"><span class="id">R-S11hw-disabled</span>', "exact requester normative requirement"),
    ("requirements", '<div class="req"><span class="id">R-S11ib</span>', '<div class="req"><span class="id">R-S11ib-disabled</span>', "retained requester normative requirement"),
    ("requirements", "<tr><td>368</td>", "<tr><td>368-disabled</td>", "Appendix C row"),
    ("requirements", "<tr><td>382</td>", "<tr><td>382-disabled</td>", "exact requester Appendix C row"),
    ("requirements", "<tr><td>387</td>", "<tr><td>387-disabled</td>", "retained requester Appendix C row"),
    ("hardening", "### R-S11hg/R-S11e-245 — endpoint-specific Windows service credential/control protocols", "### R-S11hg-disabled/R-S11e-245 — endpoint-specific Windows service credential/control protocols", "hardening ledger"),
    ("hardening", "### R-S11hw/R-S11e-260 — exact Windows service-owned RDP-policy requester role", "### R-S11hw-disabled/R-S11e-260 — exact Windows service-owned RDP-policy requester role", "exact requester hardening ledger"),
    ("hardening", "### R-S11ib/R-S11e-265 — retained Windows RDP-policy requester through final mutation", "### R-S11ib-disabled/R-S11e-265 — retained Windows RDP-policy requester through final mutation", "retained requester hardening ledger"),
    ("native_watch", "The same identity additionally binds R-S11ib and Appendix C #387.", "The same identity no longer binds R-S11ib and Appendix C #387.", "retained requester digest binding"),
    ("requirements", '<div class="req"><span class="id">R-S11ic</span>', '<div class="req"><span class="id">R-S11ic-disabled</span>', "retained service-main requester normative requirement"),
    ("requirements", "<tr><td>388</td>", "<tr><td>388-disabled</td>", "retained service-main requester Appendix C row"),
    ("hardening", "### R-S11ic/R-S11e-266 — retained Windows service-main supervisor authority through exact actions", "### R-S11ic-disabled/R-S11e-266 — retained Windows service-main supervisor authority through exact actions", "retained service-main requester hardening ledger"),
    ("native_watch", "The same identity additionally binds R-S11ic and Appendix C #388.", "The same identity no longer binds R-S11ic and Appendix C #388.", "retained service-main requester digest binding"),
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
