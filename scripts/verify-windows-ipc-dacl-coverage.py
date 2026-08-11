#!/usr/bin/env python3
"""Windows production-listener DACL and desktop URL-IPC verifier."""

from __future__ import annotations

import argparse
import re
from collections import Counter
from pathlib import Path
from typing import Dict, Iterable, Tuple


class VerificationError(RuntimeError):
    pass


def require(source: str, needle: str, label: str) -> None:
    if needle not in source:
        raise VerificationError(f"missing {label}")


def absent(source: str, needle: str, label: str) -> None:
    if needle in source:
        raise VerificationError(f"stale/forbidden {label}")


def region(source: str, start: str, end: str, label: str) -> str:
    begin = source.find(start)
    if begin < 0:
        raise VerificationError(f"missing {label} start")
    finish = source.find(end, begin + len(start))
    if finish < 0:
        raise VerificationError(f"missing {label} end")
    return source[begin:finish]


def require_all(source: str, needles: Iterable[Tuple[str, str]]) -> None:
    for needle, label in needles:
        require(source, needle, label)


def require_order(source: str, needles: Iterable[str], label: str) -> None:
    offset = 0
    for needle in needles:
        index = source.find(needle, offset)
        if index < 0:
            raise VerificationError(f"missing or reordered {label}: {needle}")
        offset = index + len(needle)


def load_sources(repo: Path) -> Dict[str, str]:
    paths = {
        "ipc": "src/ipc.rs",
        "auth": "src/ipc/auth.rs",
        "cm": "src/ui_cm_interface.rs",
        "whiteboard": "src/whiteboard/server.rs",
        "server": "src/server.rs",
        "windows": "src/platform/windows.rs",
        "macos": "src/platform/macos.rs",
        "model": "flutter/lib/models/model.dart",
        "consts": "flutter/lib/consts.dart",
        "requirements": "requirements.html",
        "hardening": "HARDENING_STATUS.md",
        "verify": "scripts/verify.sh",
        "apple": "scripts/apple-conform-check.sh",
    }
    sources = {
        key: (repo / relative).read_text(encoding="utf-8")
        for key, relative in paths.items()
    }
    rust_sources = {}
    for path in sorted((repo / "src").rglob("*.rs")):
        relative = path.relative_to(repo).as_posix()
        rust_sources[relative] = path.read_text(encoding="utf-8")
    sources["rust_sources"] = rust_sources  # type: ignore[assignment]
    return sources


def validate_listener_inventory(sources: Dict[str, str]) -> None:
    expected = Counter(
        {
            ("src/ipc.rs", '""'): 1,
            ("src/ipc.rs", "password::USER_PASSWORD_IPC_POSTFIX"): 1,
            ("src/ipc.rs", "postfix"): 1,
            ("src/ipc.rs", "password::SERVICE_PASSWORD_IPC_POSTFIX"): 1,
            ("src/ipc.rs", "password::SERVICE_CREDENTIAL_IPC_POSTFIX"): 1,
            ("src/ipc.rs", "WINDOWS_SERVICE_CREDENTIAL_IPC_POSTFIX"): 1,
            ("src/ipc.rs", "WINDOWS_SERVICE_MAIN_CONTROL_IPC_POSTFIX"): 1,
            ("src/ipc.rs", '"_pa"'): 1,
            ("src/platform/windows.rs", "crate::POSTFIX_SERVICE"): 2,
            (
                "src/platform/windows.rs",
                "ipc::WINDOWS_SERVICE_SAS_IPC_POSTFIX",
            ): 2,
            ("src/server.rs", '"_url"'): 1,
            ("src/ui_cm_interface.rs", '"_cm"'): 1,
            ("src/whiteboard/server.rs", "&postfix"): 1,
        }
    )
    observed: Counter[Tuple[str, str]] = Counter()
    token_occurrences = 0
    definition_occurrences = 0
    import_occurrences = 0
    rust_sources = sources["rust_sources"]  # type: ignore[assignment]
    for relative, source in rust_sources.items():
        token_occurrences += len(re.findall(r"\bnew_listener\b", source))
        definition_occurrences += len(
            re.findall(r"\bfn\s+new_listener\s*\(", source, flags=re.DOTALL)
        )
        import_occurrences += len(
            re.findall(r"\buse\b[^;]*\bnew_listener\b", source, flags=re.DOTALL)
        )
        for match in re.finditer(
            r"(?<!fn )\bnew_listener\s*\((.*?)\)", source, flags=re.DOTALL
        ):
            argument = re.sub(r"\s+", " ", match.group(1)).strip()
            observed[(relative, argument)] += 1
    expected_calls = sum(expected.values())
    if (
        definition_occurrences != 1
        or import_occurrences != 1
        or token_occurrences != expected_calls + 2
    ):
        raise VerificationError(
            "Windows IPC listener token inventory drift: "
            f"definitions={definition_occurrences}, imports={import_occurrences}, "
            f"tokens={token_occurrences}, expected_calls={expected_calls}"
        )
    if observed != expected:
        missing = expected - observed
        unexpected = observed - expected
        raise VerificationError(
            "Windows IPC listener call-site inventory drift: "
            f"missing={dict(missing)}, unexpected={dict(unexpected)}"
        )


def validate(sources: Dict[str, str]) -> None:
    validate_listener_inventory(sources)

    whiteboard_name = region(
        sources["ipc"],
        "const WHITEBOARD_ENDPOINT_NAME_CONTEXT:",
        "\n#[cfg(any(not(any(target_os = \"android\", target_os = \"ios\")), test))]\n"
        "pub(crate) fn whiteboard_ipc_postfix_is_valid(",
        "shared whiteboard endpoint-name policy",
    )
    require_all(
        whiteboard_name,
        (
            (
                'const WHITEBOARD_ENDPOINT_POSTFIX_PREFIX: &str = "_whiteboard_";',
                "shared whiteboard postfix prefix",
            ),
        ),
    )
    whiteboard_postfix = region(
        sources["ipc"],
        "pub(crate) fn whiteboard_endpoint_postfix(",
        "\n#[cfg(not(any(target_os = \"android\", target_os = \"ios\")))]\npub(crate) fn whiteboard_endpoint_postfix_from_env(",
        "whiteboard endpoint postfix construction",
    )
    require_all(
        whiteboard_postfix,
        (
            ('"{}{}"', "shared-prefix endpoint rendering"),
            (
                "WHITEBOARD_ENDPOINT_POSTFIX_PREFIX,",
                "shared whiteboard postfix prefix use",
            ),
            (
                "whiteboard_endpoint_name_suffix(launch_token)?",
                "token-derived whiteboard endpoint suffix",
            ),
        ),
    )
    absent(
        whiteboard_postfix,
        '"_whiteboard_{}"',
        "duplicated whiteboard postfix literal",
    )

    shared_classifier = region(
        sources["ipc"],
        "pub(crate) fn whiteboard_ipc_postfix_is_valid(",
        "\n#[cfg(not(any(target_os = \"android\", target_os = \"ios\")))]\n"
        "const WHITEBOARD_PROCESS_ROLE:",
        "shared whiteboard endpoint classifier",
    )
    require_all(
        shared_classifier,
        (
            (
                ".strip_prefix(WHITEBOARD_ENDPOINT_POSTFIX_PREFIX)",
                "shared whiteboard prefix validation",
            ),
            ("suffix.len() == 32", "exact whiteboard suffix length"),
            ("byte.is_ascii_digit()", "whiteboard decimal hex validation"),
            ("(b'a'..=b'f').contains(&byte)", "lowercase whiteboard hex validation"),
        ),
    )

    classifier_wrapper = region(
        sources["auth"],
        "fn windows_whiteboard_ipc_postfix_is_valid(",
        "\n#[cfg(any(windows, test))]\n#[inline]\n"
        "pub(crate) fn windows_ipc_postfix_uses_restricted_dacl(",
        "Windows whiteboard classifier wrapper",
    )
    require(
        classifier_wrapper,
        "super::whiteboard_ipc_postfix_is_valid(postfix)",
        "single shared whiteboard classifier delegation",
    )
    absent(
        classifier_wrapper,
        "strip_prefix",
        "duplicated Windows whiteboard classifier",
    )

    classifier = region(
        sources["auth"],
        "pub(crate) fn windows_ipc_postfix_uses_restricted_dacl(",
        "\n#[cfg(windows)]\npub(crate) const WINDOWS_NAMED_PIPE_CLIENT_ACCESS_MASK:",
        "Windows IPC listener-postfix policy",
    )
    require_all(
        classifier,
        (
            ("postfix.is_empty()", "main endpoint classification"),
            (
                "postfix == super::password::USER_PASSWORD_IPC_POSTFIX",
                "user-password endpoint classification",
            ),
            (
                "hbb_common::config::is_service_ipc_postfix(postfix)",
                "service endpoint classification",
            ),
            (
                "postfix == super::WINDOWS_SERVICE_CREDENTIAL_IPC_POSTFIX",
                "service-credential endpoint classification",
            ),
            (
                "postfix == super::WINDOWS_SERVICE_MAIN_CONTROL_IPC_POSTFIX",
                "service-control endpoint classification",
            ),
            (
                "postfix == super::WINDOWS_SERVICE_SAS_IPC_POSTFIX",
                "service-SAS endpoint classification",
            ),
            ("postfix == WINDOWS_URL_IPC_POSTFIX", "URL endpoint classification"),
            ('postfix == "_cm"', "connection-manager endpoint classification"),
            (
                "|| windows_whiteboard_ipc_postfix_is_valid(postfix)",
                "whiteboard endpoint classification",
            ),
        ),
    )

    attributes = region(
        sources["auth"],
        "pub(crate) fn windows_ipc_listener_security_attributes(",
        "\n#[cfg(windows)]\npub(crate) fn windows_ipc_listener_sddl(",
        "Windows listener security-attribute construction",
    )
    require_all(
        attributes,
        (
            (
                "let sddl = windows_ipc_listener_sddl(postfix)?;",
                "mandatory listener SDDL construction",
            ),
            (
                "parity_tokio_ipc::SecurityAttributes::from_sddl(&sddl)",
                "explicit listener security attributes",
            ),
        ),
    )
    absent(
        attributes,
        "SecurityAttributes::empty()",
        "default/null Windows listener security attributes",
    )

    sddl_policy = region(
        sources["auth"],
        "pub(crate) fn windows_ipc_listener_sddl(",
        "\n#[cfg(windows)]\npub(crate) fn windows_sensitive_pipe_security(",
        "Windows listener SDDL admission",
    )
    require_all(
        sddl_policy,
        (
            (
                "if !windows_ipc_postfix_uses_restricted_dacl(postfix)",
                "exhaustive postfix gate",
            ),
            (
                'bail!("Unsupported Windows IPC endpoint has no explicit DACL policy")',
                "unknown endpoint refusal",
            ),
            (
                "windows_restricted_ipc_sddl(",
                "restricted SDDL construction",
            ),
        ),
    )

    dacl = region(
        sources["auth"],
        "fn windows_restricted_ipc_sddl(",
        "\n#[cfg(windows)]\npub(crate) fn ensure_windows_ipc_server_matches_current(",
        "Windows restricted IPC DACL",
    )
    require_all(
        dacl,
        (
            (
                '"D:P(D;;0x{:08x};;;NU)(A;;0x{:08x};;;SY)"',
                "protected System-only DACL base",
            ),
            (
                "WINDOWS_NAMED_PIPE_FULL_ACCESS_MASK",
                "object-specific named-pipe full-access mask",
            ),
            (
                '"(A;;0x{:08x};;;{})"',
                "narrow active-session client ACE",
            ),
            (
                "WINDOWS_NAMED_PIPE_CLIENT_ACCESS_MASK",
                "narrow client access mask use",
            ),
        ),
    )
    require_all(
        sources["auth"],
        (
            (
                "WINDOWS_NAMED_PIPE_FULL_ACCESS_MASK: u32 = 0x001f_01ff",
                "exact object-specific named-pipe full-access mask",
            ),
        ),
    )
    for principal in (";;;WD", ";;;AN", ";;;BA"):
        absent(dacl, principal, f"ambient {principal} DACL principal")

    regression = region(
        sources["auth"],
        "fn r_s11e63_windows_ipc_postfix_uses_restricted_dacl_policy()",
        "\n    #[test]\n    #[cfg(windows)]\n    fn r_s11e63_windows_unknown_ipc_listener_has_no_default_dacl_fallback()",
        "Windows listener DACL regression",
    )
    require_all(
        regression,
        (
            (
                'windows_ipc_postfix_uses_restricted_dacl("_cm")',
                "CM DACL regression",
            ),
            (
                '"_whiteboard_0123456789abcdef0123456789abcdef"',
                "valid whiteboard postfix regression",
            ),
            (
                '"_whiteboard_0123456789abcdef0123456789abcde"',
                "short whiteboard postfix rejection",
            ),
            (
                '"_whiteboard_0123456789abcdef0123456789abcdeg"',
                "non-hex whiteboard postfix rejection",
            ),
        ),
    )
    unknown_listener_regression = region(
        sources["auth"],
        "fn r_s11e63_windows_unknown_ipc_listener_has_no_default_dacl_fallback()",
        "\n    #[test]\n    #[cfg(windows)]\n    fn windows_service_control_and_sas_dacls_are_system_only()",
        "unknown Windows listener refusal regression",
    )
    require(
        unknown_listener_regression,
        'windows_ipc_listener_security_attributes("_portable_service").is_err()',
        "unknown listener refusal regression",
    )

    require_all(
        sources["cm"],
        (
            (
                'ipc::new_listener("_cm").await',
                "connection-manager listener call site",
            ),
            (
                "ipc::authorize_cm_ipc_connection(&stream)",
                "connection-manager process-role authorization",
            ),
            (
                "ipc::answer_cm_endpoint_challenge(&mut stream).await",
                "connection-manager launch-proof authorization",
            ),
        ),
    )
    require_all(
        sources["whiteboard"],
        (
            ("new_listener(&postfix).await", "whiteboard listener call site"),
            (
                "ipc::authorize_whiteboard_ipc_connection(&stream, expected_parent_pid)",
                "whiteboard parent authorization",
            ),
            (
                "ipc::answer_whiteboard_endpoint_challenge(&mut stream).await",
                "whiteboard launch-proof authorization",
            ),
        ),
    )

    desktop_url_protocol = region(
        sources["ipc"],
        "pub(crate) enum DesktopUrlIpcRequest {",
        "\n}\n\nimpl DesktopUrlIpcRequest",
        "closed desktop URL IPC request protocol",
    )
    require(
        sources["ipc"][
            max(0, sources["ipc"].find("pub(crate) enum DesktopUrlIpcRequest {") - 100) :
            sources["ipc"].find("pub(crate) enum DesktopUrlIpcRequest {")
        ],
        '#[serde(tag = "t", deny_unknown_fields)]',
        "desktop URL IPC unknown-field denial",
    )
    require_all(
        desktop_url_protocol,
        (
            ("OpenUrl { url: String },", "typed desktop URL open operation"),
            ("Activate {},", "typed desktop activation operation"),
            ("CloseAll {},", "typed desktop close-all operation"),
        ),
    )
    if desktop_url_protocol.count("\n    ") != 3:
        raise VerificationError("desktop URL IPC protocol gained an extra operation")

    require_all(
        sources["ipc"],
        (
            (
                "pub(crate) const DESKTOP_URL_IPC_MAX_FRAME_BYTES: usize = 8 * 1024;",
                "desktop URL IPC frame cap",
            ),
            (
                "const DESKTOP_URL_IPC_MAX_LINK_BYTES: usize = 1024;",
                "desktop URL IPC link limit",
            ),
            (
                "const DESKTOP_URL_IPC_MAX_ADDRESS_BYTES: usize = 512;",
                "desktop URL IPC address limit",
            ),
            (
                "pub(crate) const DESKTOP_URL_IPC_IO_TIMEOUT_MS: u64 = 1_000;",
                "desktop URL IPC deadline",
            ),
        ),
    )

    desktop_url_validator = region(
        sources["ipc"],
        "fn validate_desktop_url_ipc_open_url(url: &str) -> ResultType<()> {",
        "\n}\n\n#[cfg(not(any(target_os = \"android\", target_os = \"ios\")))]",
        "desktop URL IPC semantic validator",
    )
    require_all(
        desktop_url_validator,
        (
            (
                "url.len() > DESKTOP_URL_IPC_MAX_LINK_BYTES",
                "desktop URL IPC link-length enforcement",
            ),
            (
                "url.strip_prefix(&prefix)",
                "desktop URL IPC exact application scheme",
            ),
            (
                "remainder.split_once('/')",
                "desktop URL IPC canonical operation/address split",
            ),
            ('"file-transfer"', "desktop URL IPC operation allow-list"),
            (
                "address.len() > DESKTOP_URL_IPC_MAX_ADDRESS_BYTES",
                "desktop URL IPC address-length enforcement",
            ),
            (
                "!hbb_common::is_ip_str(address) && !hbb_common::is_domain_port_str(address)",
                "desktop URL IPC direct-address enforcement",
            ),
        ),
    )

    data_protocol = region(
        sources["ipc"],
        "pub enum Data {",
        "\n}\n\n#[cfg(not(any(target_os = \"android\", target_os = \"ios\")))]",
        "cross-purpose IPC data protocol",
    )
    absent(data_protocol, "UrlLink", "desktop URL variant in cross-purpose Data")
    absent(sources["ipc"], "IPC_ACTION_CLOSE", "desktop URL close sentinel")
    absent(sources["consts"], "kUrlActionClose", "Dart desktop URL close sentinel")

    desktop_url_constructor = region(
        sources["ipc"],
        "pub(crate) fn new_desktop_url(conn: T) -> Self {",
        "\n    }\n\n    #[cfg(not(any(target_os = \"android\", target_os = \"ios\")))]",
        "desktop URL IPC framed constructor",
    )
    require(
        desktop_url_constructor,
        "Self::new_with_max_packet_length(conn, DESKTOP_URL_IPC_MAX_FRAME_BYTES)",
        "desktop URL IPC constructor frame cap",
    )
    if sources["ipc"].count('postfix == "_url"') != 2:
        raise VerificationError(
            "desktop URL IPC connecting-constructor platform coverage drift"
        )
    if sources["ipc"].count("ConnectionTmpl::new_desktop_url(client)") != 2:
        raise VerificationError(
            "desktop URL IPC connecting streams are not both frame-capped"
        )

    typed_transport = region(
        sources["ipc"],
        "pub(crate) async fn send_desktop_url_request_timeout(",
        "\n    #[cfg(target_os = \"windows\")]",
        "desktop URL IPC typed transport",
    )
    require_all(
        typed_transport,
        (
            (
                "request: &DesktopUrlIpcRequest",
                "typed desktop URL IPC writer parameter",
            ),
            ("self.send_json_timeout(request, ms_timeout)", "bounded typed writer"),
            (
                "ResultType<DesktopUrlIpcRequest>",
                "typed desktop URL IPC reader result",
            ),
            (
                "timeout(ms_timeout, self.next_json_strict()).await??",
                "strict deadline-bound desktop URL IPC reader",
            ),
        ),
    )

    desktop_url_sender = region(
        sources["ipc"],
        "pub async fn send_url_scheme(url: String) -> ResultType<()> {",
        "\n#[cfg(target_os = \"windows\")]\nasync fn windows_service_main_request(",
        "desktop URL IPC typed senders",
    )
    require_all(
        desktop_url_sender,
        (
            (
                "DesktopUrlIpcRequest::from_url(url)?",
                "desktop URL IPC open sender validation",
            ),
            (
                'connect(DESKTOP_URL_IPC_IO_TIMEOUT_MS, "_url")',
                "desktop URL IPC connect deadline",
            ),
            (
                "DesktopUrlIpcRequest::CloseAll {}",
                "typed desktop close-all sender",
            ),
            (
                "DesktopUrlIpcRequest::Activate {}",
                "typed desktop activation sender",
            ),
        ),
    )

    desktop_url_receiver = region(
        sources["server"],
        "pub async fn start_ipc_url_server() {",
        "\n#[cfg(test)]\nmod credential_generation_tests",
        "desktop URL IPC receiver",
    )
    require_order(
        desktop_url_receiver,
        (
            "crate::ipc::Connection::new_desktop_url(conn)",
            "crate::ipc::authorize_url_ipc_sender(&conn)",
            ".next_desktop_url_request_timeout(",
            ".and_then(crate::ipc::DesktopUrlIpcRequest::validate)",
            '"name": "on_url_scheme_received"',
            '"name": "on_desktop_instance_activate_requested"',
            '"name": "on_desktop_instances_close_requested"',
        ),
        "desktop URL IPC receiver authority and dispatch",
    )
    for needle, label in (
        ("Connection::new(conn)", "unbounded desktop URL IPC accepted constructor"),
        ("next_timeout(1000)", "legacy desktop URL IPC reader"),
        ("Data::UrlLink", "cross-purpose desktop URL IPC receiver"),
    ):
        absent(desktop_url_receiver, needle, label)

    require_all(
        sources["macos"],
        (
            (
                "crate::ipc::activate_main_instance()",
                "typed macOS desktop activation sender",
            ),
        ),
    )
    absent(
        sources["macos"],
        'handle_url_scheme("".to_owned())',
        "empty-string macOS activation sentinel",
    )

    require_order(
        sources["model"],
        (
            "name == 'on_url_scheme_received'",
            "onUrlSchemeReceived(evt);",
            "name == 'on_desktop_instance_activate_requested'",
            "onDesktopInstanceActivateRequested();",
            "name == 'on_desktop_instances_close_requested'",
            "onDesktopInstancesCloseRequested();",
        ),
        "distinct Dart desktop URL IPC event dispatch",
    )
    require_all(
        sources["model"],
        (
            (
                'debugPrint("Rejected malformed desktop URL IPC event.");',
                "malformed Dart desktop URL event rejection",
            ),
            (
                "onDesktopInstanceActivateRequested()",
                "Dart desktop activation handler",
            ),
            (
                "onDesktopInstancesCloseRequested()",
                "Dart desktop close-all handler",
            ),
        ),
    )

    for source, needle, label in (
        (
            sources["requirements"],
            '<span class="id">R-S11aw</span>',
            "R-S11aw requirement",
        ),
        (
            sources["requirements"],
            "Every production Windows IPC listener is born with an explicit local DACL",
            "R-S11aw title",
        ),
        (sources["requirements"], "<tr><td>171</td>", "Appendix C #171"),
        (
            sources["hardening"],
            "R-S11e-63 — complete Windows production-listener DACL coverage",
            "R-S11e-63 ledger",
        ),
        (
            sources["verify"],
            'echo "== (3b-iii-d9cm) Windows production-listener DACL coverage (R-S11aw/R-S11e-63) =="',
            "shared source gate",
        ),
        (
            sources["requirements"],
            '<span class="id">R-S11ea</span>',
            "R-S11ea desktop URL IPC requirement",
        ),
        (
            sources["requirements"],
            "<tr><td>280</td>",
            "Appendix C #280",
        ),
        (
            sources["hardening"],
            "R-S11ea/R-S11e-145 — desktop URL/instance handoff closed protocol and resource budget",
            "R-S11e-145 ledger",
        ),
        (
            sources["verify"],
            'echo "== (3b-iii-f4) Desktop URL/instance IPC has one closed bounded operation protocol (R-S11ea) =="',
            "desktop URL IPC shared source gate",
        ),
        (
            sources["apple"],
            'echo "== (2b-iii-c1) R-S11ea macOS desktop URL/instance closed bounded protocol =="',
            "desktop URL IPC Apple source gate",
        ),
    ):
        require(source, needle, label)


Mutation = Tuple[str, str, str, str]


MUTATIONS: Tuple[Mutation, ...] = (
    (
        "cm",
        'match ipc::new_listener("_cm").await {',
        'let _unexpected = ipc::new_listener("_future").await;\n    match ipc::new_listener("_cm").await {',
        "production listener inventory",
    ),
    ("auth", '|| postfix == "_cm"', '|| postfix == "_cm_disabled"', "CM DACL policy"),
    (
        "auth",
        "|| windows_whiteboard_ipc_postfix_is_valid(postfix)",
        "|| false && windows_whiteboard_ipc_postfix_is_valid(postfix)",
        "whiteboard DACL policy",
    ),
    (
        "auth",
        "super::whiteboard_ipc_postfix_is_valid(postfix)",
        "postfix.starts_with(\"_whiteboard_\")",
        "shared whiteboard classifier delegation",
    ),
    ("ipc", "suffix.len() == 32", "suffix.len() == 31", "whiteboard suffix length"),
    (
        "ipc",
        "(b'a'..=b'f').contains(&byte)",
        "byte.is_ascii_alphabetic()",
        "lowercase whiteboard hex alphabet",
    ),
    (
        "auth",
        "let sddl = windows_ipc_listener_sddl(postfix)?;",
        "if !windows_ipc_postfix_uses_restricted_dacl(postfix) { return Ok(parity_tokio_ipc::SecurityAttributes::empty()); }\n    let sddl = windows_ipc_listener_sddl(postfix)?;",
        "default-security fallback absence",
    ),
    (
        "auth",
        "Unsupported Windows IPC endpoint has no explicit DACL policy",
        "Unknown Windows IPC endpoint uses default policy",
        "unknown endpoint refusal",
    ),
    (
        "auth",
        '"D:P(D;;0x{:08x};;;NU)(A;;0x{:08x};;;SY)"',
        '"D:P(D;;0x{:08x};;;NU)(A;;0x{:08x};;;SY)(A;;GR;;;WD)"',
        "Everyone-free DACL",
    ),
    (
        "auth",
        "WINDOWS_NAMED_PIPE_FULL_ACCESS_MASK: u32 = 0x001f_01ff",
        "WINDOWS_NAMED_PIPE_FULL_ACCESS_MASK: u32 = 0x101f_01ff",
        "object-specific named-pipe full-access mask",
    ),
    (
        "auth",
        'windows_ipc_listener_security_attributes("_portable_service").is_err()',
        'windows_ipc_listener_security_attributes("_portable_service").is_ok()',
        "unknown endpoint regression",
    ),
    (
        "ipc",
        'const WHITEBOARD_ENDPOINT_POSTFIX_PREFIX: &str = "_whiteboard_";',
        'const WHITEBOARD_ENDPOINT_POSTFIX_PREFIX: &str = "_whiteboard2_";',
        "shared whiteboard endpoint prefix",
    ),
    (
        "cm",
        'ipc::new_listener("_cm").await',
        'ipc::new_listener("_cm_legacy").await',
        "CM production call site",
    ),
    (
        "whiteboard",
        "ipc::answer_whiteboard_endpoint_challenge(&mut stream).await",
        "ipc::answer_whiteboard_endpoint_challenge_legacy(&mut stream).await",
        "whiteboard application authentication",
    ),
    (
        "requirements",
        '<span class="id">R-S11aw</span>',
        '<span class="id">R-S11az</span>',
        "R-S11aw requirement",
    ),
    ("requirements", "<tr><td>171</td>", "<tr><td>9171</td>", "Appendix C #171"),
    (
        "hardening",
        "R-S11e-63 — complete Windows production-listener DACL coverage",
        "R-S11e-63 — default Windows helper DACLs retained",
        "R-S11e-63 ledger",
    ),
    (
        "verify",
        'echo "== (3b-iii-d9cm) Windows production-listener DACL coverage (R-S11aw/R-S11e-63) =="',
        'echo "== (3b-iii-d9cm) Windows partial-listener DACL coverage (R-S11aw/R-S11e-63) =="',
        "shared source gate",
    ),
    (
        "ipc",
        "pub(crate) const DESKTOP_URL_IPC_MAX_FRAME_BYTES: usize = 8 * 1024;",
        "pub(crate) const DESKTOP_URL_IPC_MAX_FRAME_BYTES: usize = 80 * 1024;",
        "desktop URL IPC frame cap",
    ),
    (
        "ipc",
        '#[serde(tag = "t", deny_unknown_fields)]\npub(crate) enum DesktopUrlIpcRequest {',
        '#[serde(tag = "t")]\npub(crate) enum DesktopUrlIpcRequest {',
        "desktop URL IPC unknown-field denial",
    ),
    (
        "ipc",
        "CloseAll {},\n}",
        "CloseAll {},\n    Reconfigure {},\n}",
        "closed desktop URL IPC operation vocabulary",
    ),
    (
        "ipc",
        "!hbb_common::is_ip_str(address) && !hbb_common::is_domain_port_str(address)",
        "!hbb_common::is_ip_str(address)",
        "desktop URL IPC direct-address semantics",
    ),
    (
        "ipc",
        "Self::new_with_max_packet_length(conn, DESKTOP_URL_IPC_MAX_FRAME_BYTES)",
        "Self::new(conn)",
        "desktop URL IPC accepted constructor cap",
    ),
    (
        "ipc",
        'if postfix == "_url" {\n                    ConnectionTmpl::new_desktop_url(client)',
        'if postfix == "_url" {\n                    ConnectionTmpl::new(client)',
        "desktop URL IPC Unix connecting constructor cap",
    ),
    (
        "ipc",
        "ResultType<DesktopUrlIpcRequest> {\n        Ok(timeout(ms_timeout, self.next_json_strict()).await??)",
        "ResultType<DesktopUrlIpcRequest> {\n        Ok(self.next_json_strict().await?)",
        "desktop URL IPC read deadline",
    ),
    (
        "ipc",
        "send_desktop_url_ipc_request(DesktopUrlIpcRequest::from_url(url)?).await",
        "send_desktop_url_ipc_request(DesktopUrlIpcRequest::OpenUrl { url }).await",
        "desktop URL IPC sender validation",
    ),
    (
        "server",
        "let mut conn = crate::ipc::Connection::new_desktop_url(conn);",
        "let mut conn = crate::ipc::Connection::new(conn);",
        "desktop URL IPC accepted constructor",
    ),
    (
        "server",
        ".and_then(crate::ipc::DesktopUrlIpcRequest::validate)",
        ".map(|request| request)",
        "desktop URL IPC receiver semantic revalidation",
    ),
    (
        "server",
        '"name": "on_desktop_instance_activate_requested"',
        '"name": "on_url_scheme_received"',
        "distinct desktop activation event",
    ),
    (
        "macos",
        "crate::ipc::activate_main_instance()",
        'crate::platform::handle_url_scheme("".to_owned())',
        "typed macOS desktop activation",
    ),
    (
        "model",
        "name == 'on_desktop_instances_close_requested'",
        "name == 'on_url_scheme_received'",
        "distinct Dart desktop close dispatch",
    ),
    (
        "requirements",
        '<span class="id">R-S11ea</span>',
        '<span class="id">R-S11ez</span>',
        "R-S11ea requirement",
    ),
    (
        "requirements",
        "<tr><td>280</td>",
        "<tr><td>9280</td>",
        "Appendix C #280",
    ),
    (
        "hardening",
        "R-S11ea/R-S11e-145 — desktop URL/instance handoff closed protocol and resource budget",
        "R-S11ea/R-S11e-145 — desktop URL sentinel compatibility",
        "R-S11e-145 ledger",
    ),
    (
        "verify",
        'echo "== (3b-iii-f4) Desktop URL/instance IPC has one closed bounded operation protocol (R-S11ea) =="',
        'echo "== (3b-iii-f4) Desktop URL/instance IPC retains string control compatibility (R-S11ea) =="',
        "desktop URL IPC shared source gate",
    ),
    (
        "apple",
        'echo "== (2b-iii-c1) R-S11ea macOS desktop URL/instance closed bounded protocol =="',
        'echo "== (2b-iii-c1) R-S11ea macOS desktop URL/instance string compatibility =="',
        "desktop URL IPC Apple source gate",
    ),
)


RUST_SOURCE_KEYS = {
    "ipc": "src/ipc.rs",
    "auth": "src/ipc/auth.rs",
    "cm": "src/ui_cm_interface.rs",
    "whiteboard": "src/whiteboard/server.rs",
    "server": "src/server.rs",
    "windows": "src/platform/windows.rs",
    "macos": "src/platform/macos.rs",
}


def run_mutations(sources: Dict[str, str]) -> None:
    for key, old, new, label in MUTATIONS:
        if sources[key].count(old) != 1:
            raise VerificationError(f"mutation anchor is not unique for {label}")
        mutated = dict(sources)
        mutated[key] = sources[key].replace(old, new, 1)
        if key in RUST_SOURCE_KEYS:
            rust_sources = dict(sources["rust_sources"])  # type: ignore[arg-type]
            rust_sources[RUST_SOURCE_KEYS[key]] = mutated[key]
            mutated["rust_sources"] = rust_sources  # type: ignore[assignment]
        try:
            validate(mutated)
        except VerificationError:
            continue
        raise VerificationError(f"mutation was not rejected: {label}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path("."))
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    sources = load_sources(args.repo.resolve())
    validate(sources)
    if args.self_test:
        run_mutations(sources)
    print(
        "Windows production-listener DACL semantic validation: OK"
        + (f" ({len(MUTATIONS)} mutations)" if args.self_test else "")
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
