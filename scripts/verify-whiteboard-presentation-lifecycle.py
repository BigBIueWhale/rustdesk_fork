#!/usr/bin/env python3
"""Verify exact-owner whiteboard presentation lifecycle and idle redraw behavior."""

from __future__ import annotations

import argparse
import ast
import hashlib
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


def extract_braced_item(source: str, signature: str, label: str) -> str:
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
    raise VerificationError(f"unterminated body for {label}")


def load_sources(repo: Path) -> Dict[str, str]:
    paths = {
        "ipc": "src/ipc.rs",
        "connection": "src/server/connection.rs",
        "input": "src/server/input_service.rs",
        "client": "src/whiteboard/client.rs",
        "server": "src/whiteboard/server.rs",
        "windows": "src/whiteboard/windows.rs",
        "macos": "src/whiteboard/macos.rs",
        "linux": "src/whiteboard/linux.rs",
        "requirements": "requirements.html",
        "hardening": "HARDENING_STATUS.md",
        "native_watch": "docs/NATIVE-CODEC-WATCH.md",
        "verify": "scripts/verify.sh",
        "apple": "scripts/apple-conform-check.sh",
        "workspace": "scripts/verify-verifier-workspace.py",
    }
    return {
        key: (repo / relative).read_text(encoding="utf-8")
        for key, relative in paths.items()
    }


def validate(sources: Dict[str, str]) -> None:
    ipc = sources["ipc"]
    client = sources["client"]
    server = sources["server"]
    connection = sources["connection"]
    platforms = {
        "Windows": sources["windows"],
        "macOS": sources["macos"],
        "Linux": sources["linux"],
    }

    command = extract_braced_item(
        ipc, "pub(crate) enum WhiteboardIpcCommand", "whiteboard command protocol"
    )
    require_order(
        command,
        (
            "Bind",
            "Cursor",
            "cursor: crate::whiteboard::Cursor",
            "Close",
            "Shutdown",
        ),
        "closed cursor-only whiteboard command vocabulary",
    )
    for forbidden, label in (
        ("Event {", "generic whiteboard event command"),
        ("event:", "generic whiteboard event payload"),
        ("CustomEvent", "helper-internal lifecycle event on the wire"),
    ):
        forbid(command, forbidden, label)
    require(
        ipc,
        'br#"{\"t\":\"Event\",\"conn_id\":7,\"token\":\"token\",\"event\":{\"t\":\"Clear\"}}"#',
        "generic event/clear wire rejection regression",
    )

    option = extract_braced_item(
        connection,
        "if let Ok(q) = o.show_my_cursor.enum_value()",
        "whiteboard option transition",
    )
    require_order(
        option,
        (
            "if q == BoolOption::Yes",
            "crate::whiteboard::is_supported()",
            "if not_support_msg.is_empty()",
            "if self.is_authed_remote_conn()",
            "self.show_my_cursor = true;",
            "whiteboard::register_whiteboard(self.inner.id);",
            "self.show_my_cursor = false;",
            "whiteboard::unregister_whiteboard(self.inner.id);",
            "self.show_my_cursor = false;",
            "whiteboard::unregister_whiteboard(self.inner.id);",
            "self.send(msg_out).await;",
            "self.show_my_cursor = false;",
            "whiteboard::unregister_whiteboard(self.inner.id);",
        ),
        "enable-only support probe and exact disable/non-Remote/unsupported retirement",
    )
    if option.count("whiteboard::register_whiteboard(self.inner.id);") != 1:
        raise VerificationError("whiteboard option must have exactly one registration edge")
    if option.count("whiteboard::unregister_whiteboard(self.inner.id);") != 3:
        raise VerificationError(
            "whiteboard option must retire non-Remote, unsupported, and disabled demand"
        )
    forbid(
        option,
        "if not_support_msg.is_empty() {\n                        whiteboard::unregister_whiteboard",
        "support-dependent disable retirement",
    )

    update = extract_braced_item(
        client,
        "pub fn update_whiteboard_cursor(conn_id: i32, cursor: Cursor)",
        "typed cursor publication API",
    )
    require_order(
        update,
        (
            "let mut commands = [None, None];",
            "conn.last_cursor_evt.cursor",
            "whiteboard_cursor_command(conn, conn_id, cursor)",
            "commands.into_iter().flatten().enumerate()",
            "state.send_command(command)",
        ),
        "fixed two-slot typed cursor publication",
    )
    require(
        client,
        "TrySendError::Full(WhiteboardIpcCommand::Cursor { .. })",
        "cursor-only lossy overflow",
    )
    require(
        client,
        "WhiteboardCommandAdmission::CursorDropped",
        "typed cursor drop diagnostic",
    )
    require(
        client,
        "let mut pending: [Option<(i32, String, Cursor)>;",
        "fixed pending cursor flush storage",
    )
    for forbidden, label in (
        ("CustomEvent", "helper-internal event in the client producer"),
        ("get_key_cursor", "formatted whiteboard presentation key"),
        ("WhiteboardIpcCommand::Event", "generic client event command"),
        ("let mut pending = Vec::new()", "periodic pending-cursor heap vector"),
    ):
        forbid(client, forbidden, label)
    input_source = sources["input"]
    if input_source.count("whiteboard::update_whiteboard_cursor(") != 2:
        raise VerificationError("both cursor producers must use the typed cursor API")
    forbid(input_source, "whiteboard::update_whiteboard(", "generic cursor event API")

    require(
        server,
        "WhiteboardEventLifecycle<EventLoopProxy<(i32, CustomEvent)>>",
        "numeric event-loop owner identity",
    )
    require(
        server,
        "proxy.send_event((0, CustomEvent::Exit))",
        "reserved terminal event owner",
    )
    if server.count("proxy.send_event((0, CustomEvent::Exit))") != 2:
        raise VerificationError(
            "both terminal event paths must use the reserved numeric owner"
        )
    action = extract_braced_item(
        server, "enum WhiteboardIpcAction", "typed helper action"
    )
    require_order(
        action,
        ("Cursor(i32, Cursor)", "Clear(i32)", "Shutdown"),
        "typed numeric helper action vocabulary",
    )
    authority = extract_braced_item(
        server, "impl WhiteboardIpcState", "whiteboard connection authority"
    )
    require_order(
        authority,
        (
            "WhiteboardIpcCommand::Bind",
            "WhiteboardIpcCommand::Cursor",
            "Some(WhiteboardIpcAction::Cursor(conn_id, cursor))",
            "WhiteboardIpcCommand::Close",
            "self.active.remove(&conn_id);",
            "Some(WhiteboardIpcAction::Clear(conn_id))",
            "WhiteboardIpcCommand::Shutdown",
        ),
        "cursor update and close-owned clear derivation",
    )
    handler = extract_braced_item(
        server, "async fn handle_new_stream(", "whiteboard helper stream owner"
    )
    require_order(
        handler,
        (
            "WhiteboardIpcAction::Cursor(conn_id, cursor)",
            "CustomEvent::Cursor(cursor)",
            "WhiteboardIpcAction::Clear(conn_id)",
            "CustomEvent::Clear",
            "WhiteboardIpcAction::Shutdown",
        ),
        "internal lifecycle event derivation after command authority",
    )
    for forbidden, label in (
        ("get_key_cursor", "formatted presentation identity"),
        ("WhiteboardIpcCommand::Event", "generic helper event command"),
        ("EventLoopProxy<(String, CustomEvent)>", "string event-loop identity"),
    ):
        forbid(server, forbidden, label)

    presentation_owner = extract_braced_item(
        server,
        "pub(super) struct WhiteboardPresentationState<C, R>",
        "shared presentation owner storage",
    )
    require_order(
        presentation_owner,
        ("cursors: HashMap<i32, C>", "ripples: HashMap<i32, VecDeque<R>>"),
        "numeric per-owner cursor/ripple storage",
    )
    presentation = extract_braced_item(
        server,
        "impl<C, R> WhiteboardPresentationState<C, R>",
        "shared presentation owner",
    )
    require_order(
        presentation,
        (
            "if conn_id <= 0",
            "self.cursors.len() >= ipc::WHITEBOARD_IPC_MAX_ACTIVE_CONNECTIONS",
            "self.ripples.entry(conn_id).or_default()",
            "ripples.len() == WHITEBOARD_PRESENTATION_MAX_RIPPLES_PER_OWNER",
            "ripples.pop_front();",
            "ripples.push_back(ripple);",
            "self.cursors.insert(conn_id, cursor);",
            "self.cursors.remove(&conn_id);",
            "self.ripples.remove(&conn_id);",
            "self.cursors.get(&conn_id)",
            "ripples.retain(|ripple| keep(ripple));",
            "self.ripples.retain(|_, ripples| !ripples.is_empty());",
        ),
        "bounded exact-owner cursor/ripple state and final clear",
    )
    require(
        server,
        "pub(super) const WHITEBOARD_PRESENTATION_MAX_RIPPLES_PER_OWNER: usize = 64;",
        "per-owner ripple ceiling",
    )
    require(
        server,
        "pub(super) const RIPPLE_FRAME_INTERVAL: Duration = Duration::from_millis(16);",
        "bounded ripple frame deadline",
    )
    for test in (
        "r_s11hp_whiteboard_presentation_clear_is_exact_owner_final",
        "r_s11hp_whiteboard_presentation_owners_and_ripples_are_bounded",
    ):
        require(server, test, f"{test} regression")

    for platform_name, platform in platforms.items():
        require(
            platform,
            "WhiteboardPresentationState",
            f"{platform_name} shared presentation owner",
        )
        require(
            platform,
            "CustomEvent::Clear",
            f"{platform_name} exact clear handling",
        )
        require(
            platform,
            "presentation.clear(conn_id);",
            f"{platform_name} owner resource retirement",
        )
        require(
            platform,
            "ControlFlow::WaitUntil",
            f"{platform_name} active-ripple frame deadline",
        )
        require(
            platform,
            "ControlFlow::Wait",
            f"{platform_name} idle event-loop wait",
        )
        require(
            platform,
            "RIPPLE_FRAME_INTERVAL",
            f"{platform_name} shared frame interval",
        )
        for forbidden, label in (
            ("ControlFlow::Poll", "continuous idle polling"),
            ("last_cursors", "parallel cursor map"),
            ("get_key_cursor", "formatted presentation identity"),
            ("ApplicationHandler<(String, CustomEvent)>", "string event-loop identity"),
        ):
            forbid(platform, forbidden, f"{platform_name} {label}")

    windows = sources["windows"]
    require_order(
        windows,
        (
            "StartCause::ResumeTimeReached",
            "let had_ripples = presentation.has_ripples();",
            "presentation.retain_ripples(Ripple::is_active)",
            "window.request_redraw();",
            "presentation.update(conn_id, cursor, ripple)",
            "CustomEvent::Clear",
            "presentation.clear(conn_id);",
            "window.request_redraw();",
        ),
        "Windows demand-driven redraw and exact retirement",
    )

    linux = sources["linux"]
    require_order(
        linux,
        (
            "impl ApplicationHandler<(i32, CustomEvent)>",
            "fn new_events",
            "StartCause::ResumeTimeReached",
            "let had_ripples = state.presentation.has_ripples();",
            "state.presentation.retain_ripples(Ripple::is_active);",
            "state.window.request_redraw();",
            "presentation.update(conn_id, cursor, ripple)",
            "CustomEvent::Clear",
            "state.presentation.clear(conn_id);",
            "fn about_to_wait",
            "ControlFlow::WaitUntil",
            "ControlFlow::Wait",
        ),
        "Linux demand-driven redraw and exact retirement",
    )

    macos = sources["macos"]
    require_order(
        macos,
        (
            "struct CursorTextLayout",
            "EventLoop<(i32, CustomEvent)>",
            "cursor_text_layouts: &mut HashMap<i32, CursorTextLayout>",
            "presentation.retain_ripples",
            "presentation.cursor_entries()",
            "cursor_text_layouts.insert",
            "StartCause::ResumeTimeReached",
            "presentation.update(",
            "CustomEvent::Clear",
            "presentation.clear(conn_id);",
            "cursor_text_layouts.remove(&conn_id);",
        ),
        "macOS owner-bound cursor/ripple/layout lifecycle",
    )
    require_order(
        macos,
        (
            "StartCause::ResumeTimeReached { .. } =>",
            "let had_ripples = presentation.has_ripples();",
            "presentation.retain_ripples(|(_, ripple)| ripple.is_active());",
            "if had_ripples",
            "window.window.request_redraw();",
            "ControlFlow::WaitUntil",
            "ControlFlow::Wait",
        ),
        "macOS deadline-owned ripple expiry and final redraw",
    )
    require_order(
        macos,
        (
            "let previous_window_id =",
            "presentation.cursor(conn_id).map(|info| info.window_id);",
            "let mut matched = false;",
            "(cursor.x as f64) >= r",
            "(cursor.y as f64) >= b",
            "matched = true;",
            "presentation.update(",
            "if previous_window_id != Some(window.window.id())",
            "previous.window.request_redraw();",
            "if !matched",
            "presentation.clear(conn_id);",
            "cursor_text_layouts.remove(&conn_id);",
        ),
        "macOS cross-monitor and unmapped-coordinate retirement",
    )
    for forbidden, label in (
        ("setNeedsDisplay:true", "self-perpetuating redraw request"),
        ("window_ripples", "window-only ripple ownership"),
        ("HashMap<(String, u32), CoreGraphicsTextLayout>", "history-shaped layout cache"),
        ("EventLoopBuilder::<(String, CustomEvent)>", "string event-loop identity"),
    ):
        forbid(macos, forbidden, f"macOS {label}")
    if macos.count("cursor_text_layouts.remove(&conn_id);") != 2:
        raise VerificationError(
            "macOS must retire the owner layout on unmapped coordinates and exact Clear"
        )

    focused_gate = (
        "python3 scripts/verify-whiteboard-presentation-lifecycle.py --repo . --self-test"
    )
    behavior_gate = (
        "cargo test --lib --features linux-pkg-config,flutter r_s11hp_ --color never"
    )
    for key, needle, label in (
        ("verify", focused_gate, "shared focused gate"),
        ("verify", behavior_gate, "shared behavior gate"),
        ("apple", focused_gate, "Apple focused gate"),
        (
            "requirements",
            '<div class="req"><span class="id">R-S11hp</span>',
            "normative presentation requirement",
        ),
        ("requirements", "<tr><td>376</td>", "Appendix C presentation disposition"),
        (
            "hardening",
            "### R-S11hp/R-S11e-253 — exact-owner whiteboard presentation and redraw lifecycle",
            "hardening presentation ledger",
        ),
        (
            "workspace",
            "def validate_whiteboard_presentation_lifecycle_contract(sources):",
            "independent workspace contract",
        ),
        (
            "workspace",
            '            "whiteboard_presentation_lifecycle_verifier": (\n'
            '                repo / "scripts/verify-whiteboard-presentation-lifecycle.py"\n'
            '            ).read_text(encoding="utf-8"),',
            "independent focused-verifier source binding",
        ),
    ):
        require(sources[key], needle, label)

    workspace_module = ast.parse(sources["workspace"])
    validate_sources_function = next(
        (
            node
            for node in workspace_module.body
            if isinstance(node, ast.FunctionDef) and node.name == "validate_sources"
        ),
        None,
    )
    if validate_sources_function is None:
        raise VerificationError("independent presentation lifecycle dispatch is absent")
    dispatches = [
        node
        for node in validate_sources_function.body
        if isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Name)
        and node.value.func.id
        == "validate_whiteboard_presentation_lifecycle_contract"
    ]
    if len(dispatches) != 1:
        raise VerificationError(
            "independent presentation lifecycle dispatch must occur exactly once"
        )

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
    ("ipc", "    Cursor {\n", "    Event {\n", "typed cursor command"),
    ("ipc", "cursor: crate::whiteboard::Cursor", "event: crate::whiteboard::CustomEvent", "cursor-only payload"),
    (
        "connection",
        "use crate::whiteboard;\n                if q == BoolOption::Yes {",
        "use crate::whiteboard;\n                if q != BoolOption::Yes {",
        "enable-only support path",
    ),
    ("connection", "self.show_my_cursor = true;", "self.show_my_cursor = false;", "Remote enable state"),
    ("connection", "                    whiteboard::unregister_whiteboard(self.inner.id);\n                }\n", "                }\n", "disable retirement"),
    ("client", "pub fn update_whiteboard_cursor", "pub fn update_whiteboard", "typed cursor API"),
    ("client", "TrySendError::Full(WhiteboardIpcCommand::Cursor { .. })", "TrySendError::Full(_)", "cursor-only lossy overflow"),
    ("client", "let mut pending: [Option<(i32, String, Cursor)>;", "let mut pending = Vec::new(); //", "fixed pending flush"),
    ("server", "WhiteboardEventLifecycle<EventLoopProxy<(i32, CustomEvent)>>", "WhiteboardEventLifecycle<EventLoopProxy<(String, CustomEvent)>>", "numeric event owner"),
    ("server", "proxy.send_event((0, CustomEvent::Exit))", "proxy.send_event((-1, CustomEvent::Exit))", "reserved terminal owner"),
    ("server", "    Cursor(i32, Cursor),", "    Event(String, CustomEvent),", "typed helper cursor action"),
    ("server", "    Clear(i32),", "    Clear(String),", "typed helper clear action"),
    ("server", "Some(WhiteboardIpcAction::Cursor(conn_id, cursor))", "None", "authorized cursor forwarding"),
    ("server", "Some(WhiteboardIpcAction::Clear(conn_id))", "None", "close-owned clear derivation"),
    ("server", "cursors: HashMap<i32, C>", "cursors: HashMap<String, C>", "numeric presentation owner"),
    ("server", "ripples: HashMap<i32, VecDeque<R>>", "ripples: Vec<R>", "per-owner ripple state"),
    ("server", "self.cursors.len() >= ipc::WHITEBOARD_IPC_MAX_ACTIVE_CONNECTIONS", "false", "presentation owner ceiling"),
    ("server", "WHITEBOARD_PRESENTATION_MAX_RIPPLES_PER_OWNER: usize = 64", "WHITEBOARD_PRESENTATION_MAX_RIPPLES_PER_OWNER: usize = usize::MAX", "ripple ceiling"),
    ("server", "ripples.pop_front();", "ripples.clear();", "oldest-ripple eviction"),
    ("server", "self.cursors.remove(&conn_id);", "// cursor retained", "cursor clear"),
    ("server", "self.ripples.remove(&conn_id);", "// ripples retained", "ripple clear"),
    ("server", "self.cursors.get(&conn_id)", "None // owner lookup omitted", "presentation owner lookup"),
    ("server", "fn r_s11hp_whiteboard_presentation_clear_is_exact_owner_final", "fn whiteboard_presentation_clear_is_advisory", "clear regression"),
    ("server", "fn r_s11hp_whiteboard_presentation_owners_and_ripples_are_bounded", "fn whiteboard_presentation_is_unbounded", "bound regression"),
    ("windows", "ControlFlow::WaitUntil", "ControlFlow::Poll", "Windows active animation deadline"),
    ("windows", "presentation.retain_ripples(Ripple::is_active);\n                if had_ripples", "// deadline expiry omitted\n                if had_ripples", "Windows deadline expiry"),
    ("windows", "presentation.clear(conn_id);", "// presentation clear omitted", "Windows exact clear"),
    ("macos", "EventLoopBuilder::<(i32, CustomEvent)>", "EventLoopBuilder::<(String, CustomEvent)>", "macOS numeric owner"),
    ("macos", "cursor_text_layouts.remove(&conn_id);", "// layout retained", "macOS layout retirement"),
    ("macos", "previous.window.request_redraw();", "// previous monitor retained", "macOS previous-monitor redraw"),
    ("macos", "(cursor.x as f64) >= r", "(cursor.x as f64) > r", "macOS half-open horizontal monitor bound"),
    ("macos", "(cursor.y as f64) >= b", "(cursor.y as f64) > b", "macOS half-open vertical monitor bound"),
    ("macos", "if !matched {", "if false {", "macOS unmapped-coordinate retirement"),
    ("macos", "ControlFlow::WaitUntil", "ControlFlow::Poll", "macOS active animation deadline"),
    ("macos", "presentation.retain_ripples(|(_, ripple)| ripple.is_active());\n                    if had_ripples", "// deadline expiry omitted\n                    if had_ripples", "macOS deadline expiry"),
    ("linux", "impl ApplicationHandler<(i32, CustomEvent)>", "impl ApplicationHandler<(String, CustomEvent)>", "Linux numeric owner"),
    ("linux", "state.presentation.clear(conn_id);", "// presentation clear omitted", "Linux exact clear"),
    ("linux", "ControlFlow::WaitUntil", "ControlFlow::Poll", "Linux active animation deadline"),
    ("linux", "state.presentation.retain_ripples(Ripple::is_active);", "// deadline expiry omitted", "Linux deadline expiry"),
    ("verify", "python3 scripts/verify-whiteboard-presentation-lifecycle.py --repo . --self-test", "true # presentation gate disabled", "shared focused gate"),
    ("verify", "cargo test --lib --features linux-pkg-config,flutter r_s11hp_ --color never", "true # presentation tests disabled", "shared behavior gate"),
    ("apple", "python3 scripts/verify-whiteboard-presentation-lifecycle.py --repo . --self-test", "true # presentation gate disabled", "Apple focused gate"),
    ("requirements", '<div class="req"><span class="id">R-S11hp</span>', '<div class="req"><span class="id">R-S11hp-disabled</span>', "normative requirement"),
    ("requirements", "<tr><td>376</td>", "<tr><td>376-disabled</td>", "Appendix C disposition"),
    ("hardening", "### R-S11hp/R-S11e-253 — exact-owner whiteboard presentation and redraw lifecycle", "### R-S11hp-disabled/R-S11e-253 — exact-owner whiteboard presentation and redraw lifecycle", "hardening ledger"),
    ("workspace", "    validate_whiteboard_presentation_lifecycle_contract(sources)\n", "    validate_whiteboard_presentation_lifecycle_contract_disabled(sources)\n", "independent dispatch"),
    ("workspace", '            "whiteboard_presentation_lifecycle_verifier": (\n', '            "whiteboard_presentation_lifecycle_verifier_disabled": (\n', "focused-verifier binding"),
)


def run_self_test(sources: Dict[str, str]) -> None:
    for key, old, new, label in MUTATIONS:
        if old not in sources[key]:
            raise VerificationError(f"self-test fixture missing for {label}")
        mutated = dict(sources)
        mutated[key] = sources[key].replace(old, new, 1)
        try:
            validate(mutated)
        except (VerificationError, SyntaxError):
            continue
        raise VerificationError(f"self-test mutation survived: {label}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path("."))
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    sources = load_sources(args.repo.resolve())
    validate(sources)
    if args.self_test:
        run_self_test(sources)
        print(
            "Whiteboard presentation lifecycle verifier self-test passed "
            f"({len(MUTATIONS)} mutations)"
        )
    else:
        print("Whiteboard presentation lifecycle verifier passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VerificationError as error:
        print(f"Whiteboard presentation lifecycle verifier failed: {error}")
        raise SystemExit(1)
