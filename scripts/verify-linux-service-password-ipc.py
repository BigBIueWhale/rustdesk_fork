#!/usr/bin/env python3
import argparse
import sys
from pathlib import Path


COMMIT_FN = "async fn commit_service_owned_unattended_password_change"
LINUX_CFG = '#[cfg(target_os = "linux")]'
SCOPE_MARKER = "let _scope = UserMainIpcScope::new();"
CONNECT_MARKER = 'let mut c = connect(ms_timeout, "").await?;'
AUTH_MARKER = "authenticate_linux_service_owned_main_server(&c)?;"
SEND_MARKER = "c.send(&Data::CommitServiceOwnedUnattendedPasswordChange(value))"
COMMIT_VARIANT = "Data::CommitServiceOwnedUnattendedPasswordChange"
RESULT_MARKER = "Data::ServiceOwnedUnattendedPasswordChangeResult(ok)"


class VerificationError(RuntimeError):
    pass


def find_matching_brace(source: str, open_brace: int) -> int:
    depth = 0
    i = open_brace
    in_line_comment = False
    in_block_comment = 0
    in_string = False
    in_char = False
    escape = False
    while i < len(source):
        ch = source[i]
        nxt = source[i + 1] if i + 1 < len(source) else ""
        if in_line_comment:
            if ch == "\n":
                in_line_comment = False
            i += 1
            continue
        if in_block_comment:
            if ch == "/" and nxt == "*":
                in_block_comment += 1
                i += 2
                continue
            if ch == "*" and nxt == "/":
                in_block_comment -= 1
                i += 2
                continue
            i += 1
            continue
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            i += 1
            continue
        if in_char:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == "'":
                in_char = False
            i += 1
            continue
        if ch == "/" and nxt == "/":
            in_line_comment = True
            i += 2
            continue
        if ch == "/" and nxt == "*":
            in_block_comment = 1
            i += 2
            continue
        if ch == '"':
            in_string = True
            i += 1
            continue
        if ch == "'":
            in_char = True
            i += 1
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise VerificationError("commit helper body has no matching closing brace")


def extract_function_body(source: str, signature: str) -> str:
    start = source.find(signature)
    if start == -1:
        raise VerificationError(f"missing function: {signature}")
    next_start = source.find(signature, start + len(signature))
    if next_start != -1:
        raise VerificationError(f"duplicate function marker: {signature}")
    open_brace = source.find("{", start)
    if open_brace == -1:
        raise VerificationError(f"function has no opening brace: {signature}")
    close_brace = find_matching_brace(source, open_brace)
    return source[open_brace + 1 : close_brace]


def find_unique_required(body: str, marker: str) -> int:
    pos = body.find(marker)
    if pos == -1:
        raise VerificationError(f"missing marker in commit helper: {marker}")
    if body.find(marker, pos + len(marker)) != -1:
        raise VerificationError(f"duplicate marker in commit helper: {marker}")
    return pos


def require_linux_cfg_before(body: str, marker_pos: int, after_pos: int, marker_name: str) -> None:
    cfg_pos = body.rfind(LINUX_CFG, after_pos, marker_pos)
    if cfg_pos == -1:
        raise VerificationError(f"{marker_name} is not guarded by the Linux cfg marker")


def validate_commit_helper(source: str) -> None:
    body = extract_function_body(source, COMMIT_FN)
    scope = find_unique_required(body, SCOPE_MARKER)
    connect = find_unique_required(body, CONNECT_MARKER)
    auth = find_unique_required(body, AUTH_MARKER)
    send = find_unique_required(body, SEND_MARKER)
    first_commit_variant = find_unique_required(body, COMMIT_VARIANT)
    result = find_unique_required(body, RESULT_MARKER)
    awaited_send = body.find(".await?", send)

    if not (scope < connect < auth < send):
        raise VerificationError("commit helper must scope/connect, authenticate receiver, then send password")
    require_linux_cfg_before(body, scope, 0, "main IPC scope")
    require_linux_cfg_before(body, auth, connect, "main-server receiver authentication")
    if first_commit_variant < auth:
        raise VerificationError("password-bearing commit variant appears before receiver authentication")
    if awaited_send == -1 or not (send < awaited_send < result):
        raise VerificationError("password-bearing commit send must be awaited before reading the result")
    if "allow_err!" in body:
        raise VerificationError("commit helper must propagate send/read failures, not hide them with allow_err!")


def self_test() -> None:
    good = f"""
{COMMIT_FN}(value: String) -> ResultType<bool> {{
    {LINUX_CFG}
    {SCOPE_MARKER}
    let ms_timeout = 1_000;
    {CONNECT_MARKER}
    {LINUX_CFG}
    {AUTH_MARKER}
    {SEND_MARKER}
        .await?;
    if let Some({RESULT_MARKER}) =
        c.next_timeout(ms_timeout).await?
    {{
        Ok(ok)
    }} else {{
        Ok(false)
    }}
}}
"""
    validate_commit_helper(good)
    bad_send_first = good.replace(
        f"{AUTH_MARKER}\n    {SEND_MARKER}",
        f"{SEND_MARKER}\n        .await?;\n    {AUTH_MARKER}",
    )
    try:
        validate_commit_helper(bad_send_first)
    except VerificationError:
        pass
    else:
        raise VerificationError("self-test accepted send-before-auth commit helper")
    bad_missing_auth = good.replace(f"    {LINUX_CFG}\n    {AUTH_MARKER}\n", "")
    try:
        validate_commit_helper(bad_missing_auth)
    except VerificationError:
        pass
    else:
        raise VerificationError("self-test accepted commit helper without receiver authentication")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify Linux service-owned password IPC source-order invariants."
    )
    parser.add_argument("--repo", default=".", help="repository root")
    parser.add_argument("--self-test", action="store_true", help="run verifier negative tests")
    args = parser.parse_args()

    try:
        if args.self_test:
            self_test()
        source = Path(args.repo, "src/ipc.rs").read_text()
        validate_commit_helper(source)
    except (OSError, VerificationError) as exc:
        print(f"verify-linux-service-password-ipc: FAIL: {exc}", file=sys.stderr)
        return 1
    print("verify-linux-service-password-ipc: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
