#!/usr/bin/env python3
"""Verify Linux CM/PA authority across the nondumpable service-child boundary."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Dict, Iterable, Tuple


class VerificationError(RuntimeError):
    pass


def require(source: str, needle: str, label: str) -> None:
    if needle not in source:
        raise VerificationError(f"missing {label}")


def absent(source: str, needle: str, label: str) -> None:
    if needle in source:
        raise VerificationError(f"forbidden {label}")


def ordered(source: str, needles: Iterable[str], label: str) -> None:
    position = -1
    for needle in needles:
        position = source.find(needle, position + 1)
        if position < 0:
            raise VerificationError(f"missing or out-of-order {label}: {needle!r}")


def block(source: str, marker: str, label: str) -> str:
    start = source.find(marker)
    if start < 0:
        raise VerificationError(f"missing {label}")
    opening = source.find("{", start + len(marker))
    if opening < 0:
        raise VerificationError(f"missing {label} body")
    depth = 0
    for offset in range(opening, len(source)):
        character = source[offset]
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                return source[start : offset + 1]
    raise VerificationError(f"unterminated {label}")


def region(source: str, start: str, end: str, label: str) -> str:
    begin = source.find(start)
    if begin < 0:
        raise VerificationError(f"missing {label} start")
    finish = source.find(end, begin + len(start))
    if finish < 0:
        raise VerificationError(f"missing {label} end")
    return source[begin:finish]


def load_sources(repo: Path) -> Dict[str, str]:
    paths = {
        "auth": "src/ipc/auth.rs",
        "ipc": "src/ipc.rs",
        "fs": "src/ipc/fs.rs",
        "connection": "src/server/connection.rs",
        "audio": "src/server/audio_service.rs",
        "requirements": "requirements.html",
        "hardening": "HARDENING_STATUS.md",
        "verify": "scripts/verify.sh",
    }
    return {
        key: (repo / relative).read_text(encoding="utf-8")
        for key, relative in paths.items()
    }


def validate(sources: Dict[str, str]) -> None:
    auth = sources["auth"]
    identity = block(auth, "pub struct LinuxProcessIdentity", "minimal Linux identity")
    for field in ("pid: u32", "uid: u32", "start_time: String"):
        require(identity, field, f"minimal Linux identity {field}")
    for field in (
        "first_arg",
        "cm_launch_token",
        "cm_launch_parent",
        "executable",
        "environment",
    ):
        absent(identity, field, f"ptrace-gated identity field {field}")

    peer = block(
        auth,
        "pub(crate) fn linux_kernel_peer_process_identity",
        "kernel socket peer identity",
    )
    ordered(
        peer,
        (
            "stream.peer_pid()",
            "stream.peer_uid()",
            "linux_kernel_process_identity_by_pid(peer_pid)?",
            "if identity.uid != peer_uid",
        ),
        "SO_PEERCRED pid/uid and process-start binding",
    )
    endpoint = block(auth, "pub(crate) fn authenticate_cm_endpoint", "CM child admission")
    ordered(
        endpoint,
        (
            "linux_kernel_peer_process_identity(stream, \"_cm\")?",
            "if identity.uid != expected_uid",
            "linux_proc_parent_pid(identity.pid)?",
            "if actual_parent != expected_parent",
        ),
        "exact CM socket uid and direct-parent proof",
    )
    for forbidden in ("let identity = peer_process_identity(", "first_arg", "cm_launch_token"):
        absent(endpoint, forbidden, f"CM admission private-proc dependency {forbidden}")

    owner = block(auth, "pub(crate) fn linux_cm_owner_identity", "CM launch-parent identity")
    ordered(
        owner,
        (
            "CM_LAUNCH_PARENT_ENV",
            "linux_proc_parent_pid(std::process::id())?",
            "if actual_parent != expected_parent",
            "linux_kernel_process_identity_by_pid(expected_parent)",
        ),
        "CM launch marker and actual-parent convergence",
    )
    owner_stream = block(
        auth,
        "pub(crate) fn authenticate_linux_cm_owner_stream",
        "CM-to-owner stream proof",
    )
    ordered(
        owner_stream,
        (
            "linux_cm_owner_identity()?",
            "ensure_linux_process_identity_matches(stream, &expected, \"\")?",
        ),
        "CM main-stream exact owner proof",
    )
    liveness = block(
        auth,
        "pub(crate) fn linux_cm_child_identity_is_live",
        "CM direct-child liveness",
    )
    ordered(
        liveness,
        (
            "linux_process_identity_is_live(identity)",
            "linux_proc_parent_pid(identity.pid)",
            "parent == expected_parent",
        ),
        "PID-reuse-safe direct-child liveness",
    )
    cm_listener = block(
        auth,
        "pub(crate) fn authorize_cm_ipc_connection",
        "CM listener admission",
    )
    ordered(
        cm_listener,
        (
            '#[cfg(target_os = "linux")]',
            "authenticate_linux_cm_owner_stream(stream)",
            "return false",
            "return true",
            '#[cfg(not(target_os = "linux"))]',
            "ensure_peer_executable_matches_current_by_pid_opt",
        ),
        "Linux parent proof before non-Linux executable policy",
    )

    ipc = sources["ipc"]
    role = block(ipc, "fn cm_role_bound_challenge", "CM role-bound challenge")
    require(role, 'matches!(role, "--cm" | "--cm-no-ui")', "closed CM role set")
    require(role, 'format!("{role}\\0{challenge}")', "role/challenge domain binding")
    launch_proof = block(
        ipc, "fn cm_launch_proof_for_challenge", "CM endpoint proof constructor"
    )
    ordered(
        launch_proof,
        (
            "cm_role_bound_challenge(role, challenge)?",
            "helper_launch_proof_for_challenge",
        ),
        "role binding before endpoint HMAC",
    )
    current_role = block(ipc, "fn current_cm_process_role", "current CM role")
    ordered(
        current_role,
        (
            "std::env::args()",
            "args.next()",
            "if args.next().is_some()",
            'matches!(role.as_str(), "--cm" | "--cm-no-ui")',
        ),
        "complete exact CM argv role",
    )
    answer = block(
        ipc, "pub(crate) async fn answer_cm_endpoint_challenge", "CM proof answer"
    )
    ordered(
        answer,
        (
            "current_cm_process_role()?",
            "verify_cm_server_proof",
            "&role",
            "cm_endpoint_proof_for_challenge",
            "&role",
        ),
        "same exact role in mutual CM proof",
    )
    cm_validation = block(
        ipc,
        "pub(crate) async fn validate_cm_connection_authority",
        "CM connection authority validation",
    )
    ordered(
        cm_validation,
        (
            '#[cfg(target_os = "linux")]',
            'connect(1_000, "").await?',
            "authenticate_linux_cm_owner_stream(&stream)?",
            "main_ipc_request_on_stream(stream, request, 1_000).await?",
        ),
        "CM owner authentication before capability validation",
    )
    pa_validation = block(
        ipc,
        "async fn validate_pulse_audio_start_authority",
        "PulseAudio start authority",
    )
    ordered(
        pa_validation,
        (
            "linux_cm_owner_identity()?",
            "if &expected_owner != owner",
            "connect_for_uid(1_000, owner.uid(), \"\").await?",
            "ensure_linux_process_identity_matches(&stream, owner, \"\")?",
            "ValidatePulseAudioStart",
        ),
        "PA exact parent and main-owner validation",
    )
    require(
        ipc,
        "PulseAudioStart {\n        owner: LinuxProcessIdentity,",
        "minimal PA owner payload",
    )
    require(
        ipc,
        "ipc_auth::linux_kernel_peer_process_identity(stream, \"\")",
        "main-side minimal PA peer derivation",
    )
    for test in (
        "r_s11e95_cm_endpoint_proof_is_launch_token_and_role_bound",
        "r_s11e95_linux_kernel_identity_is_pid_reuse_and_direct_parent_bound",
    ):
        require(ipc + auth, test, f"focused {test} regression")
    require(
        ipc,
        'verify_cm_endpoint_proof(&challenge, &proof, &launch_token, "--cm-no-ui").is_err()',
        "wrong-role HMAC rejection",
    )

    connection = sources["connection"]
    require(
        connection,
        "CM_PEER_IDENTITIES: Arc::<Mutex<Vec<(i32, crate::ipc::LinuxProcessIdentity)>>>",
        "minimal retained CM identity",
    )
    expected_cm = block(
        connection,
        "pub(crate) fn expected_cm_peer_identity_for_conn_ids",
        "audio-subscriber CM identity lookup",
    )
    require(
        expected_cm,
        "linux_cm_child_identity_is_live(cm_peer_identity, std::process::id())",
        "retained CM identity direct-parent revalidation",
    )
    connect_cm = block(
        connection, "async fn connect_authenticated_cm", "Linux CM connection"
    )
    ordered(
        connect_cm,
        (
            "connect_for_uid(ms_timeout, uid, \"_cm\").await?",
            "authenticate_cm_endpoint(",
            "std::process::id()",
            "authenticate_cm_endpoint_launch_proof(",
            "expected_arg",
        ),
        "kernel parent proof before role-bound launch proof",
    )
    launch = region(
        connection,
        "if stream.is_none() {",
        "\n            for _ in 0..20 {",
        "CM launch branch",
    )
    require(
        launch,
        "crate::common::run_me_with_env_and_parent_death(args, cm_launch_env())?",
        "all Linux CM launches parent-death bound",
    )
    require(
        launch,
        '#[cfg(any(target_os = "macos", target_os = "windows"))]\n'
        "                let child = crate::run_me_with_env(args, cm_launch_env())?;",
        "plain helper launch confined to macOS/Windows",
    )

    fs_source = sources["fs"]
    probe = block(fs_source, "async fn probe_existing_listener", "incumbent listener probe")
    ordered(
        probe,
        (
            "authenticate_cm_endpoint(&stream, current_euid(), expected_launch_parent)",
            "authenticate_cm_endpoint_launch_proof(",
            "&expected_launch_token",
            "&expected_arg",
        ),
        "incumbent CM parent and role proof",
    )
    require(
        probe,
        "ensure_linux_process_identity_matches(&stream, &expected, \"_pa\")",
        "incumbent PA minimal identity proof",
    )

    audio = sources["audio"]
    for marker in (
        "expected_peer: crate::ipc::LinuxProcessIdentity",
        "fn expected_pa_peer(conn_ids: &[i32]) -> ResultType<crate::ipc::LinuxProcessIdentity>",
        "crate::ipc::ensure_linux_process_identity_matches(stream, authority.expected_peer(), \"_pa\")",
        "crate::ipc::linux_cm_child_identity_is_live(peer, std::process::id())",
        "let owner = crate::ipc::current_linux_process_identity()?",
    ):
        require(audio, marker, f"PA minimal authority {marker}")
    absent(audio, "crate::ipc::PeerProcessIdentity", "PA ptrace-gated full identity")

    for key, needle, label in (
        ("requirements", '<span class="id">R-S11cc</span>', "R-S11cc requirement"),
        ("requirements", "<tr><td>222</td>", "Appendix C #222"),
        (
            "hardening",
            "R-S11cc/R-S11e-95 — Linux nondumpable service child and connection-manager use kernel parent authority",
            "R-S11e-95 hardening ledger",
        ),
        (
            "verify",
            "python3 scripts/verify-linux-nondumpable-cm.py --repo . --self-test",
            "shared focused-verifier wiring",
        ),
    ):
        require(sources[key], needle, label)


Mutation = Tuple[str, str, str, str]

MUTATIONS: Tuple[Mutation, ...] = (
    (
        "auth",
        "    start_time: String,\n}\n\n#[cfg(target_os = \"linux\")]\nimpl LinuxProcessIdentity",
        "    start_time: String,\n    first_arg: String,\n}\n\n#[cfg(target_os = \"linux\")]\nimpl LinuxProcessIdentity",
        "minimal identity field closure",
    ),
    (
        "auth",
        "let peer_uid = stream.peer_uid().ok_or_else(|| {\n"
        "        anyhow::anyhow!(\"Failed to resolve peer uid on ipc channel '{}'\", postfix)\n"
        "    })?;\n"
        "    let identity = linux_kernel_process_identity_by_pid(peer_pid)?;",
        "let peer_uid = Some(0).ok_or_else(|| {\n"
        "        anyhow::anyhow!(\"Failed to resolve peer uid on ipc channel '{}'\", postfix)\n"
        "    })?;\n"
        "    let identity = linux_kernel_process_identity_by_pid(peer_pid)?;",
        "kernel socket uid",
    ),
    (
        "auth",
        "if actual_parent != expected_parent {\n        bail!(\n            \"_cm endpoint parent mismatch",
        "if false {\n        bail!(\n            \"_cm endpoint parent mismatch",
        "CM direct-parent rejection",
    ),
    (
        "auth",
        "if actual_parent != expected_parent {\n        bail!(\n            \"connection-manager owner changed",
        "if false {\n        bail!(\n            \"connection-manager owner changed",
        "CM owner parent convergence",
    ),
    (
        "auth",
        "if let Err(err) = authenticate_linux_cm_owner_stream(stream) {",
        "if let Err(err) = ensure_peer_executable_matches_current_by_pid_opt(stream.peer_pid(), \"_cm\") {",
        "CM listener owner proof",
    ),
    (
        "ipc",
        'Ok(format!("{role}\\0{challenge}"))',
        "Ok(challenge.to_owned())",
        "CM role HMAC binding",
    ),
    (
        "ipc",
        "let role = current_cm_process_role()?;",
        'let role = "--cm".to_owned();',
        "CM exact current role",
    ),
    (
        "ipc",
        "ipc_auth::authenticate_linux_cm_owner_stream(&stream)?;",
        "let _ = &stream;",
        "CM main owner authentication",
    ),
    (
        "ipc",
        "if &expected_owner != owner {\n        bail!(\"pulse audio capture owner is not the connection-manager launch parent\");",
        "if false {\n        bail!(\"pulse audio capture owner is not the connection-manager launch parent\");",
        "PA exact launch parent",
    ),
    (
        "connection",
        "crate::common::run_me_with_env_and_parent_death(args, cm_launch_env())?",
        "crate::run_me_with_env(args, cm_launch_env())?",
        "Linux CM parent-death launch",
    ),
    (
        "connection",
        "crate::ipc::linux_cm_child_identity_is_live(cm_peer_identity, std::process::id())",
        "crate::ipc::linux_process_identity_is_live(cm_peer_identity)",
        "retained CM direct-parent liveness",
    ),
    (
        "fs",
        "if authenticate_cm_endpoint(&stream, current_euid(), expected_launch_parent).is_err() {",
        "if false {",
        "incumbent CM parent proof",
    ),
    (
        "audio",
        "crate::ipc::linux_cm_child_identity_is_live(peer, std::process::id())",
        "crate::ipc::linux_process_identity_is_live(peer)",
        "PA live CM direct-parent proof",
    ),
    (
        "requirements",
        '<span class="id">R-S11cc</span>',
        '<span class="id">R-S11cc-disabled</span>',
        "R-S11cc requirement",
    ),
    (
        "requirements",
        "<tr><td>222</td>",
        "<tr><td>222-disabled</td>",
        "Appendix C #222",
    ),
    (
        "hardening",
        "R-S11cc/R-S11e-95 — Linux nondumpable service child and connection-manager use kernel parent authority",
        "R-S11cc/R-S11e-95 — Linux connection-manager trusts same uid",
        "hardening ledger",
    ),
    (
        "verify",
        "python3 scripts/verify-linux-nondumpable-cm.py --repo . --self-test",
        "true # nondumpable CM verifier removed",
        "shared gate wiring",
    ),
)


def run_mutations(sources: Dict[str, str]) -> None:
    for key, old, new, label in MUTATIONS:
        if sources[key].count(old) != 1:
            raise VerificationError(
                f"mutation anchor for {label} must be unique, found {sources[key].count(old)}"
            )
        mutated = dict(sources)
        mutated[key] = sources[key].replace(old, new, 1)
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
        "Linux nondumpable CM/PA authority validation: OK"
        + (f" ({len(MUTATIONS)} mutations)" if args.self_test else "")
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, UnicodeError, VerificationError) as error:
        print(
            f"Linux nondumpable CM/PA authority verification failed: {error}",
            file=__import__("sys").stderr,
        )
        raise SystemExit(1)
