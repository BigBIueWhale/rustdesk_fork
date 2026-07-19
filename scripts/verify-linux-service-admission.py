#!/usr/bin/env python3
"""R-S11at/R-S11e-60 Linux protected-service admission verifier."""

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
        raise VerificationError(f"stale/forbidden {label}")


def ordered(source: str, needles: Iterable[str], label: str) -> None:
    position = -1
    for needle in needles:
        position = source.find(needle, position + 1)
        if position < 0:
            raise VerificationError(f"missing or out-of-order {label}: {needle}")


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
        "ipc": "src/ipc.rs",
        "auth": "src/ipc/auth.rs",
        "linux": "src/platform/linux.rs",
        "requirements": "requirements.html",
        "hardening": "HARDENING_STATUS.md",
        "verify": "scripts/verify.sh",
    }
    return {
        key: (repo / relative).read_text(encoding="utf-8")
        for key, relative in paths.items()
    }


def validate(sources: Dict[str, str]) -> None:
    ipc = sources["ipc"]
    auth = sources["auth"]
    linux = sources["linux"]

    cached_accessor = region(
        linux,
        "pub fn get_active_userid_cached() -> Option<String> {",
        "\n#[inline]\n/// Returns the active uid from a fresh seat0 lookup",
        "cached-only active UID accessor",
    )
    require(
        cached_accessor,
        "get_active_user_id_name_from_cache().map(|(uid, _)| uid)",
        "cached-only active UID read",
    )
    for needle in ("get_values_of_seat0", "get_active_userid_fresh", "Command::"):
        absent(cached_accessor, needle, "live lookup in cached-only accessor")

    prefilter = region(
        auth,
        "fn linux_service_peer_requires_fresh_active_uid_lookup(",
        "\n#[cfg(any(target_os = \"linux\", target_os = \"macos\"))]\n#[inline]\npub(crate) fn peer_uid_from_fd",
        "Linux active UID negative prefilter",
    )
    for needle, label in (
        ("(peer_uid, cached_active_uid)", "peer/cache tuple proof"),
        ("peer_uid != 0", "root fresh-lookup exclusion"),
        ("peer_uid == active_uid", "cached UID equality prefilter"),
    ):
        require(prefilter, needle, label)
    require(
        prefilter,
        "(Some(peer_uid), Some(active_uid)) if peer_uid != 0 && peer_uid == active_uid",
        "exact non-root cached-UID match prefilter",
    )

    snapshot = region(
        auth,
        "pub(crate) fn service_scoped_ipc_authorization_snapshot_from_stream<T>(",
        "\n#[cfg(any(target_os = \"linux\", target_os = \"macos\"))]\npub(crate) fn authorize_service_scoped_ipc_authorization_snapshot",
        "service-scoped authorization snapshot",
    )
    ordered(
        snapshot,
        (
            "let peer_uid = peer_uid_from_fd(fd);",
            '#[cfg(target_os = "macos")]\n    let active_uid = active_uid_fresh();',
            '#[cfg(target_os = "linux")]\n    let active_uid = if peer_uid == Some(0) {',
            "let cached_active_uid = active_uid_cached();",
            "linux_service_peer_requires_fresh_active_uid_lookup(peer_uid, cached_active_uid)",
            "active_uid_fresh()",
            "cached_active_uid",
            "is_allowed_service_peer_uid(uid, active_uid)",
        ),
        "root/cache/fresh/final Linux authorization order",
    )
    require(
        snapshot,
        "if linux_service_peer_requires_fresh_active_uid_lookup(peer_uid, cached_active_uid) {\n            active_uid_fresh()\n        } else {\n            cached_active_uid\n        }",
        "fresh lookup only after cached non-root match",
    )
    if snapshot.count("active_uid_fresh()") != 2:
        raise VerificationError("authorization snapshot does not have exact macOS and gated Linux fresh lookups")

    worker = region(
        ipc,
        "async fn run_service_ipc(postfix: &str, listeners: PreparedServiceIpc)",
        "\n#[cfg(target_os = \"linux\")]\nasync fn handle_sensitive_linux_service_ipc_transaction",
        "protected service IPC worker",
    )
    password = region(
        worker,
        "result = password_incoming.next() => {",
        "\n            result = incoming.next() => {",
        "protected password admission branch",
    )
    ordered(
        password,
        (
            "try_acquire_service_password_ipc_transaction_slot()",
            "service_scoped_ipc_authorization_snapshot_from_stream(",
            "peer_process_identity_from_stream(",
            "handle_sensitive_linux_service_ipc_transaction(\n                        stream,\n                        identity,\n                        permit,",
        ),
        "password permit before identity work and retained dispatch",
    )
    generic = region(
        worker,
        "result = incoming.next() => {",
        "\n        }\n    }\n    #[cfg(target_os = \"macos\")]",
        "protected generic admission branch",
    )
    ordered(
        generic,
        (
            "Connection::new_protected_service(stream)",
            "try_acquire_service_ipc_transaction_slot()",
            "authorize_service_scoped_ipc_connection(&stream, postfix)",
            "transactions.spawn(async move",
            "let _permit = permit;",
            "handle_service_ipc_transaction(stream, &postfix).await;",
        ),
        "generic permit before identity work and retained dispatch",
    )
    absent(auth, "fn service_authorization_status(&self)", "unowned alternate fresh-lookup path")
    require(
        auth,
        "fn r_s11e60_linux_service_active_uid_lookup_prefilter_is_negative_only()",
        "focused Rust prefilter regression",
    )

    for source, needle, label in (
        (sources["requirements"], '<span class="id">R-S11at</span>', "R-S11at requirement"),
        (sources["requirements"], "Linux protected-service identity work is permit-owned and cache-prefiltered", "R-S11at title"),
        (sources["requirements"], "<tr><td>168</td>", "Appendix C #168"),
        (sources["requirements"], "World-connectable Linux protected sockets performed root active-session work before bounded admission", "Appendix C #168 disposition"),
        (sources["hardening"], "R-S11e-60 — Linux protected-service admission owns active-session identity work", "R-S11e-60 ledger"),
        (sources["verify"], "Linux protected-service bounded identity admission (R-S11at/R-S11e-60)", "shared source gate"),
    ):
        require(source, needle, label)


Mutation = Tuple[str, str, str, str]


MUTATIONS: Tuple[Mutation, ...] = (
    ("linux", "get_active_user_id_name_from_cache().map(|(uid, _)| uid)", "Some(get_values_of_seat0(&[1])[0].clone())", "cached-only accessor"),
    ("auth", "peer_uid != 0 && peer_uid == active_uid", "peer_uid == active_uid", "root fresh-lookup exclusion"),
    ("auth", "peer_uid != 0 && peer_uid == active_uid", "peer_uid != 0 || peer_uid == active_uid", "cached UID equality prefilter"),
    ("auth", "let active_uid = if peer_uid == Some(0) {", "let active_uid = if peer_uid == Some(u32::MAX) {", "root lookup short circuit"),
    ("auth", "        } else {\n            cached_active_uid\n        }\n    };", "        } else {\n            active_uid_fresh()\n        }\n    };", "negative cache rejection without live lookup"),
    ("ipc", "                let Some(permit) = try_acquire_service_password_ipc_transaction_slot() else {\n                    continue;\n                };\n                #[cfg(target_os = \"linux\")]", "                #[cfg(target_os = \"linux\")]", "password pre-authorization permit"),
    ("ipc", "                let Some(permit) = try_acquire_service_ipc_transaction_slot() else {\n                    continue;\n                };\n                #[cfg(target_os = \"linux\")]", "                #[cfg(target_os = \"linux\")]", "generic pre-authorization permit"),
    ("ipc", "                        identity,\n                        permit,", "                        identity,\n                        unsafe { std::mem::zeroed() },", "password permit transfer"),
    ("ipc", "                    let _permit = permit;", "                    drop(permit);", "generic permit lifetime"),
    ("auth", "    pub(crate) fn peer_pid(&self) -> Option<u32> {", "    fn service_authorization_status(&self) { let _ = active_uid_fresh(); }\n\n    pub(crate) fn peer_pid(&self) -> Option<u32> {", "alternate unowned fresh lookup"),
    ("auth", "fn r_s11e60_linux_service_active_uid_lookup_prefilter_is_negative_only()", "fn linux_service_prefilter_is_untested()", "focused Rust regression"),
    ("requirements", '<span class="id">R-S11at</span>', '<span class="id">R-S11az</span>', "R-S11at requirement"),
    ("requirements", "<tr><td>168</td>", "<tr><td>9168</td>", "Appendix C #168"),
    ("hardening", "R-S11e-60 — Linux protected-service admission owns active-session identity work", "R-S11e-60 — unbounded Linux identity admission", "R-S11e-60 ledger"),
    ("verify", "Linux protected-service bounded identity admission (R-S11at/R-S11e-60)", "Linux protected-service unbounded identity admission (R-S11at/R-S11e-60)", "shared source gate"),
)


def run_mutations(sources: Dict[str, str]) -> None:
    for key, old, new, label in MUTATIONS:
        if sources[key].count(old) != 1:
            raise VerificationError(f"mutation anchor is not unique for {label}")
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
        "Linux protected-service admission semantic validation: OK"
        + (f" ({len(MUTATIONS)} mutations)" if args.self_test else "")
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
