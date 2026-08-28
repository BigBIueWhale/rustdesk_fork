#!/usr/bin/env python3
"""Verify bounded Linux service selected-session observation and selector ownership."""

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


def rust_block(source: str, marker: str, label: str) -> str:
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
    return source[begin : finish + len(end)]


def load_sources(repo: Path) -> Dict[str, str]:
    paths = {
        "linux": "src/platform/linux.rs",
        "verify": "scripts/verify.sh",
        "requirements": "requirements.html",
        "hardening": "HARDENING_STATUS.md",
    }
    return {
        key: (repo / relative).read_text(encoding="utf-8")
        for key, relative in paths.items()
    }


def validate(sources: Dict[str, str]) -> None:
    linux = sources["linux"]
    exact_limits = (
        "const PROC_SNAPSHOT_MAX_NUMERIC_ENTRIES: usize = 16_384;",
        "const PROC_SNAPSHOT_MAX_SELECTED_PROCESSES: usize = 2_048;",
        "const PROC_SNAPSHOT_MAX_ENVIRONMENT_CANDIDATES: usize = 64;",
        "const PROC_SNAPSHOT_MAX_TOTAL_BYTES: usize = 4 * 1024 * 1024;",
        "const PROC_CMDLINE_MAX_BYTES: usize = 16 * 1024;",
        "const PROC_CMDLINE_MAX_ARGS: usize = 256;",
        "const PROC_ENVIRON_MAX_BYTES: usize = 64 * 1024;",
        "const PROC_ENV_VALUE_MAX_BYTES: usize = 4 * 1024;",
    )
    for limit in exact_limits:
        require(linux, limit, f"exact observation limit {limit}")

    budget = rust_block(linux, "impl ProcSnapshotBudget", "process observation budget")
    for counter, limit, variant in (
        ("numeric_entries", "PROC_SNAPSHOT_MAX_NUMERIC_ENTRIES", "NumericEntries"),
        (
            "selected_processes",
            "PROC_SNAPSHOT_MAX_SELECTED_PROCESSES",
            "SelectedProcesses",
        ),
        (
            "environment_candidates",
            "PROC_SNAPSHOT_MAX_ENVIRONMENT_CANDIDATES",
            "EnvironmentCandidates",
        ),
    ):
        ordered(
            budget,
            (
                f"self.{counter} += 1;",
                f"if self.{counter} > {limit}",
                f"ProcSnapshotLimit::{variant}",
            ),
            f"{counter} limit",
        )
    ordered(
        budget,
        (
            ".checked_add(count)",
            "*total <= PROC_SNAPSHOT_MAX_TOTAL_BYTES",
            "ProcSnapshotLimit::TotalBytes",
        ),
        "aggregate byte limit",
    )

    member = rust_block(linux, "enum ProcMember", "closed proc member vocabulary")
    require(member, "Cgroup,", "cgroup member")
    require(member, "Cmdline,", "cmdline member")
    require(member, "Environ,", "environ member")
    if member.count(",") != 3:
        raise VerificationError("proc member vocabulary is not the exact three-member set")
    member_names = rust_block(
        linux,
        "impl ProcMember",
        "closed proc member name selection",
    )
    for needle in (
        'Self::Cgroup => b"cgroup\\0"',
        'Self::Cmdline => b"cmdline\\0"',
        'Self::Environ => b"environ\\0"',
    ):
        require(member_names, needle, "fixed proc member name")

    namespace = region(
        linux,
        "struct ProcNamespaceIdentity",
        "enum BoundedProcFile",
        "selector-namespace identity boundary",
    )
    selector_namespace = rust_block(
        linux,
        "enum SelectorNamespace",
        "closed selector namespace vocabulary",
    )
    require(selector_namespace, "Mount,", "mount selector namespace")
    require(selector_namespace, "Network,", "network selector namespace")
    if selector_namespace.count(",") != 2:
        raise VerificationError(
            "selector namespace vocabulary is not the exact two-member set"
        )
    for needle, label in (
        ("device: u64", "namespace device identity"),
        ("inode: u64", "namespace inode identity"),
        ("mount: ProcNamespaceIdentity", "mount namespace identity"),
        ("network: ProcNamespaceIdentity", "network namespace identity"),
        (
            "struct ProcSelectorNamespaceAuthority",
            "retained current namespace authority",
        ),
        (
            "identity: ProcSelectorNamespaceIdentity",
            "retained current namespace identity",
        ),
        ("_mount_handle: File", "retained current mount namespace handle"),
        ("_network_handle: File", "retained current network namespace handle"),
        ("enum SelectorNamespace", "closed selector namespace vocabulary"),
        ('Self::Mount => "/proc/self/ns/mnt"', "fixed current mount namespace"),
        ('Self::Network => "/proc/self/ns/net"', "fixed current network namespace"),
        ('Self::Mount => b"ns/mnt\\0"', "fixed process mount namespace"),
        ('Self::Network => b"ns/net\\0"', "fixed process network namespace"),
        ("metadata.is_file().then_some", "namespace object type proof"),
        ("process_dir.as_raw_fd()", "opened process-directory handle for namespace"),
        ("hbb_common::libc::O_RDONLY", "read-only namespace open"),
        ("hbb_common::libc::O_CLOEXEC", "close-on-exec namespace open"),
        ("File::from_raw_fd(fd)", "owned namespace descriptor"),
        ("_mount_handle: mount", "retained opened current mount namespace"),
        ("_network_handle: network", "retained opened current network namespace"),
        ("process_selector_namespace_identity(process_dir) == Some(expected)", "exact namespace equality"),
    ):
        require(namespace, needle, label)
    for forbidden in ("read_link", "read_to_string", "PathBuf"):
        absent(namespace, forbidden, "text/path-derived namespace identity")

    reader = rust_block(
        linux,
        "fn read_bounded_proc_reader(",
        "bounded proc member reader",
    )
    ordered(
        reader,
        (
            "PROC_SNAPSHOT_MAX_TOTAL_BYTES.saturating_sub(budget.total_bytes)",
            "let read_limit = per_file_limit.min(remaining);",
            ".take((read_limit as u64).saturating_add(1))",
            ".read_to_end(&mut bytes)",
            "budget.charge_bytes(bytes.len())?;",
            "if read_result.is_err()",
            "BoundedProcFile::Unavailable",
            "if bytes.len() > per_file_limit",
            "BoundedProcFile::Oversized",
        ),
        "limit-plus-one read and complete-value refusal",
    )

    member_reader = rust_block(
        linux,
        "fn read_bounded_proc_member(",
        "handle-relative proc member reader",
    )
    for needle, label in (
        ("process_dir.as_raw_fd()", "opened process-directory handle"),
        ("hbb_common::libc::openat(", "handle-relative open"),
        ("hbb_common::libc::O_RDONLY", "read-only member open"),
        ("hbb_common::libc::O_CLOEXEC", "close-on-exec member open"),
        ("hbb_common::libc::O_NOFOLLOW", "no-follow member open"),
        ("File::from_raw_fd(fd)", "owned exact member descriptor"),
    ):
        require(member_reader, needle, label)
    absent(member_reader, "PathBuf", "path-reopened proc member")

    cmdline_parser = rust_block(
        linux,
        "fn parse_proc_cmdline_args(",
        "complete cmdline parser",
    )
    for needle, label in (
        ("cmdline.last() != Some(&0)", "terminal cmdline delimiter"),
        ("args.len() == PROC_CMDLINE_MAX_ARGS", "argument-count limit"),
        ("std::str::from_utf8(part)", "strict cmdline UTF-8"),
    ):
        require(cmdline_parser, needle, label)

    classifier = region(
        linux,
        "fn process_is_kded(",
        "fn observe_desktop_processes(",
        "exact desktop process classifier",
    )
    for needle, label in (
        ('process_basename_eq(args, "xdg-desktop-portal")', "portal basename"),
        ("process_is_xwayland(args)", "Xwayland basename"),
        ('process_basename_eq(args, "ibus-daemon")', "ibus basename"),
        ('process_basename_eq(args, "goa-daemon")', "GOA basename"),
        ("process_is_kded(args)", "kded numeric basename"),
        ("process_is_rustdesk_tray(args, app_name)", "exact tray argv"),
        ('arg == "--tray"', "actual tray role argument"),
        ('process_basename_eq(args, "xfce4-panel")', "XFCE basename"),
        ('process_basename_eq(args, "sddm-greeter")', "SDDM basename"),
    ):
        require(classifier, needle, label)
    for needle in ("Regex", "proc_cmdline_string", ".contains("):
        absent(classifier, needle, "generic process-text classifier")
    absent(classifier, 'arg == "+--tray"', "invented plus-prefixed tray argument")

    observer = rust_block(
        linux,
        "fn observe_desktop_processes(",
        "selected desktop process observer",
    )
    ordered(
        observer,
        (
            '.filter(|parsed| parsed.to_string() == uid)',
            "current_selector_namespace_authority()?",
            'std::fs::read_dir("/proc")',
            "budget.charge_numeric_entry()?;",
            "open_proc_process_dir(&entry)",
            "process_dir.metadata()",
            "metadata.uid() != uid_num",
            "current_selector_namespaces.identity",
            "budget.charge_selected_process()?;",
            "read_proc_cmdline_args(&process_dir, &mut budget)?",
            "classify_desktop_process(&args, &app_name)",
            "budget.charge_environment_candidate()?;",
            "ProcMember::Environ",
            "PROC_ENVIRON_MAX_BYTES",
            "process_dir.metadata()",
            "metadata.uid() != uid_num",
            "current_selector_namespaces.identity",
            "if kind == DesktopProcessKind::Xwayland",
            ".push(DesktopProcessEnvironment { pid, kind, environ });",
        ),
        "UID-and-selector-namespace-checked handle-relative selected process observation",
    )
    if observer.count("current_selector_namespaces.identity") != 2:
        raise VerificationError("selected desktop observer lacks exact pre/post namespace proof")
    absent(
        observer,
        "drop(current_selector_namespaces)",
        "premature current namespace handle release",
    )
    if observer.count('std::fs::read_dir("/proc")') != 1:
        raise VerificationError("selected desktop observer has more than one proc walk")
    for forbidden in (".flatten()", "std::fs::read(", "read_to_string", "Regex::new"):
        absent(observer, forbidden, "unbounded or generic selected process observation")

    parser = region(
        linux,
        "fn proc_environ_value(",
        "impl DesktopProcessSnapshot",
        "typed desktop environment parsing",
    )
    for needle, label in (
        ("value.len() > PROC_ENV_VALUE_MAX_BYTES", "per-value byte limit"),
        ("std::str::from_utf8(value).ok()?", "non-lossy UTF-8 validation"),
        ("found.replace(value).is_some()", "duplicate selector refusal"),
        (
            "!environ.is_empty() && environ.last() != Some(&0)",
            "terminal environment delimiter",
        ),
        ("byte.is_ascii_control()", "control-byte rejection"),
        ("normalize_local_x_display_name(&display)", "local DISPLAY normalization"),
        ("xauthority_from_environ_for_display(environ, &display)", "same-record Xauthority binding"),
    ):
        require(parser, needle, label)
    absent(parser, "String::from_utf8_lossy", "lossy selector conversion")

    snapshot_selection = rust_block(
        linux,
        "impl DesktopProcessSnapshot",
        "typed desktop snapshot selection",
    )
    for needle, label in (
        ("process.kind == kind", "typed process-kind selection"),
        ("DesktopSessionEnvironment::from_environ(&process.environ)", "one-record environment parse"),
        ("process.pid > best_pid", "deterministic PID tie break"),
        ("local_x_display_names_share_server(&environment.display, display)", "selected X server binding"),
    ):
        require(snapshot_selection, needle, label)

    service_identity = rust_block(
        linux,
        "struct ServiceChildDesktopIdentity",
        "complete service-child desktop identity",
    )
    for needle, label in (
        ("sid: String", "selected session ID"),
        ("username: String", "selected username"),
        ("uid: String", "selected UID"),
        ("protocol: String", "selected protocol"),
        ("environment: DesktopSessionEnvironment", "selected endpoint environment"),
    ):
        require(service_identity, needle, label)
    identity_update = rust_block(
        linux,
        "fn update_service_child_desktop_identity(",
        "service-child identity update",
    )
    for needle, label in (
        ("ServiceChildDesktopIdentity::from_desktop(desktop)", "typed identity snapshot"),
        ("if *previous == selected", "stable identity comparison"),
        ("*previous = selected", "changed identity commit"),
    ):
        require(identity_update, needle, label)

    service_loop = rust_block(linux, "pub fn start_os_service(", "Linux service loop")
    for needle, label in (
        (
            "let mut root_server_desktop = ServiceChildDesktopIdentity::default();",
            "root-child identity ownership",
        ),
        (
            "let mut user_server_desktop = ServiceChildDesktopIdentity::default();",
            "user-child identity ownership",
        ),
        (
            "update_service_child_desktop_identity(&mut root_server_desktop, &desktop)",
            "root-child identity refresh",
        ),
        (
            "update_service_child_desktop_identity(&mut user_server_desktop, &desktop)",
            "user-child identity refresh",
        ),
    ):
        require(service_loop, needle, label)
    if service_loop.count("update_service_child_desktop_identity(") != 2:
        raise VerificationError("service loop does not update exactly both child identities")

    refresh = rust_block(
        linux,
        "fn refresh_selected_environment(",
        "single selected-session observation transaction",
    )
    if refresh.count("observe_desktop_processes(&self.uid)?") != 1:
        raise VerificationError("selected-session refresh does not own exactly one snapshot")
    ordered(
        refresh,
        (
            "let is_wayland = self.is_wayland();",
            "if !is_wayland",
            "self.get_display_x11();",
            "if self.display.is_empty()",
            "let snapshot = observe_desktop_processes(&self.uid)?;",
            "if is_wayland",
            "snapshot.xwayland_running",
            "self.get_display_xauth_xwayland(&snapshot);",
            "self.get_display_xauth_wayland(&snapshot);",
            "self.get_xauth_x11(&snapshot);",
        ),
        "one snapshot after exact-session display admission",
    )

    desktop = region(
        linux,
        "mod desktop {",
        "pub struct WakeLock",
        "desktop selected-session implementation",
    )
    for forbidden in (
        "for _ in 1..=10",
        "sleep_millis(300)",
        "matching_process_cmdlines",
        "get_envs(",
        "get_env(",
        "is_xwayland_running()",
        "kded[0-9]+",
    ):
        absent(desktop, forbidden, "repeated or regex-shaped desktop observation")

    for test_name in (
        "fn r_s11e207_desktop_process_classification_is_exact()",
        "fn r_s11e207_proc_observation_rejects_oversized_or_partial_values()",
        "fn r_s11e207_service_child_replacement_tracks_complete_selected_desktop()",
        "fn r_s11e207_desktop_snapshot_keeps_one_validated_process_environment()",
        "fn r_s11e257_desktop_selector_process_requires_the_same_interpretation_namespaces()",
    ):
        require(linux, test_name, f"compiled regression {test_name}")

    for source_key, needle, label in (
        (
            "verify",
            "python3 scripts/verify-linux-service-session-observation.py --repo . --self-test",
            "shared focused-verifier wiring",
        ),
        (
            "verify",
            "cargo test --offline --locked --lib --features linux-pkg-config r_s11e207_",
            "compiled regression wiring",
        ),
        (
            "verify",
            "cargo test --offline --locked --lib --features linux-pkg-config r_s11e257_",
            "selector-namespace regression wiring",
        ),
        (
            "requirements",
            '<span class="id">R-S11ft</span>',
            "selected-session observation requirement",
        ),
        ("requirements", "<tr><td>328</td>", "Appendix C #328"),
        (
            "hardening",
            "R-S11ft/R-S11e-207 Linux selected-session observation authority",
            "selected-session observation hardening ledger",
        ),
        (
            "requirements",
            '<span class="id">R-S11ht</span>',
            "selector-namespace requirement",
        ),
        ("requirements", "<tr><td>379</td>", "Appendix C #379"),
        (
            "hardening",
            "R-S11ht/R-S11e-257 Linux desktop-selector namespace authority",
            "selector-namespace hardening ledger",
        ),
    ):
        require(sources[source_key], needle, label)


Mutation = Tuple[str, str, str, str]

MUTATIONS: Tuple[Mutation, ...] = (
    (
        "linux",
        "const PROC_SNAPSHOT_MAX_TOTAL_BYTES: usize = 4 * 1024 * 1024;",
        "const PROC_SNAPSHOT_MAX_TOTAL_BYTES: usize = usize::MAX;",
        "exact observation limit",
    ),
    (
        "linux",
        ".take((read_limit as u64).saturating_add(1))",
        ".take(u64::MAX)",
        "limit-plus-one read",
    ),
    (
        "linux",
        "budget.charge_bytes(bytes.len())?;",
        "let _ = bytes.len();",
        "limit-plus-one read",
    ),
    (
        "linux",
        "budget.charge_bytes(bytes.len())?;\n    if read_result.is_err() {",
        "if read_result.is_err() {\n        return Ok(BoundedProcFile::Unavailable);\n    }\n    budget.charge_bytes(bytes.len())?;",
        "limit-plus-one read and complete-value refusal",
    ),
    (
        "linux",
        "if cmdline.last() != Some(&0) {",
        "if false {",
        "terminal cmdline delimiter",
    ),
    (
        "linux",
        "process_dir.as_raw_fd(),\n            member,",
        "hbb_common::libc::AT_FDCWD,\n            member,",
        "opened process-directory handle",
    ),
    (
        "linux",
        "hbb_common::libc::O_RDONLY\n                | hbb_common::libc::O_CLOEXEC\n                | hbb_common::libc::O_NOFOLLOW,",
        "hbb_common::libc::O_RDONLY | hbb_common::libc::O_CLOEXEC,",
        "no-follow member open",
    ),
    (
        "linux",
        'Self::Mount => "/proc/self/ns/mnt"',
        'Self::Mount => "/proc/1/ns/mnt"',
        "fixed current mount namespace",
    ),
    (
        "linux",
        "enum SelectorNamespace {\n    Mount,\n    Network,\n}",
        "enum SelectorNamespace {\n    Mount,\n    Network,\n    Foreign,\n}",
        "exact two-member set",
    ),
    (
        "linux",
        "_mount_handle: File,",
        "_mount_handle: (),",
        "retained current mount namespace handle",
    ),
    (
        "linux",
        "_network_handle: File,",
        "_network_handle: (),",
        "retained current network namespace handle",
    ),
    (
        "linux",
        "_mount_handle: mount,",
        "_mount_handle: network,",
        "retained opened current mount namespace",
    ),
    (
        "linux",
        "_network_handle: network,",
        "_network_handle: mount,",
        "retained opened current network namespace",
    ),
    (
        "linux",
        "let current_selector_namespaces = current_selector_namespace_authority()?;\n    let entries =",
        "let current_selector_namespaces = current_selector_namespace_authority()?;\n    drop(current_selector_namespaces);\n    let entries =",
        "premature current namespace handle release",
    ),
    (
        "linux",
        'Self::Network => "/proc/self/ns/net"',
        'Self::Network => "/proc/1/ns/net"',
        "fixed current network namespace",
    ),
    (
        "linux",
        'Self::Network => b"ns/net\\0"',
        'Self::Network => b"ns/mnt\\0"',
        "fixed process network namespace",
    ),
    (
        "linux",
        "process_selector_namespace_identity(process_dir) == Some(expected)",
        "process_selector_namespace_identity(process_dir).is_some()",
        "exact namespace equality",
    ),
    (
        "linux",
        "|| !process_shares_selector_namespaces(\n                &process_dir,\n                current_selector_namespaces.identity,\n            )\n        {\n            continue;\n        }\n        budget.charge_selected_process()?;",
        "{\n            continue;\n        }\n        budget.charge_selected_process()?;",
        "UID-and-selector-namespace-checked",
    ),
    (
        "linux",
        "|| !process_shares_selector_namespaces(\n                &process_dir,\n                current_selector_namespaces.identity,\n            )\n        {\n            continue;\n        }\n        if kind == DesktopProcessKind::Xwayland",
        "{\n            continue;\n        }\n        if kind == DesktopProcessKind::Xwayland",
        "UID-and-selector-namespace-checked",
    ),
    (
        "linux",
        "if kind == DesktopProcessKind::Xwayland {",
        "if true {",
        "UID-and-selector-namespace-checked",
    ),
    (
        "linux",
        '.filter(|parsed| parsed.to_string() == uid)\n        .ok_or(ProcSnapshotError::InvalidUid)?;',
        ".filter(|_| true)\n        .ok_or(ProcSnapshotError::InvalidUid)?;",
        "UID-and-selector-namespace-checked",
    ),
    (
        "linux",
        "budget.charge_environment_candidate()?;",
        "let _ = kind;",
        "UID-and-selector-namespace-checked",
    ),
    (
        "linux",
        'args.iter().skip(1).any(|arg| arg == "--tray")',
        'args.iter().skip(1).any(|arg| arg == "+--tray")',
        "actual tray role argument",
    ),
    (
        "linux",
        "if found.replace(value).is_some() {",
        "if false {",
        "duplicate selector refusal",
    ),
    (
        "linux",
        "if !environ.is_empty() && environ.last() != Some(&0) {",
        "if false {",
        "terminal environment delimiter",
    ),
    (
        "linux",
        "update_service_child_desktop_identity(&mut root_server_desktop, &desktop)",
        "update_service_child_desktop_identity(&mut user_server_desktop, &desktop)",
        "root-child identity refresh",
    ),
    (
        "linux",
        "let snapshot = observe_desktop_processes(&self.uid)?;",
        "let snapshot = observe_desktop_processes(&self.uid)?;\n            let _second = observe_desktop_processes(&self.uid)?;",
        "exactly one snapshot",
    ),
    (
        "linux",
        "fn r_s11e207_proc_observation_rejects_oversized_or_partial_values()",
        "fn disabled_207_proc_observation_rejects_oversized_or_partial_values()",
        "compiled regression",
    ),
    (
        "linux",
        "fn r_s11e257_desktop_selector_process_requires_the_same_interpretation_namespaces()",
        "fn disabled_257_desktop_selector_process_requires_the_same_interpretation_namespaces()",
        "compiled regression",
    ),
    (
        "linux",
        "fn r_s11e207_service_child_replacement_tracks_complete_selected_desktop()",
        "fn disabled_207_service_child_replacement_tracks_complete_selected_desktop()",
        "compiled regression",
    ),
    (
        "verify",
        "python3 scripts/verify-linux-service-session-observation.py --repo . --self-test",
        "true # selected-session observation verifier removed",
        "shared focused-verifier wiring",
    ),
    (
        "verify",
        "cargo test --offline --locked --lib --features linux-pkg-config r_s11e257_",
        "true # selector-namespace regression removed",
        "selector-namespace regression wiring",
    ),
    (
        "requirements",
        '<span class="id">R-S11ft</span>',
        '<span class="id">R-S11ft-disabled</span>',
        "selected-session observation requirement",
    ),
    (
        "requirements",
        "<tr><td>328</td>",
        "<tr><td>328-disabled</td>",
        "Appendix C #328",
    ),
    (
        "hardening",
        "R-S11ft/R-S11e-207 Linux selected-session observation authority",
        "R-S11ft-disabled/R-S11e-207 Linux selected-session observation authority",
        "selected-session observation hardening ledger",
    ),
    (
        "requirements",
        '<span class="id">R-S11ht</span>',
        '<span class="id">R-S11ht-disabled</span>',
        "selector-namespace requirement",
    ),
    (
        "requirements",
        "<tr><td>379</td>",
        "<tr><td>379-disabled</td>",
        "Appendix C #379",
    ),
    (
        "hardening",
        "R-S11ht/R-S11e-257 Linux desktop-selector namespace authority",
        "R-S11ht-disabled/R-S11e-257 Linux desktop-selector namespace authority",
        "selector-namespace hardening ledger",
    ),
)


def run_mutations(sources: Dict[str, str]) -> None:
    for key, old, new, expected in MUTATIONS:
        if sources[key].count(old) != 1:
            raise VerificationError(f"mutation fixture is not unique: {expected}")
        mutated = dict(sources)
        mutated[key] = sources[key].replace(old, new, 1)
        try:
            validate(mutated)
        except VerificationError as error:
            if expected not in str(error):
                raise VerificationError(
                    f"mutation {expected!r} failed for the wrong reason: {error}"
                ) from error
        else:
            raise VerificationError(f"mutation survived: {expected}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=".", help="repository root")
    parser.add_argument("--self-test", action="store_true", help="run mutation fixtures")
    args = parser.parse_args()
    sources = load_sources(Path(args.repo).resolve())
    validate(sources)
    if args.self_test:
        run_mutations(sources)
    print("verify-linux-service-session-observation: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
