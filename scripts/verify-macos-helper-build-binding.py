#!/usr/bin/env python3
"""R-S11au/R-S11e-61 macOS helper current-build binding verifier."""

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
        "auth": "src/ipc/auth.rs",
        "ipc": "src/ipc.rs",
        "macos": "src/platform/macos.rs",
        "install": "src/platform/privileges_scripts/install.scpt",
        "requirements": "requirements.html",
        "hardening": "HARDENING_STATUS.md",
        "verify": "scripts/verify.sh",
        "apple": "scripts/apple-conform-check.sh",
    }
    return {
        key: (repo / relative).read_text(encoding="utf-8")
        for key, relative in paths.items()
    }


def validate(sources: Dict[str, str]) -> None:
    auth = sources["auth"]
    ipc = sources["ipc"]
    macos = sources["macos"]
    install = sources["install"]

    require(
        auth,
        'const MACOS_INSTALLED_APP_REQUIREMENT: &str = r#"=anchor apple generic and '
        'certificate leaf[subject.OU] = "HZF9JMC8YN" and identifier '
        '"com.carriez.rustdesk""#;',
        "runtime installed-app designated requirement",
    )
    require(
        install,
        'set app_requirement to "=anchor apple generic and certificate leaf[subject.OU] = '
        '\\"HZF9JMC8YN\\" and identifier \\"com.carriez.rustdesk\\""',
        "installer installed-app designated requirement",
    )

    static_validation = region(
        auth,
        "fn macos_static_code_satisfies_requirement(",
        '\n#[cfg(target_os = "macos")]\nfn macos_peer_code(',
        "macOS static code validation",
    )
    ordered(
        static_validation,
        (
            "MacosCodeSigningFlags::STRICT_VALIDATE",
            "MacosCodeSigningFlags::CHECK_ALL_ARCHITECTURES",
            "if is_dir",
            "MacosCodeSigningFlags::CHECK_NESTED_CODE",
            "code.check_validity(validation_flags, &requirement)",
        ),
        "all-architecture nested static validation",
    )

    no_follow_open = region(
        auth,
        "fn macos_open_regular_file_no_follow(",
        '\n#[cfg(target_os = "macos")]\nfn macos_regular_files_have_same_contents',
        "no-follow helper file open",
    )
    require(
        no_follow_open,
        "custom_flags(crate::libc::O_CLOEXEC | crate::libc::O_NOFOLLOW)",
        "no-follow close-on-exec file open",
    )

    comparator = region(
        auth,
        "fn macos_regular_files_have_same_contents(",
        '\n#[cfg(target_os = "macos")]\npub(crate) fn macos_deployed_helper_matches_installed_app_bytes',
        "bounded helper byte comparator",
    )
    for needle, label in (
        ("macos_open_regular_file_no_follow(left)", "left no-follow open"),
        ("macos_open_regular_file_no_follow(right)", "right no-follow open"),
        ("left_file.metadata()", "left descriptor metadata"),
        ("right_file.metadata()", "right descriptor metadata"),
        ("!left_metadata.is_file()", "left regular file requirement"),
        ("!right_metadata.is_file()", "right regular file requirement"),
        ("left_metadata.len() != right_metadata.len()", "length precheck"),
        ("BufReader::new(left_file)", "bounded left reader"),
        ("BufReader::new(right_file)", "bounded right reader"),
        ("[0u8; 64 * 1024]", "fixed comparison buffer"),
        ("left_buffer[..left_read] != right_buffer[..right_read]", "byte equality"),
        ("if left_read == 0", "complete EOF proof"),
    ):
        require(comparator, needle, label)
    absent(comparator, "fs::read(", "whole-helper allocation")

    binding = region(
        auth,
        "pub(crate) fn macos_deployed_helper_matches_installed_app_bytes() -> bool {",
        '\n#[cfg(target_os = "macos")]\n#[inline]\nfn macos_executable_matches_expected_path',
        "deployed/current-app byte binding",
    )
    ordered(
        binding,
        (
            "Path::new(MACOS_PRIVILEGED_HELPER_EXEC)",
            "macos_installed_app_bundled_helper_path()",
        ),
        "deployed-to-bundled helper comparison",
    )
    require(
        ipc,
        "pub(crate) use ipc_auth::macos_deployed_helper_matches_installed_app_bytes;",
        "platform-visible helper binding proof",
    )

    helper_trust = region(
        auth,
        "fn macos_privileged_helper_path_is_expected_and_trusted(current_exe: &Path) -> bool {",
        '\n#[cfg(target_os = "macos")]\n#[inline]\nfn macos_installed_app_path_is_expected_and_trusted',
        "privileged helper runtime trust",
    )
    ordered(
        helper_trust,
        (
            "macos_executable_matches_expected_path(current_exe, expected)",
            "macos_path_has_expected_type_and_permissions(",
            "macos_privileged_helper_satisfies_code_requirement(expected)",
            "macos_installed_app_path_is_expected_and_trusted(",
            "macos_deployed_helper_matches_installed_app_bytes()",
        ),
        "runtime helper identity and current-build binding",
    )

    status = region(
        macos,
        "pub fn is_installed_daemon(prompt: bool) -> bool {",
        "\n#[inline]\nfn service_installation_is_current",
        "macOS service current-state check",
    )
    ordered(
        status,
        (
            "service_plists_exist(&daemon_plist_file, &agent_plist_file)",
            "crate::ipc::macos_deployed_helper_matches_installed_app_bytes()",
            "if !prompt",
            "service_install_context(daemon_plist_file, agent_plist_file)",
            "run_service_install(context);",
        ),
        "stale helper detection and reinstall path",
    )
    require(
        macos,
        "plists_exist && helper_matches_current_app",
        "plist-and-current-helper status conjunction",
    )
    require(
        macos,
        '.replace("/Applications/RustDesk.app", &app_bundle)',
        "installed-app template binding",
    )

    bundled = region(
        macos,
        "fn bundled_service_executable() -> Option<PathBuf> {",
        "\nfn run_checked_command(",
        "fixed bundled helper resolver",
    )
    ordered(
        bundled,
        (
            '"/Applications/{}.app/Contents/MacOS"',
            "if current_exe_dir != installed_macos_dir",
            'current_exe_dir.join("service")',
            "std::fs::symlink_metadata(&bundled_service_exec)",
            "metadata.file_type().is_symlink()",
            "!metadata.is_file()",
        ),
        "fixed installed non-symlink helper source",
    )

    uninstall = region(
        macos,
        "pub fn uninstall_service(show_new_window: bool, sync: bool) -> bool {",
        "\n}\n\npub fn get_cursor_pos()",
        "macOS service uninstall",
    )
    require(
        uninstall,
        "service_artifacts_exist(&daemon_plist_file, &agent_plist_file)",
        "partial/stale service uninstall admission",
    )
    absent(uninstall, "is_installed_daemon(false)", "current-only uninstall gate")
    require(
        macos,
        "fn r_s11e61_macos_service_status_requires_current_helper_bytes()",
        "focused current-state regression",
    )

    for needle, label in (
        ('set app_bundle to "/Applications/RustDesk.app"', "fixed app bundle"),
        ('set expected_bundled_service_exec to "/Applications/RustDesk.app/Contents/MacOS/service"', "fixed bundled helper"),
        ('set app_requirement to "=anchor apple generic', "app designated requirement"),
        ("set verify_installed_app to", "outer app verifier"),
        ('quoted form of bundled_service_exec & " != " & quoted form of expected_bundled_service_exec', "fixed helper input equality"),
        ("/usr/bin/codesign --verify --deep --strict --all-architectures -R", "deep all-architecture app verification"),
        ("set verify_current_build_binding to verify_installed_app", "post-copy outer app revalidation"),
        ('/usr/bin/cmp -s " & quoted form of bundled_service_exec & " " & quoted form of service_exec', "deployed helper byte equality"),
        ("/usr/bin/codesign --verify --strict --all-architectures -R", "all-architecture helper verification"),
    ):
        require(install, needle, label)
    install_order = install[install.find("set sh to ") :]
    ordered(
        install_order,
        (
            "reject_symlinks",
            "verify_installed_app",
            "verify_bundled_service_exec",
            "install_service_exec",
            "write_daemon_plist",
            "write_agent_plist",
            "verify_service_exec",
            "verify_current_build_binding",
            "unload_existing_service",
            "load_service",
        ),
        "installer verify/copy/reverify/load transaction",
    )

    for source, needle, label in (
        (sources["requirements"], '<span class="id">R-S11au</span>', "R-S11au requirement"),
        (sources["requirements"], "macOS privileged helper is bound to the current signed app build", "R-S11au title"),
        (sources["requirements"], "<tr><td>169</td>", "Appendix C #169"),
        (sources["hardening"], "R-S11e-61 — macOS privileged helper current-build binding", "R-S11e-61 ledger"),
        (sources["verify"], 'echo "== (3b-iii-d9ck) macOS privileged helper current-build binding (R-S11au/R-S11e-61) =="', "shared source gate"),
        (sources["apple"], 'echo "== (2b-iii-c5a) macOS privileged helper current-build binding (R-S11au/R-S11e-61) =="', "Apple source gate"),
    ):
        require(source, needle, label)


Mutation = Tuple[str, str, str, str]


MUTATIONS: Tuple[Mutation, ...] = (
    ("auth", "MacosCodeSigningFlags::CHECK_ALL_ARCHITECTURES", "MacosCodeSigningFlags::NONE", "all-architecture static validation"),
    ("auth", "validation_flags |= MacosCodeSigningFlags::CHECK_NESTED_CODE;", "validation_flags |= MacosCodeSigningFlags::NONE;", "nested app validation"),
    ("auth", "crate::libc::O_CLOEXEC | crate::libc::O_NOFOLLOW", "crate::libc::O_CLOEXEC", "no-follow helper file open"),
    ("auth", "left_file.metadata()", "fs::metadata(left)", "left descriptor metadata"),
    ("auth", "right_file.metadata()", "fs::metadata(right)", "right descriptor metadata"),
    ("auth", "left_metadata.len() != right_metadata.len()", "false", "helper length proof"),
    ("auth", "left_buffer[..left_read] != right_buffer[..right_read]", "false", "helper byte proof"),
    ("auth", "macos_deployed_helper_matches_installed_app_bytes()\n}", "true\n}", "runtime build binding"),
    ("ipc", "pub(crate) use ipc_auth::macos_deployed_helper_matches_installed_app_bytes;", "// current helper binding removed", "platform status binding"),
    ("macos", "plists_exist && helper_matches_current_app", "plists_exist || helper_matches_current_app", "status conjunction"),
    ("macos", "crate::ipc::macos_deployed_helper_matches_installed_app_bytes(),", "true,", "stale upgrade detection"),
    ("macos", "if current_exe_dir != installed_macos_dir", "if false", "fixed installed app source"),
    ("macos", "metadata.file_type().is_symlink() || !metadata.is_file()", "!metadata.is_file()", "bundled helper symlink rejection"),
    ("macos", "service_artifacts_exist(&daemon_plist_file, &agent_plist_file)", "is_installed_daemon(false)", "partial-state uninstall"),
    ("macos", "fn r_s11e61_macos_service_status_requires_current_helper_bytes()", "fn macos_service_current_state_is_untested()", "focused regression"),
    ("macos", '.replace("/Applications/RustDesk.app", &app_bundle)', '.replace("/Applications/RustDesk.app", "/Applications/RustDesk.app")', "installed-app template binding"),
    ("install", 'set app_requirement to "=anchor apple generic and certificate leaf[subject.OU] = \\"HZF9JMC8YN\\" and identifier \\"com.carriez.rustdesk\\""', 'set app_requirement to "=anchor apple generic and certificate leaf[subject.OU] = \\"HZF9JMC8YN\\" and identifier \\"com.carriez.stale\\""', "pinned installed-app requirement"),
    ("install", 'quoted form of bundled_service_exec & " != " & quoted form of expected_bundled_service_exec', 'quoted form of bundled_service_exec & " = " & quoted form of expected_bundled_service_exec', "fixed helper input"),
    ("install", "--deep --strict --all-architectures", "--strict --all-architectures", "deep app verification"),
    ("install", "set verify_current_build_binding to verify_installed_app", "set verify_current_build_binding to \"\"", "post-copy app validation"),
    ("install", "verify_service_exec & verify_current_build_binding & unload_existing_service", "verify_service_exec & unload_existing_service", "pre-load current build proof"),
    ("requirements", '<span class="id">R-S11au</span>', '<span class="id">R-S11az</span>', "R-S11au requirement"),
    ("requirements", "<tr><td>169</td>", "<tr><td>9169</td>", "Appendix C #169"),
    ("hardening", "R-S11e-61 — macOS privileged helper current-build binding", "R-S11e-61 — stale helper accepted", "R-S11e-61 ledger"),
    ("verify", 'echo "== (3b-iii-d9ck) macOS privileged helper current-build binding (R-S11au/R-S11e-61) =="', 'echo "== (3b-iii-d9ck) macOS stale helper acceptance (R-S11au/R-S11e-61) =="', "shared source gate"),
    ("apple", 'echo "== (2b-iii-c5a) macOS privileged helper current-build binding (R-S11au/R-S11e-61) =="', 'echo "== (2b-iii-c5a) macOS stale helper acceptance (R-S11au/R-S11e-61) =="', "Apple source gate"),
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
        "macOS helper current-build binding semantic validation: OK"
        + (f" ({len(MUTATIONS)} mutations)" if args.self_test else "")
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
