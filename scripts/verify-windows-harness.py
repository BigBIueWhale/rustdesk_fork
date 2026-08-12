#!/usr/bin/env python3
"""Structural, behavioral, and mutation verifier for the Windows build harness."""

from __future__ import annotations

import argparse
import ast
import json
import os
import pathlib
import re
import signal
import subprocess
import sys


class VerificationError(RuntimeError):
    pass


FILES = {
    "buildrs": "build.rs",
    "cargo": "Cargo.toml",
    "portable_build": "libs/portable/build.rs",
    "portable_cargo": "libs/portable/Cargo.toml",
    "resource": "res/windows_resource.rs",
    "host": "scripts/build-windows-vm.sh",
    "lib": "scripts/lib.sh",
    "runtime": "scripts/windows-helper-runtime.sh",
    "closure": "scripts/verify-private-tree-closure.py",
    "publication": "scripts/publish-windows-result.py",
    "offline": "scripts/windows-offline-manifest.py",
    "frb": "scripts/frb-codegen.sh",
    "guest": "scripts/run-build.ps1",
    "build": "scripts/build-windows.ps1",
    "installed_probe": "scripts/windows-installed-service-probe.ps1",
    "installed_result": "scripts/verify-windows-installed-service-result.py",
    "full_peer_result": "scripts/verify-windows-full-peer-presentation-result.py",
    "full_peer_controller": "scripts/windows-full-peer-presentation-controller.ps1",
    "full_peer_fixture": "scripts/windows-full-peer-presentation-fixture.ps1",
    "probe_client": "examples/probe_client.rs",
    "orchestrator": "build.py",
    "pe": "scripts/canonicalize-pe.py",
    "msi": "scripts/canonicalize-msi.py",
    "watch": "scripts/native-codec-watch.sh",
    "port": "res/vcpkg/libvpx/portfile.cmake",
    "metadata": "res/vcpkg/libvpx/vcpkg.json",
    "requirements": "requirements.html",
    "hardening": "HARDENING_STATUS.md",
    "verify": "scripts/verify.sh",
    "ipc": "src/ipc.rs",
    "windows": "src/platform/windows.rs",
    "direct_service": "src/direct_service.rs",
}


def require(source: str, literal: str, description: str) -> None:
    if literal not in source:
        raise VerificationError(f"missing {description}: {literal}")


def require_count(source: str, literal: str, minimum: int, description: str) -> None:
    count = source.count(literal)
    if count < minimum:
        raise VerificationError(
            f"insufficient {description}: found {count}, expected at least {minimum}: {literal}"
        )


def require_exact_count(source: str, literal: str, expected: int, description: str) -> None:
    count = source.count(literal)
    if count != expected:
        raise VerificationError(
            f"invalid {description}: found {count}, expected exactly {expected}: {literal}"
        )


def reject(source: str, pattern: str, description: str) -> None:
    if re.search(pattern, source, re.MULTILINE):
        raise VerificationError(f"forbidden {description}")


def require_order(source: str, literals: tuple[str, ...], description: str) -> None:
    cursor = -1
    for literal in literals:
        location = source.find(literal, cursor + 1)
        if location < 0 or location <= cursor:
            raise VerificationError(f"invalid {description}: {literal}")
        cursor = location


def shell_function(source: str, name: str) -> str:
    match = re.search(rf"(?m)^{re.escape(name)}\(\) \{{\s*$", source)
    if match is None:
        raise VerificationError(f"missing shell function: {name}")
    following = re.search(r"(?m)^[A-Za-z_][A-Za-z0-9_]*\(\) \{\s*$", source[match.end() :])
    end = len(source) if following is None else match.end() + following.start()
    return source[match.start() : end]


def html_requirement(source: str, requirement_id: str) -> str:
    marker = f'<div class="req"><span class="id">{requirement_id}</span>'
    start = source.find(marker)
    if start < 0:
        raise VerificationError(f"missing HTML requirement: {requirement_id}")
    end = source.find("</div></div>", start)
    if end < 0:
        raise VerificationError(f"unterminated HTML requirement: {requirement_id}")
    return source[start : end + len("</div></div>")]


def powershell_function(source: str, name: str) -> str:
    match = re.search(rf"(?mi)^function\s+{re.escape(name)}(?:\([^\n]*\))?\s*\{{\s*$", source)
    if match is None:
        raise VerificationError(f"missing PowerShell function: {name}")
    following = re.search(r"(?mi)^function\s+[A-Za-z_][A-Za-z0-9_-]*", source[match.end() :])
    end = len(source) if following is None else match.end() + following.start()
    return source[match.start() : end]


def parse_python(source: str, name: str) -> ast.Module:
    try:
        return ast.parse(source, filename=name)
    except SyntaxError as exc:
        raise VerificationError(f"invalid Python syntax in {name}: {exc}") from exc


def python_function(tree: ast.Module, name: str) -> ast.FunctionDef:
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise VerificationError(f"missing Python function: {name}")


def require_python_call(
    tree: ast.Module,
    function_name: str,
    called_name: str,
    description: str,
) -> None:
    function = python_function(tree, function_name)
    for node in ast.walk(function):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == called_name:
            return
    raise VerificationError(
        f"missing {description}: {function_name} must call {called_name}"
    )


def require_direct_python_call(
    tree: ast.Module,
    function_name: str,
    called_name: str,
    description: str,
) -> None:
    function = python_function(tree, function_name)
    for statement in function.body:
        if not isinstance(statement, ast.Expr) or not isinstance(statement.value, ast.Call):
            continue
        called = statement.value.func
        if isinstance(called, ast.Name) and called.id == called_name:
            return
    raise VerificationError(
        f"missing {description}: {function_name} must directly call {called_name}"
    )


def reject_ambient_windows_python(source: str) -> None:
    command = re.compile(
        r"(?i)^(?:&\s+)?(?:python(?:3)?(?:\.exe)?|py(?:\.exe)?|pip(?:3)?(?:\.exe)?)(?:\s|$)"
    )
    start_process = re.compile(
        r"(?i)\bStart-Process\s+(?:python(?:3)?(?:\.exe)?|py(?:\.exe)?|pip(?:3)?(?:\.exe)?)(?:\s|$)"
    )
    command_lookup = re.compile(
        r"(?i)^&\s*\(\s*Get-Command\s+(?:python(?:3)?(?:\.exe)?|py(?:\.exe)?|pip(?:3)?(?:\.exe)?)(?:\s|\))"
    )
    pip_module = re.compile(r"(?i)(?:^|\s)-m\s+pip(?:\s|$)")
    for line_number, line in enumerate(source.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if (
            command.search(stripped)
            or start_process.search(stripped)
            or command_lookup.search(stripped)
            or pip_module.search(stripped)
        ):
            raise VerificationError(
                f"scripts/build-windows.ps1:{line_number}: ambient Python/pip invocation: {stripped}"
            )


def validate_powershell_lexically(source: str, name: str) -> None:
    stack: list[tuple[str, int]] = []
    pairs = {")": "(", "]": "[", "}": "{"}
    opening = set(pairs.values())
    state = "normal"
    line = 1
    index = 0
    while index < len(source):
        char = source[index]
        next_char = source[index + 1] if index + 1 < len(source) else ""
        if char == "\n":
            line += 1
            if state == "comment":
                state = "normal"
            index += 1
            continue
        if state == "comment":
            index += 1
            continue
        if state == "block-comment":
            if char == "#" and next_char == ">":
                state = "normal"
                index += 2
            else:
                index += 1
            continue
        if state == "single":
            if char == "'" and next_char == "'":
                index += 2
            elif char == "'":
                state = "normal"
                index += 1
            else:
                index += 1
            continue
        if state == "double":
            if char == chr(96):
                index += 2
            elif char == '"':
                state = "normal"
                index += 1
            else:
                index += 1
            continue
        if state in ("here-single", "here-double"):
            line_start = source.rfind("\n", 0, index) + 1
            if index == line_start:
                terminator = "'@" if state == "here-single" else '"@'
                if source.startswith(terminator, index):
                    state = "normal"
                    index += 2
                    continue
            index += 1
            continue
        if char == "#":
            state = "comment"
        elif char == "<" and next_char == "#":
            state = "block-comment"
            index += 1
        elif char == "'":
            state = "single"
        elif char == '"':
            state = "double"
        elif char == "@" and next_char in ("'", '"'):
            state = "here-single" if next_char == "'" else "here-double"
            index += 1
        elif char in opening:
            stack.append((char, line))
        elif char in pairs:
            if not stack or stack[-1][0] != pairs[char]:
                raise VerificationError(f"{name}:{line}: unbalanced {char}")
            stack.pop()
        index += 1
    if state not in ("normal", "comment"):
        raise VerificationError(f"{name}: unterminated PowerShell lexical state {state}")
    if stack:
        token, token_line = stack[-1]
        raise VerificationError(f"{name}:{token_line}: unclosed {token}")


def validate_port(source: str, metadata_source: str) -> None:
    metadata = json.loads(metadata_source)
    if type(metadata.get("port-version")) is not int or metadata["port-version"] != 1:
        raise VerificationError("libvpx port-version is not integer 1")
    lines = source.splitlines()
    starts = [
        index
        for index, line in enumerate(lines)
        if re.fullmatch(r"\s*vcpkg_extract_source_archive\s*\(\s*SOURCE_PATH\s*", line)
    ]
    if len(starts) != 1:
        raise VerificationError("libvpx extraction block count is not one")
    start = starts[0]
    depth = 0
    end = None
    for index in range(start, len(lines)):
        line = re.sub(r"#.*$", "", lines[index])
        depth += line.count("(") - line.count(")")
        if depth == 0:
            end = index
            break
        if depth < 0:
            raise VerificationError("libvpx extraction block is unbalanced")
    if end is None:
        raise VerificationError("libvpx extraction block is unterminated")
    normalized = [line.strip() for line in lines[start : end + 1] if line.strip()]
    expected = [
        "vcpkg_extract_source_archive(SOURCE_PATH",
        'ARCHIVE "${_libvpx_archive}"',
        "PATCHES",
        '"${_libvpx_security_patch}"',
        "0003-add-uwp-v142-and-v143-support.patch",
        "0004-remove-library-suffixes.patch",
        ")",
    ]
    if normalized != expected:
        raise VerificationError(f"libvpx extraction patch order is not exact: {normalized!r}")


def validate_sources(sources: dict[str, str]) -> None:
    buildrs = sources["buildrs"]
    cargo = sources["cargo"]
    portable_build = sources["portable_build"]
    portable_cargo = sources["portable_cargo"]
    resource = sources["resource"]
    host = sources["host"]
    lib = sources["lib"]
    runtime = sources["runtime"]
    closure = sources["closure"]
    publication = sources["publication"]
    offline = sources["offline"]
    frb = sources["frb"]
    guest = sources["guest"]
    build = sources["build"]
    installed_probe = sources["installed_probe"]
    installed_result = sources["installed_result"]
    full_peer_result = sources["full_peer_result"]
    full_peer_controller = sources["full_peer_controller"]
    full_peer_fixture = sources["full_peer_fixture"]
    probe_client = sources["probe_client"]
    orchestrator = sources["orchestrator"]
    pe = sources["pe"]
    msi = sources["msi"]
    watch = sources["watch"]
    requirements = sources["requirements"]
    hardening = sources["hardening"]
    verify = sources["verify"]
    ipc = sources["ipc"]
    windows = sources["windows"]
    direct_service = sources["direct_service"]

    orchestrator_tree = parse_python(orchestrator, "build.py")
    publication_tree = parse_python(publication, "scripts/publish-windows-result.py")
    offline_tree = parse_python(offline, "scripts/windows-offline-manifest.py")
    pe_tree = parse_python(pe, "scripts/canonicalize-pe.py")
    msi_tree = parse_python(msi, "scripts/canonicalize-msi.py")
    installed_result_tree = parse_python(
        installed_result, "scripts/verify-windows-installed-service-result.py"
    )
    parse_python(
        full_peer_result, "scripts/verify-windows-full-peer-presentation-result.py"
    )

    require(cargo, "windows-full-peer-presentation-probe = []", "non-default Windows full-peer probe feature")
    default_feature_line = re.search(r'(?m)^default\s*=\s*\[(.*)\]$', cargo)
    if default_feature_line is None or "windows-full-peer-presentation-probe" in default_feature_line.group(1):
        fail("Windows full-peer presentation probe feature is absent from or present in the default feature line")
    for source, description in (
        (direct_service, "direct listener"),
        (build, "Windows build"),
    ):
        require(source, "windows-full-peer-presentation-probe", f"{description} probe-feature binding")
    require(
        direct_service,
        "std::net::SocketAddr::from(([127, 0, 0, 1], port as u16))",
        "compile-time exact-loopback full-peer listener",
    )
    require_order(
        build,
        ("function Emit-Artifacts", "function Build-FullPeerPresentationProbe", "Emit-Artifacts\nBuild-FullPeerPresentationProbe"),
        "release artifact completion before separate full-peer bundle build",
    )
    for literal, description in (
        ("release dist inventory or bytes", "release-dist post-probe hash assertion"),
        ("--features 'flutter,windows-full-peer-presentation-probe'", "exact probe feature build"),
        ("build.py --flutter --skip-cargo", "probe Flutter bundle build against exact probe DLL"),
        ("probe_listener_policy = '127.0.0.1:21118'", "probe receipt loopback policy"),
        (
            "$actualDistNames = @($distBefore.Keys | Sort-Object -CaseSensitive)",
            "order-independent case-sensitive actual release-dist set",
        ),
        (
            "$canonicalDistNames = @($expectedDistNames | Sort-Object -CaseSensitive)",
            "order-independent case-sensitive expected release-dist set",
        ),
        (
            "if (($actualDistNames -join ',') -cne ($canonicalDistNames -join ',')) {",
            "case-sensitive canonical release-dist set comparison",
        ),
    ):
        require(build, literal, description)
    for literal, description in (
        ("GetExtendedTcpTable", "native TCP owner-table observation"),
        ("Assert-TcpSessionUnchanged", "uninterrupted TCP session gate"),
        ("$liveRows.Count -ne 3", "exact one-listener/one-session TCP surface"),
        ("$preexistingPortRows.Count -ne 0", "initially empty probe port"),
        ("the real viewer window process is not the exact TCP-owning process generation", "viewer window/TCP process generation binding"),
        ("probe bundle process survived exact cleanup", "exact-bundle process retirement"),
        ("Find-PasswordEdit", "real password-dialog automation"),
        ("for ($index = 0; $index -lt 120; $index++)", "one-hundred-twenty-frame focus stimulus"),
        ("$unfocusedDuration -lt 60000", "sixty-second focus stimulus duration"),
        ("$minimizedDuration -lt 10000", "ten-second minimized stimulus duration"),
        ("minimized_duration_ms = $minimizedDuration", "measured minimized-duration receipt"),
        ("Wait-FileIntegerAtLeast $movePath ($moveBefore + 1)", "non-overlapping mapped-pointer proof"),
        ("unfocused_updates", "unfocused visual freshness evidence"),
        ("minimize_restore", "minimize/restore freshness evidence"),
        ("remote_input_delivered", "real remote-input evidence"),
    ):
        require(full_peer_controller, literal, description)
    reject(full_peer_controller, r"(?<!127\.)0\.0\.0\.0:21118", "wildcard full-peer listener")
    reject(full_peer_controller, r"mouse_event", "same-desktop click as remote-input evidence")
    require(full_peer_fixture, "$form.TopMost = $true", "unoccluded controlled-screen fixture")
    require(full_peer_fixture, "$panel.Add_MouseMove($mouseMoveHandler)", "source-side remote pointer observation")
    require(
        host,
        "source=$SOURCE_SNAPSHOT/scripts/verify-windows-full-peer-presentation-result.py,target=/authority/verify.py,readonly",
        "immutable host-side full-peer result verifier",
    )
    require(
        shell_function(host, "validate_guest_progress"),
        'full_peer_markers[0] != "windows-full-peer-presentation-controller.ps1 exit=0"',
        "full-peer guest completion marker",
    )
    require_order(
        guest,
        (
            'Mark "windows-full-peer-presentation-controller.ps1 exit=$fullPeerExit"',
            "installed-SCM transaction intentionally leaves its LocalSystem service listening",
            'Mark "windows-installed-service-probe.ps1 exit=$installedServiceExit"',
        ),
        "portable full-peer listener retirement before installed LocalSystem listener",
    )
    for literal, description in (
        ("range(120)", "closed verifier frame inventory"),
        ('len(updates) != 120', "closed verifier exact frame count"),
        ('60_000,\n        300_000,', "closed verifier sustained-duration floor"),
        ('typed_int(restore["minimized_duration_ms"], 10_000, 300_000', "closed verifier minimized-duration floor"),
    ):
        require(full_peer_result, literal, description)

    for manifest in (cargo, portable_cargo):
        reject(manifest, r"(?m)^\[package[.]metadata[.]winres\]$", "HashMap-generated Windows version metadata")
        reject(manifest, r"(?m)^winres\s*=", "winres build dependency")
    for source in (buildrs, portable_build, resource):
        reject(source, r"winres::WindowsResource|[.]set_(?:icon|manifest_file|resource_file)\(", "winres resource path")
    require(
        buildrs,
        "windows_resource::compile(version, &resource_root)",
        "shared root Windows resource producer",
    )
    reject(
        buildrs,
        r'#\[cfg\(all\(windows,\s*feature\s*=\s*"inline"\)\)\]\s*(?:fn build_manifest|build_manifest\(&version\)\?;)',
        "feature-gated root Windows resource producer",
    )
    require(
        buildrs,
        '#[cfg(windows)]\nfn build_manifest(version: &str) -> Result<(), Box<dyn Error>>',
        "all-Windows root resource producer definition",
    )
    require(
        buildrs,
        '#[cfg(windows)]\n    build_manifest(&version)?;',
        "all-Windows root resource producer invocation",
    )
    require(
        portable_build,
        'windows_resource::compile(env!("CARGO_PKG_VERSION"), resource_root)',
        "shared portable Windows resource producer",
    )
    require_count(resource, ".parse::<u16>()?;", 3, "bounded Windows numeric version fields")
    for literal, description in (
        ('env::var_os("RUSTDESK_LLVM_RC")', "explicit LLVM resource producer environment"),
        ("Command::new(&llvm_rc)", "direct LLVM resource compiler invocation"),
        ('.arg("-no-preprocess")', "resource preprocessing prohibition"),
        ('.arg("-C65001")', "explicit resource UTF-8 code page"),
        ('println!("cargo:rustc-link-lib=dylib=resource")', "compiled resource link directive"),
        ("LLVM resource compiler changed its ordered RC input", "ordered RC input stability check"),
    ):
        require(resource, literal, description)
    require_order(
        resource,
        (
            'VALUE "FileDescription", "RustDesk Remote Desktop"',
            'VALUE "FileVersion", "{version}"',
            'VALUE "LegalCopyright", "Copyright © 2025 Purslane Ltd. All rights reserved."',
            'VALUE "OriginalFilename", "rustdesk.exe"',
            'VALUE "ProductName", "RustDesk"',
            'VALUE "ProductVersion", "{version}"',
            'VALUE "Translation", 0x0409, 0x04b0',
            '1 ICON "res/icon.ico"',
            '1 24 "res/manifest.xml"',
        ),
        "canonical Windows VERSIONINFO/icon/manifest resource order",
    )
    require(buildrs, "build_manifest(&version)?;", "fallible ordered Windows resource build")
    require(build, "function Assert-DeterministicWindowsResource", "native ordered Windows resource gate")
    require(
        build,
        "Windows resource entry is absent or out of canonical order",
        "native ordered Windows resource rejection",
    )
    require(
        build,
        "    Assert-PowerShellSourceParsing\n    Assert-DeterministicWindowsResource",
        "native ordered Windows resource preflight",
    )
    for literal, description in (
        ("$LLVM_RC_EXE     = 'C:\\Program Files\\LLVM\\bin\\llvm-rc.exe'", "pinned llvm-rc path"),
        ("$LLVM_READOBJ_EXE = 'C:\\Program Files\\LLVM\\bin\\llvm-readobj.exe'", "pinned llvm-readobj path"),
        ("$LLVM_RC_SHA256  = 'f1c4e01ae6214be7e1326e6290ee96b3cd7d36e690f400a16b5e33ad3aa36f29'", "pinned llvm-rc digest"),
        ("function Assert-CompiledWindowsResource", "compiled Windows resource validator"),
        ("Find-ByteSequence $bytes $needle", "compiled VERSIONINFO order check"),
        ("Resource type (int): MANIFEST (ID 24)", "compiled manifest resource gate"),
        ("Assert-CompiledWindowsResource $applicationResource 'RustDesk library'", "library compiled-resource gate"),
        ("Assert-CompiledWindowsResource $portableResource 'RustDesk portable packer'", "portable compiled-resource gate"),
        ("Assert-WindowsExecutableVersionInfo $rustLibrary $applicationVersion 'RustDesk library'", "library linked VERSIONINFO gate"),
        ("Assert-WindowsExecutableVersionInfo $setupOut $portableVersion 'RustDesk portable packer'", "portable linked VERSIONINFO gate"),
        ("$applicationResourceHash -cne $portableResourceHash", "cross-crate compiled resource digest comparison"),
        ("root and portable crates did not emit one exact compiled Windows resource", "cross-crate compiled resource equality"),
    ):
        require(build, literal, description)

    require(cargo, '"Win32_System_SystemServices",', "Windows SystemServices feature")
    require(
        windows,
        "System::SystemServices::SECURITY_DESCRIPTOR_REVISION",
        "Windows SystemServices security-descriptor import",
    )
    require(
        windows,
        "ReplaceFileW as WinReplaceFileW",
        "unambiguous windows-rs ReplaceFileW import",
    )
    require(
        windows,
        "REPLACEFILE_WRITE_THROUGH as WIN_REPLACEFILE_WRITE_THROUGH",
        "unambiguous windows-rs ReplaceFileW flag import",
    )
    require(
        windows,
        "PIPE_ACCESS_DUPLEX, REPLACEFILE_WRITE_THROUGH as WIN_REPLACEFILE_WRITE_THROUGH",
        "FileSystem-owned named-pipe access import",
    )
    require(
        windows,
        "WinHLOCAL(self.0 .0 as *mut std::ffi::c_void)",
        "windows-rs HLOCAL pointer type",
    )
    require(
        windows,
        "OnceLock::<ServiceStatusHandle>::new()",
        "explicit Windows service status slot type",
    )
    require(
        windows,
        "mpsc::channel::<WindowsServiceSasRequest>(1)",
        "explicit Windows service SAS channel type",
    )
    require_count(
        windows,
        "incoming: &mut Option<parity_tokio_ipc::Incoming>",
        2,
        "refreshable Windows service listener ownership",
    )
    require_count(
        windows,
        "let previous = incoming\n        .take()",
        2,
        "Windows service listener close-before-rebind",
    )
    require_count(
        windows,
        "*incoming = Some(ipc::new_listener(",
        2,
        "Windows service listener restoration",
    )
    require(
        windows,
        "pub(crate) struct WindowsPathIdentity",
        "cross-module Windows path identity visibility",
    )
    require(
        verify,
        "refresh_service_ipc_listener(&mut incoming).await",
        "current Windows service listener source gate",
    )

    for source, name in ((host, "build-windows-vm.sh"), (frb, "frb-codegen.sh")):
        reject(source, r"\|\|\s*true", f"masked status in {name}")
        reject(source, r"guestfish[^\n]*\|", f"piped guestfish status in {name}")
    launch_domain = shell_function(host, "launch_domain")
    process_identity = shell_function(host, "process_identity")
    owned_process_matches = shell_function(host, "owned_process_matches")
    wait_for_owned_process_group = shell_function(host, "wait_for_owned_process_group")
    owned_process_is_live = shell_function(host, "owned_process_is_live")
    owned_process_group_is_live = shell_function(host, "owned_process_group_is_live")
    stop_owned_process = shell_function(host, "stop_owned_process")
    virsh_bounded = shell_function(host, "virsh_bounded")
    domain_name_is_listed = shell_function(host, "domain_name_is_listed")
    domain_uuid_is_listed = shell_function(host, "domain_uuid_is_listed")
    require_domain_identity_absent = shell_function(host, "require_domain_identity_absent")
    prove_owned_domain = shell_function(host, "prove_owned_domain")
    clear_domain_authority = shell_function(host, "clear_domain_authority")
    stop_and_undefine_owned_domain = shell_function(
        host, "stop_and_undefine_owned_domain"
    )
    verify_domain_xml = shell_function(host, "verify_domain_xml")
    wait_for_domain = shell_function(host, "wait_for_domain")
    path_disjointness = shell_function(host, "assert_disjoint_paths")
    preflight = shell_function(host, "preflight")
    snapshot_golden = shell_function(host, "snapshot_golden")
    verify_private_golden = shell_function(host, "verify_private_golden")
    write_manifest = shell_function(host, "write_manifest")
    write_offline_manifest = shell_function(host, "write_offline_manifest")
    verify_wix_nuget_packages = shell_function(host, "verify_wix_nuget_packages")
    build_offline_media = shell_function(host, "build_offline_media")
    build_pass_media = shell_function(host, "build_pass_media")
    prepare_overlay = shell_function(host, "prepare_overlay")
    extract_and_validate = shell_function(host, "extract_and_validate")
    host_main = shell_function(host, "main")
    run_root_identity = shell_function(host, "record_run_root_identity")
    output_parent_identity = shell_function(host, "record_output_parent_identity")
    exact_private_root_removal = shell_function(host, "remove_private_root_exact")
    completed_run_root_removal = shell_function(host, "remove_completed_run_root")
    publish_result = shell_function(host, "publish_result")
    cleanup = shell_function(host, "cleanup")
    harness_self_test = shell_function(host, "harness_self_test")
    run_root_cleanup_self_test = shell_function(host, "run_root_cleanup_self_test")

    require(host, "CREATE_TIMEOUT_SECONDS=300", "five-minute VM creation bound")
    require(host, "CONTROL_TIMEOUT_SECONDS=30", "bounded libvirt control timeout")
    require(host, "PROCESS_ADMISSION_SECONDS=10", "bounded process-group admission timeout")
    require(host, "PROCESS_STOP_SECONDS=10", "bounded process-group stop timeout")
    require(host, "export LC_ALL=C", "fixed libvirt control locale")
    require(
        preflight,
        "require_cmd qemu-img virt-install virsh xorriso git python3 realpath "
        "sha256sum sha512sum timeout setsid awk",
        "exact Windows domain lifecycle command preflight",
    )
    require(host, 'RUN_ROOT="$(mktemp -d "$STATE_DIR/windows-build-$RUN_ID.XXXXXXXX")"', "unique private run state")
    require(host, 'CURRENT_DOMAIN_UUID="$(</proc/sys/kernel/random/uuid)"', "kernel domain UUID")
    require(
        launch_domain,
        'setsid --wait virt-install --connect qemu:///session --name "$CURRENT_DOMAIN" --uuid "$CURRENT_DOMAIN_UUID"',
        "owned session/process-group virt-install",
    )
    require(host, "VM_TIMEOUT_SECONDS=7200", "two-hour VM bound")
    for literal, description in (
        ("ss -H -ltn 'sport = :53'", "host preflight scoped TCP DNS query"),
        ("ss -H -lun 'sport = :53'", "host preflight scoped UDP DNS query"),
        ("ss -H -lun 'sport = :67'", "host preflight scoped UDP DHCP query"),
        ("never request process ownership", "host preflight process-metadata exclusion"),
    ):
        require(lib, literal, description)
    reject(
        lib,
        r"(?m)^[^#\n]*\$\(ss\s+-\S*p\S*(?:\s|$)",
        "host listener process-ownership inspection",
    )
    require(host, "IFS=' ' read -r uptime _ </proc/uptime", "monotonic clock")
    require(host, "trap cleanup EXIT", "EXIT cleanup")
    for status in (129, 130, 143):
        require(host, f"signal_exit {status}", f"signal cleanup status {status}")
    require(path_disjointness, '[ "$first" != / ] && [ "$second" != / ]', "filesystem-root path rejection")
    require(path_disjointness, '[ "$first" != "$second" ]', "unequal Windows state/output paths")
    require(
        path_disjointness,
        '"$second/"*) die "$first_label must not be beneath $second_label" ;;',
        "Windows state/output descendant rejection",
    )
    require(
        path_disjointness,
        '"$first/"*) die "$second_label must not be beneath $first_label" ;;',
        "Windows state/output ancestor rejection",
    )
    require_order(
        preflight,
        (
            'planned_state="$(realpath -m -- "$STATE_DIR")"',
            'planned_output="$(realpath -m -- "$OUT_DIR")"',
            'assert_disjoint_paths "$planned_state"',
            'mkdir -p "$STATE_DIR"',
            'STATE_DIR="$(realpath -e "$STATE_DIR")"',
            'OUT_DIR="$OUT_PARENT/$(basename "$OUT_DIR")"',
            "record_output_parent_identity",
            'assert_disjoint_paths "$STATE_DIR"',
            '{ [ ! -e "$OUT_DIR" ] && [ ! -L "$OUT_DIR" ]; }',
        ),
        "pre-creation and post-canonicalization Windows path disjointness",
    )
    for literal, description in (
        (
            'metadata="$(/usr/bin/stat -c \'%u:%g:%a:%d:%i\' -- "$OUT_PARENT" 2>/dev/null)"',
            "output-parent ownership and identity sample",
        ),
        ('[ "$owner" = "$WINDOWS_HELPER_BUILD_UID" ]', "output-parent owner proof"),
        ('[ "$group" = "$WINDOWS_HELPER_BUILD_GID" ]', "output-parent group proof"),
        (
            '[ $((8#$mode & 8#7022)) -eq 0 ]',
            "output-parent special/group/world-write rejection",
        ),
        ('OUT_PARENT_ID="$device:$inode"', "retained output-parent device/inode"),
    ):
        require(output_parent_identity, literal, description)
    for description in (
        "Windows path-disjointness self-test accepted equal paths",
        "Windows path-disjointness self-test accepted output beneath state",
        "Windows path-disjointness self-test accepted state beneath output",
        "Windows path-disjointness self-test accepted the filesystem root",
    ):
        require(host, description, description)
    require(
        process_identity,
        '''printf '%s %s %s %s\\n' "$1" "${20}" "$3" "$4"''',
        "state/start/process-group/session identity sample",
    )
    require(
        process_identity,
        'stat="${stat##*) }"',
        "robust retained-leader proc-stat boundary",
    )
    require(
        owned_process_group_is_live,
        'stat="${stat##*) }"',
        "robust process-group proc-stat boundary",
    )
    require(
        owned_process_group_is_live,
        '[ "$group" = "$CURRENT_VIRT_PID" ] \\\n'
        '            && [ "$session" = "$CURRENT_VIRT_PID" ]',
        "complete retained process-group/session scan",
    )
    require(
        owned_process_group_is_live,
        '[ "$state" != Z ] && [ "$state" != X ]',
        "complete retained live-descendant scan",
    )
    for body, description in (
        (owned_process_matches, "owned process identity gate"),
        (owned_process_is_live, "owned live-process identity gate"),
    ):
        require(body, '[ "$start" = "$CURRENT_VIRT_START" ]', f"start time in {description}")
        require(body, '[ "$group" = "$CURRENT_VIRT_PID" ]', f"process group in {description}")
        require(body, '[ "$session" = "$CURRENT_VIRT_PID" ]', f"session in {description}")
    for literal, description in (
        (
            'deadline=$(( $(monotonic_seconds) + PROCESS_ADMISSION_SECONDS ))',
            "monotonic process-group admission deadline",
        ),
        (
            '[ "$start" = "$CURRENT_VIRT_START" ] || return 1',
            "admission start-identity refusal",
        ),
        (
            '[ "$state" != Z ] && [ "$state" != X ] || return 1',
            "admission live-state refusal",
        ),
        (
            'if [ "$group" = "$CURRENT_VIRT_PID" ] \\\n'
            '            && [ "$session" = "$CURRENT_VIRT_PID" ]; then',
            "admission group/session proof",
        ),
        (
            '[ "$(monotonic_seconds)" -lt "$deadline" ] || return 1',
            "admission deadline refusal",
        ),
    ):
        require(wait_for_owned_process_group, literal, description)
    require(
        launch_domain,
        "wait_for_owned_process_group \\\n"
        '        || die "could not prove virt-install process-group admission"',
        "post-launch process-group admission",
    )
    require(owned_process_is_live, '[ "$state" != Z ] && [ "$state" != X ]', "exited child detection")
    require(stop_owned_process, 'kill -TERM -- "-$CURRENT_VIRT_PID"', "owned group TERM")
    require(stop_owned_process, 'kill -KILL -- "-$CURRENT_VIRT_PID"', "owned group KILL fallback")
    require_order(
        stop_owned_process,
        (
            'kill -KILL -- "-$CURRENT_VIRT_PID"',
            'wait "$CURRENT_VIRT_PID" 2>/dev/null || :',
            'deadline=$(( $(monotonic_seconds) + PROCESS_STOP_SECONDS ))',
        ),
        "KILL leader reap before final process-group drain",
    )
    require(
        stop_owned_process,
        '[ ! -e "/proc/$CURRENT_VIRT_PID" ] || return 1',
        "reused leader identity refusal",
    )
    require_count(
        stop_owned_process,
        "owned_process_group_is_live",
        6,
        "complete process-group drain",
    )
    require_count(
        stop_owned_process,
        'deadline=$(( $(monotonic_seconds) + PROCESS_STOP_SECONDS ))',
        2,
        "TERM/KILL deadlines",
    )
    require(virsh_bounded, "setsid --wait \\\n", "detached bounded virsh")
    require(
        virsh_bounded,
        'virsh --connect qemu:///session "$@" </dev/null',
        "closed virsh input",
    )
    require(
        virsh_bounded,
        'setsid --wait \\\n'
        '        timeout --foreground --kill-after=2 "$CONTROL_TIMEOUT_SECONDS" \\\n'
        '        virsh --connect qemu:///session "$@" </dev/null',
        "bounded fixed-session noninteractive libvirt control wrapper",
    )
    direct_virsh = re.findall(r"(?m)^[ \t]*virsh(?:[ \t]|$)", host)
    if len(direct_virsh) != 1:
        raise VerificationError(
            f"libvirt calls do not all pass through virsh_bounded: found {len(direct_virsh)} direct invocations"
        )
    require_order(
        launch_domain,
        (
            'CURRENT_DOMAIN_UUID="$(</proc/sys/kernel/random/uuid)"',
            'assert_uuid "$CURRENT_DOMAIN_UUID"',
            '[[ "$CURRENT_DOMAIN" =~ ^[A-Za-z0-9._-]+$ ]]',
            'CURRENT_VM_DEADLINE=$(( $(monotonic_seconds) + VM_TIMEOUT_SECONDS ))',
            "require_domain_identity_absent",
            "CURRENT_DOMAIN_CREATION_STARTED=1",
            "setsid --wait virt-install",
            '--uuid "$CURRENT_DOMAIN_UUID"',
            "CURRENT_VIRT_PID=$!",
            'CURRENT_VIRT_START="$(process_start_time "$CURRENT_VIRT_PID")"',
            "wait_for_owned_process_group",
            'deadline=$(( $(monotonic_seconds) + CREATE_TIMEOUT_SECONDS ))',
            "stop_owned_process",
            "domain_uuid_is_listed",
            "prove_owned_domain",
            "verify_domain_xml",
            "CURRENT_DOMAIN_OWNERSHIP_COMMITTED=1",
            'virsh_bounded domstate "$CURRENT_DOMAIN_UUID"',
        ),
        "UUID absence, creation intent, launch, ownership, and state order",
    )
    require(wait_for_domain, 'if [ "$(monotonic_seconds)" -ge "$CURRENT_VM_DEADLINE" ]; then', "VM deadline test")
    require(
        wait_for_domain,
        "stop_and_undefine_owned_domain || die \"timed-out domain could not be destroyed and undefined safely\"",
        "deadline domain termination",
    )
    require(
        domain_name_is_listed,
        'names="$(virsh_bounded list --all --name)" || return 2',
        "fail-closed domain-name enumeration",
    )
    require(
        domain_uuid_is_listed,
        'uuids="$(virsh_bounded list --all --uuid)" || return 2',
        "fail-closed domain-UUID enumeration",
    )
    require(
        require_domain_identity_absent,
        "generated domain name already exists; refusing to mutate it",
        "pre-existing domain-name refusal",
    )
    require(
        require_domain_identity_absent,
        "generated domain UUID already exists; refusing to mutate it",
        "pre-existing domain-UUID refusal",
    )
    require(
        prove_owned_domain,
        'actual_name="$(virsh_bounded domname "$CURRENT_DOMAIN_UUID" 2>/dev/null)"',
        "UUID-addressed secondary name proof",
    )
    for state_assignment, description in (
        ('CURRENT_DOMAIN=""', "terminal clearing of domain name"),
        ('CURRENT_DOMAIN_UUID=""', "terminal clearing of domain UUID"),
        ("CURRENT_DOMAIN_CREATION_STARTED=0", "terminal clearing of creation intent"),
        (
            "CURRENT_DOMAIN_OWNERSHIP_COMMITTED=0",
            "terminal clearing of ownership commit",
        ),
        ('CURRENT_VM_DEADLINE=""', "terminal clearing of VM deadline"),
    ):
        require(
            clear_domain_authority,
            state_assignment,
            description,
        )
    require(
        stop_and_undefine_owned_domain,
        'if [ "$CURRENT_DOMAIN_CREATION_STARTED" = 0 ]; then',
        "no-launch no-domain-authority branch",
    )
    require(
        stop_and_undefine_owned_domain,
        'if [ "$CURRENT_DOMAIN_OWNERSHIP_COMMITTED" = 0 ]; then',
        "pre-commit no-destructive-authority branch",
    )
    require(
        stop_and_undefine_owned_domain,
        "uncommitted provision UUID exists after an ambiguous launch; preserving it",
        "ambiguous launch preservation",
    )
    require(
        stop_and_undefine_owned_domain,
        "owned UUID exists under an unexpected name; preserving run state",
        "unexpected-name UUID preservation",
    )
    require_exact_count(
        stop_and_undefine_owned_domain,
        'virsh_bounded destroy "$CURRENT_DOMAIN_UUID"',
        1,
        "UUID-addressed destroy",
    )
    require_exact_count(
        stop_and_undefine_owned_domain,
        'virsh_bounded undefine "$CURRENT_DOMAIN_UUID" --nvram',
        1,
        "UUID-addressed undefine",
    )
    require(
        verify_domain_xml,
        'virsh_bounded dumpxml "$CURRENT_DOMAIN_UUID"',
        "UUID-addressed domain XML proof",
    )
    for literal, description in (
        ('root.findall("./devices/interface")', "zero-interface domain XML proof"),
        ('graphic.get("type") != "vnc"', "exact VNC graphics type proof"),
        ('graphic.get("listen") != "127.0.0.1"', "loopback VNC graphics proof"),
        ('listeners[0].get("address") != "127.0.0.1"', "loopback VNC listen-child proof"),
    ):
        require(verify_domain_xml, literal, description)
    require_count(
        host,
        'virsh_bounded domstate "$CURRENT_DOMAIN_UUID"',
        5,
        "UUID-addressed domain state controls",
    )
    for forbidden, description in (
        ('virsh_bounded domuuid "$CURRENT_DOMAIN"', "name-addressed UUID lookup"),
        ('virsh_bounded dumpxml "$CURRENT_DOMAIN"', "name-addressed XML lookup"),
        ('virsh_bounded domstate "$CURRENT_DOMAIN"', "name-addressed state control"),
        ('virsh_bounded destroy "$CURRENT_DOMAIN"', "name-addressed destroy"),
        ('virsh_bounded undefine "$CURRENT_DOMAIN"', "name-addressed undefine"),
        ("domain_uuid_now", "legacy split name-to-UUID lookup"),
        ("virsh -c qemu:///session", "legacy interactive virsh wrapper"),
        ("--no-pkttyagent", "post-libvirt-10 virsh option"),
    ):
        if forbidden in host:
            raise VerificationError(f"forbidden {description}: {forbidden}")
    require_order(
        cleanup,
        (
            "stop_owned_process",
            "stop_and_undefine_owned_domain",
            "windows_helper_authority_close",
            "remove_completed_run_root",
        ),
        "process-before-domain-before-helper-before-state terminal cleanup",
    )
    require(
        cleanup,
        "elif ! stop_and_undefine_owned_domain; then",
        "domain cleanup blocked by inconclusive process cleanup",
    )
    require(
        cleanup,
        '[ "$RUN_COMPLETE" = 1 ] && [ "$CLEANUP_FAILED" = 0 ]',
        "completed clean transaction before run-state cleanup",
    )
    require(
        cleanup,
        "preserving Windows harness state because exact private-tree cleanup failed",
        "run-state cleanup failure preservation",
    )
    for forbidden, description in (
        ('chmod -R u+rwX "$RUN_ROOT"', "recursive run-state permission mutation"),
        ('rm -rf -- "$RUN_ROOT"', "recursive pathname run-state deletion"),
    ):
        if forbidden in cleanup:
            raise VerificationError(f"forbidden {description}: {forbidden}")
    for literal, description in (
        ('resolved="$(/usr/bin/readlink -f -- "$RUN_ROOT" 2>/dev/null)"',
         "canonical run-root proof"),
        ('metadata="$(/usr/bin/stat -c \'%u:%g:%a:%d:%i\' -- "$RUN_ROOT" 2>/dev/null)"',
         "run-root ownership and identity sample"),
        ('[ "$owner" = "$WINDOWS_HELPER_BUILD_UID" ]',
         "run-root owner proof"),
        ('[ "$group" = "$WINDOWS_HELPER_BUILD_GID" ]',
         "run-root group proof"),
        ('[ "$mode" = 700 ]',
         "run-root private mode proof"),
        ('RUN_ROOT_ID="$device:$inode"', "retained run-root device/inode"),
    ):
        require(run_root_identity, literal, description)
    require(
        exact_private_root_removal,
        "/usr/bin/env -i PATH=/usr/bin:/bin",
        "closed run-root cleanup environment",
    )
    require(
        exact_private_root_removal,
        '/usr/bin/python3 -I -S "$LIB_DIR/verify-private-tree-closure.py"',
        "isolated descriptor-safe run-root closer",
    )
    require(
        exact_private_root_removal,
        '--remove-private-root "$1" --expected-identity "$2"',
        "identity-bound run-root removal dispatch",
    )
    require_order(
        completed_run_root_removal,
        (
            '[ -n "$RUN_ROOT" ] && [ -n "$RUN_ROOT_ID" ]',
            'remove_private_root_exact "$RUN_ROOT" "$RUN_ROOT_ID"',
            '[ ! -e "$RUN_ROOT" ] && [ ! -L "$RUN_ROOT" ]',
            'RUN_ROOT=""',
            'RUN_ROOT_ID=""',
        ),
        "exact run-root retirement before authority clearing",
    )
    require_order(
        host_main,
        (
            'RUN_ROOT="$(mktemp -d "$STATE_DIR/windows-build-$RUN_ID.XXXXXXXX")"',
            "record_run_root_identity",
            'assert_safe_path "$RUN_ROOT" "private Windows run state"',
        ),
        "production run-root creation and identity binding",
    )
    require_order(
        harness_self_test,
        (
            'RUN_ROOT="$(mktemp -d /tmp/rustdesk-windows-harness-test.XXXXXXXX)"',
            'chmod 0700 "$RUN_ROOT"',
            "record_run_root_identity",
            "run_root_cleanup_self_test",
            "RUN_COMPLETE=1",
        ),
        "self-test run-root binding and substitution fixture",
    )
    for literal, description in (
        ('mv -- "$edge" "$retained"', "run-root replacement fixture"),
        ('remove_private_root_exact "$edge" "$original_id"',
         "wrong-identity cleanup rejection fixture"),
        ("run-root substitution self-test deleted a replacement edge",
         "replacement-deletion failure marker"),
        ('[ -f "$retained/created.txt" ] && [ -f "$edge/replacement.txt" ]',
         "created and replacement identity preservation proof"),
        ('remove_private_root_exact "$edge" "$replacement_id"',
         "independent replacement retirement"),
        ('remove_private_root_exact "$retained" "$original_id"',
         "independent created-tree retirement"),
    ):
        require(run_root_cleanup_self_test, literal, description)
    require_exact_count(
        host,
        "record_run_root_identity",
        3,
        "one run-root identity function and two creation bindings",
    )
    for literal, description in (
        ('modes.add_argument("--remove-private-root")',
         "private-tree exact-root removal mode"),
        ("private-tree root edge changed",
         "private-tree root edge-substitution refusal"),
        ("private-tree cleanup crosses a mount boundary",
         "private-tree mount-boundary refusal"),
        ("private tree contains a non-directory inode linked outside its boundary",
         "private-tree external-link refusal"),
        ("private-tree root removal did not consume its authenticated edge",
         "private-tree terminal edge-consumption proof"),
    ):
        require(closure, literal, description)
    require(host, "--network none", "networkless VM")
    require(host, "--graphics vnc,listen=127.0.0.1", "loopback-only Windows VM console")
    for literal, description in (
        (
            "'sleep 1; exec setsid --wait bash -c \"$1\"'",
            "delayed process-group admission fixture",
        ),
        (
            "delayed process-group fixture skipped its pre-admission state",
            "pre-admission refusal fixture",
        ),
        (
            "PROCESS_ADMISSION_SECONDS=3",
            "bounded delayed-admission fixture",
        ),
        (
            "delayed process-group fixture did not admit conclusively",
            "delayed-admission completion fixture",
        ),
    ):
        require(harness_self_test, literal, description)

    exact_domain_requirement = html_requirement(requirements, "R-S11ds")
    for literal, description in (
        (
            "Windows per-build VM owns one exact libvirt UUID from creation through terminal teardown",
            "R-S11ds requirement title",
        ),
        (
            "A selected UUID, creation intent, or unadmitted child alone",
            "normative ownership-commit boundary",
        ),
        (
            "every guest-specific post-create read or control",
            "normative UUID-only post-create control",
        ),
        (
            "use the fixed <code>qemu:///session</code> URI, C locale, one fresh "
            "<code>setsid</code> control session with standard input closed",
            "normative version-compatible noninteractive control",
        ),
        (
            "MUST NOT</span> require the post-libvirt-10.0.0 "
            "<code>--no-pkttyagent</code> option",
            "normative unsupported virsh option prohibition",
        ),
        (
            "complete retained matching client process group and session",
            "normative complete client-process authority",
        ),
        (
            "boundedly re-prove that same live identity",
            "normative process-group admission",
        ),
        (
            "unadmitted child alone",
            "normative pre-admission authority refusal",
        ),
        (
            "MUST NOT</span> request storage deletion",
            "normative storage-deletion prohibition",
        ),
        (
            "without invoking the Windows builder, <code>virt-install</code>, "
            "<code>virsh</code>, libvirt, KVM, a Windows VM",
            "source-only verification boundary",
        ),
    ):
        require(exact_domain_requirement, literal, description)
    require(requirements, "<tr><td>272</td>", "Appendix C #272 disposition")
    require(requirements, "<tr><td>291</td>", "Appendix C #291 disposition")
    require(requirements, "<tr><td>336</td>", "Appendix C #336 disposition")
    require(
        hardening,
        "R-S11ds/R-S11e-137 — Windows per-build VM owns one exact libvirt UUID",
        "R-S11ds hardening-ledger disposition",
    )
    require(
        hardening,
        "R-S11dr/R-S11ds/R-S11e-170 — exact setsid process-group admission",
        "setsid-admission hardening-ledger disposition",
    )
    require(
        hardening,
        "R-S11dr/R-S11ds/R-S11e-214 — version-compatible noninteractive "
        "session-libvirt control",
        "version-compatible session-libvirt hardening-ledger disposition",
    )
    require(
        verify,
        "python3 scripts/verify-windows-harness.py --repo . --self-test",
        "R-S11ds focused gate wiring",
    )

    run_state_requirement = html_requirement(requirements, "R-S11dt")
    for literal, description in (
        (
            "Windows build run state is device/inode-owned and removed only after every external authority retires",
            "R-S11dt requirement title",
        ),
        (
            "exact device/inode identity immediately after private creation",
            "normative run-root creation identity",
        ),
        (
            "helper Docker/configuration authority",
            "normative helper-first retirement",
        ),
        (
            "MUST NOT</span> fall back to recursive pathname cleanup",
            "normative no-pathname-fallback boundary",
        ),
        (
            "without invoking the Windows builder main path",
            "source-only run-state verification boundary",
        ),
    ):
        require(run_state_requirement, literal, description)
    require(requirements, "<tr><td>273</td>", "Appendix C #273 disposition")
    require(
        hardening,
        "R-S11dt/R-S11e-138 — Windows build run-state cleanup is identity-bound and authority-last",
        "R-S11dt hardening-ledger disposition",
    )
    publication_requirement = html_requirement(requirements, "R-S11du")
    for literal, description in (
        (
            "Windows result publication is exact-object, same-filesystem, no-clobber, durable, and authority-terminal",
            "R-S11du requirement title",
        ),
        (
            "complete candidate <span class=\"kw\">MUST</span> first be created inside the authenticated private run root",
            "normative private candidate authority",
        ),
        (
            "remove the exact remaining run-root identity through R-S11dt's "
            "descriptor-relative private-tree closure while the requested destination is still absent",
            "normative run-state finality before publication",
        ),
        (
            "same-parent <code>renameat2(RENAME_NOREPLACE)</code>",
            "normative final no-clobber publication",
        ),
        (
            "without invoking the Windows builder main path",
            "source-only publication verification boundary",
        ),
    ):
        require(publication_requirement, literal, description)
    require(requirements, "<tr><td>274</td>", "Appendix C #274 disposition")
    require(
        hardening,
        "R-S11du/R-S11e-139 — Windows result publication is exact-object and authority-terminal",
        "R-S11du hardening-ledger disposition",
    )

    require(preflight, '[ -f "$GOLDEN" ] && [ ! -L "$GOLDEN" ]', "regular golden source")
    require(preflight, 'verify_sha256 "$GOLDEN" "$SHA256_WIN11_GOLDEN_QCOW2"', "golden pre-snapshot hash")
    require(snapshot_golden, 'PRIVATE_GOLDEN="$RUN_ROOT/golden.qcow2"', "private golden path")
    require(snapshot_golden, "os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC", "exclusive private golden creation")
    require(snapshot_golden, "before = os.fstat(source_fd)", "golden pre-copy state")
    require(
        snapshot_golden,
        "not stat.S_ISREG(before.st_mode) or before.st_uid != uid or before.st_nlink != 1",
        "golden source ownership/type/link proof",
    )
    require(
        snapshot_golden,
        "stat.S_IMODE(before.st_mode) & 0o022",
        "golden source group/world write rejection",
    )
    require(snapshot_golden, "after = os.fstat(source_fd)", "golden post-copy state")
    require(
        snapshot_golden,
        "if any(getattr(before, field) != getattr(after, field) for field in stable_fields):",
        "golden source stability proof",
    )
    require(snapshot_golden, "if digest.hexdigest() != expected:", "private golden creation hash proof")
    require(
        snapshot_golden,
        "not stat.S_ISREG(copied.st_mode) or copied.st_uid != uid",
        "private golden ownership/type proof",
    )
    require(snapshot_golden, "copied.st_nlink != 1", "private golden link-count proof")
    require(snapshot_golden, "os.fchmod(destination_fd, 0o400)", "immutable private golden mode")
    require(snapshot_golden, "verify_private_golden", "private golden snapshot postcondition")
    require(
        verify_private_golden,
        '"$(stat -c \'%u:%a:%h\' "$PRIVATE_GOLDEN")" = "$(id -u):400:1"',
        "private golden ownership/mode/link proof",
    )
    require(
        verify_private_golden,
        'verify_sha256 "$PRIVATE_GOLDEN" "$SHA256_WIN11_GOLDEN_QCOW2"',
        "private golden rehash",
    )
    require(prepare_overlay, "verify_private_golden", "pre-overlay golden hash validation")
    require_count(host_main, "verify_private_golden", 3, "post-pass/pre-publication golden validation")
    require_order(
        host_main,
        (
            "snapshot_golden",
            "run_pass A",
            "verify_private_golden",
            "run_pass B",
            "verify_private_golden",
            "verify_active_online_snapshot",
            "verify_private_golden",
            "windows_helper_authority_close",
            'publish_result "$RUN_ROOT/pass-A/result"',
        ),
        "golden validation and helper retirement before publication",
    )
    require(
        host,
        'GIT_INDEX_FILE="$index" git -C "$REPO_ROOT" -c core.hooksPath=/dev/null add -A -- .',
        "isolated worktree capture",
    )
    require(host, 'first="$(capture_worktree_tree first)"', "first worktree capture")
    require(host, 'second="$(capture_worktree_tree second)"', "second worktree capture")
    for manifest in (
        "rustdesk-windows-source-manifest-v1",
        "rustdesk-windows-source-identity-v1",
    ):
        require(host, manifest, manifest)
    require(
        write_offline_manifest,
        'python3 "$SOURCE_SNAPSHOT/scripts/windows-offline-manifest.py"',
        "isolated offline-media manifest generator",
    )
    require(host, 'source "$SCRIPT_DIR/windows-helper-runtime.sh"', "shared Windows helper runtime")
    require(
        runtime,
        "run --rm --pull=never --network=none --read-only",
        "common networkless immutable Windows helper launch",
    )
    require(
        runtime,
        '--user "$WINDOWS_HELPER_BUILD_UID:$WINDOWS_HELPER_BUILD_GID"',
        "common invoking-UID Windows helper identity",
    )
    require(
        verify_wix_nuget_packages,
        'local root="$ONLINE_DIR/wix-nuget-packages"',
        "exact WiX local-package source validation",
    )
    require(
        verify_wix_nuget_packages,
        'verify_sha256 "$file" "$expected_sha"',
        "exact WiX local-package hashes",
    )
    require(
        build_offline_media,
        "genisoimage -udf -D -r -f -quiet",
        "approved internal file-link materialization",
    )
    require(
        build_offline_media,
        "/wix-nuget-packages=/online/wix-nuget-packages",
        "read-only signed WiX package media input",
    )
    require(
        build_offline_media,
        'cmp -s "$manifest" "$after"',
        "offline input/media manifest stability postcondition",
    )
    require_order(
        build_offline_media,
        (
            'write_offline_manifest "$manifest"',
            "genisoimage -udf -D -r -f -quiet",
            'write_offline_manifest "$after"',
            'cmp -s "$manifest" "$after"',
        ),
        "offline identity, materialization, and stability ordering",
    )

    offline_hash = python_function(offline_tree, "hash_regular")
    offline_link = python_function(offline_tree, "hash_internal_file_link")
    offline_calculate = python_function(offline_tree, "calculate_manifest")
    offline_write = python_function(offline_tree, "write_manifest")
    offline_self_test = python_function(offline_tree, "self_test")
    require(offline, 'FORMAT = "rustdesk-windows-offline-manifest-v2"', "exact offline manifest format")
    require(
        ast.get_source_segment(offline, offline_hash) or "",
        'flags |= os.O_NOFOLLOW',
        "no-follow offline file opening",
    )
    require(
        ast.get_source_segment(offline, offline_link) or "",
        "if not stat.S_ISREG(target_info.st_mode):",
        "single-hop regular-file alias type check",
    )
    require(
        ast.get_source_segment(offline, offline_link) or "",
        "offline symlink target is not a single-hop regular file",
        "single-hop regular-file alias policy",
    )
    require_python_call(
        offline_tree,
        "hash_internal_file_link",
        "hash_regular",
        "internal file-link target byte hashing",
    )
    require(
        ast.get_source_segment(offline, offline_calculate) or "",
        "if relative in exact_paths:",
        "exact offline path duplication rejection",
    )
    require(
        ast.get_source_segment(offline, offline_calculate) or "",
        "previous_identity != identity",
        "byte-identity-only Windows case collision policy",
    )
    require(
        ast.get_source_segment(offline, offline_calculate) or "",
        "offline input contains a directory symlink or non-directory",
        "offline directory symlink rejection",
    )
    require(
        ast.get_source_segment(offline, offline_write) or "",
        "os.link(temporary, output, follow_symlinks=False)",
        "no-clobber offline manifest publication",
    )
    require(
        ast.get_source_segment(offline, offline_self_test) or "",
        'expect_failure("link chain", link_chain)',
        "offline link-chain behavioral fixture",
    )
    for fixture in ("absolute link", "escaping link", "directory link", "directory target", "case collision", "special file"):
        require(offline, f'"{fixture}"', f"offline behavioral fixture {fixture}")
    require(
        runtime,
        'require_pinned_builder_image win-helper "$WIN_HELPER_IMAGE_ID"',
        "pinned Windows helper image",
    )
    require(host, 'require_pinned_builder_image deb-builder "$DEB_BUILDER_IMAGE_ID"', "pinned FRB builder image")
    require(
        host_main,
        'ONLINE_SNAPSHOT_PARENT="$RUN_ROOT/online-snapshot"',
        "private per-run online snapshot path",
    )
    require(
        host_main,
        'create_private_online_snapshot "$ONLINE_SNAPSHOT_PARENT"',
        "private online snapshot creation",
    )
    require(
        shell_function(host, "verify_active_online_snapshot"),
        'verify_private_online_snapshot "$ONLINE_SNAPSHOT_PARENT"',
        "active online snapshot postcondition",
    )
    require(host, 'FRB_IMAGE_ID="$DEB_BUILDER_IMAGE"', "immutable FRB image handoff")
    require(build_pass_media, '--online-root "$ONLINE_DIR"', "private FRB online handoff")
    require(host, "FRB reproducibility mismatch between Windows passes", "FRB A-equals-B gate")
    require(host, "FRB manifest does not describe exactly the four canonical outputs", "exact FRB manifest")
    require(host, "FRB manifest is not a regular file", "regular FRB manifest")
    require(host, 'extracted="$(mktemp -d "$CURRENT_PASS_ROOT/extract.XXXXXXXX")"', "private extraction")
    require_order(
        host,
        (
            "wait_for_domain",
            "extract_and_validate",
            'python3 "$SOURCE_SNAPSHOT/scripts/canonicalize-pe.py"',
            "publish_result",
        ),
        "shutdown/extract/validate/publish ordering",
    )
    require_order(
        extract_and_validate,
        (
            'msi_input_sha256="$(sha256sum "$extracted/rustdesk.msi"',
            'mv -- "$extracted/rustdesk.msi" "$msi_input"',
            "windows_helper_small_run",
            'source=$msi_input,target=/authority/input.msi,readonly',
            'source=$SOURCE_SNAPSHOT/scripts/canonicalize-msi.py,target=/authority/canonicalize-msi.py,readonly',
            '/usr/bin/python3 /authority/canonicalize-msi.py /authority/input.msi',
            '--output /out/rustdesk.msi',
            '--contract-out /out/contract.json',
            '[ "$msi_input_sha256" = "$(sha256sum "$msi_input"',
            '[ "$msi_output_sha256" = "$msi_input_sha256" ]',
            'mv -- "$msi_output" "$extracted/rustdesk.msi"',
            'rm -f -- "$msi_input" "$msi_contract"',
        ),
        "confined invoking-UID host MSI canonical-form validation",
    )
    require_order(
        extract_and_validate,
        (
            'mv -- "$msi_output" "$extracted/rustdesk.msi"',
            'source=$SOURCE_SNAPSHOT/scripts/verify-windows-installed-service-result.py,target=/authority/verify.py,readonly',
            'source=$extracted,target=/evidence,readonly',
            "/usr/bin/python3 /authority/verify.py",
            "--result /evidence/windows-installed-service-result.json",
            "--identity /authority/source-identity.json",
            "--setup /evidence/rustdesk-setup.exe",
            "--msi /evidence/rustdesk.msi",
            "--domain-xml /authority/domain.xml",
            'install -m 0644 "$CURRENT_PASS_ROOT/domain.xml" "$result/domain.xml"',
        ),
        "canonical-artifact installed-SCM receipt validation and domain retention",
    )
    require_order(
        extract_and_validate,
        (
            "sha256sum rustdesk-setup.exe >rustdesk-setup.exe.sha256",
            "sha256sum rustdesk.msi >rustdesk.msi.sha256",
            "chmod 0644 -- rustdesk-setup.exe.sha256 rustdesk.msi.sha256",
        ),
        "canonical publication checksum source modes",
    )
    for temporary_cleanup in (
        'rm -f -- "$extracted/rustdesk-setup.exe"',
        'rm -f -- "$setup_input"',
        'rm -f -- "$msi_input" "$msi_contract"',
    ):
        require(
            extract_and_validate,
            temporary_cleanup,
            "noninteractive write-protected artifact-validation cleanup",
        )
    require(
        extract_and_validate,
        "guest MSI was not already in exact canonical form",
        "host MSI idempotence rejection",
    )
    require(host, "guest completion marker count is not exactly one", "explicit guest marker count")
    require(host, "guest source-verification marker", "guest source proof")
    require(host, 'if not data.endswith(b"\\r\\n"):', "canonical Windows progress CRLF")
    require(host, 'raw_lines = data.split(b"\\r\\n")', "strict progress line splitting")
    require(host, 'raw.decode("ascii")', "strict progress ASCII decoding")
    require(host, "non-CRLF guest progress self-test was accepted", "non-CRLF progress behavioral fixture")
    require(
        host,
        'exit_markers[0] != "build-windows.ps1 exit=0"',
        "CRLF-normalized exact guest success marker",
    )
    reject(host, r"mapfile\s+-t\s+exit_markers", "CR-bearing shell progress parsing")
    require(host, "assert_safe_path", "mount path delimiter gate")
    require(
        write_manifest,
        'dos_device = re.compile(r"^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\\..*)?$", re.IGNORECASE)',
        "reserved Win32 device-name rejection",
    )
    require(write_manifest, "folded = relative.casefold()", "Windows case-folded path identity")
    require(write_manifest, "previous = case_paths.get(folded)", "source case-collision rejection")
    require(write_manifest, "generated_folded = {name.casefold(): name for name in generated}", "generated namespace map")
    require(
        write_manifest,
        "if relative.casefold() in generated_folded:",
        "generated directory namespace rejection",
    )
    require(
        write_manifest,
        "reserved = generated_folded.get(relative.casefold())",
        "generated file namespace rejection",
    )
    for generated_name in (
        '.source-manifest.json',
        '.source-identity.json',
        '.source-date-epoch',
        '.build-run-id',
        '.source-manifest.json.tmp',
        '.source-identity.json.tmp',
        'run-build.ps1',
    ):
        require(write_manifest, f'"{generated_name}"', f"host generated namespace {generated_name}")
    require(host, "source tree contains an unmanifested empty directory", "exact source directories")
    require(host, 'chmod -R a-w "$media_root"', "immutable source media tree")
    require(host, "source identity changed while source media was created", "source identity media postcondition")
    for literal, description in (
        (
            '[ "$result" = "$RUN_ROOT/pass-A/result" ]',
            "exact pass-A publication source",
        ),
        (
            '[ -n "$RUN_ROOT_ID" ] && [ -n "$OUT_PARENT_ID" ]',
            "complete publication identities",
        ),
        (
            '/usr/bin/python3 -I -S "$SCRIPT_DIR/publish-windows-result.py"',
            "isolated Windows publication helper",
        ),
        ('--run-root-identity "$RUN_ROOT_ID"', "run-root identity handoff"),
        ('--output-parent-identity "$OUT_PARENT_ID"', "output-parent identity handoff"),
        ('--pending "$pending"', "pending candidate name handoff"),
        ('--pending-identity "$pending_identity"', "pending candidate identity handoff"),
        ('--destination "$destination"', "single-edge destination handoff"),
    ):
        require(publish_result, literal, description)
    require_order(
        publish_result,
        (
            "--prepare",
            'read -r pending pending_identity extra <<<"$authority"',
            "remove_completed_run_root",
            "--commit",
        ),
        "prepare/retire-run-root/final-commit publication order",
    )
    require(
        publish_result,
        r'[[ "$pending" =~ ^\.windows-output-pending-[0-9a-f]{64}$ ]]',
        "pending candidate name authority validation",
    )
    require(
        publish_result,
        r'[[ "$pending_identity" =~ ^(0|[1-9][0-9]*):[1-9][0-9]*$ ]]',
        "pending candidate identity authority validation",
    )
    for forbidden, description in (
        ('.windows-publish.XXXXXXXX', "external pathname staging"),
        ('mv -T --no-clobber -- "$staging" "$OUT_DIR"', "GNU mv publication fallback"),
        ('install -m 0644 "$result/$name" "$staging/$name"', "shell pathname artifact copy"),
    ):
        if forbidden in publish_result:
            raise VerificationError(f"forbidden {description}: {forbidden}")
    require_exact_count(
        publish_result,
        '/usr/bin/python3 -I -S "$SCRIPT_DIR/publish-windows-result.py"',
        2,
        "exact prepare/commit isolated publisher invocations",
    )
    require_exact_count(
        publish_result,
        '--output-parent-identity "$OUT_PARENT_ID"',
        2,
        "exact prepare/commit output-parent identity handoffs",
    )

    publication_prepare = python_function(publication_tree, "prepare")
    publication_commit = python_function(publication_tree, "commit")
    publication_open = python_function(publication_tree, "open_bound_directory")
    publication_regular = python_function(publication_tree, "open_regular")
    publication_copy = python_function(publication_tree, "copy_regular")
    publication_verify = python_function(publication_tree, "verify_result")
    publication_rename = python_function(publication_tree, "rename_noreplace")
    for literal, description in (
        ("RENAME_NOREPLACE = 1", "renameat2 no-clobber flag"),
        ('CANDIDATE_NAME = ".windows-output-candidate"', "private candidate name"),
        (
            'PENDING_RE = re.compile(r"^\\.windows-output-pending-[0-9a-f]{64}$")',
            "kernel-random pending-name grammar",
        ),
        ('SOURCE_COMPONENTS = ("pass-A", "result")', "exact source components"),
        ('ARTIFACTS = ("rustdesk-setup.exe", "rustdesk.msi")', "closed artifact inventory"),
        (
            '"build-windows.stderr.txt",\n    "build-windows.stdout.txt",\n'
            '    "domain.xml",\n    "run-build-progress.txt",\n'
            '    "windows-installed-service-probe.stderr.txt",\n'
            '    "windows-installed-service-probe.stdout.txt",\n'
            '    "windows-installed-service-result.json",\n'
            '    "windows-full-peer-presentation.stderr.txt",\n'
            '    "windows-full-peer-presentation.stdout.txt",\n'
            '    "windows-full-peer-server.stderr.txt",\n'
            '    "windows-full-peer-server.stdout.txt",\n'
            '    "windows-full-peer-viewer.stderr.txt",\n'
            '    "windows-full-peer-viewer.stdout.txt",\n'
            '    "windows-full-peer-probe-build-receipt.json",\n'
            '    "windows-full-peer-presentation-result.json",',
            "bounded installed-SCM and full-peer diagnostic inventory",
        ),
        ("system.posix_acl_access", "output authority ACL rejection"),
        ("source artifact {artifact} does not match its checksum", "source checksum binding"),
        ("published Windows output edge is not the authenticated candidate", "published-edge identity proof"),
        ("self-test accepted a substituted output parent", "parent substitution fixture"),
        ("self-test accepted a substituted pending output", "pending substitution fixture"),
        ("self-test accepted an occupied destination", "destination collision fixture"),
        ("self-test accepted a {suffix} source", "linked/extra source fixtures"),
    ):
        require(publication, literal, description)
    for literal, description in (
        ("os.O_DIRECTORY | os.O_NOFOLLOW", "no-follow directory acquisition"),
        ("identity(opened) != expected", "expected directory identity proof"),
        ("opened.st_uid != os.getuid() or opened.st_gid != os.getgid()", "invoking-principal ownership proof"),
        ("mode & 0o7000 or mode & 0o022", "unsafe output-parent mode rejection"),
    ):
        require(ast.get_source_segment(publication, publication_open) or "", literal, description)
    for literal, description in (
        ("stable_file(before) != stable_file(os.fstat(source))", "source-copy stability proof"),
        ("os.fchmod(destination, 0o644)", "canonical artifact mode"),
        ("os.fsync(destination)", "artifact synchronization"),
    ):
        require(ast.get_source_segment(publication, publication_copy) or "", literal, description)
    for literal, description in (
        ("before.st_nlink != 1", "single-link source-file proof"),
        ("stable_file(before) != stable_file(opened)", "source-file open stability proof"),
        ("os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW", "no-follow source-file opening"),
    ):
        require(
            ast.get_source_segment(publication, publication_regular) or "",
            literal,
            description,
        )
    require(
        ast.get_source_segment(publication, publication_verify) or "",
        "digest.hexdigest() != parsed[artifact][0]",
        "post-copy artifact checksum proof",
    )
    for literal, description in (
        ('getattr(library, "renameat2", None)', "libc renameat2 resolution"),
        ("RENAME_NOREPLACE", "no-clobber rename dispatch"),
        ("error == errno.EXDEV", "cross-filesystem refusal"),
    ):
        require(ast.get_source_segment(publication, publication_rename) or "", literal, description)
    publication_prepare_source = ast.get_source_segment(publication, publication_prepare) or ""
    for literal, description in (
        ("run_info.st_dev != parent_info.st_dev", "same-filesystem precondition"),
        ("os.mkdir(CANDIDATE_NAME, 0o700, dir_fd=run_root)", "run-root candidate creation"),
        ("if actual != parsed[artifact][0]:", "source artifact checksum binding"),
        ('verify_result(candidate, source_entries, "private Windows output candidate")', "candidate verification"),
        ("os.fsync(candidate)", "candidate directory synchronization"),
        ("os.fsync(run_root)", "source namespace synchronization"),
        ("os.fsync(output_parent)", "destination namespace synchronization"),
        (
            'pending = f".windows-output-pending-{os.urandom(32).hex()}"',
            "kernel-random pending candidate name",
        ),
        (
            "rename_noreplace(run_root, CANDIDATE_NAME, output_parent, pending)",
            "descriptor-relative no-clobber pending park",
        ),
        (
            "identity(pending_info) != identity(candidate_info)",
            "authenticated pending-edge identity",
        ),
        ('verify_result(candidate, source_entries, "pending Windows output")', "pending output revalidation"),
    ):
        require(publication_prepare_source, literal, description)
    require_count(
        publication_prepare_source,
        "reprove_path(",
        4,
        "run-root/output-parent path-edge reproving",
    )
    publication_commit_source = ast.get_source_segment(publication, publication_commit) or ""
    for literal, description in (
        ("PENDING_RE.fullmatch(pending) is None", "pending-name validation"),
        ("identity(candidate_info) != expected_pending", "pending identity validation"),
        ('verify_result(candidate, entries, "pending Windows output")', "pending precommit revalidation"),
        ("os.fsync(candidate)", "pending candidate synchronization"),
        (
            "rename_noreplace(output_parent, pending, output_parent, destination)",
            "same-parent no-clobber final publication",
        ),
        ("os.fsync(output_parent)", "final namespace synchronization"),
        ("identity(published) != identity(candidate_info)", "authenticated final identity"),
        ('verify_result(candidate, entries, "published Windows output")', "published output revalidation"),
    ):
        require(publication_commit_source, literal, description)
    require_count(
        publication_commit_source,
        "reprove_path(",
        2,
        "final output-parent path-edge reproving",
    )
    for forbidden, description in (
        ("shutil.", "shutil pathname publication"),
        ("subprocess.", "publication subprocess"),
    ):
        if forbidden in publication:
            raise VerificationError(f"forbidden {description}: {forbidden}")
    for forbidden, description in (
        ("os.rename(", "overwrite-capable Python rename"),
        ("os.replace(", "overwrite-capable Python replacement"),
    ):
        if forbidden in publication_prepare_source or forbidden in publication_commit_source:
            raise VerificationError(f"forbidden production {description}: {forbidden}")
    require_exact_count(
        publication,
        "os.rename(output_parent, retained_parent)",
        1,
        "one test-only output-parent substitution",
    )
    require_order(
        host_main,
        (
            "run_pass A",
            'if [ "${DOUBLE_BUILD:-1}" = "1" ]; then',
            "run_pass B",
            'elif [ "${DOUBLE_BUILD:-1}" != "0" ]; then',
            'die "DOUBLE_BUILD must be 0 or 1"',
            "windows_helper_authority_close",
            'publish_result "$RUN_ROOT/pass-A/result"',
        ),
        "direct Windows double-build contract",
    )

    require(frb, "--source-root", "explicit FRB source interface")
    require(frb, "--online-root", "explicit FRB online interface")
    require(frb, "--output-root", "explicit FRB output interface")
    require(frb, "FRB output root must not exist", "absent FRB output root")
    require(frb, '--user "$BUILD_UID:$BUILD_GID"', "invoking FRB uid/gid")
    require(frb, '[[ "$IMAGE_ID" =~ ^sha256:[0-9a-f]{64}$ ]]', "immutable FRB image ID")
    require(
        frb,
        'WORK_ROOT="$(umask 077 && mktemp -d "$OUTPUT_PARENT/.frb-work.XXXXXXXX")"',
        "private FRB generation",
    )
    require(frb, 'require_pinned_builder_image deb-builder "$IMAGE_ID"', "FRB image provenance")
    require(frb, "verify_online_shas", "FRB archive pins")
    require(frb, "FRB installation metadata does not match the pinned build contract", "FRB tool metadata")
    require(frb, "FRB source snapshot has a writable entry", "read-only FRB source")
    require(frb, "FRB input is not one nonempty regular file", "regular FRB inputs")
    require(frb, '--read-only --user "$BUILD_UID:$BUILD_GID"', "read-only FRB container")
    require(frb, 'mv -T --no-clobber -- "$PUBLISH_ROOT" "$OUTPUT_ROOT"', "atomic FRB directory publication")
    reject(frb, r'rm\s+-f\s+--\s+"\$REPO_ROOT/', "live-tree FRB deletion")
    for output in (
        "src/bridge_generated.rs",
        "src/bridge_generated.io.rs",
        "flutter/lib/generated_bridge.dart",
        "flutter/lib/generated_bridge.freezed.dart",
    ):
        require(frb, output, f"FRB output {output}")

    validate_powershell_lexically(guest, "scripts/run-build.ps1")
    validate_powershell_lexically(build, "scripts/build-windows.ps1")
    guest_safe_path = powershell_function(guest, "Assert-SafeRelativePath")
    guest_manifest = powershell_function(guest, "Assert-SourceManifest")
    guest_offline_manifest = powershell_function(guest, "Assert-OfflineManifest")
    require(guest, "$ErrorActionPreference = 'Stop'", "fail-loud guest policy")
    reject(guest, r"SilentlyContinue", "guest masked error")
    require(
        guest_safe_path,
        "if ($component -imatch '^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\\..*)?$')",
        "guest reserved Win32 device-name rejection",
    )
    require(
        guest_safe_path,
        "[StringComparer]::OrdinalIgnoreCase.Equals($rootComponent, $name)",
        "guest generated namespace case-folding",
    )
    require(
        guest_safe_path,
        "-not ($components.Count -eq 1 -and [StringComparer]::Ordinal.Equals($Path, 'run-build.ps1'))",
        "guest generated runner exception bound to exact spelling",
    )
    require(guest_safe_path, "$rootComponent = $components[0]", "generated namespace root-component binding")
    for generated_name in (
        '.source-manifest.json',
        '.source-identity.json',
        '.source-date-epoch',
        '.build-run-id',
        '.source-manifest.json.tmp',
        '.source-identity.json.tmp',
        'run-build.ps1',
    ):
        require(guest_safe_path, f"'{generated_name}'", f"guest generated namespace {generated_name}")
    require(guest, "Assert-SourceManifest $sourceMedia", "media manifest proof")
    require(guest, "Assert-SourceManifest $source", "copied manifest proof")
    require(guest, "Assert-OfflineManifest $offlineMedia", "OFFLINE media manifest proof")
    require(
        guest_offline_manifest,
        "$manifest.format -cne 'rustdesk-windows-offline-manifest-v2'",
        "exact OFFLINE manifest format",
    )
    require(
        guest_offline_manifest,
        "$manifest.directories -isnot [Array]",
        "OFFLINE directory array type proof",
    )
    require(
        guest_offline_manifest,
        "$caseFileIdentity.ContainsKey($relative)",
        "byte-identical-only OFFLINE case collision proof",
    )
    require(
        guest_offline_manifest,
        "Get-FileHash -LiteralPath $path -Algorithm SHA256",
        "OFFLINE file byte verification",
    )
    require(
        guest_offline_manifest,
        "$actualFiles.Count -ne $declaredFiles.Count",
        "exact OFFLINE file count",
    )
    require(
        guest_offline_manifest,
        "$actualDirectories.Count -ne $declaredDirectories.Count",
        "exact OFFLINE directory count",
    )
    require(
        guest_offline_manifest,
        "if (-not $declaredFiles.Contains($relative))",
        "undeclared OFFLINE file rejection",
    )
    require(
        guest_offline_manifest,
        "if (-not $declaredDirectories.Contains($relative))",
        "undeclared OFFLINE directory rejection",
    )
    require(guest, 'Mark "offline-verified manifest=$($identity.offline_manifest_sha256)"', "OFFLINE guest proof marker")
    require(host, "guest OFFLINE-verification marker count is not exactly one", "authoritative OFFLINE guest marker")
    require(
        guest_manifest,
        "($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0",
        "directory reparse rejection",
    )
    require(
        guest_manifest,
        "$actualDirectories.Count -ne $expectedDirectories.Count",
        "exact copied directory count",
    )
    require(
        guest_manifest,
        "if (-not $expectedDirectories.Contains($relative))",
        "undeclared copied directory rejection",
    )
    require(guest, "Remove-Item -LiteralPath $legacySource -Recurse -Force", "legacy source removal")
    require(
        guest,
        "($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0",
        "safe legacy source traversal",
    )
    require(
        guest,
        "if (Test-Path -LiteralPath $legacySource) {\n        Fail 'legacy C:\\src was not fully removed'",
        "legacy source removal postcondition",
    )
    require(guest, "$buildParent = 'C:\\rustdesk-build'", "stable source parent")
    require(guest, "$source = Join-Path $buildParent 'source'", "stable Windows build root")
    require(guest, "stable source directory already exists", "stable source absence proof")
    reject(
        guest,
        r"Join-Path\s+\$buildParent\s+\(\[string\]\$identity[.]build_run_id\)",
        "pass-specific Windows build root",
    )
    require_order(
        guest,
        (
            "$out = $null",
            "$transcriptStarted = $false",
            "$outputRoots = @(",
            "Start-Transcript",
            "$transcriptStarted = $true",
            "Stop-Computer -Force",
        ),
        "outer guest startup/shutdown finality",
    )
    require(guest, "if ($null -ne $out)", "failure logging without pre-established OUTPUT authority")
    require(guest, "$manifest.files -isnot [Array]", "source manifest array type proof")
    require(guest_manifest, "$entry.path -isnot [string]", "source path JSON type proof")
    require(guest_manifest, "Get-JsonInt64 $entry.size", "source size JSON integer proof")
    require_order(
        guest,
        (
            "$identity = Get-Content",
            "Assert-OfflineManifest $offlineMedia",
            "Assert-SourceManifest $sourceMedia",
            "$legacySource = 'C:\\src'",
            "& powershell.exe",
        ),
        "guest identity before cleanup/build",
    )
    for variable in (
        "RUSTDESK_SOURCE_COMMIT",
        "RUSTDESK_SOURCE_TREE",
        "RUSTDESK_SOURCE_MANIFEST_SHA256",
        "RUSTDESK_OFFLINE_MANIFEST_SHA256",
        "RUSTDESK_FORK_VERSION",
        "RUSTDESK_TARGET",
        "SOURCE_DATE_EPOCH",
    ):
        require(guest, f"$env:{variable}", f"guest export {variable}")

    require_order(
        build,
        ("function Preflight", "Assert-BuildIdentity", "Assert-PowerShellSourceParsing", "function Build"),
        "build identity before build cleanup",
    )
    require(build, "    Assert-BuildIdentity\n    Assert-PowerShellSourceParsing", "preflight identity invocation")
    require(build, "source identity schema is not exact", "build source schema proof")
    require(build, "source manifest hash changed after guest verification", "build manifest recheck")
    require(
        build,
        "windows_credential_lost_reply_stop_and_apply_remain_consistent",
        "lost-reply stop/apply recovery source gate",
    )
    require(
        build,
        "windows_credential_operation_bound_failures_remain_terminal_during_recovery",
        "operation-bound terminal recovery source gate",
    )
    reject(build, r"\$installedVpxKey", "sidecar-authorized libvpx reuse")
    require_order(
        build,
        (
            "vcpkg.exe' remove --recurse 'libvpx:x64-windows-static'",
            "stale compiled libvpx bytes remain after mandatory removal",
            "libvpx --classic",
            "Set-Content -LiteralPath $vpxInstalledKey",
        ),
        "mandatory clean libvpx rebuild",
    )
    for option in ("--fork-version", "--source-commit", "--source-tree", "--target"):
        require(build, option, f"MSI identity option {option}")
        require(host, option, f"host MSI identity option {option}")
    for option, value in (
        ("--fork-version", "$env:RUSTDESK_FORK_VERSION"),
        ("--source-commit", "$env:RUSTDESK_SOURCE_COMMIT"),
        ("--source-tree", "$env:RUSTDESK_SOURCE_TREE"),
        ("--target", "$env:RUSTDESK_TARGET"),
    ):
        require(build, f"'{option}',\n        {value}", f"MSI identity binding {option}")
    require(build, '$cacheName = "msys2-$toolName"', "MinGW pkgconf cache destination")

    reject_ambient_windows_python(build)
    python_toolchain = powershell_function(build, "Assert-PythonToolchain")
    require(build, "$PYTHON_VERSION  = '3.11.9'", "exact Python 3.11.9 pin")
    require(build, "$PYTHON_EXE      = 'C:\\Program Files\\Python311\\python.exe'", "absolute pinned Python path")
    require(
        python_toolchain,
        "$reported = ((& $executable --version 2>&1) | Out-String).Trim()",
        "pinned Python version query",
    )
    require(
        python_toolchain,
        '$reported -cne "Python $PYTHON_VERSION"',
        "exact Python version comparison",
    )
    require(
        python_toolchain,
        "foreach ($commandName in @('python.exe', 'python3.exe'))",
        "ambient Python command-resolution audit",
    )
    require(python_toolchain, "$command.Source -cne $expected", "pinned Python command authority")
    require(python_toolchain, "pinned Python executables are not byte-identical", "python/python3 byte identity")
    require(build, "function Get-OrdinaryPathItem", "Windows ancestor reparse gate")
    require(build, "path traverses a reparse point", "Windows ancestor reparse rejection")
    require(build, "[Management.Automation.Language.Parser]::ParseFile", "native PowerShell parser proof")
    require(build, "$errors.Count -ne 0", "native PowerShell parse error rejection")
    require(
        build,
        "'scripts\\windows-installed-service-probe.ps1'",
        "native installed-service PowerShell parse coverage",
    )
    for literal, description in (
        (
            "cargo test --offline --locked --example probe_client --features flutter --color never redirected_probe_password_is_bounded_and_line_framed",
            "native redirected probe credential test",
        ),
        (
            "cargo build --offline --locked --release --example probe_client --features flutter --color never",
            "release installed-SCM CPace probe build",
        ),
        (
            "target\\release\\examples\\probe_client.exe",
            "exact release CPace probe output",
        ),
    ):
        require(build, literal, description)

    require_order(
        guest,
        (
            "build-windows.stdout.txt",
            "build-windows.stderr.txt",
            "$savedErrorActionPreference = $ErrorActionPreference",
            "$ErrorActionPreference = 'Continue'",
            "1> $buildStdout",
            "2> $buildStderr",
            "$buildExit = $LASTEXITCODE",
            "$ErrorActionPreference = $savedErrorActionPreference",
            "build-windows.ps1 exit=$buildExit",
            "windows-installed-service-probe.stdout.txt",
            "windows-installed-service-probe.stderr.txt",
            "$savedErrorActionPreference = $ErrorActionPreference",
            "$ErrorActionPreference = 'Continue'",
            "windows-installed-service-probe.ps1",
            "1> $installedServiceStdout",
            "2> $installedServiceStderr",
            "$installedServiceExit = $LASTEXITCODE",
            "$ErrorActionPreference = $savedErrorActionPreference",
            "windows-installed-service-probe.ps1 exit=$installedServiceExit",
            "installed-service probe did not publish its exact result receipt",
            "foreach ($name in @('rustdesk-setup.exe'",
        ),
        "guest build, installed-SCM transaction, and artifact-copy order",
    )
    if guest.count("$savedErrorActionPreference = $ErrorActionPreference") != 2:
        fail("guest must isolate both native PowerShell diagnostic-capture boundaries")
    if guest.count("$ErrorActionPreference = $savedErrorActionPreference") != 2:
        fail("guest must restore fail-loud behavior after both diagnostic-capture boundaries")
    for literal, description in (
        ("Assert-BoundedOrdinaryDiagnostic $buildStdout (64 * 1024 * 1024)", "bounded Windows build stdout"),
        ("Assert-BoundedOrdinaryDiagnostic $buildStderr (64 * 1024 * 1024)", "bounded Windows build stderr"),
    ):
        require(guest, literal, description)
    for literal, description in (
        ("1> $installedServiceStdout", "installed-SCM stdout capture"),
        ("2> $installedServiceStderr", "installed-SCM stderr capture"),
        ("Assert-BoundedOrdinaryDiagnostic $diagnostic 65536", "installed-SCM diagnostic size bound"),
        ("[IO.FileAttributes]::ReparsePoint", "installed-SCM diagnostic reparse rejection"),
    ):
        require(guest, literal, description)
    require(
        shell_function(host, "validate_guest_progress"),
        'installed_markers[0] != "windows-installed-service-probe.ps1 exit=0"',
        "installed-SCM guest completion marker",
    )
    for diagnostic in (
        "build-windows.stdout.txt",
        "build-windows.stderr.txt",
        "windows-installed-service-probe.stdout.txt",
        "windows-installed-service-probe.stderr.txt",
    ):
        require(host, diagnostic, f"retained {diagnostic}")
        require(publication, diagnostic, f"published {diagnostic}")

    bounded_native = powershell_function(build, "Invoke-BoundedNativeProcess")
    for literal, description in (
        ("$process.WaitForExit($TimeoutSeconds * 1000)", "bounded native Windows process wait"),
        ("System32\\taskkill.exe", "exact timed-out process-tree termination tool"),
        ("/PID ([string]$process.Id) /T /F", "owned process-tree termination"),
        ("$process.WaitForExit(10000)", "bounded native termination drain"),
    ):
        require(bounded_native, literal, description)
    for literal, description in (
        ("-Path $textureCoreTest", "bounded native texture-core execution"),
        ("$env:MSBUILDDISABLENODEREUSE = '1'", "MSBuild node-reuse disablement"),
        ("-Path $msbuildExe", "bounded exact MSBuild execution"),
        ("/nodeReuse:false", "per-invocation MSBuild node-reuse disablement"),
        ("/maxCpuCount:1", "single-node deterministic MSI build"),
        ("-Description 'locked offline WiX restore'", "bounded locked WiX restore"),
        ("-Description 'WiX MSI build'", "bounded WiX compile"),
    ):
        require(build, literal, description)

    installed_main = powershell_function(installed_probe, "Invoke-MainProbe")
    installed_limited = powershell_function(
        installed_probe, "Invoke-LimitedCredentialAttempt"
    )
    installed_task = powershell_function(installed_probe, "Invoke-LimitedTask")
    installed_process = powershell_function(installed_probe, "Invoke-RedirectedProcess")
    installed_cm_roundtrip = powershell_function(installed_probe, "Invoke-CmFileRoundTrip")
    installed_exact_stop = powershell_function(installed_probe, "Stop-ExactProcessGeneration")
    installed_service = powershell_function(installed_probe, "Get-ExactServiceProof")
    installed_child = powershell_function(installed_probe, "Get-ExactServiceChild")
    installed_cm = powershell_function(installed_probe, "Get-ExactConnectionManager")
    for literal, description in (
        ("QueryServiceConfigW", "typed SCM configuration query"),
        ("QueryServiceStatusEx", "typed SCM status/PID query"),
        ("QueryFullProcessImageNameW", "live process-image proof"),
        ("GetTokenInformation", "live token-elevation proof"),
        ("GetProcessTimes", "PID-reuse-resistant process generation proof"),
        ("ProcessIdToSessionId", "live process-session proof"),
        ("TerminateProcess", "exact-generation termination primitive"),
        ("WaitForSingleObject", "exact-generation termination finality"),
        ("if (wait == WAIT_OBJECT_0) { return false; }", "signaled-process liveness refusal"),
        ("CommandLineToArgvW", "exact service-child argv parser"),
        ("rustdesk-windows-installed-service-probe-v2", "versioned installed-SCM receipt"),
        ("R-S11gj-Limited-Must-Fail-7x!", "synthetic least-privilege fixture"),
        ("R-S11gj-Wrong-Image-Must-Fail-8y!", "synthetic wrong-image fixture"),
        ("R-S11gj-First-Rotation-9z!", "synthetic first rotation fixture"),
        ("R-S11gj-Second-Rotation-A0!", "synthetic second rotation fixture"),
    ):
        require(installed_probe, literal, description)
    for literal, description in (
        ("$start.UseShellExecute = $false", "direct process creation"),
        ("$start.RedirectStandardInput = $true", "redirected credential ingress"),
        ("$process.StandardInput.WriteLine($InputLine)", "stdin-only fixture delivery"),
        ("$process.WaitForExit($TimeoutSeconds * 1000)", "bounded exact-process wait"),
        ("$process.Kill()", "deadline-owned exact child cleanup"),
    ):
        require(installed_process, literal, description)
    require(installed_task, "$definition.Principal.LogonType = 3", "interactive-token task context")
    require(installed_task, "$definition.Principal.RunLevel = 0", "least-privilege Task Scheduler token")
    require(
        installed_task,
        "^RustDeskInstalledProbe-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}-[AB]$",
        "exact run-bound temporary Task Scheduler name",
    )
    require(installed_task, "-Mode',\n        'LimitedCredentialAttempt'", "typed limited helper mode")
    reject(installed_task, r"R-S11gj-(?:Limited|Wrong|First|Second)", "credential fixture in Task Scheduler arguments")
    require(installed_limited, "if ($token.Elevated)", "limited-token fail-closed proof")
    require(installed_limited, "$LimitedFixture $false", "limited mutation rejection transaction")
    windows_password_start = ipc.find(
        "fn set_windows_service_owned_unattended_password(v: SensitivePassword)"
    )
    windows_password_end = ipc.find(
        '#[cfg(target_os = "macos")]', windows_password_start + 1
    )
    if windows_password_start < 0 or windows_password_end < 0:
        raise VerificationError("missing bounded Windows service-password client entry point")
    windows_password_entry = ipc[windows_password_start:windows_password_end]
    require_order(
        windows_password_entry,
        (
            "validate_unattended_password_value(&v)?;",
            "require_current_exe_is_fixed_service_runtime()?;",
            "set_windows_service_owned_unattended_password_with_ack(v)?",
        ),
        "fixed-image preflight before Windows service-password transport",
    )
    require(
        installed_probe,
        "Invoke-RedirectedProcess $Executable '--password-stdin' $Password 60",
        "password mutation fixture confined to redirected stdin",
    )
    for literal, description in (
        ("$proof.ServiceType -ne 0x10", "SCM own-process proof"),
        ("$proof.StartType -ne 2", "SCM automatic-start proof"),
        ("$proof.StartName -cne 'LocalSystem'", "SCM LocalSystem proof"),
        ("$proof.State -ne 4", "SCM running-state proof"),
        ("Assert-SystemProcess $proof.Process", "SCM live process-token/image proof"),
    ):
        require(installed_service, literal, description)
    for literal, description in (
        ("ParentProcessId = $($ServiceProof.ProcessId)", "SCM direct-child selection"),
        ("$arguments.Count -ne 3", "complete service-child role arity"),
        ("$arguments[1] -cne '--server'", "exact child server role"),
        ("$arguments[2] -cne '--service-owned-server'", "exact service-owned marker"),
        ("$matches.Count -gt 1", "duplicate child refusal"),
    ):
        require(installed_child, literal, description)
    for literal, description in (
        ("ParentProcessId = $($ServiceChild.ProcessId)", "CM direct-owner selection"),
        ("$arguments.Count -ne 2", "complete CM role arity"),
        ("$arguments[1] -cne '--cm'", "exact CM role"),
        ("$process.UserSid -cne $InteractiveToken.UserSid", "interactive CM principal proof"),
        ("$process.SessionId -ne $InteractiveToken.SessionId", "interactive CM session proof"),
        ("$matches.Count -gt 1", "duplicate CM refusal"),
    ):
        require(installed_cm, literal, description)
    for literal, description in (
        ("--password-stdin ok cmfiletransfer", "strict CM probe mode"),
        ("[FT-DIR-RESPONSE ", "CM directory-response requirement"),
        ("probe_client: PASS", "strict probe terminal PASS"),
    ):
        require(installed_cm_roundtrip, literal, description)
    require(
        installed_exact_stop,
        "TerminateExactProcessGeneration(\n        [uint32]$Generation.ProcessId",
        "handle-bound exact-generation termination",
    )
    require(
        installed_exact_stop,
        "Wait-ExactProcessGenerationGone $Generation $Label",
        "terminated-generation finality",
    )
    for literal, description in (
        ("canonicalize-pe.py", "final setup-byte canonicalization"),
        ("Invoke-RedirectedProcess $canonicalSetup '--silent-install'", "canonical setup execution"),
        ("stdout=$installStdout; stderr=$installStderr", "bounded canonical setup failure diagnostics"),
        ("$installedSha256 -cne $builtSha256", "installed executable byte proof"),
        ("Invoke-LimitedTask $installed", "same-principal least-token rejection"),
        ("$wrongExe $WrongImageFixture $false", "copied-image rejection"),
        ("$installed $FirstFixture $true", "first installed-image mutation"),
        ("$installed $SecondFixture $true", "rotated installed-image mutation"),
        ("Invoke-KeyProbe $SecondFixture 'ok'", "new credential CPace proof"),
        ("Invoke-KeyProbe $FirstFixture 'fail'", "old credential CPace refusal"),
        ("Wait-ExactProcessGenerationGone $servicePreRestart.Process", "SCM supervisor generation retirement proof"),
        ("Wait-ExactProcessGenerationGone $childPreRestart", "SCM child generation retirement proof"),
        ("Wait-ExactProcessGenerationGone $cmPreRestart", "SCM CM generation retirement proof"),
        ("$controller.Start()", "SCM restart transaction"),
        ("second_credential_keyed_after_restart = $true", "durable credential reload receipt"),
    ):
        require(installed_main, literal, description)
    require_order(
        installed_main,
        (
            "$installed $FirstFixture $true",
            "Invoke-KeyProbe $FirstFixture 'ok'",
            "Invoke-LimitedTask $installed",
            "Invoke-KeyProbe $FirstFixture 'ok'",
            "Invoke-KeyProbe $LimitedFixture 'fail'",
            "$wrongExe $WrongImageFixture $false",
            "Invoke-KeyProbe $FirstFixture 'ok'",
            "Invoke-KeyProbe $WrongImageFixture 'fail'",
            "$installed $SecondFixture $true",
        ),
        "baseline, rejection-preservation, rotation transaction order",
    )
    require_order(
        installed_main,
        (
            "Invoke-CmFileRoundTrip $FirstFixture 'initial installed LocalSystem CM round-trip'",
            "$cmInitial = Get-ExactConnectionManager",
            "Invoke-CmFileRoundTrip $FirstFixture 'reused installed LocalSystem CM round-trip'",
            "$cmReused = Get-ExactConnectionManager",
            "Stop-ExactProcessGeneration $cmInitial",
            "Invoke-CmFileRoundTrip $FirstFixture 'stale-generation recovery CM round-trip'",
            "$cmAfterStaleRecovery = Get-ExactConnectionManager",
            "Stop-ExactProcessGeneration $childBefore",
            "Wait-ExactProcessGenerationGone $cmAfterStaleRecovery",
            "$childAfterAbrupt = Get-ExactServiceChild",
            "Invoke-CmFileRoundTrip $FirstFixture 'abrupt-owner recovery CM round-trip'",
            "$cmAfterAbrupt = Get-ExactConnectionManager",
            "Invoke-LimitedTask $installed",
            "Invoke-CmFileRoundTrip $SecondFixture 'pre-SCM-stop retained CM round-trip'",
            "$cmPreRestart = Get-ExactConnectionManager",
            "$controller.Stop()",
            "Wait-ExactProcessGenerationGone $cmPreRestart",
            "$controller.Start()",
            "Invoke-CmFileRoundTrip $SecondFixture 'post-SCM-restart CM round-trip'",
            "$cmAfterRestart = Get-ExactConnectionManager",
        ),
        "installed LocalSystem CM lifecycle transaction order",
    )
    for literal, description in (
        (
            "first_credential_preserved_after_limited_rejection = $true",
            "limited rejection preservation receipt",
        ),
        ("limited_fixture_rejected = $true", "limited fixture refusal receipt"),
        (
            "first_credential_preserved_after_copied_image_rejection = $true",
            "copied-image rejection preservation receipt",
        ),
        ("copied_image_fixture_rejected = $true", "copied-image fixture refusal receipt"),
    ):
        require(installed_main, literal, description)

    for literal, description in (
        ("--password-stdin requires redirected standard input", "CPace probe terminal refusal"),
        ("if stdin.is_terminal()", "CPace probe live terminal check"),
        ("PROBE_PASSWORD_MAX_BYTES: usize = 4096", "CPace probe credential bound"),
        ("sodiumoxide::utils::memzero", "CPace probe input erasure"),
        ("std::mem::take(value).into_bytes()", "argv compatibility value ownership"),
        ("drop(pw);", "pre-network CPace password retirement"),
        ('mode == "cmfiletransfer"', "strict CM file-transfer mode"),
        ("received_directory = true", "strict CM directory-response observation"),
        ('mode == "cmfiletransfer" && !received_directory', "strict CM directory-response refusal"),
    ):
        require(probe_client, literal, description)

    installed_validate = ast.get_source_segment(
        installed_result, python_function(installed_result_tree, "validate")
    ) or ""
    installed_validate_domain = ast.get_source_segment(
        installed_result, python_function(installed_result_tree, "validate_domain")
    ) or ""
    installed_self_test = ast.get_source_segment(
        installed_result, python_function(installed_result_tree, "self_test")
    ) or ""
    for literal, description in (
        ("set(result) != RESULT_FIELDS", "closed installed-SCM receipt schema"),
        ('result["setup_sha256"] != sha256(setup_path', "canonical setup hash binding"),
        ('result["msi_sha256"] != sha256(msi_path', "canonical MSI hash binding"),
        ('result["installed_exe_sha256"] != result["built_exe_sha256"]', "installed image hash equality"),
        ('result["domain_network_interfaces"] != 0', "zero-interface receipt requirement"),
        ('require_exact_bool(result, "limited_token_elevated", False)', "limited token receipt proof"),
        ("SCM restart did not change the supervisor generation", "supervisor-generation result proof"),
        ("SCM restart did not change the service-owned child generation", "child-generation result proof"),
        ("abrupt owner recovery did not change the service-owned child generation", "abrupt-owner child result proof"),
        ("stale CM recovery did not change the CM generation", "stale CM result proof"),
        ("retained CM generation was not reused before SCM restart", "retained CM reuse result proof"),
        ("SCM restart did not change the CM generation", "SCM CM-generation result proof"),
        ('result["cm_roundtrip_count"] != 6', "six-round-trip result proof"),
    ):
        require(installed_validate, literal, description)
    require(installed_validate_domain, 'root.findall("./devices/interface")', "result verifier zero-interface XML proof")
    require(installed_validate_domain, 'graphic.get("listen") != "127.0.0.1"', "result verifier loopback VNC proof")
    for fixture in (
        "limited rejection",
        "limited rejection preservation",
        "copied-image fixture refusal",
        "setup binding",
        "closed schema",
        "SCM generation",
        "abrupt owner generation",
        "stale CM generation",
        "retained CM reuse",
        "SCM CM generation",
        "CM round-trip count",
    ):
        require(installed_self_test, f'("{fixture}", changed)', f"installed-SCM result mutation {fixture}")
    installed_requirement = html_requirement(requirements, "R-S11gj")
    for literal, description in (
        ("zero virtual network interfaces", "zero-interface installed-SCM requirement"),
        ("TASK_RUNLEVEL_LUA", "least-privilege installed-SCM requirement"),
        ("bounded redirected stdin", "stdin-only installed-SCM requirement"),
        (
            "Thus neither negative may pass merely because a caller mutated state and then reported failure.",
            "negative rejection-preservation requirement",
        ),
        (
            "The Windows client <span class=\"kw\">MUST</span> prove its own current executable is the fixed installed runtime before it opens the service-password transport",
            "client fixed-image preflight requirement",
        ),
        ("distinct supervisor and child generations", "restart-generation installed-SCM requirement"),
        ("strict secret-free receipt", "secret-free installed-SCM receipt requirement"),
    ):
        require(installed_requirement, literal, description)
    require(requirements, "<tr><td>345</td>", "installed-SCM Appendix C row")
    require(
        hardening,
        "R-S11gj/R-S11e-222 — exact installed Windows SCM credential authority",
        "installed-SCM hardening ledger",
    )
    for literal, description in (
        (
            "EXACT-COMMIT NATIVE TRANSACTION GREEN AT `0a12ed407e63129cac4065f4418911ab71adf3ca`",
            "installed-SCM exact-commit native status",
        ),
        (
            "`0018db4b-b79a-4cff-88a0-3f7adf949ec8-A`",
            "installed-SCM exact native run identity",
        ),
    ):
        require(hardening, literal, description)
    require(
        requirements,
        '<span class="pill p-harden">EXACT-COMMIT NATIVE TRANSACTION GREEN</span>',
        "installed-SCM Appendix native status",
    )
    require(
        host,
        'verify_sha256 "$ONLINE_DIR/olefile-${OLEFILE_VERSION}-py2.py3-none-any.whl" "$SHA256_OLEFILE_0_47"',
        "olefile wheel hash pin",
    )
    require(build, "python-wheels\\olefile-0.47-py2.py3-none-any.whl", "exact olefile 0.47 wheel")
    require(build, "$OLEFILE_SHA256  = '543c7da2a7adadf21214938bb79c83ea12b473a4b6ee4ad4bf854e7715e13d1f'", "guest olefile digest pin")
    require(build, "Get-FileHash -LiteralPath $olefileWheel -Algorithm SHA256", "guest olefile digest proof")
    require(build, "isinstance(loader, zipimport.zipimporter)", "olefile zip-wheel loader proof")
    require_count(build, "os.path.normcase(os.path.abspath(loader.archive)) != wheel", 2, "olefile wheel authority proofs")
    require_count(build, "if olefile.__version__ != '0.47':", 2, "exact olefile version proofs")
    require(
        build,
        "raise SystemExit('olefile did not load through the verified wheel')",
        "PowerShell-safe olefile probe quoting",
    )
    require(
        build,
        "expected_options = ['--output', '--contract-out', '--fork-version', '--source-commit', '--source-tree', '--target']",
        "PowerShell-safe MSI runner quoting",
    )
    require(build, "if len(arguments) != 13 or arguments[1::2] != expected_options", "isolated MSI argument-vector proof")
    require(
        build,
        "& $PYTHON_EXE -I -S -c $olefileProbe $olefileWheel",
        "isolated olefile wheel probe",
    )
    require(
        build,
        "& $PYTHON_EXE -I -S -c $isolatedOlefileRunner $olefileWheel @msiCanonicalizerArguments",
        "isolated MSI canonicalizer runner",
    )
    for pinned_call in (
        "& $PYTHON_EXE build.py --flutter",
        "& $PYTHON_EXE preprocess.py --arp -d $msiDist",
        "& $PYTHON_EXE .\\generate.py -f $setupPayloadDir -o . -e $setupPayloadMsi",
    ):
        require(build, pinned_call, f"pinned Python invocation {pinned_call}")

    build_flutter_windows = python_function(orchestrator_tree, "build_flutter_windows")
    require(orchestrator, "canonicalizer_input = pe.with_name(f'.canonicalize-input-{pe.name}')", "distinct PE input path")
    require_order(
        ast.get_source_segment(orchestrator, build_flutter_windows) or "",
        (
            "os.link(pe, canonicalizer_input)",
            "os.unlink(pe)",
            "'scripts/canonicalize-pe.py'",
            "'--output'",
            "str(pe)",
            "str(canonicalizer_input)",
            "canonicalizer_input.unlink()",
        ),
        "PE absent-output orchestration",
    )

    canonicalize_bytes = ast.get_source_segment(pe, python_function(pe_tree, "canonicalize_bytes")) or ""
    pe_canonicalize = ast.get_source_segment(pe, python_function(pe_tree, "canonicalize")) or ""
    pe_publish = ast.get_source_segment(pe, python_function(pe_tree, "_publish_absent")) or ""
    pe_verify_published = ast.get_source_segment(
        pe, python_function(pe_tree, "_verify_published_file")
    ) or ""
    pe_publish_success, pe_publish_cleanup = pe_publish.split(
        "except BaseException as original:", 1
    )
    pe_self_test = ast.get_source_segment(pe, python_function(pe_tree, "self_test")) or ""
    require(pe, "IMAGE_DEBUG_TYPE_REPRO = 16", "bounded repro debug type")
    require(
        pe,
        '() if os.name == "nt" else ("st_mode", "st_ctime_ns")',
        "platform-correct PE source stability fields",
    )
    require(
        pe,
        '() if os.name == "nt" else ("st_mode",)',
        "published PE stability fields",
    )
    require(pe, "debug_type == IMAGE_DEBUG_TYPE_REPRO", "repro-only payload clearing")
    require(canonicalize_bytes, "authorized = pe_fields + debug_ranges", "complete PE mutation authorization union")
    require(canonicalize_bytes, "image.data[start:end] = b\"\\0\" * (end - start)", "bounded PE mutation application")
    require_direct_python_call(pe_tree, "canonicalize_bytes", "_prove_only_authorized_changes", "PE authorized mutation proof")
    require(
        pe_canonicalize,
        "if os.path.abspath(input_path) == os.path.abspath(output_path):",
        "distinct PE input/output rejection",
    )
    require_direct_python_call(pe_tree, "canonicalize", "_publish_absent", "absent PE publication")
    require(pe_publish, "if os.path.lexists(output_path):", "occupied PE output rejection")
    require(pe_publish, "os.link(temporary, output_path, follow_symlinks=False)", "no-clobber PE publication")
    require_order(
        pe_publish_success,
        (
            "os.link(temporary, output_path, follow_symlinks=False)",
            "os.close(descriptor)",
            "descriptor = -1",
            "os.unlink(temporary)",
            "final_state = _verify_published_file(output_path, output_identity, content)",
        ),
        "Windows-closeable PE publication",
    )
    require(
        pe_publish,
        "final_state = _verify_published_file(output_path, output_identity, content)",
        "reopened published PE postcondition",
    )
    require(
        pe_verify_published,
        'if b"".join(chunks) != expected_content:',
        "reopened published PE byte postcondition",
    )
    require_order(
        pe_publish_cleanup,
        (
            "os.close(descriptor)",
            "_make_deletable(output_path)",
            "os.unlink(output_path)",
            "_make_deletable(temporary)",
            "os.unlink(temporary)",
        ),
        "Windows PE rollback handle release",
    )
    require(pe_publish, "_make_deletable(output_path)", "Windows PE rollback deletion authority")
    require(pe_canonicalize, "_require_real_directory_path", "PE ancestor reparse rejection")
    require(pe_canonicalize, "canonicalization is not idempotent", "PE idempotence postcondition")
    require_python_call(pe_tree, "self_test", "_prove_only_authorized_changes", "PE authorization self-test")
    require(pe_self_test, "mutation outside the authorization union was accepted", "PE unauthorized-mutation fixture")
    require(pe_self_test, "pre-existing output path was overwritten", "PE occupied-output fixture")
    require(pe_self_test, "in-place output path was accepted", "PE distinct-output fixture")
    require(pe, "usage: canonicalize-pe.py --output ABSENT_OUTPUT INPUT.exe", "PE absent-output CLI")
    require(pe, "canonicalize-pe self-test: ok", "PE synthetic tests")

    msi_layout = ast.get_source_segment(msi, python_function(msi_tree, "_cabinet_layout")) or ""
    msi_stream = ast.get_source_segment(msi, python_function(msi_tree, "_cabinet_stream")) or ""
    msi_canonicalize = ast.get_source_segment(msi, python_function(msi_tree, "canonicalize")) or ""
    msi_verify = ast.get_source_segment(msi, python_function(msi_tree, "_verify_file")) or ""
    msi_sync = ast.get_source_segment(msi, python_function(msi_tree, "_open_sync_regular")) or ""
    msi_self_test = ast.get_source_segment(msi, python_function(msi_tree, "self_test")) or ""
    require(msi, "FMTID_SUMMARY_INFORMATION", "exact SummaryInformation FMTID")
    require(msi_stream, "if len(candidates) != 1:", "unique embedded cabinet count")
    require(msi_stream, "MSI must contain exactly one valid embedded cabinet", "unique embedded CAB rejection")
    require(msi_layout, "if flags & 0x0003:", "previous/next cabinet chaining rejection")
    require(msi_layout, "if folder_count != 1 or file_count == 0:", "exact one-folder cabinet")
    require(msi_layout, "order = (folder_index, folder_offset, folded)", "canonical cabinet file order key")
    require(msi_layout, "if previous_order is not None and order <= previous_order:", "strict cabinet file order")
    require(msi_layout, "if folder_offset != previous_end:", "contiguous cabinet file coverage")
    require(
        msi_layout,
        "if previous_end_by_folder.get(0) != folder_uncompressed[0]:",
        "complete cabinet folder coverage",
    )
    require(msi, 'struct.pack_into("<H", mutable, date_offset, 0x0021)', "CAB date normalization")
    require(msi, 'struct.pack_into("<H", mutable, time_offset, 0)', "CAB time normalization")
    require(msi, 'struct.pack_into("<Q", root, 100, 0)', "root create timestamp")
    require(msi, 'struct.pack_into("<Q", root, 108, 0)', "root modify timestamp")
    require(
        msi_canonicalize,
        "if len({os.path.normcase(path), os.path.normcase(output), os.path.normcase(contract_output)}) != 3:",
        "distinct MSI input/output/contract paths",
    )
    require(
        msi_canonicalize,
        "if os.path.lexists(output) or os.path.lexists(contract_output):",
        "absent MSI output and contract paths",
    )
    require(msi_canonicalize, "os.link(temporary, output, follow_symlinks=False)", "no-clobber MSI publication")
    require(
        msi_canonicalize,
        "os.link(contract_temporary, contract_output, follow_symlinks=False)",
        "no-clobber cabinet contract publication",
    )
    require_order(
        msi_canonicalize,
        (
            "os.link(contract_temporary, contract_output, follow_symlinks=False)",
            "os.unlink(contract_temporary)",
            "if _read_file(contract_output) != contract_bytes:",
            "os.chmod(contract_output, 0o400)",
        ),
        "Windows-deletable contract publication before read-only finalization",
    )
    require(msi_canonicalize, "_make_deletable(contract_output)", "Windows MSI contract rollback authority")
    require(msi_canonicalize, "_require_real_directory_path", "MSI ancestor reparse rejection")
    require(msi_verify, '"format": "rustdesk-msi-cabinet-contract-v1"', "MSI cabinet contract")
    require(msi_verify, '"cabinet_sha256": hashlib.sha256(cabinet).hexdigest()', "cabinet byte digest contract")
    require(msi_verify, '"sequence": index', "cabinet sequence contract")
    require(msi, "MSI input, absent outputs, and all identity options are required", "MSI absent-output CLI")
    for mutation in ("cabinet-chain", "file-order", "file-overlap"):
        require(msi_self_test, f'"{mutation}"', f"MSI behavioral fixture {mutation}")
    require(
        msi,
        'flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0)',
        "portable MSI open flags",
    )
    require(
        msi,
        '() if os.name == "nt" else ("st_mode", "st_ctime_ns")',
        "platform-correct MSI stability fields",
    )
    require(msi, 'if os.name != "nt":', "portable MSI directory durability")
    require(
        msi_sync,
        'flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0)',
        "Windows-writable MSI sync handle",
    )
    require(msi_sync, "state.st_nlink != 1", "one-link MSI sync handle")
    require(
        msi_sync,
        "(state.st_dev, state.st_ino) != expected_identity",
        "exact MSI sync handle identity",
    )
    require(
        msi_canonicalize,
        "output_sync = _open_sync_regular(output, output_identity)",
        "canonical MSI writable sync handle",
    )
    require(
        msi_canonicalize,
        "contract_sync = _open_sync_regular(contract_output, contract_identity)",
        "MSI contract writable sync handle",
    )
    require(msi_canonicalize, "if output_sync >= 0:", "partial MSI sync handle cleanup")
    require(msi_canonicalize, "if contract_sync >= 0:", "partial contract sync handle cleanup")
    require(msi, "source_descriptor = -1", "closed MSI source descriptor")
    require(msi, "canonicalize-msi self-test: ok", "MSI synthetic tests")

    require(build, "$canonicalMsiDir = Join-Path $SRC 'target\\canonical-msi'", "private MSI output directory")
    require(
        build,
        "$msiCanonicalizerInput = Join-Path $canonicalMsiDir 'canonicalizer-input.msi'",
        "distinct one-link MSI canonicalizer input",
    )
    require(build, "canonical MSI output directory is not a fresh ordinary directory", "fresh MSI output directory proof")
    require_order(
        build,
        (
            "[IO.File]::Copy($msiBuiltOut, $msiCanonicalizerInput, $false)",
            "$msiCanonicalizerInputItem = Get-OrdinaryPathItem $msiCanonicalizerInput $true",
            "$msiCanonicalizerInputHash = (Get-FileHash -LiteralPath $msiCanonicalizerInput -Algorithm SHA256).Hash",
            "'scripts\\canonicalize-msi.py'",
            "$msiCanonicalizerInput",
            "'--output'",
            "$msiOut",
            "'--contract-out'",
            "$msiContract",
            "& $PYTHON_EXE -I -S -c $isolatedOlefileRunner $olefileWheel @msiCanonicalizerArguments",
            "Remove-Item -LiteralPath $msiCanonicalizerInput -Force",
        ),
        "isolated one-link MSI absent-output canonicalization",
    )
    require(
        build,
        "WiX output or canonicalizer input changed during canonicalization",
        "MSI source/input stability proof",
    )
    require(
        build,
        "$msi = Join-Path $SRC 'target\\canonical-msi\\rustdesk.msi'",
        "canonical MSI artifact emission",
    )
    require(build, "canonical MSI cabinet contract schema is not exact", "exact cabinet contract schema")
    require(build, "$cabinetContract.files -isnot [Array]", "cabinet contract array type proof")
    require(build, "Get-JsonInt64 $entry.folder", "one-folder contract integer proof")
    require(build, "$sequence -ne ($index + 1)", "contiguous contract sequence comparison")
    require(build, "$offset -ne $expectedOffset", "contiguous contract offset comparison")
    require(build, "$expectedOffset -gt ([Int64][UInt32]::MaxValue - $size)", "cabinet extent overflow proof")
    require(
        build,
        "SELECT `DiskId`, `LastSequence`, `Cabinet` FROM `Media` ORDER BY `DiskId`",
        "Windows Installer Media table comparison",
    )
    require(build, "$mediaRows.Count -ne 1", "exact one-row Media table")
    require(build, "[Int64]$mediaRows[0].Values[1] -ne $contractFiles.Count", "Media all-files coverage")
    require(build, "$zeroRows.Count -ne 0", "COM zero-row behavior proof")
    require(
        build,
        "SELECT `File`, `FileSize`, `Sequence` FROM `File` ORDER BY `Sequence`",
        "Windows Installer File table comparison",
    )
    require(build, "$fileRows.Count -ne $contractFiles.Count", "File/contract count comparison")
    require(build, "$row[0] -cne $entry.id", "File ID comparison")
    require(build, "[Int64]$row[1] -ne (Get-JsonInt64 $entry.size", "File size comparison")
    require(build, "[Int64]$row[2] -ne (Get-JsonInt64 $entry.sequence", "File sequence comparison")
    require(build, "$value -is [int] -or $value -is [long]", "COM integer variant type proof")
    require(build, "$value -isnot [string]", "COM string variant type proof")
    require(
        build,
        "$database = $installer.OpenDatabase([string]$msiOut, [int]0)",
        "direct typed Windows Installer database open",
    )
    reject(
        build,
        r"\.GetType\(\)\.InvokeMember\(\s*'OpenDatabase'",
        "reflection-bound Windows Installer database open",
    )
    require(build, "return $rows.ToArray()", "PowerShell-safe COM row array materialization")
    reject(build, r"return\s+@\(\$rows\)", "PowerShell generic-list dynamic enumeration")
    require(build, 'SELECT ``Data`` FROM ``_Streams`` WHERE ``Name`` = \'$Name\'', "Windows Installer _Streams byte query")
    require(build, "'DataSize'", "_Streams declared byte size")
    require(build, "'ReadStream'", "_Streams byte reader")
    require(build, "[Text.EncoderFallback]::ExceptionFallback", "lossless _Streams byte decoding")
    require(build, "$chunk -isnot [string]", "_Streams chunk variant type proof")
    require(build, "$bytes = $encoding.GetBytes($chunk)", "_Streams string-to-byte conversion")
    require(build, "$sha.TransformBlock($bytes, 0, $bytes.Length, $bytes, 0)", "incremental _Streams byte hashing")
    require(build, "if ($null -ne $extra)", "_Streams native null EOF acceptance")
    require(build, "$extra.Length -ne 0", "_Streams exact byte extent")
    require(build, "$second = $view.GetType().InvokeMember('Fetch'", "duplicate _Streams row check")
    require(build, "$cabinetDigest -cne $cabinetContract.cabinet_sha256", "_Streams/cabinet digest comparison")
    require(build, "$viewClosed = $true", "successful COM view close proof")

    for mutation in (
        "patch-block-remove",
        "patch-block-substitute",
        "patch-block-reorder",
        "port-version",
        "guest-mingw-cache-name",
    ):
        require(watch, mutation, f"codec watcher mutation {mutation}")
    validate_port(sources["port"], sources["metadata"])


def load_sources(repo: pathlib.Path) -> dict[str, str]:
    sources = {}
    for name, relative in FILES.items():
        path = repo / relative
        if not path.is_file():
            raise VerificationError(f"missing harness file: {relative}")
        sources[name] = path.read_text(encoding="utf-8")
    return sources


def run_bounded_self_test(
    repo: pathlib.Path,
    command: list[str],
    expected_output: str,
    description: str,
    timeout_seconds: int,
) -> None:
    try:
        process = subprocess.Popen(
            command,
            cwd=repo,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=(os.name == "posix"),
        )
    except OSError as exc:
        raise VerificationError(f"could not start {description}: {exc}") from exc
    try:
        stdout, stderr = process.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired as exc:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
        stdout, stderr = process.communicate()
        detail = (stdout + stderr).strip()
        raise VerificationError(
            f"{description} exceeded {timeout_seconds}s timeout"
            + (f": {detail[-2000:]}" if detail else "")
        ) from exc
    if process.returncode != 0:
        detail = (stdout + stderr).strip()
        raise VerificationError(
            f"{description} failed with exit {process.returncode}"
            + (f": {detail[-2000:]}" if detail else "")
        )
    if expected_output not in stdout:
        detail = (stdout + stderr).strip()
        raise VerificationError(
            f"{description} did not report its success marker {expected_output!r}"
            + (f": {detail[-2000:]}" if detail else "")
        )


def run_behavioral_self_tests(repo: pathlib.Path) -> None:
    tests = (
        (
            ["bash", "scripts/build-windows-vm.sh", "--self-test"],
            "build-windows-vm self-test: ok",
            "Windows VM harness behavioral self-test",
            45,
        ),
        (
            [sys.executable, "scripts/windows-offline-manifest.py", "--self-test"],
            "windows-offline-manifest self-test: ok",
            "Windows offline-media manifest behavioral self-test",
            20,
        ),
        (
            [sys.executable, "scripts/publish-windows-result.py", "--self-test"],
            "publish-windows-result self-test: ok",
            "Windows result-publication behavioral self-test",
            20,
        ),
        (
            [sys.executable, "scripts/canonicalize-pe.py", "--self-test"],
            "canonicalize-pe self-test: ok",
            "PE canonicalizer behavioral self-test",
            20,
        ),
        (
            [sys.executable, "scripts/canonicalize-msi.py", "--self-test"],
            "canonicalize-msi self-test: ok",
            "MSI canonicalizer behavioral self-test",
            20,
        ),
        (
            [sys.executable, "scripts/verify-windows-installed-service-result.py", "--self-test"],
            "verify-windows-installed-service-result self-test: ok",
            "installed Windows SCM result behavioral self-test",
            20,
        ),
        (
            [sys.executable, "scripts/verify-windows-full-peer-presentation-result.py", "--self-test"],
            "verify-windows-full-peer-presentation-result self-test: ok",
            "Windows full-peer presentation result behavioral self-test",
            20,
        ),
    )
    for command, marker, description, timeout_seconds in tests:
        run_bounded_self_test(repo, command, marker, description, timeout_seconds)


def run_self_test(repo: pathlib.Path, sources: dict[str, str]) -> None:
    mutations = [
        (
            "Windows host preflight process-metadata exclusion",
            "lib",
            "ss -H -ltn 'sport = :53'",
            "ss -H -ltnp 'sport = :53'",
        ),
        (
            "Windows full-peer probe non-default feature",
            "cargo",
            "windows-full-peer-presentation-probe = []",
            "windows-full-peer-presentation-probe-retired = []",
        ),
        (
            "Windows full-peer exact loopback bind",
            "direct_service",
            "std::net::SocketAddr::from(([127, 0, 0, 1], port as u16))",
            "std::net::SocketAddr::from(([0, 0, 0, 0], port as u16))",
        ),
        (
            "Windows full-peer release inventory actual ordering",
            "build",
            "$actualDistNames = @($distBefore.Keys | Sort-Object -CaseSensitive)",
            "$actualDistNames = @($distBefore.Keys)",
        ),
        (
            "Windows full-peer release inventory canonical ordering",
            "build",
            "$canonicalDistNames = @($expectedDistNames | Sort-Object -CaseSensitive)",
            "$canonicalDistNames = @($expectedDistNames)",
        ),
        (
            "Windows full-peer release inventory exact comparison",
            "build",
            "if (($actualDistNames -join ',') -cne ($canonicalDistNames -join ',')) {",
            "if (($actualDistNames -join ',') -ceq ($canonicalDistNames -join ',')) {",
        ),
        (
            "Windows full-peer sustained frame count",
            "full_peer_controller",
            "for ($index = 0; $index -lt 120; $index++)",
            "for ($index = 0; $index -lt 12; $index++)",
        ),
        (
            "Windows full-peer sustained duration",
            "full_peer_controller",
            "$unfocusedDuration -lt 60000",
            "$unfocusedDuration -lt 6000",
        ),
        (
            "Windows full-peer minimized duration",
            "full_peer_controller",
            "$minimizedDuration -lt 10000",
            "$minimizedDuration -lt 1000",
        ),
        (
            "Windows full-peer minimized-duration receipt",
            "full_peer_controller",
            "minimized_duration_ms = $minimizedDuration",
            "minimized_duration_ms = 10000",
        ),
        (
            "Windows full-peer exact live TCP surface",
            "full_peer_controller",
            "$liveRows.Count -ne 3",
            "$liveRows.Count -eq 3",
        ),
        (
            "Windows full-peer window/TCP process binding",
            "full_peer_controller",
            "the real viewer window process is not the exact TCP-owning process generation",
            "viewer process binding skipped",
        ),
        (
            "Windows full-peer non-overlapping pointer observation",
            "full_peer_fixture",
            "$panel.Add_MouseMove($mouseMoveHandler)",
            "$panel.Add_MouseDown($mouseMoveHandler)",
        ),
        (
            "Windows full-peer closed verifier frame count",
            "full_peer_result",
            "len(updates) != 120",
            "len(updates) != 12",
        ),
        (
            "Windows full-peer closed verifier minimized-duration floor",
            "full_peer_result",
            'typed_int(restore["minimized_duration_ms"], 10_000, 300_000',
            'typed_int(restore["minimized_duration_ms"], 1_000, 300_000',
        ),
        (
            "pinned LLVM Windows resource input",
            "resource",
            "Command::new(&llvm_rc)",
            'Command::new("rc.exe")',
        ),
        (
            "ordered Windows resource fields",
            "resource",
            'VALUE "FileDescription", "RustDesk Remote Desktop"\nVALUE "FileVersion", "{version}"',
            'VALUE "FileVersion", "{version}"\nVALUE "FileDescription", "RustDesk Remote Desktop"',
        ),
        (
            "obsolete root winres metadata",
            "cargo",
            "[build-dependencies]",
            '[package.metadata.winres]\n[build-dependencies]',
        ),
        (
            "obsolete portable winres metadata",
            "portable_cargo",
            '[target.\'cfg(target_os = "windows")\'.dependencies]',
            '[package.metadata.winres]\n[target.\'cfg(target_os = "windows")\'.dependencies]',
        ),
        (
            "portable shared Windows resource producer",
            "portable_build",
            'windows_resource::compile(env!("CARGO_PKG_VERSION"), resource_root)',
            "Ok(())",
        ),
        (
            "all-Windows root resource producer",
            "buildrs",
            '#[cfg(windows)]\nfn build_manifest(version: &str) -> Result<(), Box<dyn Error>>',
            '#[cfg(all(windows, feature = "inline"))]\nfn build_manifest(version: &str) -> Result<(), Box<dyn Error>>',
        ),
        (
            "native ordered Windows resource gate",
            "build",
            "    Assert-PowerShellSourceParsing\n    Assert-DeterministicWindowsResource",
            "    Assert-PowerShellSourceParsing\n    Write-Host 'resource gate skipped'",
        ),
        (
            "native portable compiled-resource gate",
            "build",
            "    Assert-CompiledWindowsResource $portableResource 'RustDesk portable packer'",
            "    Write-Host 'portable compiled resource skipped'",
        ),
        (
            "native linked library VERSIONINFO gate",
            "build",
            "    Assert-WindowsExecutableVersionInfo $rustLibrary $applicationVersion 'RustDesk library'",
            "    Write-Host 'linked library VERSIONINFO skipped'",
        ),
        (
            "cross-crate compiled resource equality",
            "build",
            "$applicationResourceHash -cne $portableResourceHash",
            "$applicationResourceHash -cne $applicationResourceHash",
        ),
        (
            "Windows SystemServices feature",
            "cargo",
            '    "Win32_System_SystemServices",',
            '    # "Win32_System_SystemServices" removed',
        ),
        (
            "Windows ReplaceFileW API identity",
            "windows",
            "ReplaceFileW as WinReplaceFileW",
            "ReplaceFileW",
        ),
        (
            "Windows HLOCAL pointer identity",
            "windows",
            "WinHLOCAL(self.0 .0 as *mut std::ffi::c_void)",
            "WinHLOCAL(self.0 .0 as *mut c_void)",
        ),
        (
            "Windows service status slot type",
            "windows",
            "OnceLock::<ServiceStatusHandle>::new()",
            "OnceLock::new()",
        ),
        (
            "Windows service SAS channel type",
            "windows",
            "mpsc::channel::<WindowsServiceSasRequest>(1)",
            "mpsc::channel(1)",
        ),
        (
            "Windows service listener close-before-rebind",
            "windows",
            "let previous = incoming\n        .take()",
            "let previous = incoming\n        .as_mut()",
        ),
        (
            "Windows progress CRLF parser",
            "host",
            'if not data.endswith(b"\\r\\n"):',
            'if not data.endswith(b"\\n"):',
        ),
        (
            "Windows path identity visibility",
            "windows",
            "pub(crate) struct WindowsPathIdentity",
            "struct WindowsPathIdentity",
        ),
        (
            "Windows listener source gate",
            "verify",
            "refresh_service_ipc_listener(&mut incoming).await",
            "refresh_service_ipc_listener(incoming).await",
        ),
        (
            "Windows state/output filesystem root",
            "host",
            '{ [ "$first" != / ] && [ "$second" != / ]; } \\\n        || die "$first_label and $second_label cannot be disjoint from the filesystem root"',
            "true # filesystem root accepted",
        ),
        (
            "Windows state/output equality",
            "host",
            '[ "$first" != "$second" ] \\\n        || die "$first_label and $second_label must be disjoint"',
            "true # equal paths accepted",
        ),
        (
            "Windows state/output descendant",
            "host",
            '"$second/"*) die "$first_label must not be beneath $second_label" ;;',
            '"$second/"*) : ;;',
        ),
        (
            "Windows state/output ancestor",
            "host",
            '"$first/"*) die "$second_label must not be beneath $first_label" ;;',
            '"$first/"*) : ;;',
        ),
        (
            "planned Windows path disjointness",
            "host",
            'assert_disjoint_paths "$planned_state" "Windows harness state" \\\n        "$planned_output" "Windows output"',
            "true # planned path disjointness removed",
        ),
        (
            "canonical Windows path disjointness",
            "host",
            'assert_disjoint_paths "$STATE_DIR" "Windows harness state" "$OUT_DIR" "Windows output"',
            "true # canonical path disjointness removed",
        ),
        (
            "direct Windows double-build",
            "host",
            'if [ "${DOUBLE_BUILD:-1}" = "1" ]; then',
            'if [ "${DOUBLE_BUILD:-1}" = "0" ]; then',
        ),
        ("domain UUID", "host", '--uuid "$CURRENT_DOMAIN_UUID"', '--uuid "$RUN_ID"'),
        ("VM deadline", "host", "VM_TIMEOUT_SECONDS=7200", "VM_TIMEOUT_SECONDS=0"),
        ("VM creation deadline", "host", "CREATE_TIMEOUT_SECONDS=300", "CREATE_TIMEOUT_SECONDS=0"),
        ("control timeout", "host", "CONTROL_TIMEOUT_SECONDS=30", "CONTROL_TIMEOUT_SECONDS=0"),
        (
            "bounded process-group admission timeout",
            "host",
            "PROCESS_ADMISSION_SECONDS=10",
            "PROCESS_ADMISSION_SECONDS=0",
        ),
        ("process stop deadline", "host", "PROCESS_STOP_SECONDS=10", "PROCESS_STOP_SECONDS=0"),
        ("fixed libvirt control locale", "host", "export LC_ALL=C", "export LC_ALL=en_US.UTF-8"),
        (
            "exact Windows domain lifecycle command preflight",
            "host",
            "require_cmd qemu-img virt-install virsh xorriso git python3 realpath "
            "sha256sum sha512sum timeout setsid awk",
            "require_cmd qemu-img virt-install virsh xorriso git python3 realpath "
            "sha256sum sha512sum timeout setsid",
        ),
        ("setsid wait", "host", "setsid --wait virt-install", "setsid virt-install"),
        (
            "detached bounded virsh",
            "host",
            'setsid --wait \\\n'
            '        timeout --foreground --kill-after=2 "$CONTROL_TIMEOUT_SECONDS"',
            'timeout --foreground --kill-after=2 "$CONTROL_TIMEOUT_SECONDS"',
        ),
        (
            "closed virsh input",
            "host",
            'virsh --connect qemu:///session "$@" </dev/null',
            'virsh --connect qemu:///session "$@"',
        ),
        (
            "post-libvirt-10 virsh option absence",
            "host",
            "export LC_ALL=C",
            "export LC_ALL=C\n# --no-pkttyagent is not a compatible control boundary",
        ),
        (
            "fail-closed domain-name enumeration",
            "host",
            'names="$(virsh_bounded list --all --name)" || return 2',
            'names="$(virsh_bounded domuuid "$CURRENT_DOMAIN")" || return 1',
        ),
        (
            "fail-closed domain-UUID enumeration",
            "host",
            'uuids="$(virsh_bounded list --all --uuid)" || return 2',
            'uuids="$(virsh_bounded list --uuid)" || return 1',
        ),
        (
            "pre-existing domain-name refusal",
            "host",
            "generated domain name already exists; refusing to mutate it",
            "generated domain name already exists; destroying it",
        ),
        (
            "pre-existing domain-UUID refusal",
            "host",
            "generated domain UUID already exists; refusing to mutate it",
            "generated domain UUID already exists; adopting it",
        ),
        (
            "creation-intent authority boundary",
            "host",
            "CURRENT_DOMAIN_CREATION_STARTED=1",
            "CURRENT_DOMAIN_CREATION_STARTED=0",
        ),
        (
            "ownership-commit authority boundary",
            "host",
            "CURRENT_DOMAIN_OWNERSHIP_COMMITTED=1",
            "CURRENT_DOMAIN_OWNERSHIP_COMMITTED=0",
        ),
        (
            "no-launch no-domain-authority branch",
            "host",
            'if [ "$CURRENT_DOMAIN_CREATION_STARTED" = 0 ]; then',
            'if [ "$CURRENT_DOMAIN_CREATION_STARTED" = 1 ]; then',
        ),
        (
            "pre-commit no-destructive-authority branch",
            "host",
            'if [ "$CURRENT_DOMAIN_OWNERSHIP_COMMITTED" = 0 ]; then',
            'if [ "$CURRENT_DOMAIN_OWNERSHIP_COMMITTED" = 1 ]; then',
        ),
        (
            "UUID-addressed secondary name proof",
            "host",
            'virsh_bounded domname "$CURRENT_DOMAIN_UUID"',
            'virsh_bounded domname "$CURRENT_DOMAIN"',
        ),
        (
            "ambiguous launch preservation",
            "host",
            "uncommitted provision UUID exists after an ambiguous launch; preserving it",
            "uncommitted provision UUID exists after an ambiguous launch; destroying it",
        ),
        (
            "UUID-addressed domain XML proof",
            "host",
            'virsh_bounded dumpxml "$CURRENT_DOMAIN_UUID"',
            'virsh_bounded dumpxml "$CURRENT_DOMAIN"',
        ),
        (
            "UUID-addressed domain state controls",
            "host",
            'virsh_bounded domstate "$CURRENT_DOMAIN_UUID"',
            'virsh_bounded domstate "$CURRENT_DOMAIN"',
        ),
        (
            "UUID-addressed destroy",
            "host",
            'virsh_bounded destroy "$CURRENT_DOMAIN_UUID"',
            'virsh_bounded destroy "$CURRENT_DOMAIN"',
        ),
        (
            "UUID-addressed undefine",
            "host",
            'virsh_bounded undefine "$CURRENT_DOMAIN_UUID" --nvram',
            'virsh_bounded undefine "$CURRENT_DOMAIN" --nvram',
        ),
        (
            "process-before-domain-before-helper-before-state terminal cleanup",
            "host",
            "elif ! stop_and_undefine_owned_domain; then",
            "if ! stop_and_undefine_owned_domain; then",
        ),
        (
            "run-root retained device/inode identity",
            "host",
            'RUN_ROOT_ID="$device:$inode"',
            'RUN_ROOT_ID="$RUN_ROOT"',
        ),
        (
            "production run-root creation identity binding",
            "host",
            'RUN_ROOT="$(mktemp -d "$STATE_DIR/windows-build-$RUN_ID.XXXXXXXX")"\n'
            "    record_run_root_identity",
            'RUN_ROOT="$(mktemp -d "$STATE_DIR/windows-build-$RUN_ID.XXXXXXXX")"\n'
            "    true # run-root identity not recorded",
        ),
        (
            "helper-before-run-state cleanup",
            "host",
            "if ! windows_helper_authority_close; then",
            "if ! retire_windows_helper_authority; then",
        ),
        (
            "output-parent retained device/inode identity",
            "host",
            'OUT_PARENT_ID="$device:$inode"',
            'OUT_PARENT_ID="$OUT_PARENT"',
        ),
        (
            "output-parent identity binding",
            "host",
            'OUT_DIR="$OUT_PARENT/$(basename "$OUT_DIR")"\n'
            "    record_output_parent_identity",
            'OUT_DIR="$OUT_PARENT/$(basename "$OUT_DIR")"\n'
            "    true # output-parent identity not recorded",
        ),
        (
            "helper retirement before publication",
            "host",
            "windows_helper_authority_close \\\n"
            '        || die "Windows helper authority could not retire before artifact publication"\n'
            '    publish_result "$RUN_ROOT/pass-A/result"',
            "retire_windows_helper_authority \\\n"
            '        || die "Windows helper authority could not retire before artifact publication"\n'
            '    publish_result "$RUN_ROOT/pass-A/result"',
        ),
        (
            "isolated Windows publication prepare helper",
            "host",
            '/usr/bin/python3 -I -S "$SCRIPT_DIR/publish-windows-result.py" \\\n'
            "            --prepare",
            '/usr/bin/python3 "$SCRIPT_DIR/publish-windows-result.py" \\\n'
            "            --prepare",
        ),
        (
            "isolated Windows publication commit helper",
            "host",
            '/usr/bin/python3 -I -S "$SCRIPT_DIR/publish-windows-result.py" \\\n'
            "            --commit",
            '/usr/bin/python3 "$SCRIPT_DIR/publish-windows-result.py" \\\n'
            "            --commit",
        ),
        (
            "publication output-parent identity handoff",
            "host",
            '--output-parent-identity "$OUT_PARENT_ID"',
            '--output-parent-identity "$OUT_PARENT"',
        ),
        (
            "run-root retirement before final publication",
            "host",
            "remove_completed_run_root \\\n"
            '        || die "Windows private run state could not retire before final publication"',
            "true # private run state not retired before final publication",
        ),
        (
            "pending candidate authority parsing",
            "host",
            'read -r pending pending_identity extra <<<"$authority"',
            'read -r pending pending_identity <<<"$authority"',
        ),
        (
            "publication no-clobber primitive",
            "publication",
            "RENAME_NOREPLACE = 1",
            "RENAME_NOREPLACE = 0",
        ),
        (
            "publication expected directory identity",
            "publication",
            "if identity(opened) != expected:",
            "if identity(opened) == expected:",
        ),
        (
            "publication principal ownership",
            "publication",
            "if opened.st_uid != os.getuid() or opened.st_gid != os.getgid():",
            "if opened.st_uid != os.getuid():",
        ),
        (
            "publication unsafe parent-mode rejection",
            "publication",
            "elif mode & 0o7000 or mode & 0o022 or mode & 0o700 != 0o700:",
            "elif mode & 0o7000 or mode & 0o700 != 0o700:",
        ),
        (
            "publication source-file single-link proof",
            "publication",
            "or before.st_nlink != 1",
            "or before.st_nlink < 1",
        ),
        (
            "publication closed artifact inventory",
            "publication",
            'ARTIFACTS = ("rustdesk-setup.exe", "rustdesk.msi")',
            'ARTIFACTS = ("rustdesk-setup.exe", "rustdesk.msi", "unexpected")',
        ),
        (
            "publication same-filesystem precondition",
            "publication",
            "if run_info.st_dev != parent_info.st_dev:",
            "if run_info.st_dev == parent_info.st_dev:",
        ),
        (
            "publication private candidate authority",
            "publication",
            "os.mkdir(CANDIDATE_NAME, 0o700, dir_fd=run_root)",
            "os.mkdir(CANDIDATE_NAME, 0o700, dir_fd=output_parent)",
        ),
        (
            "publication source checksum binding",
            "publication",
            "if actual != parsed[artifact][0]:",
            "if actual != actual:",
        ),
        (
            "canonical publication checksum source modes",
            "host",
            "chmod 0644 -- rustdesk-setup.exe.sha256 rustdesk.msi.sha256",
            "chmod 0600 -- rustdesk-setup.exe.sha256 rustdesk.msi.sha256",
        ),
        (
            "publication candidate synchronization",
            "publication",
            "os.fsync(candidate)",
            "os.fstat(candidate)",
        ),
        (
            "publication destination synchronization",
            "publication",
            "os.fsync(output_parent)",
            "os.fstat(output_parent)",
        ),
        (
            "publication pending-name grammar",
            "publication",
            'PENDING_RE = re.compile(r"^\\.windows-output-pending-[0-9a-f]{64}$")',
            'PENDING_RE = re.compile(r"^\\.windows-output-pending-.*$")',
        ),
        (
            "publication descriptor-relative pending park",
            "publication",
            "rename_noreplace(run_root, CANDIDATE_NAME, output_parent, pending)",
            "rename_noreplace(output_parent, CANDIDATE_NAME, output_parent, pending)",
        ),
        (
            "publication pending identity",
            "publication",
            "if identity(candidate_info) != expected_pending:",
            "if identity(candidate_info) == expected_pending:",
        ),
        (
            "publication authenticated pending edge",
            "publication",
            "identity(pending_info) != identity(candidate_info)",
            "identity(pending_info) != identity(pending_info)",
        ),
        (
            "publication same-parent final edge",
            "publication",
            "rename_noreplace(output_parent, pending, output_parent, destination)",
            "rename_noreplace(output_parent, destination, output_parent, pending)",
        ),
        (
            "publication authenticated destination edge",
            "publication",
            "identity(published) != identity(candidate_info)",
            "identity(published) != identity(published)",
        ),
        (
            "R-S11du requirement",
            "requirements",
            '<span class="id">R-S11du</span>',
            '<span class="id">R-S11du-disabled</span>',
        ),
        (
            "normative exact run-root retirement before final publication",
            "requirements",
            "remove the exact remaining run-root identity through R-S11dt's "
            "descriptor-relative private-tree closure while the requested destination is still absent",
            "leave the run root for cleanup after final publication",
        ),
        (
            "Appendix C #274 disposition",
            "requirements",
            "<tr><td>274</td>",
            "<tr><td>274-disabled</td>",
        ),
        (
            "R-S11du hardening-ledger disposition",
            "hardening",
            "R-S11du/R-S11e-139 — Windows result publication is exact-object and authority-terminal",
            "R-S11du/R-S11e-139 — Windows result publication is pathname-owned",
        ),
        (
            "identity-bound run-root removal",
            "host",
            '--remove-private-root "$1" --expected-identity "$2"',
            'rm -rf -- "$1"',
        ),
        (
            "run-root removal isolated Python",
            "host",
            '/usr/bin/python3 -I -S "$LIB_DIR/verify-private-tree-closure.py"',
            '/usr/bin/python3 "$LIB_DIR/verify-private-tree-closure.py"',
        ),
        (
            "run-root removal closed environment",
            "host",
            "/usr/bin/env -i PATH=/usr/bin:/bin",
            "/usr/bin/env PATH=/usr/bin:/bin",
        ),
        (
            "run-root authority clearing after absence",
            "host",
            '{ [ ! -e "$RUN_ROOT" ] && [ ! -L "$RUN_ROOT" ]; } || return 1\n'
            '    RUN_ROOT=""\n'
            '    RUN_ROOT_ID=""',
            'RUN_ROOT=""\n'
            '    RUN_ROOT_ID=""',
        ),
        (
            "run-root substitution preservation fixture",
            "host",
            "run-root substitution self-test deleted a replacement edge",
            "run-root substitution self-test accepted replacement deletion",
        ),
        (
            "private-tree mount-boundary semantics",
            "closure",
            "private-tree cleanup crosses a mount boundary",
            "private-tree cleanup accepts a mount boundary",
        ),
        (
            "owned session",
            "host",
            '&& [ "$session" = "$CURRENT_VIRT_PID" ]',
            '&& [ -n "$session" ]',
        ),
        (
            "wait_for_owned_process_group",
            "host",
            "wait_for_owned_process_group() {",
            "wait_for_unowned_process_group() {",
        ),
        (
            "admission start-identity refusal",
            "host",
            '[ "$start" = "$CURRENT_VIRT_START" ] || return 1',
            '[ -n "$start" ] || return 1',
        ),
        (
            "admission live-state refusal",
            "host",
            '[ "$state" != Z ] && [ "$state" != X ] || return 1',
            "true # terminal admission accepted",
        ),
        (
            "post-launch process-group admission",
            "host",
            "wait_for_owned_process_group \\\n"
            '        || die "could not prove virt-install process-group admission"',
            "true # process-group admission omitted",
        ),
        (
            "delayed process-group admission fixture",
            "host",
            "'sleep 1; exec setsid --wait bash -c \"$1\"'",
            "'exec setsid --wait bash -c \"$1\"'",
        ),
        (
            "pre-admission refusal fixture",
            "host",
            "delayed process-group fixture skipped its pre-admission state",
            "delayed process-group fixture accepted its pre-admission state",
        ),
        (
            "delayed-admission completion fixture",
            "host",
            "delayed process-group fixture did not admit conclusively",
            "delayed process-group fixture admission was ignored",
        ),
        (
            "robust retained-leader proc-stat boundary",
            "host",
            'stat="$(<"/proc/$pid/stat")" || return 1\n'
            '    stat="${stat##*) }"',
            'stat="$(<"/proc/$pid/stat")" || return 1\n'
            '    stat="${stat#*) }"',
        ),
        (
            "robust process-group proc-stat boundary",
            "host",
            'stat="$(<"$path")" || continue\n'
            '        stat="${stat##*) }"',
            'stat="$(<"$path")" || continue\n'
            '        stat="${stat#*) }"',
        ),
        (
            "complete process-group drain",
            "host",
            "while owned_process_group_is_live \\\n"
            '            && [ "$(monotonic_seconds)" -lt "$deadline" ]; do',
            "while owned_process_is_live \\\n"
            '            && [ "$(monotonic_seconds)" -lt "$deadline" ]; do',
        ),
        (
            "reused leader identity refusal",
            "host",
            '[ ! -e "/proc/$CURRENT_VIRT_PID" ] || return 1',
            '[ -e "/proc/$CURRENT_VIRT_PID" ] || return 1',
        ),
        (
            "owned process group KILL",
            "host",
            'kill -KILL -- "-$CURRENT_VIRT_PID"',
            'kill -KILL -- "$CURRENT_VIRT_PID"',
        ),
        (
            "KILL leader reap before final process-group drain",
            "host",
            'kill -KILL -- "-$CURRENT_VIRT_PID" || return 1\n'
            '            wait "$CURRENT_VIRT_PID" 2>/dev/null || :',
            'kill -KILL -- "-$CURRENT_VIRT_PID" || return 1',
        ),
        (
            "deadline domain termination",
            "host",
            'stop_and_undefine_owned_domain || die "timed-out domain could not be destroyed and undefined safely"',
            'die "Windows build timed out"',
        ),
        ("private state", "host", "windows-build-$RUN_ID.XXXXXXXX", "windows-build-fixed"),
        ("zombie reap", "host", '[ "$state" != Z ] && [ "$state" != X ]', "true"),
        (
            "golden exclusive snapshot",
            "host",
            "os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC",
            "os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_CLOEXEC",
        ),
        (
            "golden source ownership",
            "host",
            "not stat.S_ISREG(before.st_mode) or before.st_uid != uid or before.st_nlink != 1",
            "not stat.S_ISREG(before.st_mode)",
        ),
        (
            "golden source stability",
            "host",
            "if any(getattr(before, field) != getattr(after, field) for field in stable_fields):",
            "if all(getattr(before, field) != getattr(after, field) for field in stable_fields):",
        ),
        (
            "golden snapshot hash",
            "host",
            "if digest.hexdigest() != expected:",
            "if not digest.hexdigest():",
        ),
        ("golden immutable mode", "host", "os.fchmod(destination_fd, 0o400)", "os.fchmod(destination_fd, 0o600)"),
        (
            "golden pre-overlay rehash",
            "host",
            "prepare_overlay() {\n    verify_private_golden",
            "prepare_overlay() {\n    :",
        ),
        (
            "golden pre-publication rehash",
            "host",
            "verify_active_online_snapshot\n"
            "    verify_private_golden\n"
            "    windows_helper_authority_close",
            "verify_active_online_snapshot\n"
            "    windows_helper_authority_close",
        ),
        (
            "worktree capture",
            "host",
            'GIT_INDEX_FILE="$index" git -C "$REPO_ROOT" -c core.hooksPath=/dev/null add -A -- .',
            'git -C "$REPO_ROOT" add -A -- .',
        ),
        ("networkless VM", "host", "--network none", "--network default"),
        (
            "loopback-only Windows VM console",
            "host",
            "--graphics vnc,listen=127.0.0.1",
            "--graphics vnc,listen=0.0.0.0",
        ),
        (
            "R-S11ds requirement",
            "requirements",
            '<span class="id">R-S11ds</span>',
            '<span class="id">R-S11ds-disabled</span>',
        ),
        (
            "normative ownership-commit boundary",
            "requirements",
            "A selected UUID, creation intent, or unadmitted child alone",
            "A selected UUID, creation intent, or unadmitted child always",
        ),
        (
            "normative complete client-process authority",
            "requirements",
            "complete retained matching client process group and session",
            "retained matching client leader",
        ),
        (
            "normative process-group admission",
            "requirements",
            "boundedly re-prove that same live identity",
            "optionally inspect that live identity",
        ),
        (
            "normative version-compatible noninteractive control",
            "requirements",
            "use the fixed <code>qemu:///session</code> URI, C locale, one fresh "
            "<code>setsid</code> control session with standard input closed",
            "use an interactive system-libvirt control process",
        ),
        (
            "Appendix C #272 disposition",
            "requirements",
            "<tr><td>272</td>",
            "<tr><td>272-disabled</td>",
        ),
        (
            "Appendix C #291 disposition",
            "requirements",
            "<tr><td>291</td>",
            "<tr><td>291-disabled</td>",
        ),
        (
            "Appendix C #336 disposition",
            "requirements",
            "<tr><td>336</td>",
            "<tr><td>336-disabled</td>",
        ),
        (
            "R-S11ds hardening-ledger disposition",
            "hardening",
            "R-S11ds/R-S11e-137 — Windows per-build VM owns one exact libvirt UUID",
            "R-S11ds/R-S11e-137 — Windows per-build VM owns a mutable name",
        ),
        (
            "setsid-admission hardening-ledger disposition",
            "hardening",
            "R-S11dr/R-S11ds/R-S11e-170 — exact setsid process-group admission",
            "R-S11dr/R-S11ds/R-S11e-170 — ambient setsid process-group admission",
        ),
        (
            "version-compatible session-libvirt hardening-ledger disposition",
            "hardening",
            "R-S11dr/R-S11ds/R-S11e-214 — version-compatible noninteractive "
            "session-libvirt control",
            "R-S11dr/R-S11ds/R-S11e-214 — interactive session-libvirt control",
        ),
        (
            "R-S11ds focused gate wiring",
            "verify",
            "python3 scripts/verify-windows-harness.py --repo . --self-test",
            "true # Windows per-build domain gate removed",
        ),
        (
            "R-S11dt requirement",
            "requirements",
            '<span class="id">R-S11dt</span>',
            '<span class="id">R-S11dt-disabled</span>',
        ),
        (
            "normative no-pathname-fallback boundary",
            "requirements",
            "MUST NOT</span> fall back to recursive pathname cleanup",
            "MAY</span> fall back to recursive pathname cleanup",
        ),
        (
            "Appendix C #273 disposition",
            "requirements",
            "<tr><td>273</td>",
            "<tr><td>273-disabled</td>",
        ),
        (
            "R-S11dt hardening-ledger disposition",
            "hardening",
            "R-S11dt/R-S11e-138 — Windows build run-state cleanup is identity-bound and authority-last",
            "R-S11dt/R-S11e-138 — Windows build run-state cleanup is pathname-owned",
        ),
        (
            "host reserved device namespace",
            "host",
            "con|prn|aux|nul|com[1-9]|lpt[1-9]",
            "con|prn|aux|nul",
        ),
        (
            "host generated namespace",
            "host",
            "if relative.casefold() in generated_folded:",
            "if False:",
        ),
        ("FRB user", "frb", '--user "$BUILD_UID:$BUILD_GID"', ""),
        (
            "image provenance",
            "runtime",
            'require_pinned_builder_image win-helper "$WIN_HELPER_IMAGE_ID"',
            "freeze_image win-helper",
        ),
        (
            "WiX package media mapping",
            "host",
            "/wix-nuget-packages=/online/wix-nuget-packages",
            "/wix-nuget-packages=/online/pub-cache",
        ),
        (
            "online snapshot",
            "host",
            'create_private_online_snapshot "$ONLINE_SNAPSHOT_PARENT"',
            "require_online_complete",
        ),
        (
            "offline link materialization",
            "host",
            "genisoimage -udf -D -r -f -quiet",
            "genisoimage -udf -D -r -quiet",
        ),
        (
            "offline no-follow file open",
            "offline",
            'flags |= os.O_NOFOLLOW',
            'flags |= os.O_APPEND',
        ),
        (
            "offline single-hop link target",
            "offline",
            "if not stat.S_ISREG(target_info.st_mode):",
            "if False:",
        ),
        (
            "offline case-collision byte identity",
            "offline",
            "previous_path == relative or previous_identity != identity",
            "previous_path == relative",
        ),
        (
            "offline exact path identity",
            "offline",
            "if relative in exact_paths:",
            "if False:",
        ),
        ("source media", "host", 'chmod -R a-w "$media_root"', ""),
        (
            "source case collision",
            "host",
            "previous = case_paths.get(folded)",
            "previous = None",
        ),
        (
            "FRB online root",
            "host",
            '--source-root "$SOURCE_SNAPSHOT" --online-root "$ONLINE_DIR" --output-root "$frb_root"',
            '--source-root "$SOURCE_SNAPSHOT" --cache-root "$ONLINE_DIR" --output-root "$frb_root"',
        ),
        ("FRB image provenance", "frb", 'require_pinned_builder_image deb-builder "$IMAGE_ID"', 'docker image inspect "$IMAGE_ID"'),
        ("FRB exact manifest", "host", "FRB manifest does not describe exactly the four canonical outputs", "FRB manifest accepted"),
        ("FRB read-only source", "frb", "FRB source snapshot has a writable entry", "FRB source snapshot accepted"),
        ("FRB publish", "frb", 'mv -T --no-clobber -- "$PUBLISH_ROOT" "$OUTPUT_ROOT"', 'cp -a "$PUBLISH_ROOT" "$OUTPUT_ROOT"'),
        ("guest fail loud", "guest", "$ErrorActionPreference = 'Stop'", "$ErrorActionPreference = 'Continue'"),
        (
            "guest reserved device namespace",
            "guest",
            "con|prn|aux|nul|com[1-9]|lpt[1-9]",
            "con|prn|aux|nul",
        ),
        (
            "guest generated namespace",
            "guest",
            "[StringComparer]::OrdinalIgnoreCase.Equals($rootComponent, $name)",
            "[StringComparer]::Ordinal.Equals($rootComponent, $name)",
        ),
        ("guest generated root", "guest", "$rootComponent = $components[0]", "$rootComponent = $Path"),
        ("guest outer shutdown", "guest", "$out = $null", "$out = 'C:\\missing'"),
        (
            "guest OFFLINE media proof",
            "guest",
            "    Assert-OfflineManifest $offlineMedia ([string]$identity.offline_manifest_sha256)",
            "    Write-Output $offlineMedia",
        ),
        (
            "guest exact OFFLINE file count",
            "guest",
            "$actualFiles.Count -ne $declaredFiles.Count",
            "$actualFiles.Count -lt 0",
        ),
        ("guest JSON integer", "guest", "Get-JsonInt64 $entry.size", "[Int64]$entry.size"),
        (
            "legacy source",
            "guest",
            "Remove-Item -LiteralPath $legacySource -Recurse -Force",
            "Write-Output $legacySource",
        ),
        (
            "legacy source reparse",
            "guest",
            "($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0",
            "$false",
        ),
        (
            "directory reparse",
            "guest",
            "($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0",
            "$false",
        ),
        (
            "extra directory",
            "guest",
            "if (-not $expectedDirectories.Contains($relative))",
            "if ($false)",
        ),
        (
            "stable Windows build root",
            "guest",
            "$source = Join-Path $buildParent 'source'",
            "$source = Join-Path $buildParent ([string]$identity.build_run_id)",
        ),
        (
            "source identity",
            "build",
            "    Assert-BuildIdentity\n    Assert-PowerShellSourceParsing",
            "    Assert-EnvironmentOnly\n    Assert-PowerShellSourceParsing",
        ),
        (
            "Windows credential recovery source gate",
            "build",
            "windows_credential_operation_bound_failures_remain_terminal_during_recovery",
            "windows_credential_restart_non_applied_results_wait_for_reapplication",
        ),
        ("libvpx rebuild", "build", "stale compiled libvpx bytes remain after mandatory removal", ""),
        (
            "MSI source tree",
            "build",
            "'--source-tree',\n        $env:RUSTDESK_SOURCE_TREE",
            "'--source-branch',\n        $env:RUSTDESK_SOURCE_TREE",
        ),
        ("Python pin", "build", "$PYTHON_VERSION  = '3.11.9'", "$PYTHON_VERSION  = '3.11'"),
        (
            "pinned Python path",
            "build",
            "$PYTHON_EXE      = 'C:\\Program Files\\Python311\\python.exe'",
            "$PYTHON_EXE      = 'python.exe'",
        ),
        (
            "ambient Python",
            "build",
            "& $PYTHON_EXE build.py --flutter",
            "python build.py --flutter",
        ),
        (
            "olefile isolation flags",
            "build",
            "& $PYTHON_EXE -I -S -c $olefileProbe $olefileWheel",
            "& $PYTHON_EXE -c $olefileProbe $olefileWheel",
        ),
        (
            "olefile wheel authority",
            "build",
            "os.path.normcase(os.path.abspath(loader.archive)) != wheel",
            "False",
        ),
        (
            "olefile version",
            "build",
            "if olefile.__version__ != '0.47':",
            'if not olefile.__version__:',
        ),
        (
            "PowerShell-safe Python command literal",
            "build",
            "raise SystemExit('olefile did not load through the verified wheel')",
            'raise SystemExit("olefile did not load through the verified wheel")',
        ),
        (
            "olefile guest digest",
            "build",
            "Get-FileHash -LiteralPath $olefileWheel -Algorithm SHA256",
            "Get-Item -LiteralPath $olefileWheel",
        ),
        (
            "Python companion identity",
            "build",
            "pinned Python executables are not byte-identical",
            "pinned Python executables are accepted",
        ),
        (
            "native PowerShell parsing",
            "build",
            "[Management.Automation.Language.Parser]::ParseFile",
            "[Management.Automation.Language.Parser]::ParseInput",
        ),
        (
            "isolated MSI argument vector",
            "build",
            "if len(arguments) != 13 or arguments[1::2] != expected_options",
            "if not arguments",
        ),
        (
            "Windows ancestor reparse",
            "build",
            "path traverses a reparse point",
            "path reparse accepted",
        ),
        (
            "orchestrated PE distinct output",
            "orchestrator",
            "os.unlink(pe)",
            "pass",
        ),
        ("PE repro type", "pe", "IMAGE_DEBUG_TYPE_REPRO = 16", "IMAGE_DEBUG_TYPE_REPRO = 2"),
        (
            "PE Windows source stability fields",
            "pe",
            '() if os.name == "nt" else ("st_mode", "st_ctime_ns")',
            '("st_mode", "st_ctime_ns")',
        ),
        (
            "PE authorization union",
            "pe",
            "authorized = pe_fields + debug_ranges",
            "authorized = pe_fields",
        ),
        (
            "PE authorization proof",
            "pe",
            "    _prove_only_authorized_changes(source, result, authorized)\n    return result",
            "    return result",
        ),
        (
            "PE distinct output",
            "pe",
            "if os.path.abspath(input_path) == os.path.abspath(output_path):",
            "if False:",
        ),
        (
            "PE occupied output",
            "pe",
            "if os.path.lexists(output_path):",
            "if False:",
        ),
        (
            "PE Windows descriptor release",
            "pe",
            "        os.close(descriptor)\n        descriptor = -1\n        if not _same_file_identity(temporary_state, os.lstat(temporary)):",
            "        os.fsync(descriptor)\n        if not _same_file_identity(temporary_state, os.lstat(temporary)):",
        ),
        (
            "PE reopened output postcondition",
            "pe",
            "final_state = _verify_published_file(output_path, output_identity, content)",
            "final_state = os.lstat(output_path)",
        ),
        ("PE rollback", "pe", "_make_deletable(output_path)", "os.unlink(output_path)"),
        (
            "MSI one folder",
            "msi",
            "if folder_count != 1 or file_count == 0:",
            "if folder_count == 0 or file_count == 0:",
        ),
        ("MSI no chaining", "msi", "if flags & 0x0003:", "if flags & 0x0002:"),
        (
            "MSI file order",
            "msi",
            "if previous_order is not None and order <= previous_order:",
            "if False:",
        ),
        (
            "MSI contiguous files",
            "msi",
            "if folder_offset != previous_end:",
            "if folder_offset < previous_end:",
        ),
        (
            "MSI full folder coverage",
            "msi",
            "if previous_end_by_folder.get(0) != folder_uncompressed[0]:",
            "if previous_end_by_folder.get(0, 0) > folder_uncompressed[0]:",
        ),
        (
            "MSI distinct outputs",
            "msi",
            "if len({os.path.normcase(path), os.path.normcase(output), os.path.normcase(contract_output)}) != 3:",
            "if False:",
        ),
        (
            "MSI absent outputs",
            "msi",
            "if os.path.lexists(output) or os.path.lexists(contract_output):",
            "if False:",
        ),
        (
            "MSI contract output",
            "build",
            "'--contract-out',\n        $msiContract",
            "'--contract-out',\n        $msiOut",
        ),
        (
            "MSI distinct canonicalizer input copy",
            "build",
            "[IO.File]::Copy($msiBuiltOut, $msiCanonicalizerInput, $false)",
            "[IO.File]::Copy($msiBuiltOut, $msiBuiltOut, $true)",
        ),
        (
            "MSI canonicalizer input argument",
            "build",
            "'scripts\\canonicalize-msi.py',\n        $msiCanonicalizerInput,",
            "'scripts\\canonicalize-msi.py',\n        $msiBuiltOut,",
        ),
        (
            "host MSI absent-output invocation",
            "host",
            "--output /out/rustdesk.msi \\\n            --contract-out /out/contract.json",
            "--output /out/input.msi \\\n            --contract-out /out/contract.json",
        ),
        (
            "host MSI invoking-UID ownership",
            "runtime",
            '--user "$WINDOWS_HELPER_BUILD_UID:$WINDOWS_HELPER_BUILD_GID"',
            "--user 0:0",
        ),
        (
            "host MSI noninteractive cleanup",
            "host",
            'rm -f -- "$msi_input" "$msi_contract"',
            'rm -- "$msi_input" "$msi_contract"',
        ),
        (
            "host MSI canonical idempotence",
            "host",
            '[ "$msi_output_sha256" = "$msi_input_sha256" ]',
            '[ "$msi_output_sha256" = "$msi_output_sha256" ]',
        ),
        (
            "canonical MSI artifact emission",
            "build",
            "$msi = Join-Path $SRC 'target\\canonical-msi\\rustdesk.msi'",
            "$msi = Join-Path $SRC 'res\\msi\\Package\\bin\\x64\\Release\\en-us\\Package.msi'",
        ),
        (
            "MSI contract read-only finalization",
            "msi",
            "os.chmod(contract_output, 0o400)",
            "os.chmod(contract_temporary, 0o400)",
        ),
        ("MSI contract rollback", "msi", "_make_deletable(contract_output)", "os.unlink(contract_output)"),
        (
            "MSI contract JSON integer",
            "build",
            "Get-JsonInt64 $entry.folder",
            "[Int64]$entry.folder",
        ),
        ("MSI Media comparison", "build", "$mediaRows.Count -ne 1", "$mediaRows.Count -lt 1"),
        ("MSI zero-row comparison", "build", "$zeroRows.Count -ne 0", "$zeroRows.Count -lt 0"),
        (
            "MSI COM row array materialization",
            "build",
            "return $rows.ToArray()",
            "return @($rows)",
        ),
        (
            "MSI direct typed database open",
            "build",
            "$database = $installer.OpenDatabase([string]$msiOut, [int]0)",
            "$database = $installer.OpenDatabase($msiOut, 0)",
        ),
        (
            "MSI native null stream EOF",
            "build",
            "if ($null -ne $extra)",
            "if ($extra -isnot [string])",
        ),
        (
            "MSI File size comparison",
            "build",
            "[Int64]$row[1] -ne (Get-JsonInt64 $entry.size",
            "[Int64]$row[1] -lt 0",
        ),
        (
            "MSI stream digest comparison",
            "build",
            "$cabinetDigest -cne $cabinetContract.cabinet_sha256",
            "$cabinetDigest -cne $cabinetDigest",
        ),
        (
            "MSI strict stream conversion",
            "build",
            "[Text.EncoderFallback]::ExceptionFallback",
            "[Text.EncoderFallback]::ReplacementFallback",
        ),
        (
            "MSI stream byte hashing",
            "build",
            "$sha.TransformBlock($bytes, 0, $bytes.Length, $bytes, 0)",
            "$null = $bytes",
        ),
        (
            "MSI Windows flags",
            "msi",
            'flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0)',
            "flags = os.O_RDONLY | os.O_CLOEXEC",
        ),
        (
            "MSI Windows writable sync handle",
            "msi",
            'flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0)',
            'flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0)',
        ),
        (
            "MSI exact output sync identity",
            "msi",
            "output_sync = _open_sync_regular(output, output_identity)",
            "output_sync = _open_sync_regular(output, contract_identity)",
        ),
        (
            "MSI Windows stability fields",
            "msi",
            '() if os.name == "nt" else ("st_mode", "st_ctime_ns")',
            '("st_mode", "st_ctime_ns")',
        ),
        (
            "installed-SCM least-privilege task token",
            "installed_probe",
            "$definition.Principal.RunLevel = 0",
            "$definition.Principal.RunLevel = 1",
        ),
        (
            "installed-SCM run-bound temporary task name",
            "installed_probe",
            "^RustDeskInstalledProbe-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}-[AB]$",
            "^RustDeskInstalledProbe-[0-9a-f-]{38}$",
        ),
        (
            "installed-SCM redirected credential ingress",
            "installed_probe",
            "Invoke-RedirectedProcess $Executable '--password-stdin' $Password 60",
            "Invoke-RedirectedProcess $Executable '--password' $Password 60",
        ),
        (
            "installed-SCM canonical setup execution",
            "installed_probe",
            "Invoke-RedirectedProcess $canonicalSetup '--silent-install'",
            "Invoke-RedirectedProcess $setupInput '--silent-install'",
        ),
        (
            "installed-SCM limited-fixture refusal",
            "installed_probe",
            "Invoke-KeyProbe $LimitedFixture 'fail'",
            "Invoke-KeyProbe $LimitedFixture 'ok'",
        ),
        (
            "installed-SCM copied-image fixture refusal",
            "installed_probe",
            "Invoke-KeyProbe $WrongImageFixture 'fail'",
            "Invoke-KeyProbe $WrongImageFixture 'ok'",
        ),
        (
            "installed-SCM preservation receipt",
            "installed_probe",
            "first_credential_preserved_after_limited_rejection = $true",
            "first_credential_preserved_after_limited_rejection = $false",
        ),
        (
            "installed-SCM normative rejection preservation",
            "requirements",
            "Thus neither negative may pass merely because a caller mutated state and then reported failure.",
            "A negative may pass merely because a caller mutated state and then reported failure.",
        ),
        (
            "installed-SCM client fixed-image preflight",
            "ipc",
            "crate::platform::windows::require_current_exe_is_fixed_service_runtime()?;",
            "",
        ),
        (
            "installed-SCM normative client preflight",
            "requirements",
            "The Windows client <span class=\"kw\">MUST</span> prove its own current executable is the fixed installed runtime before it opens the service-password transport",
            "The Windows client may open the service-password transport before proving its own executable",
        ),
        (
            "installed-SCM exact-commit native status",
            "hardening",
            "EXACT-COMMIT NATIVE TRANSACTION GREEN AT `0a12ed407e63129cac4065f4418911ab71adf3ca`",
            "EXACT-CURRENT NATIVE TRANSACTION PENDING",
        ),
        (
            "installed-SCM exact native run identity",
            "hardening",
            "`0018db4b-b79a-4cff-88a0-3f7adf949ec8-A`",
            "`0018db4b-b79a-4cff-88a0-3f7adf949ec8-B`",
        ),
        (
            "installed-SCM Appendix native status",
            "requirements",
            '<span class="pill p-harden">EXACT-COMMIT NATIVE TRANSACTION GREEN</span>',
            '<span class="pill p-open">EXACT-CURRENT NATIVE RUN PENDING</span>',
        ),
        (
            "installed-SCM service-generation retirement",
            "installed_probe",
            "Wait-ExactProcessGenerationGone $servicePreRestart.Process 'SCM supervisor generation'",
            "Wait-ExactProcessGenerationGone $serviceAfter.Process 'SCM supervisor generation'",
        ),
        (
            "installed-SCM exact CM termination",
            "installed_probe",
            "TerminateExactProcessGeneration(\n        [uint32]$Generation.ProcessId",
            "TerminateExactProcessGeneration(\n        [uint32]0",
        ),
        (
            "installed-SCM signaled-process liveness",
            "installed_probe",
            "if (wait == WAIT_OBJECT_0) { return false; }",
            "if (wait == WAIT_OBJECT_0) { return true; }",
        ),
        (
            "installed-SCM strict CM directory response",
            "installed_probe",
            "$last.Stdout.Contains('[FT-DIR-RESPONSE ')",
            "$last.Stdout.Contains('[FT-PEERINFO ')",
        ),
        (
            "installed-SCM v2 lifecycle receipt",
            "installed_probe",
            "rustdesk-windows-installed-service-probe-v2",
            "rustdesk-windows-installed-service-probe-v1",
        ),
        (
            "installed-SCM CM result relation",
            "installed_result",
            'result["cm_roundtrip_count"] != 6',
            'result["cm_roundtrip_count"] < 0',
        ),
        (
            "strict CPace CM directory requirement",
            "probe_client",
            'mode == "cmfiletransfer" && !received_directory',
            'mode == "cmfiletransfer" && false',
        ),
        (
            "Windows VM VNC loopback binding proof",
            "host",
            'graphic.get("listen") != "127.0.0.1"',
            'graphic.get("listen") != "0.0.0.0"',
        ),
        (
            "installed-SCM confined result verifier",
            "host",
            "--result /evidence/windows-installed-service-result.json",
            "--result /evidence/build-log.txt",
        ),
        (
            "installed-SCM limited-token result proof",
            "installed_result",
            'require_exact_bool(result, "limited_token_elevated", False)',
            'require_exact_bool(result, "limited_token_elevated", True)',
        ),
        (
            "CPace probe terminal-input refusal",
            "probe_client",
            "if stdin.is_terminal()",
            "if false",
        ),
        (
            "installed-SCM normative zero-interface boundary",
            "requirements",
            "zero virtual network interfaces",
            "one virtual network interface",
        ),
        (
            "installed-SCM hardening ledger",
            "hardening",
            "R-S11gj/R-S11e-222 — exact installed Windows SCM credential authority",
            "R-S11gj/R-S11e-999 — exact installed Windows SCM credential authority",
        ),
        ("watch patch reorder", "watch", "patch-block-reorder", "patch-order-ignored"),
        (
            "port patch order",
            "port",
            '        "${_libvpx_security_patch}"\n        0003-add-uwp-v142-and-v143-support.patch',
            '        0003-add-uwp-v142-and-v143-support.patch\n        "${_libvpx_security_patch}"',
        ),
        ("port-version", "metadata", '"port-version": 1', '"port-version": 2'),
    ]
    for description, name, old, new in mutations:
        mutated = dict(sources)
        if old not in mutated[name]:
            raise VerificationError(f"self-test fixture is absent for {description}")
        mutated[name] = mutated[name].replace(old, new, 1)
        try:
            validate_sources(mutated)
        except VerificationError:
            continue
        raise VerificationError(f"self-test mutation was accepted: {description}")
    run_behavioral_self_tests(repo)
    print(
        "verify-windows-harness self-test: ok "
        f"({len(mutations)} mutations, 7 bounded behavioral suites)"
    )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=pathlib.Path, default=pathlib.Path.cwd())
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    sources = load_sources(args.repo.resolve())
    validate_sources(sources)
    if args.self_test:
        run_self_test(args.repo.resolve(), sources)
    else:
        print("verify-windows-harness: ok")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (VerificationError, json.JSONDecodeError) as exc:
        print(f"verify-windows-harness: FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
