#!/usr/bin/env python3
"""Verify exact transient libvirt storage ownership for Windows harnesses."""

from __future__ import annotations

import argparse
import ast
import os
import pathlib
import re
import stat
import subprocess
import sys
import tempfile
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass


class VerificationError(RuntimeError):
    pass


FILES = {
    "helper": "scripts/windows-libvirt-storage-pool.py",
    "library": "scripts/windows-libvirt-storage-pools.sh",
    "build": "scripts/build-windows-vm.sh",
    "provision": "scripts/provision-windows-vm.sh",
    "presentation": "scripts/smoke-flutter-presentation-windows.sh",
    "verify": "scripts/verify.sh",
    "requirements": "requirements.html",
    "hardening": "HARDENING_STATUS.md",
    "workspace": "scripts/verify-verifier-workspace.py",
    "focused": "scripts/verify-windows-libvirt-storage-pools.py",
}


def require(source: str, literal: str, label: str) -> None:
    if literal not in source:
        raise VerificationError(f"missing {label}: {literal}")


def require_exact_count(source: str, literal: str, expected: int, label: str) -> None:
    observed = source.count(literal)
    if observed != expected:
        raise VerificationError(
            f"invalid {label}: found {observed}, expected {expected}: {literal}"
        )


def reject(source: str, pattern: str, label: str) -> None:
    if re.search(pattern, source, re.MULTILINE):
        raise VerificationError(f"forbidden {label}")


def require_order(source: str, literals: tuple[str, ...], label: str) -> None:
    cursor = -1
    for literal in literals:
        location = source.find(literal, cursor + 1)
        if location < 0 or location <= cursor:
            raise VerificationError(f"invalid {label}: {literal}")
        cursor = location


def shell_function(source: str, name: str) -> str:
    match = re.search(rf"(?m)^{re.escape(name)}\(\) \{{\s*$", source)
    if match is None:
        raise VerificationError(f"missing shell function: {name}")
    following = re.search(
        r"(?m)^[A-Za-z_][A-Za-z0-9_]*\(\) \{\s*$", source[match.end() :]
    )
    end = len(source) if following is None else match.end() + following.start()
    return source[match.start() : end]


def string_assignment(source: str, name: str) -> str:
    tree = ast.parse(source)
    values = []
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if isinstance(target, ast.Name) and target.id == name:
            if not isinstance(node.value, ast.Constant) or not isinstance(
                node.value.value, str
            ):
                raise VerificationError(f"{name} is not a string constant")
            values.append(node.value.value)
    if len(values) != 1:
        raise VerificationError(f"expected one {name} string assignment, found {len(values)}")
    return values[0]


def validate(sources: dict[str, str]) -> None:
    try:
        ast.parse(sources["helper"], filename=FILES["helper"])
        ast.parse(sources["focused"], filename=FILES["focused"])
    except SyntaxError as error:
        raise VerificationError(f"invalid verifier/helper Python: {error}") from error

    helper = sources["helper"]
    library = sources["library"]
    build = sources["build"]
    provision = sources["provision"]
    presentation = sources["presentation"]
    focused_driver = string_assignment(sources["focused"], "SHELL_BEHAVIOR")

    for literal, label in (
        ("MAX_XML_BYTES = 64 * 1024\n", "bounded libvirt XML"),
        ("POOL_NAME_RE = re.compile(r\"rustdesk-tpool-[0-9a-f]{32}\\Z\")", "random pool namespace"),
        ("os.O_NOFOLLOW", "descriptor no-follow acquisition"),
        ("os.O_CREAT | os.O_EXCL", "exclusive receipt creation"),
        ("metadata.st_nlink != 1", "single-link residue authority"),
        ("require_private_primary_group(uid, gid)", "private-primary-group proof"),
        ("value.attrib != {\"unit\": \"bytes\"}", "dynamic pool XML unit proof"),
        ("if [child.tag for child in root] != expected_order:", "exact pool XML ordering"),
        ("root.attrib != {\"type\": \"dir\"}", "exact directory-pool type"),
        ("actual_permissions != expected_permissions", "live target-permissions binding"),
        (
            "            or before.st_nlink != 1\n"
            "            or stat.S_IMODE(before.st_mode) != 0o600\n"
            "            or before.st_size > MAX_XML_BYTES",
            "exact poolstate mode",
        ),
        ('if hasattr(args, "uid") and (', "mutating-command principal gate"),
        ("args.uid != os.getuid()", "numeric non-root helper principal"),
        ("args.uid == 0", "root UID refusal"),
        ("args.gid == 0", "root primary-GID refusal"),
        ("format\": \"rustdesk-windows-libvirt-domain-v1", "domain-log receipt format"),
        ("os.unlink(log_name, dir_fd=log_fd)", "descriptor-relative domain-log retirement"),
        (
            "root = parse_xml(payload, allow_poolstate=True)\n"
            "        target_metadata = require_target(\n"
            "            args.target, args.target_identity, args.uid, args.gid\n"
            "        )\n"
            "        require_exact_pool(\n"
            "            root, args.name, args.uuid, args.target, target_metadata\n"
            "        )",
            "exact runtime poolstate binding",
        ),
        ('parser.add_argument("--cache-root", required=True)', "private cache-root API"),
        ('parser.add_argument("--cache-identity", required=True)', "private cache identity API"),
    ):
        require(helper, literal, label)
    reject(helper, r"\b(?:shutil\.rmtree|os\.system|subprocess\.)", "ambient helper execution or recursive deletion")

    open_function = shell_function(library, "windows_libvirt_transaction_open")
    for literal, label in (
        ('[ -z "${XDG_CACHE_HOME:-}" ] && [ -z "${XDG_CONFIG_HOME:-}" ]', "ambient XDG refusal"),
        ('[ -n "$pw_home" ] && [ "${HOME:-}" = "$pw_home" ]', "passwd/HOME identity agreement"),
        ('[ "$pw_uid" = "$WINDOWS_HELPER_BUILD_UID" ]', "passwd UID binding"),
        ('[ "$pw_gid" = "$WINDOWS_HELPER_BUILD_GID" ]', "passwd GID binding"),
        ("-name '.windows-libvirt-transaction.*' -print -quit", "stale transaction refusal"),
        ('"$parent/.windows-libvirt-transaction.XXXXXXXX"', "private control-root creation"),
        ('"$runtime_parent/.rustdesk-libvirt-runtime.XXXXXXXX"', "short private runtime-root creation"),
        ('"HOME=$private_home"', "transaction-private home injection"),
        ('"XDG_CACHE_HOME=$cache_root"', "transaction-private cache injection"),
        ('"XDG_CONFIG_HOME=$config_root"', "transaction-private config injection"),
        ('"XDG_DATA_HOME=$data_root"', "transaction-private data injection"),
        ('"XDG_RUNTIME_DIR=$runtime_root"', "transaction-private runtime injection"),
        ('"XDG_STATE_HOME=$state_root"', "transaction-private state injection"),
        ('"TMPDIR=$tmp_root"', "transaction-private temporary-directory injection"),
        ("'listen_tls = 0'", "private daemon TCP-listener refusal"),
        ("'listen_tcp = 0'", "private daemon cleartext-listener refusal"),
        ("'lock_manager = \"nop\"'", "external lock-daemon exclusion"),
        ("'stdio_handler = \"file\"'", "external log-daemon exclusion"),
        ("windows_libvirt_start_private_daemon", "private daemon admission"),
    ):
        require(open_function, literal, label)
    ambient_function = shell_function(
        library, "windows_libvirt_require_ambient_session_quiescent"
    )
    for literal, label in (
        ('"$runtime/libvirt/libvirt-sock"', "ambient session-socket refusal"),
        ('[ -d "$runtime/libvirt" ] && [ ! -L "$runtime/libvirt" ]', "ambient runtime symlink refusal"),
        ('/usr/sbin/libvirtd|/usr/sbin/virtqemud|/usr/sbin/virtstoraged|\\', "ambient user-daemon refusal"),
        ('/usr/sbin/virtproxyd|/usr/sbin/virtlogd|/usr/sbin/virtlockd|\\', "ambient proxy/log/lock daemon refusal"),
        ('\\( -type s -o -name \'*.pid\' \\)', "ambient runtime-endpoint refusal"),
        ('"$home/.config/libvirt/storage"', "ambient persistent-pool refusal"),
    ):
        require(ambient_function, literal, label)
    start_function = shell_function(library, "windows_libvirt_start_private_daemon")
    require_order(
        start_function,
        (
            'config_metadata="$(/usr/bin/stat -c',
            '[ "$(<"$config")" = $\'listen_tls = 0\\nlisten_tcp = 0\' ]',
            '[ "$(<"$qemu_config")" =',
            '/usr/bin/setsid "${WINDOWS_LIBVIRT_CLIENT_ENV[@]}"',
            '/usr/sbin/libvirtd --config "$config" --pid-file "$pid_file"',
            "WINDOWS_LIBVIRT_DAEMON_PID=$!",
            'if ! WINDOWS_LIBVIRT_DAEMON_START="$(\n        process_start_time',
            "windows_libvirt_daemon_matches",
            '[ -S "$WINDOWS_LIBVIRT_RUNTIME_ROOT/libvirt/libvirt-sock" ]',
        ),
        "private libvirtd admission",
    )
    virsh_function = shell_function(library, "windows_libvirt_virsh_bounded")
    require_order(
        virsh_function,
        (
            "windows_libvirt_daemon_matches",
            '"${WINDOWS_LIBVIRT_CLIENT_ENV[@]}"',
            "/usr/bin/virsh --connect qemu:///session",
            "windows_libvirt_daemon_matches",
        ),
        "private daemon-bound virsh execution",
    )
    stop_function = shell_function(library, "windows_libvirt_stop_private_daemon")
    require_order(
        stop_function,
        (
            "windows_libvirt_daemon_matches",
            "windows_libvirt_daemon_is_terminal_or_absent",
            '/bin/kill -TERM -- "-$WINDOWS_LIBVIRT_DAEMON_PID"',
            "windows_libvirt_process_group_is_live",
            '/bin/kill -KILL -- "-$WINDOWS_LIBVIRT_DAEMON_PID"',
            'wait "$WINDOWS_LIBVIRT_DAEMON_PID"',
        ),
        "private daemon exact process-group finality",
    )
    require(
        stop_function,
        "elif windows_libvirt_daemon_is_terminal_or_absent; then",
        "terminal-or-absent daemon identity branch",
    )

    ensure_function = shell_function(library, "windows_libvirt_ensure_transient_pool")
    require_order(
        ensure_function,
        (
            'windows_libvirt_require_target_unmanaged "$target"',
            'windows_libvirt_require_pool_absent "$name" "$pool_uuid"',
            "windows_libvirt_helper write-pool-request",
            'WINDOWS_LIBVIRT_POOL_NAMES[index]="$name"',
            'WINDOWS_LIBVIRT_POOL_UUIDS[index]="$pool_uuid"',
            'WINDOWS_LIBVIRT_POOL_TARGETS[index]="$target"',
            'WINDOWS_LIBVIRT_POOL_TARGET_IDS[index]="$target_id"',
            'virsh_bounded pool-create "$xml"',
            "windows_libvirt_prove_exact_transient_pool",
        ),
        "pre-call pool authority and post-create proof",
    )
    prove_function = shell_function(library, "windows_libvirt_prove_exact_transient_pool")
    for literal, label in (
        ('[ "$(windows_libvirt_pool_info_field "$info" State)" = running ]', "running-state proof"),
        ('[ "$(windows_libvirt_pool_info_field "$info" Persistent)" = no ]', "nonpersistent proof"),
        ('[ "$(windows_libvirt_pool_info_field "$info" Autostart)" = no ]', "non-autostart proof"),
        ('[ "$target_matches" = "$pool_uuid" ]', "exclusive target mapping"),
    ):
        require(prove_function, literal, label)

    destroy_function = shell_function(library, "windows_libvirt_destroy_transient_pool")
    require_order(
        destroy_function,
        (
            "windows_libvirt_prove_exact_transient_pool",
            'virsh_bounded pool-destroy "$pool_uuid"',
            'windows_libvirt_require_pool_absent "$name" "$pool_uuid"',
            'matches="$(windows_libvirt_pool_target_uuids "$target")"',
            "windows_libvirt_require_no_persistent_pool_files",
            "windows_libvirt_helper remove-poolstate",
        ),
        "exact transient-pool retirement",
    )
    close_function = shell_function(library, "windows_libvirt_transaction_close")
    require_order(
        close_function,
        (
            "domain_unresolved=0",
            "windows_libvirt_require_domain_absent",
            '[ "$domain_unresolved" = 0 ] || return 1',
            'windows_libvirt_destroy_transient_pool "$index" || cleanup_failed=1',
            'windows_libvirt_cleanup_domain "$index" || cleanup_failed=1',
            '[ "$cleanup_failed" = 0 ] || return 1',
            "WINDOWS_LIBVIRT_OBJECTS_RETIRED=1",
            "windows_libvirt_stop_private_daemon",
            "windows_libvirt_require_ambient_session_quiescent",
            '--remove-private-root "$WINDOWS_LIBVIRT_RUNTIME_ROOT"',
            '--remove-private-root "$WINDOWS_LIBVIRT_CONTROL_ROOT"',
        ),
        "domain-first, visit-all, authority-last cleanup",
    )
    require(
        close_function,
        'if [ "$WINDOWS_LIBVIRT_OBJECTS_RETIRED" = 0 ]; then',
        "retryable object-retirement phase",
    )
    for forbidden, label in (
        (r"\bpool-define\b", "persistent pool definition"),
        (r"\bpool-autostart\b", "pool autostart"),
        (r"\bpool-undefine\b", "persistent pool undefinition workaround"),
        (r"rm\s+-rf", "recursive ambient libvirt cleanup"),
        (r"/usr/sbin/libvirtd[^\n]*--listen", "private libvirt network listener"),
    ):
        reject(library, forbidden, label)
    require_exact_count(library, 'virsh_bounded pool-create "$xml"', 1, "single transient-pool creation sink")
    require_exact_count(library, 'virsh_bounded pool-destroy "$pool_uuid"', 1, "single exact transient-pool destroy sink")

    for launcher, label in ((build, "build"), (provision, "provision"), (presentation, "presentation")):
        require(launcher, 'source "$SCRIPT_DIR/windows-libvirt-storage-pools.sh"', f"{label} shared pool authority")
        require(launcher, "windows_libvirt_virsh_bounded", f"{label} private virsh namespace")
        require(
            launcher,
            '"${WINDOWS_LIBVIRT_CLIENT_ENV[@]}"',
            f"{label} private virt-install namespace",
        )
        reject(launcher, r"\bpool-(?:create|define|destroy|undefine|autostart)\b", f"{label} direct pool control")

    build_launch = shell_function(build, "launch_domain")
    require_order(
        build_launch,
        (
            "require_domain_identity_absent",
            'windows_libvirt_ensure_transient_pools "$CURRENT_PASS_ROOT" "$RUN_ROOT"',
            'windows_libvirt_require_targets_owned "$CURRENT_PASS_ROOT" "$RUN_ROOT"',
            'windows_libvirt_prepare_domain "$CURRENT_DOMAIN" "$CURRENT_DOMAIN_UUID"',
            "CURRENT_DOMAIN_CREATION_STARTED=1",
            "/usr/bin/virt-install",
            "verify_domain_xml",
            'windows_libvirt_require_targets_owned "$CURRENT_PASS_ROOT" "$RUN_ROOT"',
            "CURRENT_DOMAIN_OWNERSHIP_COMMITTED=1",
        ),
        "Windows build domain/pool lifecycle",
    )
    build_main = shell_function(build, "main")
    require_order(
        build_main,
        (
            'windows_libvirt_transaction_open "$RUN_ROOT"',
            "run_pass A",
            "windows_libvirt_transaction_close",
            'publish_result "$RUN_ROOT/pass-A/result"',
        ),
        "Windows build closes libvirt authority before publication",
    )
    build_cleanup = shell_function(build, "cleanup")
    require_order(
        build_cleanup,
        (
            "stop_owned_process",
            "stop_and_undefine_owned_domain",
            "windows_libvirt_transaction_close",
            "windows_helper_authority_close",
            "remove_completed_run_root",
        ),
        "Windows build domain/pool/helper/storage cleanup order",
    )

    provision_build = shell_function(provision, "build_golden")
    require_order(
        provision_build,
        (
            'windows_libvirt_transaction_open "$STATE_DIR"',
            "build_media",
            "PROVISION_DOMAIN_UUID=",
            'windows_libvirt_ensure_transient_pools "$STATE_DIR" "$ONLINE_DIR"',
            'windows_libvirt_prepare_domain "$DOMAIN" "$PROVISION_DOMAIN_UUID"',
            "qemu-img create",
            "/usr/bin/virt-install",
            'windows_libvirt_require_targets_owned "$STATE_DIR" "$ONLINE_DIR"',
            "stop_and_undefine_owned_domain",
        ),
        "golden provisioning domain/pool lifecycle",
    )
    provision_main = shell_function(provision, "main")
    require_order(
        provision_main,
        ("build_golden", "windows_libvirt_transaction_close"),
        "golden provisioning terminal pool retirement",
    )
    provision_cleanup = shell_function(provision, "cleanup_provision")
    require_order(
        provision_cleanup,
        ("stop_owned_virt_process", "stop_and_undefine_owned_domain", "windows_libvirt_transaction_close", "windows_helper_authority_close"),
        "golden provisioning cleanup order",
    )

    presentation_launch = shell_function(presentation, "launch_domain")
    require_order(
        presentation_launch,
        (
            "require_domain_identity_absent",
            'windows_libvirt_ensure_transient_pools "$RUN_ROOT"',
            'windows_libvirt_prepare_domain "$CURRENT_DOMAIN" "$CURRENT_DOMAIN_UUID"',
            "CURRENT_DOMAIN_CREATION_STARTED=1",
            "/usr/bin/virt-install",
            "verify_domain_xml",
            'windows_libvirt_require_targets_owned "$RUN_ROOT"',
        ),
        "presentation domain/pool lifecycle",
    )
    presentation_main = shell_function(presentation, "main")
    require_order(
        presentation_main,
        ("wait_for_domain", "windows_libvirt_transaction_close", "extract_and_validate"),
        "presentation pool retirement before extraction",
    )
    presentation_cleanup = shell_function(presentation, "cleanup")
    require_order(
        presentation_cleanup,
        ("stop_owned_process", "stop_and_undefine_owned_domain", "windows_libvirt_transaction_close", "windows_helper_authority_close"),
        "presentation cleanup order",
    )

    require(
        sources["verify"],
        "/usr/bin/python3 -I -S scripts/verify-windows-libvirt-storage-pools.py --repo . --self-test",
        "focused verifier wiring",
    )
    require(sources["requirements"], '<span class="id">R-S11gn</span>', "R-S11gn requirement")
    require(sources["requirements"], "<tr><td>349</td>", "Appendix C #349 disposition")
    require(
        focused_driver,
        "external receipt hardlink was removed as private state",
        "retryable post-object cleanup fixture",
    )
    require(
        sources["hardening"],
        "R-S11gn/R-S11e-226 — Windows harness transient libvirt storage ownership",
        "hardening disposition",
    )
    for literal, label in (
        ('"windows_libvirt_storage_verifier": (', "independent verifier source ownership"),
        ('"windows_libvirt_storage_library": (', "independent library source ownership"),
        ("    validate_windows_libvirt_storage_authority_contract(sources)", "independent semantic validation call"),
        ("Windows libvirt focused verifier wiring", "independent verifier-wiring mutation"),
        ("Windows libvirt transient pool creation", "independent pool-creation mutation"),
        ("Windows libvirt Appendix C #349 disposition", "independent Appendix mutation"),
    ):
        require(sources["workspace"], literal, label)


def run_command(
    command: list[str],
    *,
    input_bytes: bytes | None = None,
    expect: int = 0,
    environment: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(
        command,
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env=environment,
    )
    if result.returncode != expect:
        raise VerificationError(
            f"command returned {result.returncode}, expected {expect}: {command!r}\n"
            f"stdout={result.stdout.decode(errors='replace')}\n"
            f"stderr={result.stderr.decode(errors='replace')}"
        )
    return result


def helper_command(
    helper: pathlib.Path,
    arguments: list[str],
    *,
    input_bytes: bytes | None = None,
    success: bool = True,
    exact_status: int | None = None,
) -> subprocess.CompletedProcess[bytes]:
    environment = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
    result = subprocess.run(
        [sys.executable, "-I", "-S", os.fspath(helper), *arguments],
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env=environment,
    )
    if exact_status is not None:
        accepted = result.returncode == exact_status
    else:
        accepted = (result.returncode == 0) is success
    if not accepted:
        raise VerificationError(
            f"helper result differs for {arguments!r}: {result.returncode}; "
            f"stderr={result.stderr.decode(errors='replace')}"
        )
    return result


def identity(path: pathlib.Path) -> str:
    metadata = path.stat()
    return f"{metadata.st_dev}:{metadata.st_ino}"


def pool_arguments(
    uid: int,
    gid: int,
    control: pathlib.Path,
    name: str,
    pool_uuid: str,
    target: pathlib.Path,
) -> list[str]:
    return [
        "--control-root", os.fspath(control),
        "--control-identity", identity(control),
        "--uid", str(uid),
        "--gid", str(gid),
        "--name", name,
        "--uuid", pool_uuid,
        "--target", os.fspath(target),
        "--target-identity", identity(target),
    ]


def run_helper_behavior(helper: pathlib.Path, root: pathlib.Path) -> int:
    uid, gid = os.getuid(), os.getgid()
    control = root / "control"
    target = root / "target"
    cache_root = root / "cache"
    for directory in (control, target, cache_root):
        directory.mkdir(mode=0o700)
    log_dir = cache_root / "libvirt/qemu/log"
    runtime_dir = cache_root / "libvirt/storage/run"
    log_dir.mkdir(mode=0o700, parents=True)
    runtime_dir.mkdir(mode=0o700, parents=True)

    pool_uuid = str(uuid.uuid4())
    name = f"rustdesk-tpool-{pool_uuid.replace('-', '')}"
    helper_command(
        helper,
        ["write-pool-request", *pool_arguments(uid, gid, control, name, pool_uuid, target)],
    )
    request = control / f"pool-{pool_uuid.replace('-', '')}.xml"
    request_metadata = request.stat()
    if stat.S_IMODE(request_metadata.st_mode) != 0o600 or request_metadata.st_nlink != 1:
        raise VerificationError("pool request is not an exact mode-0600 single-link file")
    request_xml = request.read_bytes()
    verify_args = [
        "verify-pool-xml",
        "--uid", str(uid),
        "--gid", str(gid),
        "--name", name,
        "--uuid", pool_uuid,
        "--target", os.fspath(target),
        "--target-identity", identity(target),
    ]
    helper_command(
        helper,
        verify_args,
        input_bytes=request_xml,
    )
    live = ET.fromstring(request_xml)
    insertion = 2
    for label, value in (("capacity", "100"), ("allocation", "25"), ("available", "75")):
        child = ET.Element(label, {"unit": "bytes"})
        child.text = value
        live.insert(insertion, child)
        insertion += 1
    permissions = ET.SubElement(live.find("./target"), "permissions")
    ET.SubElement(permissions, "mode").text = "0700"
    ET.SubElement(permissions, "owner").text = str(uid)
    ET.SubElement(permissions, "group").text = str(gid)
    live_xml = ET.tostring(live, encoding="utf-8")
    helper_command(
        helper,
        verify_args,
        input_bytes=live_xml,
    )
    helper_command(
        helper,
        ["pool-target-match", "--target", os.fspath(target)],
        input_bytes=live_xml,
        exact_status=0,
    )
    helper_command(
        helper,
        ["pool-target-match", "--target", os.fspath(root / "other")],
        input_bytes=live_xml,
        exact_status=3,
    )

    negative_xml = []
    negative_xml.append(live_xml.replace(b"type=\"dir\"", b"type=\"fs\"", 1))
    negative_xml.append(live_xml.replace(b"<source />", b"<source><device path=\"/dev/x\" /></source>", 1))
    negative_xml.append(live_xml.replace(b"unit=\"bytes\"", b"unit=\"KiB\"", 1))
    negative_xml.append(live_xml.replace(b"<capacity", b"<extra /><capacity", 1))
    negative_xml.append(live_xml.replace(b"<name>", b"<name>duplicate</name><name>", 1))
    negative_xml.append(live_xml.replace(os.fsencode(target), os.fsencode(root / "wrong"), 1))
    negative_xml.append(live_xml.replace(b"<mode>0700</mode>", b"<mode>0750</mode>", 1))
    negative_xml.append(
        live_xml.replace(
            f"<owner>{uid}</owner>".encode(),
            f"<owner>{uid + 1}</owner>".encode(),
            1,
        )
    )
    negative_xml.append(
        live_xml.replace(
            f"<group>{gid}</group>".encode(),
            f"<group>{gid + 1}</group>".encode(),
            1,
        )
    )
    for payload in negative_xml:
        helper_command(
            helper,
            verify_args,
            input_bytes=payload,
            success=False,
        )
    helper_command(
        helper,
        verify_args,
        input_bytes=b"x" * (64 * 1024 + 1),
        success=False,
    )

    def record_domain(domain_name: str, domain_uuid: str, *, success: bool = True) -> pathlib.Path:
        helper_command(
            helper,
            [
                "record-domain",
                "--control-root", os.fspath(control),
                "--control-identity", identity(control),
                "--uid", str(uid), "--gid", str(gid),
                "--cache-root", os.fspath(cache_root),
                "--cache-identity", identity(cache_root),
                "--name", domain_name, "--uuid", domain_uuid,
            ],
            success=success,
        )
        return control / f"domain-{domain_uuid.replace('-', '')}.json"

    def cleanup_domain(domain_name: str, domain_uuid: str, *, success: bool = True) -> None:
        helper_command(
            helper,
            [
                "cleanup-domain",
                "--control-root", os.fspath(control),
                "--control-identity", identity(control),
                "--uid", str(uid), "--gid", str(gid),
                "--cache-root", os.fspath(cache_root),
                "--cache-identity", identity(cache_root),
                "--name", domain_name, "--uuid", domain_uuid,
            ],
            success=success,
        )

    domain_uuid = str(uuid.uuid4())
    record_domain("rd-domain-one", domain_uuid)
    domain_log = log_dir / "rd-domain-one.log"
    domain_log.write_text("owned log\n", encoding="ascii")
    domain_log.chmod(0o600)
    cleanup_domain("rd-domain-one", domain_uuid)
    if domain_log.exists():
        raise VerificationError("exact domain log survived successful retirement")

    preexisting_uuid = str(uuid.uuid4())
    preexisting_log = log_dir / "rd-preexisting.log"
    preexisting_log.write_text("preexisting\n", encoding="ascii")
    preexisting_log.chmod(0o600)
    record_domain("rd-preexisting", preexisting_uuid, success=False)
    if not preexisting_log.exists():
        raise VerificationError("preexisting domain log was changed")

    symlink_uuid = str(uuid.uuid4())
    record_domain("rd-symlink", symlink_uuid)
    symlink_target = log_dir / "symlink-target"
    symlink_target.write_text("target\n", encoding="ascii")
    symlink_target.chmod(0o600)
    symlink_log = log_dir / "rd-symlink.log"
    symlink_log.symlink_to(symlink_target.name)
    cleanup_domain("rd-symlink", symlink_uuid, success=False)
    if not symlink_log.is_symlink() or not symlink_target.exists():
        raise VerificationError("symlink domain-log refusal changed an object")

    linked_uuid = str(uuid.uuid4())
    record_domain("rd-linked", linked_uuid)
    linked_source = log_dir / "linked-source"
    linked_source.write_text("linked\n", encoding="ascii")
    linked_source.chmod(0o600)
    linked_log = log_dir / "rd-linked.log"
    os.link(linked_source, linked_log)
    cleanup_domain("rd-linked", linked_uuid, success=False)
    if not linked_log.exists() or linked_log.stat().st_nlink != 2:
        raise VerificationError("hard-linked domain-log refusal changed an object")

    writable_uuid = str(uuid.uuid4())
    record_domain("rd-writable", writable_uuid)
    writable_log = log_dir / "rd-writable.log"
    writable_log.write_text("writable\n", encoding="ascii")
    writable_log.chmod(0o620)
    cleanup_domain("rd-writable", writable_uuid, success=False)
    if not writable_log.exists():
        raise VerificationError("group-writable domain-log refusal removed the log")

    poolstate = ET.Element("poolstate")
    poolstate.append(ET.fromstring(live_xml))
    poolstate_path = runtime_dir / f"{name}.xml"
    poolstate_path.write_bytes(ET.tostring(poolstate, encoding="utf-8"))
    poolstate_path.chmod(0o600)
    poolstate_args = [
        "remove-poolstate", "--uid", str(uid), "--gid", str(gid),
        "--cache-root", os.fspath(cache_root),
        "--cache-identity", identity(cache_root), "--name", name,
        "--uuid", pool_uuid, "--target", os.fspath(target),
        "--target-identity", identity(target),
    ]
    helper_command(helper, poolstate_args)
    if poolstate_path.exists():
        raise VerificationError("exact runtime poolstate survived retirement")
    wrong = ET.Element("poolstate")
    changed = ET.fromstring(live_xml)
    changed.find("./target/path").text = os.fspath(root / "wrong")
    wrong.append(changed)
    poolstate_path.write_bytes(ET.tostring(wrong, encoding="utf-8"))
    poolstate_path.chmod(0o600)
    helper_command(helper, poolstate_args, success=False)
    if not poolstate_path.exists():
        raise VerificationError("mismatched runtime poolstate was removed")

    exact_poolstate = ET.Element("poolstate")
    exact_poolstate.append(ET.fromstring(live_xml))
    exact_poolstate_payload = ET.tostring(exact_poolstate, encoding="utf-8")
    poolstate_path.unlink()
    poolstate_target = runtime_dir / "poolstate-symlink-target.xml"
    poolstate_target.write_bytes(exact_poolstate_payload)
    poolstate_target.chmod(0o600)
    poolstate_path.symlink_to(poolstate_target.name)
    helper_command(helper, poolstate_args, success=False)
    if not poolstate_path.is_symlink() or not poolstate_target.exists():
        raise VerificationError("symlink runtime poolstate refusal changed an object")
    poolstate_path.unlink()
    poolstate_target.unlink()

    poolstate_path.write_bytes(exact_poolstate_payload)
    poolstate_path.chmod(0o600)
    poolstate_link = runtime_dir / "poolstate-external-link.xml"
    os.link(poolstate_path, poolstate_link)
    helper_command(helper, poolstate_args, success=False)
    if poolstate_path.stat().st_nlink != 2 or not poolstate_link.exists():
        raise VerificationError("hard-linked runtime poolstate refusal changed an object")
    poolstate_link.unlink()

    poolstate_path.chmod(0o620)
    helper_command(helper, poolstate_args, success=False)
    if not poolstate_path.exists():
        raise VerificationError("group-writable runtime poolstate was removed")
    poolstate_path.chmod(0o600)
    helper_command(helper, poolstate_args)
    if poolstate_path.exists():
        raise VerificationError("restored exact runtime poolstate survived retirement")

    missing_cache = root / "missing-cache"
    missing_cache.mkdir(mode=0o700)
    helper_command(
        helper,
        [
            "remove-poolstate", "--uid", str(uid), "--gid", str(gid),
            "--cache-root", os.fspath(missing_cache),
            "--cache-identity", identity(missing_cache), "--name", name,
            "--uuid", pool_uuid, "--target", os.fspath(target),
            "--target-identity", identity(target),
        ],
    )
    return 9 + 4 + 7


FAKE_VIRSH = r'''#!/usr/bin/env python3
import json
import os
import pathlib
import sys
import uuid
import xml.etree.ElementTree as ET

state_path = pathlib.Path(sys.argv[1])
arguments = sys.argv[2:]

def load():
    if not state_path.exists():
        return {"pools": {}, "domains": {}, "destroy_attempts": [], "fail_destroy": "", "create_fail": False}
    return json.loads(state_path.read_text(encoding="utf-8"))

def save(state):
    pending = state_path.with_suffix(".pending")
    pending.write_text(json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    os.replace(pending, state_path)

state = load()
if arguments[0] == "_meta":
    command = arguments[1]
    if command == "fail-destroy": state["fail_destroy"] = arguments[2]
    elif command == "clear-fail-destroy": state["fail_destroy"] = ""
    elif command == "create-fail": state["create_fail"] = arguments[2] == "yes"
    elif command == "info": state["pools"][arguments[2]][arguments[3].lower()] = arguments[4]
    elif command == "target":
        item = state["pools"][arguments[2]]
        root = ET.fromstring(item["xml"])
        root.find("./target/path").text = arguments[3]
        item["xml"] = ET.tostring(root, encoding="unicode")
    elif command == "seed":
        name, pool_uuid, target = arguments[2:5]
        root = ET.Element("pool", {"type": "dir"})
        ET.SubElement(root, "name").text = name
        ET.SubElement(root, "uuid").text = pool_uuid
        ET.SubElement(root, "source")
        envelope = ET.SubElement(root, "target")
        ET.SubElement(envelope, "path").text = target
        state["pools"][pool_uuid] = {"name": name, "xml": ET.tostring(root, encoding="unicode"), "persistent": "no", "autostart": "no"}
    elif command == "remove": state["pools"].pop(arguments[2])
    elif command == "count":
        if len(state["pools"]) != int(arguments[2]): raise SystemExit(1)
    elif command == "has":
        present = arguments[2] in state["pools"]
        if present != (arguments[3] == "yes"): raise SystemExit(1)
    elif command == "attempted":
        if arguments[2] not in state["destroy_attempts"]: raise SystemExit(1)
    else: raise SystemExit(2)
    save(state)
    raise SystemExit(0)

command = arguments[0]
if command == "pool-list" and arguments[1:3] == ["--all", "--name"]:
    print("\n".join(item["name"] for item in state["pools"].values()))
elif command == "pool-list" and arguments[1:3] == ["--all", "--uuid"]:
    print("\n".join(state["pools"]))
elif command == "list" and arguments[1:3] in (["--all", "--name"], ["--all", "--uuid"]):
    print("")
elif command == "pool-name":
    print(state["pools"][arguments[1]]["name"])
elif command == "pool-uuid":
    matches = [key for key, value in state["pools"].items() if value["name"] == arguments[1]]
    if len(matches) != 1: raise SystemExit(1)
    print(matches[0])
elif command == "pool-dumpxml":
    print(state["pools"][arguments[1]]["xml"])
elif command == "pool-info":
    item = state["pools"][arguments[1]]
    print(f"Name:           {item['name']}")
    print("State:          running")
    print(f"Persistent:     {item['persistent']}")
    print(f"Autostart:      {item['autostart']}")
elif command == "pool-create":
    root = ET.parse(arguments[1]).getroot()
    pool_uuid = root.findtext("./uuid")
    name = root.findtext("./name")
    state["pools"][pool_uuid] = {"name": name, "xml": ET.tostring(root, encoding="unicode"), "persistent": "no", "autostart": "no"}
    fail = state["create_fail"]
    save(state)
    if fail: raise SystemExit(1)
elif command == "pool-destroy":
    pool_uuid = arguments[1]
    state["destroy_attempts"].append(pool_uuid)
    if state["fail_destroy"] == pool_uuid:
        save(state)
        raise SystemExit(1)
    state["pools"].pop(pool_uuid)
    save(state)
else:
    raise SystemExit(f"unsupported fake virsh command: {arguments!r}")
'''


SHELL_BEHAVIOR = r'''#!/usr/bin/env bash
set -euo pipefail
repo="$1"
root="$2"
fake="$3"
state="$4"
SCRIPT_DIR="$repo/scripts"
LIB_DIR="$repo/scripts"
WINDOWS_HELPER_BUILD_UID="$(/usr/bin/id -u)"
WINDOWS_HELPER_BUILD_GID="$(/usr/bin/id -g)"
virsh_bounded() {
    /usr/bin/python3 -I -S "$fake" "$state" "$@"
}
meta() {
    /usr/bin/python3 -I -S "$fake" "$state" _meta "$@"
}
source "$SCRIPT_DIR/windows-libvirt-storage-pools.sh"

open_fixture() {
    local parent="$1"
    WINDOWS_LIBVIRT_CONTROL_ROOT="$parent/.windows-libvirt-transaction.fixture"
    WINDOWS_LIBVIRT_RUNTIME_ROOT="$parent/.rustdesk-libvirt-runtime.fixture"
    mkdir -m 0700 "$WINDOWS_LIBVIRT_CONTROL_ROOT" "$WINDOWS_LIBVIRT_RUNTIME_ROOT"
    WINDOWS_LIBVIRT_CONTROL_ROOT_ID="$(stat -c '%d:%i' "$WINDOWS_LIBVIRT_CONTROL_ROOT")"
    WINDOWS_LIBVIRT_RUNTIME_ROOT_ID="$(stat -c '%d:%i' "$WINDOWS_LIBVIRT_RUNTIME_ROOT")"
    WINDOWS_LIBVIRT_USER_HOME="$HOME"
    WINDOWS_LIBVIRT_CACHE_ROOT="$WINDOWS_LIBVIRT_CONTROL_ROOT/cache"
    WINDOWS_LIBVIRT_CONFIG_ROOT="$WINDOWS_LIBVIRT_CONTROL_ROOT/config"
    mkdir -m 0700 "$WINDOWS_LIBVIRT_CACHE_ROOT" "$WINDOWS_LIBVIRT_CONFIG_ROOT"
    mkdir -m 0700 -p \
        "$WINDOWS_LIBVIRT_CACHE_ROOT/libvirt/qemu/log" \
        "$WINDOWS_LIBVIRT_CACHE_ROOT/libvirt/storage/run" \
        "$WINDOWS_LIBVIRT_CONFIG_ROOT/libvirt/storage/autostart"
    WINDOWS_LIBVIRT_CACHE_ROOT_ID="$(stat -c '%d:%i' "$WINDOWS_LIBVIRT_CACHE_ROOT")"
    WINDOWS_LIBVIRT_CONFIG_ROOT_ID="$(stat -c '%d:%i' "$WINDOWS_LIBVIRT_CONFIG_ROOT")"
    WINDOWS_LIBVIRT_CLIENT_ENV=(/usr/bin/env -i)
    WINDOWS_LIBVIRT_OBJECTS_RETIRED=0
    WINDOWS_LIBVIRT_RUNTIME_RETIRED=0
    WINDOWS_LIBVIRT_CONTROL_RETIRED=0
}

mkdir -m 0700 "$root/parent-one" "$root/target-one" "$root/target-two"
open_fixture "$root/parent-one"
windows_libvirt_ensure_transient_pools "$root/target-one" "$root/target-two"
windows_libvirt_require_targets_owned "$root/target-one" "$root/target-two"
[ "${#WINDOWS_LIBVIRT_POOL_UUIDS[@]}" = 2 ]
first="${WINDOWS_LIBVIRT_POOL_UUIDS[0]}"
second="${WINDOWS_LIBVIRT_POOL_UUIDS[1]}"
meta fail-destroy "$second"
if windows_libvirt_transaction_close; then
    echo "visit-all cleanup accepted a failed pool destroy" >&2
    exit 1
fi
meta attempted "$first"
meta attempted "$second"
meta has "$first" no
meta has "$second" yes
[ -d "$WINDOWS_LIBVIRT_CONTROL_ROOT" ]
meta clear-fail-destroy
windows_libvirt_transaction_close
meta count 0

mkdir -m 0700 "$root/parent-two" "$root/target-three"
open_fixture "$root/parent-two"
meta create-fail yes
if windows_libvirt_ensure_transient_pool "$root/target-three"; then
    echo "ambiguous pool-create failure was accepted" >&2
    exit 1
fi
[ "${#WINDOWS_LIBVIRT_POOL_UUIDS[@]}" = 1 ]
ambiguous="${WINDOWS_LIBVIRT_POOL_UUIDS[0]}"
meta has "$ambiguous" yes
meta create-fail no
windows_libvirt_transaction_close
meta count 0

mkdir -m 0700 "$root/parent-three" "$root/target-four"
foreign_uuid="$(</proc/sys/kernel/random/uuid)"
meta seed foreign-pool "$foreign_uuid" "$root/target-four"
open_fixture "$root/parent-three"
if windows_libvirt_ensure_transient_pool "$root/target-four"; then
    echo "pre-managed target was adopted" >&2
    exit 1
fi
[ "${#WINDOWS_LIBVIRT_POOL_UUIDS[@]}" = 0 ]
windows_libvirt_transaction_close
meta has "$foreign_uuid" yes
meta remove "$foreign_uuid"

mkdir -m 0700 "$root/parent-four" "$root/target-five"
open_fixture "$root/parent-four"
windows_libvirt_ensure_transient_pool "$root/target-five"
owned="${WINDOWS_LIBVIRT_POOL_UUIDS[0]}"
meta info "$owned" Persistent yes
if windows_libvirt_require_targets_owned "$root/target-five"; then
    echo "persistent owned pool was accepted" >&2
    exit 1
fi
if windows_libvirt_transaction_close; then
    echo "persistent pool was destroyed as transaction-owned" >&2
    exit 1
fi
meta info "$owned" Persistent no
windows_libvirt_transaction_close

mkdir -m 0700 "$root/parent-five" "$root/target-six" "$root/wrong-target"
open_fixture "$root/parent-five"
windows_libvirt_ensure_transient_pool "$root/target-six"
owned="${WINDOWS_LIBVIRT_POOL_UUIDS[0]}"
meta target "$owned" "$root/wrong-target"
if windows_libvirt_require_targets_owned "$root/target-six"; then
    echo "changed pool target was accepted" >&2
    exit 1
fi
if windows_libvirt_transaction_close; then
    echo "changed-target pool was destroyed" >&2
    exit 1
fi
meta target "$owned" "$root/target-six"
windows_libvirt_transaction_close

mkdir -m 0700 "$root/parent-six" "$root/target-seven"
open_fixture "$root/parent-six"
windows_libvirt_ensure_transient_pool "$root/target-seven"
mv "$root/target-seven" "$root/target-seven-owned"
mkdir -m 0700 "$root/target-seven"
if windows_libvirt_require_targets_owned "$root/target-seven"; then
    echo "substituted target inode was accepted" >&2
    exit 1
fi
if windows_libvirt_transaction_close; then
    echo "substituted-target pool was destroyed" >&2
    exit 1
fi
rmdir "$root/target-seven"
mv "$root/target-seven-owned" "$root/target-seven"
windows_libvirt_transaction_close
meta count 0

mkdir -m 0700 "$root/parent-seven" "$root/target-eight"
open_fixture "$root/parent-seven"
windows_libvirt_ensure_transient_pool "$root/target-eight"
owned="${WINDOWS_LIBVIRT_POOL_UUIDS[0]}"
compact="${owned//-/}"
ln "$WINDOWS_LIBVIRT_CONTROL_ROOT/pool-$compact.xml" "$root/external-receipt-link"
if windows_libvirt_transaction_close; then
    echo "external receipt hardlink was removed as private state" >&2
    exit 1
fi
[ "$WINDOWS_LIBVIRT_OBJECTS_RETIRED" = 1 ]
[ "$WINDOWS_LIBVIRT_RUNTIME_RETIRED" = 1 ]
[ -d "$WINDOWS_LIBVIRT_CONTROL_ROOT" ]
meta count 0
rm "$root/external-receipt-link"
windows_libvirt_transaction_close
[ "$WINDOWS_LIBVIRT_OBJECTS_RETIRED" = 0 ]
[ -z "$WINDOWS_LIBVIRT_CONTROL_ROOT" ]
printf 'windows-libvirt shell behavior: ok\n'
'''


def run_shell_behavior(repo: pathlib.Path, root: pathlib.Path) -> int:
    fake = root / "fake-virsh.py"
    driver = root / "driver.sh"
    state_path = root / "fake-state.json"
    fake.write_text(FAKE_VIRSH, encoding="utf-8")
    driver.write_text(SHELL_BEHAVIOR, encoding="utf-8")
    fake.chmod(0o700)
    driver.chmod(0o700)
    environment = dict(os.environ)
    environment.pop("XDG_CACHE_HOME", None)
    environment.pop("XDG_CONFIG_HOME", None)
    result = run_command(
        ["/usr/bin/bash", os.fspath(driver), os.fspath(repo), os.fspath(root), os.fspath(fake), os.fspath(state_path)],
        environment=environment,
    )
    if b"windows-libvirt shell behavior: ok" not in result.stdout:
        raise VerificationError("shell behavioral suite did not reach its terminal marker")
    return 7


@dataclass(frozen=True)
class Mutation:
    source: str
    old: str
    new: str
    label: str


MUTATIONS = (
    Mutation("helper", "MAX_XML_BYTES = 64 * 1024\n", "MAX_XML_BYTES = 64 * 1024 * 1024\n", "bounded XML"),
    Mutation("helper", 'root.attrib != {"type": "dir"}', 'root.attrib.get("type") != "dir"', "exact pool type"),
    Mutation("helper", 'if [child.tag for child in root] != expected_order:', 'if not list(root):', "exact pool envelope"),
    Mutation("helper", 'value.attrib != {"unit": "bytes"}', 'value.attrib.get("unit") != "bytes"', "dynamic XML attributes"),
    Mutation("helper", "actual_permissions != expected_permissions", "False", "live target permissions"),
    Mutation("helper", "or metadata.st_nlink != 1", "or metadata.st_nlink < 1", "single-link residue"),
    Mutation(
        "helper",
        "            or before.st_nlink != 1\n"
        "            or stat.S_IMODE(before.st_mode) != 0o600\n"
        "            or before.st_size > MAX_XML_BYTES",
        "            or before.st_nlink != 1\n"
        "            or False\n"
        "            or before.st_size > MAX_XML_BYTES",
        "exact poolstate mode",
    ),
    Mutation("helper", "require_private_primary_group(uid, gid)", "pass # shared primary group accepted", "private group proof"),
    Mutation("helper", "os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC", "os.O_WRONLY | os.O_CREAT | os.O_CLOEXEC", "exclusive receipt"),
    Mutation("helper", "os.unlink(log_name, dir_fd=log_fd)", "os.unlink(os.path.join(log_dir, log_name))", "descriptor-relative log cleanup"),
    Mutation(
        "helper",
        "        require_exact_pool(\n"
        "            root, args.name, args.uuid, args.target, target_metadata\n"
        "        )",
        "        pool_identity(root)",
        "exact poolstate cleanup",
    ),
    Mutation("helper", 'parser.add_argument("--cache-identity", required=True)', 'parser.add_argument("--cache-identity")', "private cache identity"),
    Mutation("helper", 'if hasattr(args, "uid") and (', "if False and (", "mutating-command principal gate"),
    Mutation("helper", "args.uid == 0", "False", "non-root helper"),
    Mutation("library", '[ -z "${XDG_CACHE_HOME:-}" ] && [ -z "${XDG_CONFIG_HOME:-}" ]', "true # ambient XDG accepted", "XDG refusal"),
    Mutation("library", '[ -n "$pw_home" ] && [ "${HOME:-}" = "$pw_home" ]', '[ -n "$pw_home" ]', "HOME/passwd binding"),
    Mutation("library", '[ "$pw_uid" = "$WINDOWS_HELPER_BUILD_UID" ]', "true # passwd UID ignored", "passwd UID"),
    Mutation("library", '[ "$pw_gid" = "$WINDOWS_HELPER_BUILD_GID" ]', "true # passwd GID ignored", "passwd GID"),
    Mutation("library", '/usr/sbin/libvirtd|/usr/sbin/virtqemud|/usr/sbin/virtstoraged|\\', '/usr/sbin/unrelated-daemon)', "ambient daemon refusal"),
    Mutation("library", '[ -d "$runtime/libvirt" ] && [ ! -L "$runtime/libvirt" ] || return 1', '[ -d "$runtime/libvirt" ] || return 1', "ambient runtime symlink refusal"),
    Mutation("library", '"HOME=$private_home"', '"HOME=$pw_home"', "private home namespace"),
    Mutation("library", '"XDG_CACHE_HOME=$cache_root"', '"XDG_CACHE_HOME=$HOME/.cache"', "private cache namespace"),
    Mutation("library", '"XDG_CONFIG_HOME=$config_root"', '"XDG_CONFIG_HOME=$HOME/.config"', "private config namespace"),
    Mutation("library", '"XDG_DATA_HOME=$data_root"', '"XDG_DATA_HOME=$HOME/.local/share"', "private data namespace"),
    Mutation("library", '"XDG_RUNTIME_DIR=$runtime_root"', '"XDG_RUNTIME_DIR=/run/user/$WINDOWS_HELPER_BUILD_UID"', "private runtime namespace"),
    Mutation("library", '"XDG_STATE_HOME=$state_root"', '"XDG_STATE_HOME=$HOME/.local/state"', "private state namespace"),
    Mutation("library", '"TMPDIR=$tmp_root"', '"TMPDIR=/tmp"', "private temporary directory"),
    Mutation("library", "'listen_tcp = 0'", "'listen_tcp = 1'", "private daemon TCP refusal"),
    Mutation("library", "'lock_manager = \"nop\"'", "'lock_manager = \"lockd\"'", "external lock-daemon exclusion"),
    Mutation("library", "'stdio_handler = \"file\"'", "'stdio_handler = \"logd\"'", "external log-daemon exclusion"),
    Mutation("library", '/usr/sbin/libvirtd --config "$config" --pid-file "$pid_file"', '/usr/sbin/libvirtd --daemon --config "$config" --pid-file "$pid_file"', "foreground daemon ownership"),
    Mutation("library", '/usr/bin/virsh --connect qemu:///session', 'virsh --connect qemu:///session', "absolute private virsh client"),
    Mutation("library", "elif windows_libvirt_daemon_is_terminal_or_absent; then", "elif true; then # ambiguous daemon identity accepted", "terminal daemon identity"),
    Mutation("library", "windows_libvirt_require_target_unmanaged \"$target\" || return 1", "true # target adoption accepted", "unmanaged-target refusal"),
    Mutation("library", 'virsh_bounded pool-create "$xml" >/dev/null || return 1', 'virsh_bounded pool-define "$xml" >/dev/null || return 1', "transient pool creation"),
    Mutation("library", '[ "$(windows_libvirt_pool_info_field "$info" Persistent)" = no ]', "true # persistent pool accepted", "persistent refusal"),
    Mutation("library", '[ "$(windows_libvirt_pool_info_field "$info" Autostart)" = no ]', "true # autostart pool accepted", "autostart refusal"),
    Mutation("library", 'virsh_bounded pool-destroy "$pool_uuid" >/dev/null || return 1', 'virsh_bounded pool-destroy "$name" >/dev/null || return 1', "UUID destroy"),
    Mutation("library", 'windows_libvirt_destroy_transient_pool "$index" || cleanup_failed=1', 'windows_libvirt_destroy_transient_pool "$index" || return 1', "visit-all pool cleanup"),
    Mutation("library", 'windows_libvirt_cleanup_domain "$index" || cleanup_failed=1', 'windows_libvirt_cleanup_domain "$index" || return 1', "visit-all log cleanup"),
    Mutation("library", '[ "$domain_unresolved" = 0 ] || return 1', "true # live domain ignored", "domain-first cleanup"),
    Mutation("library", 'if [ "$WINDOWS_LIBVIRT_OBJECTS_RETIRED" = 0 ]; then', "if true; then # retired objects re-queried", "retryable object-retirement phase"),
    Mutation("library", "WINDOWS_LIBVIRT_OBJECTS_RETIRED=1", "WINDOWS_LIBVIRT_OBJECTS_RETIRED=0", "object-retirement commit"),
    Mutation("library", "windows_libvirt_stop_private_daemon || return 1", "true # private daemon detached", "daemon finality"),
    Mutation("library", 'windows_libvirt_require_ambient_session_quiescent \\\n        "/run/user/$WINDOWS_HELPER_BUILD_UID" "$WINDOWS_LIBVIRT_USER_HOME"', "true # escaped auxiliary daemons ignored", "post-stop daemon quiescence"),
    Mutation("library", '--remove-private-root "$WINDOWS_LIBVIRT_RUNTIME_ROOT"', '--remove-private-root "$WINDOWS_LIBVIRT_USER_HOME"', "runtime-root finality"),
    Mutation("library", "windows_libvirt_helper remove-poolstate", "true # runtime poolstate retained\n    windows_libvirt_helper user-path", "poolstate retirement"),
    Mutation("library", '--remove-private-root "$WINDOWS_LIBVIRT_CONTROL_ROOT"', '--remove-private-root "$WINDOWS_LIBVIRT_USER_HOME"', "control-root finality"),
    Mutation("build", 'source "$SCRIPT_DIR/windows-libvirt-storage-pools.sh"', "true # pool authority not sourced", "build authority wiring"),
    Mutation("build", 'windows_libvirt_ensure_transient_pools "$CURRENT_PASS_ROOT" "$RUN_ROOT"', "true # build disk parents unmanaged", "build pool creation"),
    Mutation("build", 'windows_libvirt_prepare_domain "$CURRENT_DOMAIN" "$CURRENT_DOMAIN_UUID"', "true # build log authority omitted", "build domain receipt"),
    Mutation("build", 'windows_libvirt_transaction_close \\\n        || die "Windows transient libvirt authority could not retire before artifact publication"', "true # build pool authority retained", "build terminal cleanup"),
    Mutation("build", '"${WINDOWS_LIBVIRT_CLIENT_ENV[@]}"', '"${PATH}"', "build private virt-install namespace"),
    Mutation("provision", 'windows_libvirt_ensure_transient_pools "$STATE_DIR" "$ONLINE_DIR"', "true # provision disk parents unmanaged", "provision pool creation"),
    Mutation("provision", 'windows_libvirt_prepare_domain "$DOMAIN" "$PROVISION_DOMAIN_UUID"', "true # provision log authority omitted", "provision domain receipt"),
    Mutation("provision", '"${WINDOWS_LIBVIRT_CLIENT_ENV[@]}"', '"${PATH}"', "provision private virt-install namespace"),
    Mutation("presentation", 'windows_libvirt_ensure_transient_pools "$RUN_ROOT"', "true # presentation disk parent unmanaged", "presentation pool creation"),
    Mutation("presentation", 'windows_libvirt_prepare_domain "$CURRENT_DOMAIN" "$CURRENT_DOMAIN_UUID"', "true # presentation log authority omitted", "presentation domain receipt"),
    Mutation("presentation", 'windows_libvirt_transaction_close \\\n        || die "presentation libvirt authority did not retire after domain finality"', "true # presentation pool retained", "presentation terminal cleanup"),
    Mutation("presentation", '"${WINDOWS_LIBVIRT_CLIENT_ENV[@]}"', '"${PATH}"', "presentation private virt-install namespace"),
    Mutation(
        "focused",
        '    echo "external receipt hardlink was removed as private state" >&2\n    exit 1',
        '    echo "external receipt hardlink was accepted" >&2\n    exit 1',
        "retryable post-object cleanup fixture",
    ),
    Mutation("verify", "/usr/bin/python3 -I -S scripts/verify-windows-libvirt-storage-pools.py --repo . --self-test", "true # libvirt storage verifier removed", "focused gate wiring"),
    Mutation("requirements", '<span class="id">R-S11gn</span>', '<span class="id">R-S11gn-disabled</span>', "normative requirement"),
    Mutation("requirements", "<tr><td>349</td>", "<tr><td>349-disabled</td>", "Appendix disposition"),
    Mutation("hardening", "R-S11gn/R-S11e-226 — Windows harness transient libvirt storage ownership", "R-S11gn/R-S11e-226 — Windows harness ambient storage", "hardening ledger"),
    Mutation("workspace", "    validate_windows_libvirt_storage_authority_contract(sources)", "    pass # Windows libvirt independent validation omitted", "independent validation call"),
    Mutation("workspace", '"windows_libvirt_storage_verifier": (', '"windows_libvirt_storage_verifier_disabled": (', "independent focused-source ownership"),
    Mutation("workspace", '"windows_libvirt_storage_library": (', '"windows_libvirt_storage_library_disabled": (', "independent library-source ownership"),
)


def run_mutations(sources: dict[str, str]) -> int:
    for mutation in MUTATIONS:
        original = sources[mutation.source]
        observed = original.count(mutation.old)
        if observed != 1:
            raise VerificationError(
                f"mutation target for {mutation.label} occurs {observed} times"
            )
        changed = dict(sources)
        changed[mutation.source] = original.replace(mutation.old, mutation.new, 1)
        try:
            validate(changed)
        except VerificationError:
            continue
        raise VerificationError(f"mutation was accepted: {mutation.label}")
    return len(MUTATIONS)


def load_sources(repo: pathlib.Path) -> dict[str, str]:
    return {
        key: (repo / relative).read_text(encoding="utf-8")
        for key, relative in FILES.items()
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=pathlib.Path, default=pathlib.Path("."))
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    repo = args.repo.resolve()
    sources = load_sources(repo)
    validate(sources)
    run_command(["/usr/bin/bash", "-n", os.fspath(repo / FILES["library"])])
    for key in ("build", "provision", "presentation"):
        run_command(["/usr/bin/bash", "-n", os.fspath(repo / FILES[key])])
    if args.self_test:
        with tempfile.TemporaryDirectory(prefix="windows-libvirt-storage-test.") as temporary:
            root = pathlib.Path(temporary).resolve()
            root.chmod(0o700)
            helper_root = root / "helper"
            helper_root.mkdir(mode=0o700)
            helper_checks = run_helper_behavior(repo / FILES["helper"], helper_root)
            shell_root = root / "shell"
            shell_root.mkdir(mode=0o700)
            shell_checks = run_shell_behavior(repo, shell_root)
        mutations = run_mutations(sources)
        print(
            "verify-windows-libvirt-storage-pools: PASS "
            f"({helper_checks} helper fixtures, {shell_checks} shell scenarios, "
            f"{mutations} mutations rejected)"
        )
    else:
        print("verify-windows-libvirt-storage-pools: PASS")


if __name__ == "__main__":
    try:
        main()
    except VerificationError as error:
        raise SystemExit(f"verify-windows-libvirt-storage-pools: FAIL: {error}")
