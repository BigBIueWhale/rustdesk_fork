#!/usr/bin/env python3
"""Validate the secret-free installed Windows SCM transaction receipt."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import xml.etree.ElementTree as ET


MAX_JSON_BYTES = 64 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
RUN_ID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}-[AB]$"
)
RESULT_FIELDS = {
    "format",
    "source_commit",
    "source_tree",
    "build_run_id",
    "target",
    "setup_sha256",
    "msi_sha256",
    "installed_exe_sha256",
    "built_exe_sha256",
    "installed_executable",
    "domain_network_interfaces",
    "vnc_listen",
    "service_type",
    "service_start_type",
    "service_start_name",
    "service_binary_path",
    "service_pid_before",
    "service_creation_before",
    "child_pid_before",
    "child_creation_before",
    "service_pid_after",
    "service_creation_after",
    "child_pid_after",
    "child_creation_after",
    "interactive_session_id",
    "child_pid_before_abrupt",
    "child_creation_before_abrupt",
    "child_pid_after_abrupt",
    "child_creation_after_abrupt",
    "cm_pid_initial",
    "cm_creation_initial",
    "cm_pid_after_stale_recovery",
    "cm_creation_after_stale_recovery",
    "cm_pid_after_abrupt_owner",
    "cm_creation_after_abrupt_owner",
    "cm_pid_before_restart",
    "cm_creation_before_restart",
    "cm_pid_after_restart",
    "cm_creation_after_restart",
    "cm_roundtrip_count",
    "service_process_system",
    "service_process_elevated",
    "child_process_system",
    "child_process_elevated",
    "limited_same_principal",
    "limited_same_session",
    "limited_token_elevated",
    "limited_mutation_rejected",
    "first_credential_preserved_after_limited_rejection",
    "limited_fixture_rejected",
    "copied_image_mutation_rejected",
    "first_credential_preserved_after_copied_image_rejection",
    "copied_image_fixture_rejected",
    "first_mutation_applied",
    "first_credential_keyed_before_rotation",
    "second_mutation_applied",
    "second_credential_keyed_before_restart",
    "first_credential_rejected_before_restart",
    "scm_stop_retired_exact_generations",
    "scm_restart_created_new_generations",
    "second_credential_keyed_after_restart",
    "first_credential_rejected_after_restart",
    "cm_exact_installed_image_and_role",
    "cm_interactive_principal_and_session",
    "cm_reused_one_generation",
    "cm_authenticated_file_roundtrips",
    "cm_stale_exit_recovered",
    "cm_stale_generation_replaced",
    "cm_abrupt_owner_exit_retired_generation",
    "cm_abrupt_owner_replaced_service_child",
    "cm_scm_stop_retired_generation",
    "cm_scm_restart_created_new_generation",
    "cm_authenticated_after_restart",
}
TRUE_FIELDS = {
    "service_process_system",
    "service_process_elevated",
    "child_process_system",
    "child_process_elevated",
    "limited_same_principal",
    "limited_same_session",
    "limited_mutation_rejected",
    "first_credential_preserved_after_limited_rejection",
    "limited_fixture_rejected",
    "copied_image_mutation_rejected",
    "first_credential_preserved_after_copied_image_rejection",
    "copied_image_fixture_rejected",
    "first_mutation_applied",
    "first_credential_keyed_before_rotation",
    "second_mutation_applied",
    "second_credential_keyed_before_restart",
    "first_credential_rejected_before_restart",
    "scm_stop_retired_exact_generations",
    "scm_restart_created_new_generations",
    "second_credential_keyed_after_restart",
    "first_credential_rejected_after_restart",
    "cm_exact_installed_image_and_role",
    "cm_interactive_principal_and_session",
    "cm_reused_one_generation",
    "cm_authenticated_file_roundtrips",
    "cm_stale_exit_recovered",
    "cm_stale_generation_replaced",
    "cm_abrupt_owner_exit_retired_generation",
    "cm_abrupt_owner_replaced_service_child",
    "cm_scm_stop_retired_generation",
    "cm_scm_restart_created_new_generation",
    "cm_authenticated_after_restart",
}
INTEGER_FIELDS = {
    "domain_network_interfaces",
    "service_type",
    "service_start_type",
    "service_pid_before",
    "service_creation_before",
    "child_pid_before",
    "child_creation_before",
    "service_pid_after",
    "service_creation_after",
    "child_pid_after",
    "child_creation_after",
    "interactive_session_id",
    "child_pid_before_abrupt",
    "child_creation_before_abrupt",
    "child_pid_after_abrupt",
    "child_creation_after_abrupt",
    "cm_pid_initial",
    "cm_creation_initial",
    "cm_pid_after_stale_recovery",
    "cm_creation_after_stale_recovery",
    "cm_pid_after_abrupt_owner",
    "cm_creation_after_abrupt_owner",
    "cm_pid_before_restart",
    "cm_creation_before_restart",
    "cm_pid_after_restart",
    "cm_creation_after_restart",
    "cm_roundtrip_count",
}


class VerificationError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise VerificationError(message)


def read_regular(path: Path, maximum: int, label: str) -> bytes:
    if not path.is_absolute() or path.resolve() != path:
        fail(f"{label} path is not absolute and canonical")
    info = path.lstat()
    if not path.is_file() or path.is_symlink() or info.st_nlink != 1:
        fail(f"{label} is not one ordinary file")
    if info.st_size <= 0 or info.st_size > maximum:
        fail(f"{label} size is outside the bound")
    data = path.read_bytes()
    after = path.lstat()
    fields = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns")
    if any(getattr(info, field) != getattr(after, field) for field in fields):
        fail(f"{label} changed while it was read")
    return data


def no_duplicate_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            fail(f"JSON object repeats key {key!r}")
        result[key] = value
    return result


def read_json(path: Path, label: str) -> dict[str, object]:
    data = read_regular(path, MAX_JSON_BYTES, label)
    if data.startswith(b"\xef\xbb\xbf") or not data.endswith(b"\n") or b"\r" in data:
        fail(f"{label} is not BOM-free LF-terminated JSON")
    if data.count(b"\n") != 1:
        fail(f"{label} is not one canonical JSON line")
    try:
        parsed = json.loads(data.decode("utf-8"), object_pairs_hook=no_duplicate_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"{label} is not strict UTF-8 JSON: {error}")
    if not isinstance(parsed, dict):
        fail(f"{label} root is not an object")
    return parsed


def sha256(path: Path, label: str) -> str:
    return hashlib.sha256(read_regular(path, 2 * 1024 * 1024 * 1024, label)).hexdigest()


def require_exact_bool(result: dict[str, object], field: str, expected: bool) -> None:
    if type(result.get(field)) is not bool or result[field] is not expected:
        fail(f"receipt field {field} is not exactly {expected}")


def validate_domain(path: Path) -> None:
    data = read_regular(path, 4 * 1024 * 1024, "domain XML")
    try:
        root = ET.fromstring(data)
    except ET.ParseError as error:
        fail(f"domain XML is invalid: {error}")
    if root.tag != "domain" or root.findall("./devices/interface"):
        fail("domain XML contains a guest network interface")
    graphics = root.findall("./devices/graphics")
    if len(graphics) != 1:
        fail("domain XML does not contain exactly one graphics device")
    graphic = graphics[0]
    if graphic.get("type") != "vnc" or graphic.get("listen") != "127.0.0.1":
        fail("domain XML VNC graphics is not bound to 127.0.0.1")
    listeners = graphic.findall("./listen")
    if len(listeners) != 1 or listeners[0].get("type") != "address" or listeners[0].get("address") != "127.0.0.1":
        fail("domain XML VNC listen child is not exactly loopback-addressed")


def validate(
    result_path: Path,
    identity_path: Path,
    setup_path: Path,
    msi_path: Path,
    domain_path: Path,
) -> None:
    result = read_json(result_path, "installed-service result")
    identity = read_json(identity_path, "source identity")
    if set(result) != RESULT_FIELDS:
        fail("installed-service result schema is not exact")
    if result.get("format") != "rustdesk-windows-installed-service-probe-v2":
        fail("installed-service result format is incorrect")
    if identity.get("format") != "rustdesk-windows-source-identity-v1":
        fail("source identity format is incorrect")
    for field in ("source_commit", "source_tree", "build_run_id", "target"):
        if type(result.get(field)) is not str or result[field] != identity.get(field):
            fail(f"installed-service result {field} does not match source identity")
    if not COMMIT_RE.fullmatch(result["source_commit"]) or not COMMIT_RE.fullmatch(result["source_tree"]):
        fail("installed-service result commit/tree is malformed")
    if not RUN_ID_RE.fullmatch(result["build_run_id"]) or result["target"] != "windows-x86_64":
        fail("installed-service result build identity is malformed")

    for field in ("setup_sha256", "msi_sha256", "installed_exe_sha256", "built_exe_sha256"):
        if type(result.get(field)) is not str or not SHA256_RE.fullmatch(result[field]):
            fail(f"installed-service result {field} is not a SHA-256")
    if result["setup_sha256"] != sha256(setup_path, "canonical setup"):
        fail("installed-service result does not bind the canonical setup bytes")
    if result["msi_sha256"] != sha256(msi_path, "canonical MSI"):
        fail("installed-service result does not bind the canonical MSI bytes")
    if result["installed_exe_sha256"] != result["built_exe_sha256"]:
        fail("installed executable and packaged build executable hashes differ")

    installed = r"C:\Program Files\RustDesk\RustDesk.exe"
    if result.get("installed_executable") != installed:
        fail("installed executable path is not exact")
    if result.get("service_binary_path") != f'"{installed}" --service':
        fail("SCM binary path is not the exact installed service role")
    if result.get("service_start_name") != "LocalSystem":
        fail("SCM account is not LocalSystem")
    if result.get("vnc_listen") != "127.0.0.1":
        fail("result VNC expectation is not loopback")

    for field in INTEGER_FIELDS:
        if type(result.get(field)) is not int:
            fail(f"receipt field {field} is not an integer")
    if result["domain_network_interfaces"] != 0:
        fail("result does not require a zero-interface domain")
    if result["service_type"] != 0x10 or result["service_start_type"] != 2:
        fail("SCM type/start policy is not own-process automatic")
    for field in INTEGER_FIELDS - {"domain_network_interfaces", "service_type", "service_start_type"}:
        if result[field] <= 0:
            fail(f"receipt process identity field {field} is not positive")
    if (
        result["service_pid_before"] == result["service_pid_after"]
        and result["service_creation_before"] == result["service_creation_after"]
    ):
        fail("SCM restart did not change the supervisor generation")
    if (
        result["child_pid_before"] == result["child_pid_after"]
        and result["child_creation_before"] == result["child_creation_after"]
    ):
        fail("SCM restart did not change the service-owned child generation")
    if result["cm_roundtrip_count"] != 6:
        fail("installed-service result does not bind all six CM round-trips")
    if (
        result["child_pid_before_abrupt"] == result["child_pid_after_abrupt"]
        and result["child_creation_before_abrupt"] == result["child_creation_after_abrupt"]
    ):
        fail("abrupt owner recovery did not change the service-owned child generation")
    if (
        result["cm_pid_initial"] == result["cm_pid_after_stale_recovery"]
        and result["cm_creation_initial"] == result["cm_creation_after_stale_recovery"]
    ):
        fail("stale CM recovery did not change the CM generation")
    if (
        result["cm_pid_after_stale_recovery"] == result["cm_pid_after_abrupt_owner"]
        and result["cm_creation_after_stale_recovery"] == result["cm_creation_after_abrupt_owner"]
    ):
        fail("abrupt owner recovery did not change the CM generation")
    if (
        result["cm_pid_after_abrupt_owner"] != result["cm_pid_before_restart"]
        or result["cm_creation_after_abrupt_owner"] != result["cm_creation_before_restart"]
    ):
        fail("retained CM generation was not reused before SCM restart")
    if (
        result["cm_pid_before_restart"] == result["cm_pid_after_restart"]
        and result["cm_creation_before_restart"] == result["cm_creation_after_restart"]
    ):
        fail("SCM restart did not change the CM generation")

    for field in TRUE_FIELDS:
        require_exact_bool(result, field, True)
    require_exact_bool(result, "limited_token_elevated", False)
    validate_domain(domain_path)


def synthetic_result(setup: Path, msi: Path) -> dict[str, object]:
    commit = "1" * 40
    tree = "2" * 40
    executable = r"C:\Program Files\RustDesk\RustDesk.exe"
    result: dict[str, object] = {
        "format": "rustdesk-windows-installed-service-probe-v2",
        "source_commit": commit,
        "source_tree": tree,
        "build_run_id": "12345678-1234-4123-8123-123456789abc-A",
        "target": "windows-x86_64",
        "setup_sha256": hashlib.sha256(setup.read_bytes()).hexdigest(),
        "msi_sha256": hashlib.sha256(msi.read_bytes()).hexdigest(),
        "installed_exe_sha256": "3" * 64,
        "built_exe_sha256": "3" * 64,
        "installed_executable": executable,
        "domain_network_interfaces": 0,
        "vnc_listen": "127.0.0.1",
        "service_type": 0x10,
        "service_start_type": 2,
        "service_start_name": "LocalSystem",
        "service_binary_path": f'"{executable}" --service',
        "service_pid_before": 100,
        "service_creation_before": 1000,
        "child_pid_before": 101,
        "child_creation_before": 1001,
        "service_pid_after": 200,
        "service_creation_after": 2000,
        "child_pid_after": 201,
        "child_creation_after": 2001,
        "interactive_session_id": 1,
        "child_pid_before_abrupt": 101,
        "child_creation_before_abrupt": 1001,
        "child_pid_after_abrupt": 102,
        "child_creation_after_abrupt": 1002,
        "cm_pid_initial": 110,
        "cm_creation_initial": 1010,
        "cm_pid_after_stale_recovery": 111,
        "cm_creation_after_stale_recovery": 1011,
        "cm_pid_after_abrupt_owner": 112,
        "cm_creation_after_abrupt_owner": 1012,
        "cm_pid_before_restart": 112,
        "cm_creation_before_restart": 1012,
        "cm_pid_after_restart": 210,
        "cm_creation_after_restart": 2010,
        "cm_roundtrip_count": 6,
        "limited_token_elevated": False,
    }
    for field in TRUE_FIELDS:
        result[field] = True
    return result


def write_json(path: Path, value: dict[str, object]) -> None:
    path.write_text(json.dumps(value, separators=(",", ":")) + "\n", encoding="utf-8")


def self_test() -> None:
    with tempfile.TemporaryDirectory(prefix="windows-installed-service-result-test.") as temporary:
        root = Path(temporary).resolve()
        setup = root / "rustdesk-setup.exe"
        msi = root / "rustdesk.msi"
        result_path = root / "result.json"
        identity_path = root / "identity.json"
        domain_path = root / "domain.xml"
        setup.write_bytes(b"synthetic canonical setup\n")
        msi.write_bytes(b"synthetic canonical msi\n")
        result = synthetic_result(setup, msi)
        identity = {
            "format": "rustdesk-windows-source-identity-v1",
            "source_commit": result["source_commit"],
            "source_tree": result["source_tree"],
            "build_run_id": result["build_run_id"],
            "target": result["target"],
        }
        domain_path.write_text(
            '<domain><devices><graphics type="vnc" listen="127.0.0.1">'
            '<listen type="address" address="127.0.0.1"/>'
            "</graphics></devices></domain>\n",
            encoding="utf-8",
        )
        write_json(identity_path, identity)
        write_json(result_path, result)
        validate(result_path, identity_path, setup, msi, domain_path)

        mutations: list[tuple[str, dict[str, object]]] = []
        changed = copy.deepcopy(result)
        changed["limited_mutation_rejected"] = False
        mutations.append(("limited rejection", changed))
        changed = copy.deepcopy(result)
        changed["first_credential_preserved_after_limited_rejection"] = False
        mutations.append(("limited rejection preservation", changed))
        changed = copy.deepcopy(result)
        changed["copied_image_fixture_rejected"] = False
        mutations.append(("copied-image fixture refusal", changed))
        changed = copy.deepcopy(result)
        changed["setup_sha256"] = "0" * 64
        mutations.append(("setup binding", changed))
        changed = copy.deepcopy(result)
        changed["unexpected"] = True
        mutations.append(("closed schema", changed))
        changed = copy.deepcopy(result)
        changed["service_pid_after"] = changed["service_pid_before"]
        changed["service_creation_after"] = changed["service_creation_before"]
        mutations.append(("SCM generation", changed))
        changed = copy.deepcopy(result)
        changed["child_pid_after_abrupt"] = changed["child_pid_before_abrupt"]
        changed["child_creation_after_abrupt"] = changed["child_creation_before_abrupt"]
        mutations.append(("abrupt owner generation", changed))
        changed = copy.deepcopy(result)
        changed["cm_pid_after_stale_recovery"] = changed["cm_pid_initial"]
        changed["cm_creation_after_stale_recovery"] = changed["cm_creation_initial"]
        mutations.append(("stale CM generation", changed))
        changed = copy.deepcopy(result)
        changed["cm_pid_before_restart"] = 999
        mutations.append(("retained CM reuse", changed))
        changed = copy.deepcopy(result)
        changed["cm_pid_after_restart"] = changed["cm_pid_before_restart"]
        changed["cm_creation_after_restart"] = changed["cm_creation_before_restart"]
        mutations.append(("SCM CM generation", changed))
        changed = copy.deepcopy(result)
        changed["cm_roundtrip_count"] = 5
        mutations.append(("CM round-trip count", changed))
        for label, mutation in mutations:
            write_json(result_path, mutation)
            try:
                validate(result_path, identity_path, setup, msi, domain_path)
            except VerificationError:
                continue
            raise AssertionError(f"self-test mutation was accepted: {label}")

        write_json(result_path, result)
        domain_path.write_text(
            '<domain><devices><interface type="network"/>'
            '<graphics type="vnc" listen="127.0.0.1">'
            '<listen type="address" address="127.0.0.1"/>'
            "</graphics></devices></domain>\n",
            encoding="utf-8",
        )
        try:
            validate(result_path, identity_path, setup, msi, domain_path)
        except VerificationError:
            pass
        else:
            raise AssertionError("self-test accepted a domain network interface")
    print("verify-windows-installed-service-result self-test: ok")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--result", type=Path)
    parser.add_argument("--identity", type=Path)
    parser.add_argument("--setup", type=Path)
    parser.add_argument("--msi", type=Path)
    parser.add_argument("--domain-xml", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        if any(value is not None for value in (args.result, args.identity, args.setup, args.msi, args.domain_xml)):
            parser.error("--self-test takes no path arguments")
        self_test()
        return
    values = (args.result, args.identity, args.setup, args.msi, args.domain_xml)
    if any(value is None for value in values):
        parser.error("--result, --identity, --setup, --msi, and --domain-xml are required")
    validate(args.result.resolve(), args.identity.resolve(), args.setup.resolve(), args.msi.resolve(), args.domain_xml.resolve())
    print("verify-windows-installed-service-result: ok")


if __name__ == "__main__":
    try:
        main()
    except (OSError, VerificationError) as error:
        raise SystemExit(f"verify-windows-installed-service-result failed: {error}")
