#!/usr/bin/env python3
"""Verify the native Windows full-peer focus/presentation transaction."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import pathlib
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET


HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")
TCP_SERVER = re.compile(r"5:127\.0\.0\.1:21118:127\.0\.0\.1:([1-9][0-9]*):([1-9][0-9]*)")
TCP_VIEWER = re.compile(r"5:127\.0\.0\.1:([1-9][0-9]*):127\.0\.0\.1:21118:([1-9][0-9]*)")
TCP_LISTENER = re.compile(r"2:127\.0\.0\.1:21118:0\.0\.0\.0:0:([1-9][0-9]*)")
PALETTE = {
    "teal": (0, 238, 238),
    "orange": (255, 96, 0),
    "violet": (176, 0, 255),
    "lime": (96, 255, 0),
    "pink": (255, 0, 128),
    "azure": (0, 128, 255),
}


def fail(message: str) -> None:
    raise SystemExit(f"windows full-peer presentation verification failed: {message}")


def ordinary_file(path: pathlib.Path, maximum: int | None = None) -> bytes:
    try:
        info = path.lstat()
    except OSError as exc:
        fail(f"cannot stat {path}: {exc}")
    if not path.is_file() or path.is_symlink() or info.st_nlink != 1 or info.st_size <= 0:
        fail(f"evidence path is not one nonempty ordinary file: {path}")
    if maximum is not None and info.st_size > maximum:
        fail(f"evidence path exceeds {maximum} bytes: {path}")
    try:
        return path.read_bytes()
    except OSError as exc:
        fail(f"cannot read {path}: {exc}")


def json_object(path: pathlib.Path) -> dict[str, object]:
    raw = ordinary_file(path, 65_536)
    if not raw.endswith(b"\n") or raw.endswith(b"\r\n"):
        fail(f"JSON evidence lacks one LF terminator: {path}")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        fail(f"invalid JSON at {path}: {exc}")
    if not isinstance(value, dict):
        fail(f"JSON root is not an object: {path}")
    return value


def exact_keys(value: dict[str, object], keys: set[str], label: str) -> None:
    if set(value) != keys:
        fail(f"{label} fields differ: {sorted(value)}")


def typed_bool(value: object, expected: bool, label: str) -> None:
    if not isinstance(value, bool) or value is not expected:
        fail(f"{label} is not the typed value {expected}")


def typed_int(value: object, minimum: int, maximum: int, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        fail(f"{label} is not a JSON integer")
    if value < minimum or value > maximum:
        fail(f"{label} is outside [{minimum}, {maximum}]: {value}")
    return value


def sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(ordinary_file(path)).hexdigest()


def validate_rgb(value: object, expected: str, label: str) -> None:
    if not isinstance(value, dict):
        fail(f"{label} is not an RGB object")
    exact_keys(value, {"red", "green", "blue"}, label)
    rgb = tuple(typed_int(value[channel], 0, 255, f"{label}.{channel}") for channel in ("red", "green", "blue"))
    distance = sum(abs(left - right) for left, right in zip(rgb, PALETTE[expected]))
    if distance > 90:
        fail(f"{label} is not within the admitted {expected} palette distance: {rgb}")


def validate_fixture_rect(value: object, label: str) -> None:
    if not isinstance(value, dict):
        fail(f"{label} is not an object")
    exact_keys(value, {"left", "top", "sample_x", "sample_y"}, label)
    left = typed_int(value["left"], -32_768, 32_767, f"{label}.left")
    top = typed_int(value["top"], -32_768, 32_767, f"{label}.top")
    sample_x = typed_int(value["sample_x"], -32_768, 32_767, f"{label}.sample_x")
    sample_y = typed_int(value["sample_y"], -32_768, 32_767, f"{label}.sample_y")
    if sample_x - left != 48 or sample_y - top != 48:
        fail(f"{label} sample is not the exact interior offset")


def validate_observation(value: object, expected: str, maximum: int, label: str) -> int:
    if not isinstance(value, dict):
        fail(f"{label} is not an observation object")
    exact_keys(value, {"elapsed_ms", "sample", "fixture_rect"}, label)
    elapsed = typed_int(value["elapsed_ms"], 0, maximum, f"{label}.elapsed_ms")
    validate_rgb(value["sample"], expected, f"{label}.sample")
    validate_fixture_rect(value["fixture_rect"], f"{label}.fixture_rect")
    return elapsed


def validate_domain(path: pathlib.Path) -> None:
    raw = ordinary_file(path, 1_048_576)
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        fail(f"invalid domain XML: {exc}")
    if root.findall("./devices/interface"):
        fail("Windows full-peer VM unexpectedly had a network interface")
    graphics = root.findall("./devices/graphics")
    if len(graphics) != 1:
        fail("domain does not contain exactly one graphics device")
    graphic = graphics[0]
    if graphic.get("type") != "vnc" or graphic.get("listen") != "127.0.0.1":
        fail("domain VNC graphics is not loopback-only")
    listeners = graphic.findall("./listen")
    if len(listeners) != 1 or listeners[0].get("type") != "address" or listeners[0].get("address") != "127.0.0.1":
        fail("domain VNC listener child is not loopback-only")


def validate_release_dist(receipt: dict[str, object], setup: pathlib.Path, msi: pathlib.Path) -> None:
    release_dist = receipt["release_dist"]
    if not isinstance(release_dist, dict):
        fail("build receipt release_dist is not an object")
    names = {
        "rustdesk-setup.exe",
        "rustdesk-setup.exe.sha256",
        "rustdesk.msi",
        "rustdesk.msi.sha256",
    }
    exact_keys(release_dist, names, "build receipt release_dist")
    actuals = {"rustdesk-setup.exe": setup, "rustdesk.msi": msi}
    for name, value in release_dist.items():
        if not isinstance(value, dict):
            fail(f"build receipt release_dist.{name} is not an object")
        exact_keys(value, {"size", "sha256"}, f"build receipt release_dist.{name}")
        typed_int(value["size"], 1, 1 << 31, f"build receipt release_dist.{name}.size")
        if not isinstance(value["sha256"], str) or not HEX64.fullmatch(value["sha256"]):
            fail(f"build receipt release_dist.{name}.sha256 is malformed")
        if name in actuals:
            actual = actuals[name]
            if value["size"] != actual.stat().st_size or value["sha256"] != sha256(actual):
                fail(f"build receipt does not match extracted {name}")


def self_test() -> None:
    def write_json(path: pathlib.Path, value: object) -> None:
        path.write_text(json.dumps(value, separators=(",", ":"), sort_keys=True) + "\n", encoding="utf-8")

    with tempfile.TemporaryDirectory(prefix="windows-full-peer-result-self-test-") as temporary:
        root = pathlib.Path(temporary)
        paths = {
            name: root / name
            for name in ("result.json", "receipt.json", "identity.json", "domain.xml", "setup.exe", "rustdesk.msi")
        }
        paths["setup.exe"].write_bytes(b"synthetic setup bytes\n")
        paths["rustdesk.msi"].write_bytes(b"synthetic msi bytes\n")
        commit = "1" * 40
        tree = "2" * 40
        write_json(paths["identity.json"], {"source_commit": commit, "source_tree": tree})
        domain = (
            '<domain><devices><graphics type="vnc" listen="127.0.0.1">'
            '<listen type="address" address="127.0.0.1"/>'
            "</graphics></devices></domain>\n"
        )
        paths["domain.xml"].write_text(domain, encoding="ascii")
        release_dist = {}
        for name, path in (("rustdesk-setup.exe", paths["setup.exe"]), ("rustdesk.msi", paths["rustdesk.msi"])):
            release_dist[name] = {"size": path.stat().st_size, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
            checksum = f"{release_dist[name]['sha256']}  {name}\n".encode("ascii")
            release_dist[f"{name}.sha256"] = {"size": len(checksum), "sha256": hashlib.sha256(checksum).hexdigest()}
        receipt = {
            "format": "rustdesk-windows-full-peer-probe-build-v1",
            "source_commit": commit,
            "source_tree": tree,
            "probe_features": "flutter,windows-full-peer-presentation-probe",
            "probe_listener_policy": "127.0.0.1:21118",
            "release_artifacts_unchanged": True,
            "cargo_lock_sha256": "3" * 64,
            "normal_target_dll_sha256": "4" * 64,
            "probe_target_dll_sha256": "5" * 64,
            "probe_bundle_exe_sha256": "6" * 64,
            "probe_bundle_dll_sha256": "7" * 64,
            "release_dist": release_dist,
        }
        rect = {"left": 428, "top": 52, "sample_x": 476, "sample_y": 100}

        def observation(color: str, elapsed: int) -> dict[str, object]:
            red, green, blue = PALETTE[color]
            return {
                "elapsed_ms": elapsed,
                "sample": {"red": red, "green": green, "blue": blue},
                "fixture_rect": rect,
            }

        colors = ["orange", "violet", "lime", "pink", "azure", "teal"]
        result = {
            "format": "rustdesk-windows-full-peer-presentation-result-v1",
            "verdict": "pass",
            "source_commit": commit,
            "source_tree": tree,
            "real_rustdesk_viewer": True,
            "real_rustdesk_controlled_server": True,
            "actual_capture_encode_keyed_transport_decode_flutter_texture": True,
            "test_only_loopback_listener_feature": True,
            "listener": "127.0.0.1:21118",
            "no_guest_network_interface_expected": True,
            "uninterrupted_tcp_session": True,
            "tcp_session": {
                "listener_row": "2:127.0.0.1:21118:0.0.0.0:0:123",
                "server_row": "5:127.0.0.1:21118:127.0.0.1:50000:123",
                "viewer_row": "5:127.0.0.1:50000:127.0.0.1:21118:456",
            },
            "password_typed_into_real_viewer_dialog": True,
            "remote_input_delivered": True,
            "recovery_limit_ms": 2500,
            "initial": observation("teal", 500),
            "sustained_unfocused_duration_ms": 61_000,
            "unfocused_updates": [
                {
                    "sequence": index + 1,
                    "color": colors[index % len(colors)],
                    "elapsed_ms": 250,
                    "sample": observation(colors[index % len(colors)], 250)["sample"],
                }
                for index in range(120)
            ],
            "minimize_restore": {
                "queued_source_changes": 21,
                "minimized_duration_ms": 10_500,
                "queued_final_color": "lime",
                "restored_to_queued_final_ms": 700,
                "queued_final_observation": observation("lime", 600),
                "post_restore_color": "azure",
                "post_restore_fresh_update_ms": 300,
                "post_restore_observation": observation("azure", 300),
            },
        }

        command = [
            sys.executable,
            str(pathlib.Path(__file__).resolve()),
            "--result",
            str(paths["result.json"]),
            "--build-receipt",
            str(paths["receipt.json"]),
            "--identity",
            str(paths["identity.json"]),
            "--domain-xml",
            str(paths["domain.xml"]),
            "--setup",
            str(paths["setup.exe"]),
            "--msi",
            str(paths["rustdesk.msi"]),
        ]

        def invoke(expect_success: bool) -> None:
            completed = subprocess.run(command, capture_output=True, text=True, timeout=10, check=False)
            if (completed.returncode == 0) is not expect_success:
                fail(
                    "self-test subprocess outcome differs: "
                    f"exit={completed.returncode} stdout={completed.stdout!r} stderr={completed.stderr!r}"
                )

        write_json(paths["receipt.json"], receipt)
        write_json(paths["result.json"], result)
        invoke(True)

        result["listener"] = "0.0.0.0:21118"
        write_json(paths["result.json"], result)
        invoke(False)
        result["listener"] = "127.0.0.1:21118"

        result["unfocused_updates"][0]["elapsed_ms"] = 2501
        write_json(paths["result.json"], result)
        invoke(False)
        result["unfocused_updates"][0]["elapsed_ms"] = 250
        write_json(paths["result.json"], result)

        result["sustained_unfocused_duration_ms"] = 59_999
        write_json(paths["result.json"], result)
        invoke(False)
        result["sustained_unfocused_duration_ms"] = 61_000
        write_json(paths["result.json"], result)

        final_update = result["unfocused_updates"].pop()
        write_json(paths["result.json"], result)
        invoke(False)
        result["unfocused_updates"].append(final_update)
        write_json(paths["result.json"], result)

        result["minimize_restore"]["minimized_duration_ms"] = 9_999
        write_json(paths["result.json"], result)
        invoke(False)
        result["minimize_restore"]["minimized_duration_ms"] = 10_500
        write_json(paths["result.json"], result)

        receipt["release_dist"]["rustdesk-setup.exe"]["sha256"] = "8" * 64
        write_json(paths["receipt.json"], receipt)
        invoke(False)
        receipt["release_dist"]["rustdesk-setup.exe"]["sha256"] = hashlib.sha256(paths["setup.exe"].read_bytes()).hexdigest()
        write_json(paths["receipt.json"], receipt)

        paths["domain.xml"].write_text(
            domain.replace("<devices>", "<devices><interface type=\"network\"/>"),
            encoding="ascii",
        )
        invoke(False)

    print("verify-windows-full-peer-presentation-result self-test: ok")


def main() -> None:
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        return
    parser = argparse.ArgumentParser()
    parser.add_argument("--result", type=pathlib.Path, required=True)
    parser.add_argument("--build-receipt", type=pathlib.Path, required=True)
    parser.add_argument("--identity", type=pathlib.Path, required=True)
    parser.add_argument("--domain-xml", type=pathlib.Path, required=True)
    parser.add_argument("--setup", type=pathlib.Path, required=True)
    parser.add_argument("--msi", type=pathlib.Path, required=True)
    args = parser.parse_args()

    identity = json_object(args.identity)
    for name in ("source_commit", "source_tree"):
        if not isinstance(identity.get(name), str) or not HEX40.fullmatch(identity[name]):
            fail(f"source identity {name} is malformed")
    validate_domain(args.domain_xml)

    receipt = json_object(args.build_receipt)
    exact_keys(
        receipt,
        {
            "format",
            "source_commit",
            "source_tree",
            "probe_features",
            "probe_listener_policy",
            "release_artifacts_unchanged",
            "cargo_lock_sha256",
            "normal_target_dll_sha256",
            "probe_target_dll_sha256",
            "probe_bundle_exe_sha256",
            "probe_bundle_dll_sha256",
            "release_dist",
        },
        "build receipt",
    )
    if receipt["format"] != "rustdesk-windows-full-peer-probe-build-v1":
        fail("build receipt format differs")
    if receipt["source_commit"] != identity["source_commit"] or receipt["source_tree"] != identity["source_tree"]:
        fail("build receipt source identity differs")
    if receipt["probe_features"] != "flutter,windows-full-peer-presentation-probe" or receipt["probe_listener_policy"] != "127.0.0.1:21118":
        fail("build receipt probe feature/listener policy differs")
    typed_bool(receipt["release_artifacts_unchanged"], True, "build receipt release_artifacts_unchanged")
    for name in (
        "cargo_lock_sha256",
        "normal_target_dll_sha256",
        "probe_target_dll_sha256",
        "probe_bundle_exe_sha256",
        "probe_bundle_dll_sha256",
    ):
        if not isinstance(receipt[name], str) or not HEX64.fullmatch(receipt[name]):
            fail(f"build receipt {name} is malformed")
    if receipt["normal_target_dll_sha256"] == receipt["probe_target_dll_sha256"]:
        fail("normal and probe target DLL identities are equal")
    validate_release_dist(receipt, args.setup, args.msi)

    result = json_object(args.result)
    exact_keys(
        result,
        {
            "format",
            "verdict",
            "source_commit",
            "source_tree",
            "real_rustdesk_viewer",
            "real_rustdesk_controlled_server",
            "actual_capture_encode_keyed_transport_decode_flutter_texture",
            "test_only_loopback_listener_feature",
            "listener",
            "no_guest_network_interface_expected",
            "uninterrupted_tcp_session",
            "tcp_session",
            "password_typed_into_real_viewer_dialog",
            "remote_input_delivered",
            "recovery_limit_ms",
            "initial",
            "sustained_unfocused_duration_ms",
            "unfocused_updates",
            "minimize_restore",
        },
        "runtime result",
    )
    if result["format"] != "rustdesk-windows-full-peer-presentation-result-v1" or result["verdict"] != "pass":
        fail("runtime result is not a canonical pass")
    if result["source_commit"] != identity["source_commit"] or result["source_tree"] != identity["source_tree"]:
        fail("runtime result source identity differs")
    for name in (
        "real_rustdesk_viewer",
        "real_rustdesk_controlled_server",
        "actual_capture_encode_keyed_transport_decode_flutter_texture",
        "test_only_loopback_listener_feature",
        "no_guest_network_interface_expected",
        "uninterrupted_tcp_session",
        "password_typed_into_real_viewer_dialog",
        "remote_input_delivered",
    ):
        typed_bool(result[name], True, f"runtime result {name}")
    if result["listener"] != "127.0.0.1:21118":
        fail("runtime listener is not exact loopback")
    if ipaddress.ip_address(result["listener"].split(":", 1)[0]) != ipaddress.ip_address("127.0.0.1"):
        fail("runtime listener address parsing differs")
    limit = typed_int(result["recovery_limit_ms"], 1, 2500, "runtime recovery_limit_ms")
    typed_int(
        result["sustained_unfocused_duration_ms"],
        60_000,
        300_000,
        "runtime sustained_unfocused_duration_ms",
    )

    session = result["tcp_session"]
    if not isinstance(session, dict):
        fail("runtime tcp_session is not an object")
    exact_keys(session, {"listener_row", "server_row", "viewer_row"}, "runtime tcp_session")
    if not isinstance(session["listener_row"], str) or TCP_LISTENER.fullmatch(session["listener_row"]) is None:
        fail("runtime listener TCP row is not exact loopback LISTEN")
    if not isinstance(session["server_row"], str) or TCP_SERVER.fullmatch(session["server_row"]) is None:
        fail("runtime server TCP row is not exact loopback ESTABLISHED")
    if not isinstance(session["viewer_row"], str) or TCP_VIEWER.fullmatch(session["viewer_row"]) is None:
        fail("runtime viewer TCP row is not exact loopback ESTABLISHED")
    listener_match = TCP_LISTENER.fullmatch(session["listener_row"])
    server_match = TCP_SERVER.fullmatch(session["server_row"])
    viewer_match = TCP_VIEWER.fullmatch(session["viewer_row"])
    assert listener_match is not None and server_match is not None and viewer_match is not None
    if listener_match.group(1) != server_match.group(2):
        fail("runtime listener/server TCP rows do not share one server PID")
    if server_match.group(1) != viewer_match.group(1):
        fail("runtime server/viewer TCP rows do not share one client port")

    validate_observation(result["initial"], "teal", 30_000, "runtime initial")
    updates = result["unfocused_updates"]
    color_cycle = ["orange", "violet", "lime", "pink", "azure", "teal"]
    expected_colors = [color_cycle[index % len(color_cycle)] for index in range(120)]
    if not isinstance(updates, list) or len(updates) != 120:
        fail("runtime unfocused update inventory differs")
    for index, (update, color) in enumerate(zip(updates, expected_colors)):
        if not isinstance(update, dict):
            fail(f"runtime unfocused update {index} is not an object")
        exact_keys(update, {"sequence", "color", "elapsed_ms", "sample"}, f"runtime unfocused update {index}")
        if update["sequence"] != index + 1 or update["color"] != color:
            fail(f"runtime unfocused update {index} color differs")
        typed_int(update["elapsed_ms"], 0, limit, f"runtime unfocused update {index}.elapsed_ms")
        validate_rgb(update["sample"], color, f"runtime unfocused update {index}.sample")

    restore = result["minimize_restore"]
    if not isinstance(restore, dict):
        fail("runtime minimize_restore is not an object")
    exact_keys(
        restore,
        {
            "queued_source_changes",
            "minimized_duration_ms",
            "queued_final_color",
            "restored_to_queued_final_ms",
            "queued_final_observation",
            "post_restore_color",
            "post_restore_fresh_update_ms",
            "post_restore_observation",
        },
        "runtime minimize_restore",
    )
    if restore["queued_source_changes"] != 21 or restore["queued_final_color"] != "lime" or restore["post_restore_color"] != "azure":
        fail("runtime minimize/restore stimulus differs")
    typed_int(restore["minimized_duration_ms"], 10_000, 300_000, "runtime minimized_duration_ms")
    restored = typed_int(restore["restored_to_queued_final_ms"], 0, limit, "runtime restored_to_queued_final_ms")
    observed = validate_observation(
        restore["queued_final_observation"],
        "lime",
        limit,
        "runtime queued-final observation",
    )
    if observed > restored:
        fail("runtime restore observation exceeds end-to-end restore measurement")
    post_restore = typed_int(
        restore["post_restore_fresh_update_ms"],
        0,
        limit,
        "runtime post_restore_fresh_update_ms",
    )
    post_observed = validate_observation(
        restore["post_restore_observation"],
        "azure",
        limit,
        "runtime post-restore observation",
    )
    if post_observed != post_restore:
        fail("runtime post-restore observation latency differs from its summary")

    print("windows full-peer presentation result: ok")


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        sys.exit(1)
