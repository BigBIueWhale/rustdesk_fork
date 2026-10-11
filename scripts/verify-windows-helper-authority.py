#!/usr/bin/env python3
"""Check Windows helper authority and execute its golden-domain XML admission."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET


class VerificationError(RuntimeError):
    pass


FILES = {
    "runtime": "scripts/windows-helper-runtime.sh",
    "test": "scripts/test-windows-helper-vm-runtime.sh",
    "build": "scripts/build-windows-vm.sh",
    "provision": "scripts/provision-windows-vm.sh",
    "golden": "scripts/verify-windows-golden.sh",
    "extractor": "scripts/windows-helper-extract-kernel.py",
    "library": "scripts/lib.sh",
    "outer": "scripts/smoke-verifier-vm-authority.sh",
    "guest": "scripts/smoke-verifier-vm-authority-guest.sh",
    "verify": "scripts/verify.sh",
}


def require(source: str, token: str, label: str) -> None:
    if token not in source:
        raise VerificationError(f"missing {label}")


def forbid(source: str, token: str, label: str) -> None:
    if token in source:
        raise VerificationError(f"forbidden {label}")


def require_count(source: str, token: str, expected: int, label: str) -> None:
    observed = source.count(token)
    if observed != expected:
        raise VerificationError(
            f"{label} count is {observed}, expected {expected}"
        )


def require_order(source: str, tokens: tuple[str, ...], label: str) -> None:
    offset = 0
    positions: list[int] = []
    for token in tokens:
        position = source.find(token, offset)
        if position < 0:
            raise VerificationError(f"{label} is incomplete or misordered")
        positions.append(position)
        offset = position + len(token)
    if len(set(positions)) != len(positions):
        raise VerificationError(f"{label} is incomplete or misordered")


def shell_function(source: str, name: str) -> str:
    marker = f"\n{name}() {{\n"
    start = source.find(marker)
    if start < 0:
        raise VerificationError(f"missing shell function {name}")
    end = source.find("\n}\n", start + len(marker))
    if end < 0:
        raise VerificationError(f"unterminated shell function {name}")
    return source[start + 1 : end + 2]


def validate_runtime(source: str) -> None:
    for token, label in (
        (
            "readonly WINDOWS_HELPER_VM_PREFLIGHT=\"$SCRIPT_DIR/verify-vm-entry-preflight.sh\"",
            "fixed VM preflight",
        ),
        (
            "readonly WINDOWS_HELPER_DOCKER_CLIENT=/usr/bin/docker",
            "fixed guest Docker client",
        ),
        (
            "readonly WINDOWS_HELPER_DOCKER_SOCKET=/run/rustdesk-verifier-vm/docker.sock",
            "fixed guest Docker socket",
        ),
        (
            "readonly WINDOWS_HELPER_DOCKER_CONFIG=/run/rustdesk-verifier-vm/docker-config",
            "fixed root-owned guest Docker configuration",
        ),
        ('WINDOWS_HELPER_RUNTIME_ROOT_ID=""', "runtime-root identity"),
        ("WINDOWS_HELPER_AUTHORITY_OPEN=0", "runtime open state"),
        (
            "/usr/bin/mktemp -d /tmp/rustdesk-windows-helper.XXXXXXXXXX",
            "private random runtime root",
        ),
        (
            "/usr/bin/stat -c '%d:%i' -- \"$WINDOWS_HELPER_RUNTIME_ROOT\"",
            "recorded runtime-root identity",
        ),
        (
            '--remove-private-root "$WINDOWS_HELPER_RUNTIME_ROOT"',
            "descriptor-safe exact runtime-root closer",
        ),
        (
            '--expected-identity "$WINDOWS_HELPER_RUNTIME_ROOT_ID"',
            "runtime-root cleanup identity",
        ),
        (
            'require_pinned_builder_image win-helper "$WIN_HELPER_CONFIG_ID" \\'
            '\n        windows_helper_image_provenance',
            "VM-routed helper image provenance",
        ),
        (
            "windows_helper_docker run --rm --pull=never --network=none --read-only",
            "single VM-routed container launcher",
        ),
        (
            '--user "$WINDOWS_HELPER_BUILD_UID:$WINDOWS_HELPER_BUILD_GID"',
            "numeric nonroot container identity",
        ),
        (
            "--cap-drop=ALL --security-opt=no-new-privileges",
            "capability and privilege confinement",
        ),
        (
            "--ulimit core=0:0 --ulimit nofile=4096:4096",
            "core and descriptor ceilings",
        ),
        (
            "--ulimit fsize=137438953472:137438953472",
            "file-size ceiling",
        ),
        (
            "--pids-limit=64 --memory=1g --memory-swap=1g --cpus=1",
            "small profile bounds",
        ),
        (
            "--pids-limit=64 --memory=2g --memory-swap=2g --cpus=2",
            "media profile bounds",
        ),
        (
            "--pids-limit=256 --memory=4g --memory-swap=4g --cpus=2",
            "libguestfs profile bounds",
        ),
        (
            'WINDOWS_HELPER_VALIDATED_MOUNT_VALUE="$value,bind-recursive=disabled"',
            "nonrecursive caller binds",
        ),
        (
            "Windows helper bind target must be lexically canonical",
            "canonical bind targets",
        ),
        (
            "Windows helper bind source must be a regular file or directory",
            "special-file bind refusal",
        ),
        (
            "writable Windows helper bind source must be current-UID owned",
            "writable bind ownership",
        ),
        (
            "writable Windows helper bind source must not be group/world writable",
            "writable bind mode",
        ),
        (
            "writable Windows helper file must be single-link",
            "writable bind link count",
        ),
        (
            "--device /dev/kvm:/dev/kvm:rw",
            "read/write-only KVM device grant",
        ),
        ('windows_helper_verify_archive "$archive"', "archive pre/post verification"),
        (
            '--kernel-sha256 "$SHA256_WIN_HELPER_KERNEL"',
            "independent kernel pin",
        ),
    ):
        require(source, token, label)

    require_count(
        source,
        'windows_helper_verify_archive "$archive"',
        2,
        "archive pre/post verification",
    )
    require_count(
        source,
        "--device /dev/kvm:/dev/kvm:rw",
        1,
        "single KVM device grant",
    )
    require_count(
        source,
        "windows_helper_docker run --rm --pull=never --network=none --read-only",
        1,
        "single container-launch funnel",
    )
    require_count(
        source,
        '--remove-private-root "$WINDOWS_HELPER_RUNTIME_ROOT"',
        1,
        "single runtime-root closer",
    )

    authority = shell_function(source, "windows_helper_assert_vm_authority")
    for token, label in (
        ('"${WINDOWS_HELPER_BUILD_UID:-}" = "$(/usr/bin/id -u)"', "live UID replay"),
        ('"${WINDOWS_HELPER_BUILD_GID:-}" = "$(/usr/bin/id -g)"', "live GID replay"),
        ('/usr/bin/bash "$WINDOWS_HELPER_VM_PREFLIGHT" >/dev/null', "VM preflight replay"),
    ):
        require(authority, token, label)

    docker = shell_function(source, "windows_helper_docker")
    provenance = shell_function(source, "windows_helper_image_provenance")
    for block, label in ((docker, "Docker"), (provenance, "provenance")):
        require_count(
            block,
            "windows_helper_assert_vm_authority",
            2,
            f"{label} pre/post authority replay",
        )
        for token, description in (
            (
                "/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C HOME=/nonexistent",
                "closed environment",
            ),
            ('DOCKER_HOST="unix://$WINDOWS_HELPER_DOCKER_SOCKET"', "fixed Docker host"),
            ('DOCKER_CONFIG="$WINDOWS_HELPER_DOCKER_CONFIG"', "fixed Docker config"),
        ):
            require(block, token, f"{label} {description}")
    require(
        docker,
        '"$WINDOWS_HELPER_DOCKER_CLIENT" \\'
        '\n            --host "unix://$WINDOWS_HELPER_DOCKER_SOCKET" \\'
        '\n            --config "$WINDOWS_HELPER_DOCKER_CONFIG"',
        "fixed Docker client and redundant routing",
    )
    require(
        provenance,
        '/usr/bin/python3 -I -S "$LIB_DIR/offline-image-provenance.py"',
        "isolated provenance parser",
    )

    require_order(
        shell_function(source, "windows_helper_authority_open"),
        (
            "windows_helper_assert_vm_authority",
            "/usr/bin/mktemp -d",
            "WINDOWS_HELPER_RUNTIME_ROOT_ID=",
            "/usr/bin/install -d -m 0700",
            "windows_helper_assert_vm_authority",
            "WINDOWS_HELPER_AUTHORITY_OPEN=1",
        ),
        "VM admission before runtime-root commit",
    )
    require_order(
        shell_function(source, "windows_helper_authority_close"),
        (
            'WINDOWS_HELPER_AUTHORITY_OPEN" -ne 1',
            "windows_helper_assert_vm_authority",
            "/usr/bin/env -i PATH=/usr/bin:/bin",
            '--remove-private-root "$WINDOWS_HELPER_RUNTIME_ROOT"',
            'WINDOWS_HELPER_RUNTIME_ROOT=""',
            "WINDOWS_HELPER_AUTHORITY_OPEN=0",
        ),
        "authority replay and identity-bound cleanup",
    )

    for token, label in (
        ("/var/run/docker.sock", "host Docker socket"),
        ("local_docker", "host-local Docker wrapper"),
        ("initialize_local_docker_authority", "host Docker authority initializer"),
        ("remove_local_docker_authority", "host Docker authority retirement"),
        ("--device /dev/kvm:/dev/kvm:rwm", "KVM mknod authority"),
        ("--privileged", "privileged container"),
        ("--cap-add", "added capability"),
        ("--network=host", "host network namespace"),
        ("--pid=host", "host PID namespace"),
        ("--ipc=host", "host IPC namespace"),
        ("--uts=host", "host UTS namespace"),
        ("--publish", "port publication"),
        ('rm -rf -- "$WINDOWS_HELPER_RUNTIME_ROOT"', "recursive pathname cleanup"),
    ):
        forbid(source, token, label)


def validate_callers(sources: dict[str, str]) -> None:
    for key, label in (
        ("build", "Windows build"),
        ("provision", "Windows provision"),
        ("golden", "Windows golden verification"),
    ):
        source = sources[key]
        require_order(
            source,
            (
                "set -euo pipefail",
                "export PATH=/usr/bin:/bin",
                'readonly WINDOWS_HELPER_BUILD_UID="$(/usr/bin/id -u)"',
                'readonly WINDOWS_HELPER_BUILD_GID="$(/usr/bin/id -g)"',
                '[ "$WINDOWS_HELPER_BUILD_UID" -ne 0 ]',
                '[ "$WINDOWS_HELPER_BUILD_GID" -ne 0 ]',
                'readonly SCRIPT_DIR="$(cd',
                '/usr/bin/bash "$SCRIPT_DIR/verify-vm-entry-preflight.sh" >/dev/null',
                'source "$SCRIPT_DIR/lib.sh"',
                "load_pins",
                'source "$SCRIPT_DIR/windows-helper-runtime.sh"',
            ),
            f"{label} pre-input VM admission",
        )
        require_count(
            source,
            '/usr/bin/bash "$SCRIPT_DIR/verify-vm-entry-preflight.sh" >/dev/null',
            1,
            f"{label} sole entry preflight",
        )
        for token, description in (
            ("/var/run/docker.sock", "host Docker socket"),
            ("initialize_local_docker_authority", "host Docker initializer"),
            ("local_docker", "host Docker wrapper"),
            ("docker run", "direct Docker launch"),
        ):
            forbid(source, token, f"{label} {description}")

    build = sources["build"]
    require(
        build,
        'require_pinned_builder_image deb-builder "$DEB_BUILDER_CONFIG_ID" \\'
        '\n        windows_helper_image_provenance',
        "VM-routed Debian builder provenance",
    )
    require_count(build, "windows_helper_small_run", 3, "three small operations")
    require_count(build, "windows_helper_media_run", 1, "one media operation")
    require_count(build, "windows_helper_guestfish_run", 3, "three guestfish operations")
    for key, label in (("provision", "provision"), ("golden", "golden")):
        require_count(
            sources[key],
            "windows_helper_kvm_guestfish_run",
            1,
            f"one {label} KVM inspection",
        )
        require(
            sources[key],
            'source=$GOLDEN,target=/authority/golden.qcow2,readonly',
            f"{label} exact read-only golden mount",
        )


def validate_behavioral_path(sources: dict[str, str]) -> None:
    test = sources["test"]
    for token, label in (
        ("Windows helper VM runtime test refuses root execution", "root refusal"),
        ('/usr/bin/bash "$SCRIPT_DIR/verify-vm-entry-preflight.sh" >/dev/null', "entry preflight"),
        ("windows_helper_authority_open", "real runtime open"),
        ("windows_helper_snapshot_program", "real program snapshots"),
        ("windows_helper_assert_runtime", "real runtime assertion"),
        ("expect_mount_refusal traversal", "traversal refusal"),
        ("expect_mount_refusal protected", "protected-target refusal"),
        ("expect_mount_refusal duplicate", "duplicate-target refusal"),
        ("expect_mount_refusal special", "special-file refusal"),
        ("expect_mount_refusal writable-mode", "writable-mode refusal"),
        ("expect_mount_refusal hard-link", "hard-link refusal"),
        ("expect_mount_refusal symlink", "symlink refusal"),
        ("windows_helper_small_run", "actual small-profile run"),
        ("/sys/fs/cgroup/pids.max", "container PID observation"),
        ("/sys/fs/cgroup/memory.max", "container memory observation"),
        ("/sys/fs/cgroup/cpu.max", "container CPU observation"),
        ("/proc/self/status", "container privilege observation"),
        ("/sys/class/net/lo", "container network observation"),
        ("windows_helper_authority_close", "real runtime close"),
        ("cleanup=joined", "joined-cleanup receipt"),
    ):
        require(test, token, label)

    outer = sources["outer"]
    guest = sources["guest"]
    for source, label in ((outer, "outer harness"), (guest, "guest harness")):
        require(source, "test-windows-helper-vm-runtime.sh", f"{label} test transport")
        require(
            source,
            "WINDOWS_HELPER_VM_RUNTIME=pass uid=4000 gid=4000 decisions=8 profile=small docker=real cleanup=joined",
            f"{label} runtime receipt",
        )
    for token, label in (
        (
            '/bin/bash "$WINDOWS_HELPER_RUNTIME_TEST" "$(<"$ROOT/image-id")"',
            "root refusal execution",
        ),
        ("setpriv --reuid=4001 --regid=4001 --clear-groups", "foreign-principal execution"),
        ("setpriv --reuid=4000 --regid=4000 --clear-groups", "authorized-principal execution"),
        ("authorized Windows helper runtime test failed", "authorized runtime verdict"),
    ):
        require(guest, token, label)


def validate(sources: dict[str, str]) -> None:
    validate_runtime(sources["runtime"])
    validate_callers(sources)
    validate_behavioral_path(sources)

    extractor = sources["extractor"]
    for token, label in (
        ("outer image archive contains duplicate member names", "unique archive members"),
        ('opaque_whiteout = "boot/.wh..wh..opq"', "opaque whiteout refusal"),
        ("if found != 1:", "single kernel member"),
        ("digest.hexdigest() != expected_sha256", "kernel digest verification"),
        ("os.O_EXCL", "kernel no-clobber creation"),
        ("os.fsync(parent_descriptor)", "kernel directory durability"),
    ):
        require(extractor, token, label)

    library = shell_function(sources["library"], "require_pinned_builder_image")
    for token, label in (
        ("ROLE IMAGE_REF PROVENANCE_EXECUTOR", "explicit provenance-executor API"),
        ('provenance_executor="$3"', "required provenance executor capture"),
        ('declare -F "$provenance_executor"', "executor function proof"),
        ('"$provenance_executor" "${args[@]}"', "executor dispatch"),
    ):
        require(library, token, label)

    require(
        sources["verify"],
        "python3 scripts/verify-windows-helper-authority.py --repo .",
        "shared compact source gate",
    )
    forbid(
        sources["verify"],
        "python3 scripts/verify-windows-helper-authority.py --repo . --self-test",
        "fake mutation self-test wiring",
    )


def load_sources(repo: Path) -> dict[str, str]:
    loaded: dict[str, str] = {}
    for name, relative in FILES.items():
        path = repo / relative
        if not path.is_file():
            raise VerificationError(f"missing source file: {relative}")
        loaded[name] = path.read_text(encoding="utf-8")
    return loaded


def exercise_provision_domain_xml(source: str) -> None:
    if (
        os.geteuid() == 0
        or os.getegid() == 0
        or Path("/proc/cmdline").read_text().split().count("rustdesk.verifier_vm=1") != 1
        or sorted(path.name for path in Path("/sys/class/net").iterdir()) != ["lo"]
    ):
        raise VerificationError("golden XML execution requires a nonroot zero-NIC verifier VM")
    launcher = shell_function(source, "build_golden")
    require_count(launcher, "--network none \\\n", 1, "zero-NIC golden launch")
    forbid(launcher, "--network user", "golden user-mode NIC")
    validator = shell_function(source, "verify_owned_golden_domain_xml")
    opening = "<<'PY'\n"
    require_count(validator, opening, 1, "production XML parser")
    require_count(validator, "\nPY\n", 1, "production XML parser terminator")
    program = validator.split(opening, 1)[1].split("\nPY\n", 1)[0] + "\n"
    cases = (
        ("zero-nic", (), "", ""),
        ("user-nic", ("user",), "", "a network interface"),
        ("bridge-nic", ("bridge",), "", "a network interface"),
        ("two-nics", ("user", "user"), "", "a network interface"),
        ("host-device", (), "hostdev", "a host device or filesystem passthrough"),
        ("filesystem", (), "filesystem", "a host device or filesystem passthrough"),
        ("raw-qemu", (), "{http://libvirt.org/schemas/domain/qemu/1.0}commandline",
         "raw QEMU command-line configuration"),
    )
    with tempfile.TemporaryDirectory(prefix="windows-golden-xml-") as directory:
        xml = Path(directory) / "domain.xml"
        disks = [str(Path(directory) / name) for name in
                 ("golden.qcow2", "provision.iso", "toolchains.iso", "windows.iso")]
        name = "golden-xml-test"
        uuid = "4a1b3a94-a050-47f0-bf06-7411fcb093e8"
        for label, interfaces, extra, rejection in cases:
            root = ET.Element("domain", type="kvm")
            ET.SubElement(root, "name").text = name
            ET.SubElement(root, "uuid").text = uuid
            devices = ET.SubElement(root, "devices")
            for index, path in enumerate(disks):
                disk = ET.SubElement(devices, "disk", type="file",
                                     device="disk" if index == 0 else "cdrom")
                ET.SubElement(disk, "source", file=path)
            graphic = ET.SubElement(devices, "graphics", type="vnc", listen="127.0.0.1")
            ET.SubElement(graphic, "listen", type="address", address="127.0.0.1")
            for interface_type in interfaces:
                interface = ET.SubElement(devices, "interface", type=interface_type)
                ET.SubElement(interface, "model", type="e1000e")
                if interface_type == "bridge":
                    ET.SubElement(interface, "source", bridge="br0")
            if extra:
                ET.SubElement(root if label == "raw-qemu" else devices, extra)
            xml.write_bytes(ET.tostring(root))
            xml.chmod(0o600)
            result = subprocess.run(
                ["/usr/bin/python3", "-I", "-S", "-", str(xml), name, uuid, *disks],
                input=program.encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"}, timeout=5, check=False,
            )
            expected_error = (
                f"golden domain unexpectedly has {rejection}\n".encode()
                if rejection else b""
            )
            if (
                result.returncode != (1 if rejection else 0)
                or result.stdout != b""
                or result.stderr != expected_error
            ):
                raise VerificationError(
                    f"golden XML case {label} failed: exit={result.returncode}, "
                    f"stderr={result.stderr[:4096]!r}"
                )
    print(
        f"WINDOWS_PROVISION_XML=pass uid={os.geteuid()} cases={len(cases)} "
        f"parser_sha256={hashlib.sha256(program.encode()).hexdigest()} "
        "scope=production-parser windows=unexecuted", file=sys.stderr,
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path("."))
    args = parser.parse_args()
    sources = load_sources(args.repo.resolve())
    validate(sources)
    exercise_provision_domain_xml(sources["provision"])
    print("verify-windows-helper-authority: ok")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, VerificationError, subprocess.SubprocessError) as error:
        raise SystemExit(f"verify-windows-helper-authority: FAIL: {error}")
