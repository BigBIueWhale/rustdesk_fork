#!/usr/bin/env python3
"""Check the source contract for the isolated Linux full-peer presentation harness.

This fast check deliberately does not claim to execute or reproduce the full-peer
transaction. Runtime evidence comes only from smoke-flutter-peer-presentation.sh.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path


class VerificationError(RuntimeError):
    pass


def require(source: str, needle: str, label: str) -> None:
    if needle not in source:
        raise VerificationError(f"missing {label}: {needle!r}")


def forbid(source: str, needle: str, label: str) -> None:
    if needle in source:
        raise VerificationError(f"forbidden {label}: {needle!r}")


def require_order(source: str, needles: tuple[str, ...], label: str) -> None:
    position = -1
    for needle in needles:
        position = source.find(needle, position + 1)
        if position < 0:
            raise VerificationError(f"{label}: missing or misordered {needle!r}")


PATHS = {
    "host": "scripts/smoke-flutter-peer-presentation.sh",
    "stage": "scripts/smoke-flutter-peer-presentation-stage.sh",
    "atspi_prepare": "scripts/smoke-atspi-prepare.sh",
    "atspi_packages": "scripts/smoke-atspi-packages.tsv",
    "atspi_files": "scripts/smoke-atspi-files.tsv",
    "flutter_tools_finalizer": "scripts/finalize-flutter-tools-offline.sh",
    "pins": "scripts/pins.env",
    "ready": "scripts/smoke-ready.sh",
    "linux_runner": "flutter/linux/main.cc",
    "controller": "scripts/flutter-peer-presentation-x11.c",
    "source": "scripts/flutter-peer-source-x11.c",
    "bind_shim": "scripts/smoke-bind-loopback.c",
    "entry_preflight": "scripts/verify-vm-entry-preflight.sh",
    "vm_outer": "scripts/smoke-verifier-vm-authority.sh",
    "vm_guest": "scripts/smoke-verifier-vm-authority-guest.sh",
    "verify": "scripts/verify.sh",
    "readme": "scripts/README.md",
    "requirements": "requirements.html",
}


def load(repo: Path) -> dict[str, str]:
    return {
        key: (repo / relative).read_text(encoding="utf-8")
        for key, relative in PATHS.items()
    }


def validate(sources: dict[str, str]) -> None:
    host = sources["host"]
    stage = sources["stage"]
    atspi_prepare = sources["atspi_prepare"]
    atspi_packages = sources["atspi_packages"]
    atspi_files = sources["atspi_files"]
    flutter_tools_finalizer = sources["flutter_tools_finalizer"]
    pins = sources["pins"]
    ready = sources["ready"]
    linux_runner = sources["linux_runner"]
    controller = sources["controller"]
    source = sources["source"]
    bind_shim = sources["bind_shim"]
    vm_outer = sources["vm_outer"]
    vm_guest = sources["vm_guest"]

    require_order(
        host,
        (
            "export PATH=/usr/bin:/bin",
            'readonly HOST_UID="$(/usr/bin/id -u)"',
            "for name in DOCKER_HOST DOCKER_CONFIG DOCKER_CONTEXT DOCKER_CERT_PATH",
            "readonly VERIFIER_VM_ENTRY_PREFLIGHT=$SCRIPT_DIR/verify-vm-entry-preflight.sh",
            '/usr/bin/bash "$VERIFIER_VM_ENTRY_PREFLIGHT"',
            'source "$SCRIPT_DIR/lib.sh"',
            "load_pins",
            "readonly VERIFIER_VM_AUTHORITY_ROOT=/run/rustdesk-verifier-vm",
            "peer_vm_docker() {",
            "PEER_VM_AUTHORITY_SELF_TEST=0",
            'peer_vm_docker version',
            "FLUTTER_PEER_VM_AUTHORITY=pass",
            "assert_clean_worktree",
        ),
        "VM-only authority before full-peer input admission",
    )
    for authority_contract in (
        "readonly VERIFIER_VM_DOCKER_CLIENT=/usr/bin/docker",
        "readonly VERIFIER_VM_DOCKER_SOCKET=$VERIFIER_VM_AUTHORITY_ROOT/docker.sock",
        "readonly VERIFIER_VM_DOCKER_CONFIG=$VERIFIER_VM_AUTHORITY_ROOT/docker-config",
        "/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C HOME=/nonexistent",
        'DOCKER_HOST="unix://$VERIFIER_VM_DOCKER_SOCKET"',
        'DOCKER_CONFIG="$VERIFIER_VM_DOCKER_CONFIG"',
        '--host "unix://$VERIFIER_VM_DOCKER_SOCKET"',
        '--config "$VERIFIER_VM_DOCKER_CONFIG"',
        '--self-test-vm-authority',
        "prepost=replayed workload=unexecuted",
        "8:--source-archive)",
        "source-archive authority argument order differs",
        "supplied source archive metadata differs",
        "supplied source archive digest differs",
    ):
        require(host, authority_contract, "guest-only Docker authority")
    for forbidden_authority in (
        "local_docker",
        "initialize_local_docker_authority",
        "remove_local_docker_authority",
        "/var/run/docker.sock",
    ):
        forbid(host, forbidden_authority, "host-Docker authority")

    require_order(
        host,
        (
            "assert_clean_worktree",
            'SOURCE_COMMIT="$(git rev-parse HEAD)"',
            "git archive --format=tar",
            'run_input_check "$WORKSPACE/input-pre.cid"',
            "smoke-xvfb-prepare.sh",
            "smoke-atspi-prepare.sh",
            "smoke-flutter-peer-presentation-stage.sh atspi-check",
            "smoke-flutter-peer-presentation-stage.sh pub-cache",
            "smoke-flutter-peer-presentation-stage.sh build",
            "smoke-flutter-peer-presentation-stage.sh pub-cache-check",
            'peer_vm_docker run --detach --cidfile "$SERVER_CID_FILE"',
            "--pull=never --network=none --read-only",
            'inspect_container_contract "$SERVER_CID" none server',
            '--network="container:$SERVER_CID" --read-only',
            'inspect_container_contract "$VIEWER_CID" "container:$SERVER_CID" viewer',
            'run_input_check "$WORKSPACE/input-post.cid"',
            "FLUTTER_PEER_PRESENTATION_SMOKE_OK",
        ),
        "exact-source build and separate-peer transaction",
    )
    require_order(
        host,
        (
            "SOURCE_AUTHORITY=git",
            "8:--source-archive)",
            "SUPPLIED_SOURCE_ARCHIVE=$2",
            'if [ "$SOURCE_AUTHORITY" = git ]; then',
            "supplied source archive metadata differs",
            "supplied source archive digest differs",
            'SOURCE_ARCHIVE=$SUPPLIED_SOURCE_ARCHIVE',
            'tar -xf "$SOURCE_ARCHIVE" -C "$SOURCE_SNAPSHOT"',
            "supplied source archive changed during the probe",
        ),
        "exact archive-source authority and finality",
    )
    if host.count("--network=bridge") != 0:
        raise VerificationError("the Xvfb preparation path retains a bridge network")
    if host.count("--network=none") != 8:
        raise VerificationError("the input checks/build/runtime network-none count changed")
    require(
        host,
        "source=$XVFB_INPUTS,target=/xvfb-inputs,readonly,bind-recursive=disabled",
        "read-only offline Xvfb package input",
    )
    if host.count('run_input_check "$WORKSPACE/input-') != 2:
        raise VerificationError("persistent inputs need pre- and post-transaction checks")
    require(host, "dbus-run-session --", "private accessibility sessions")
    if host.count("dbus-run-session --") != 2:
        raise VerificationError("the preflight and viewer each need one private accessibility session")
    require_order(
        host,
        (
            'run_owned_container "$WORKSPACE/atspi-prepare.cid"',
            "smoke-atspi-prepare.sh",
            'run_owned_container "$WORKSPACE/atspi-check.cid"',
            "--env DISPLAY=:97",
            "--env HOME=/tmp/atspi-home",
            "--env XDG_RUNTIME_DIR=/tmp/atspi-runtime",
            "--env XDG_DATA_DIRS=/atspi-root/usr/share:/usr/local/share:/usr/share",
            "dbus-run-session --",
            "smoke-flutter-peer-presentation-stage.sh atspi-check",
            'atspi_check_status=$?',
            'cat "$WORKSPACE/atspi-check.log"',
            "private AT-SPI activation preflight exited",
            "FLUTTER_PEER_ATSPI_RUNTIME_OK",
            "smoke-flutter-peer-presentation-stage.sh pub-cache",
            "smoke-flutter-peer-presentation-stage.sh build",
        ),
        "fast private AT-SPI activation before the expensive build",
    )
    require(host, 'readonly VIEWER_PASSWD="$WORKSPACE/viewer.passwd"', "private passwd witness")
    require(
        host,
        'readonly VIEWER_PASSWD_ENTRY="rustdesk-evidence:x:$HOST_UID:$HOST_GID:RustDesk peer evidence:/tmp/viewer-home:/usr/sbin/nologin"',
        "exact numeric-nonroot passwd identity",
    )
    require(host, 'chmod 0400 "$VIEWER_PASSWD.tmp"', "private passwd witness mode")
    require(
        host,
        'source=$VIEWER_PASSWD,target=/etc/passwd,readonly,bind-recursive=disabled',
        "read-only viewer passwd mount",
    )
    if host.count("target=/etc/passwd") != 2:
        raise VerificationError("only the AT-SPI preflight and viewer may receive the passwd witness")
    require_order(
        host,
        (
            'readonly VIEWER_CID_FILE="$WORKSPACE/viewer.cid"',
            'peer_vm_docker run --cidfile "$VIEWER_CID_FILE"',
            'source=$VIEWER_PASSWD,target=/etc/passwd,readonly,bind-recursive=disabled',
            "dbus-run-session --",
        ),
        "viewer passwd identity mount",
    )
    require(host, "/etc/passwd)", "inspected passwd mount destination")
    require(host, '[ "$writable" = false ]', "inspected read-only passwd mount")
    require(host, "private viewer passwd witness changed during runtime", "passwd witness finality")
    for endpoint in ("SERVER", "VIEWER"):
        require(
            host,
            f'readonly {endpoint}_MACHINE_ID="$WORKSPACE/{endpoint.lower()}.machine-id"',
            f"private {endpoint.lower()} machine identity",
        )
        require(
            host,
            f'source=${endpoint}_MACHINE_ID,target=/etc/machine-id,readonly,bind-recursive=disabled',
            f"read-only {endpoint.lower()} machine-id mount",
        )
    require(
        host,
        '[ "$SERVER_MACHINE_ID_VALUE" != "$VIEWER_MACHINE_ID_VALUE" ]',
        "distinct endpoint machine identities",
    )
    if host.count("target=/etc/machine-id") != 3:
        raise VerificationError("the preflight and each runtime endpoint need a private machine identity")
    require(host, "/etc/machine-id)", "inspected machine-id mount destination")
    require(host, "machine_id_mounts=0", "machine-id mount cardinality")
    require(host, '&& [ "$machine_id_mounts" -eq 1 ]', "one machine-id per endpoint")
    require(host, "private endpoint machine identity changed during runtime", "machine-id finality")
    require(host, 'readonly EVIDENCE_PUB_CACHE="$ONLINE_DIR/pub-cache"', "canonical Pub-cache input")
    require(
        host,
        'readonly EVIDENCE_PUB_CACHE_SHA256="$SHA256_PUB_CACHE_CLOSURE_V1"',
        "canonical Pub-cache digest",
    )
    require(host, '"$HOST_UID:$HOST_GID:500"', "sealed canonical Pub-cache metadata")
    require(
        host,
        'source=$EVIDENCE_PUB_CACHE,target=/evidence-pub-cache,readonly',
        "read-only canonical Pub-cache mount",
    )
    require_order(
        host,
        (
            "local cid=$1 expected_network=$2 label=$3",
            "local expected_passwd_source= expected_machine_id_source= expected_atspi_mounts=0 mounts_path",
            "local record_kind source destination writable extra",
            "local network ipc pid uts privileged read_only user ports devices caps security",
            "local source_mounts=0 output_mounts=0 xvfb_root_mounts=0 xkbcomp_mounts=0 coord_mounts=0",
            "local passwd_mounts=0 machine_id_mounts=0",
            "local atspi_root_mounts=0 atspi_launcher_mounts=0 atspi_registry_mounts=0",
            "local receipt_ends=0",
            "network=\"$(peer_vm_docker container inspect --format '{{.HostConfig.NetworkMode}}' \"$cid\")\"",
            'mounts_path="$WORKSPACE/$label.mounts.tsv"',
        ),
        "nounset-safe inspected-container receipt path",
    )
    require(host, '[ "$network" = "$expected_network" ]', "inspected network mode")
    require(host, '{ [ -z "$ipc" ] || [ "$ipc" = private ]; }', "private IPC namespace")
    require(host, '[ -z "$pid" ] && [ -z "$uts" ]', "private PID and UTS namespaces")
    require(host, "[ \"$ports\" = null ] || [ \"$ports\" = '{}' ]", "no port publication")
    require(host, "[ \"$caps\" = '[\"ALL\"]' ]", "all capabilities dropped")
    require(host, '[ "$user" = "$HOST_UID:$HOST_GID" ]', "numeric nonroot user")
    require(host, '[ "$privileged" = false ] && [ "$read_only" = true ]', "read-only unprivileged rootfs")
    require(host, "'[\"no-new-privileges\"]'|'[\"no-new-privileges:true\"]'", "no-new-privileges")
    require(host, '{{end}}{{printf "end"}}', "unambiguous inspected-mount terminator")
    require(
        host,
        '[ "$record_kind" = bind ] && [ "$receipt_ends" -eq 0 ]',
        "bind-only pre-terminator receipt",
    )
    require(host, "[[ \"$source\" != */docker.sock ]] && [[ \"$source\" != /dev/* ]]", "unsafe mount rejection")
    for expected_mount in (
        '[ "$source" = "$SOURCE_SNAPSHOT" ] && [ "$writable" = false ]',
        '[ "$source" = "$BUILD_OUTPUT" ] && [ "$writable" = false ]',
        '[ "$source" = "$XVFB_ROOT" ] && [ "$writable" = false ]',
        '[ "$source" = "$XVFB_ROOT/usr/bin/xkbcomp" ] && [ "$writable" = false ]',
        '[ "$source" = "$COORD" ] && [ "$writable" = true ]',
        '[ "$source" = "$ATSPI_ROOT" ] && [ "$writable" = false ]',
        '[ "$source" = "$ATSPI_ROOT/usr/libexec/at-spi-bus-launcher" ]',
        '[ "$source" = "$ATSPI_ROOT/usr/libexec/at-spi2-registryd" ]',
        '[ "$source" = "$ATSPI_ROOT/usr/share/defaults/at-spi2" ]',
        '[ "$source" = "$ATSPI_ROOT/usr/share/dbus-1/accessibility-services" ]',
    ):
        require(host, expected_mount, "exact inspected runtime mount")
    require(
        host,
        '*) die "$label receives an unexpected mount destination: $destination" ;;',
        "unexpected mount rejection",
    )
    require(
        host,
        '[ "$receipt_ends" -eq 1 ] && [ "$source_mounts" -eq 1 ]',
        "exact runtime mount cardinality",
    )
    require(host, "expected_atspi_mounts=1", "viewer-only AT-SPI runtime projection")
    require(
        host,
        '[ "$atspi_root_mounts" -eq "$expected_atspi_mounts" ]',
        "zero-server/one-viewer AT-SPI mount cardinality",
    )
    require(host, 'require_exact_local_image deb-builder "$DEB_BUILDER_CONFIG_ID"', "exact runtime builder image")
    require(host, 'require_exact_local_image devcheck "$DEV_CHECK_IMAGE_CONFIG_ID"', "exact verifier runtime image")
    forbid(host, 'require_exact_local_image devcheck "$DEV_CHECK_IMAGE_ID"', "publication index used as a runtime image")
    if host.count('source=$ONLINE_DIR,target=/online,readonly') != 1:
        raise VerificationError("only the persistent-input verifier may mount the complete online root")
    require(
        host,
        'source=$BUILD_INPUT_ROOT,target=/online,readonly,bind-recursive=disabled',
        "empty build-input namespace root",
    )
    require_order(
        host,
        (
            'mkdir -p "$BUILD_INPUT_ROOT/cargo-vendor" "$BUILD_INPUT_ROOT/frb-tool/bin"',
            '"$BUILD_INPUT_ROOT/vcpkg/installed/x64-linux"',
            'touch "$BUILD_INPUT_ROOT/rust-${RUST_VERSION}.tar.xz"',
            '"$BUILD_INPUT_ROOT/frb-tool/bin/flutter_rust_bridge_codegen"',
            'chmod -R a-w "$BUILD_INPUT_ROOT"',
            'source=$BUILD_INPUT_ROOT,target=/online,readonly,bind-recursive=disabled',
        ),
        "sealed exact nested-mount namespace skeleton",
    )
    for relative in (
        "rust-${RUST_VERSION}.tar.xz",
        "flutter-${FLUTTER_VERSION}.tar.xz",
        "llvm-${LLVM_VERSION}.tar.xz",
        "cargo-vendor",
        "cargo-vendor-config.toml",
        "frb-tool/bin/flutter_rust_bridge_codegen",
        "vcpkg/installed/x64-linux",
    ):
        require(
            host,
            f"source=$ONLINE_DIR/{relative},target=/online/{relative},readonly,bind-recursive=disabled",
            f"exact build-input mount {relative}",
        )
    forbid(host, "require_online_complete", "unrelated full-online closure gate")
    forbid(host, "local_docker_image_provenance", "host Python image verifier")
    forbid(host, "/usr/bin/python3", "host Python execution")
    require(host, "assert_clean_worktree", "clean postcondition")
    require(host, "source archive changed during the probe", "exact source postcondition")
    for unsafe in (
        "sudo ", "--privileged", "--publish", "--network=host", "/var/run/docker.sock",
        "systemctl", "ufw ", "iptables", "nft ", "/dev/kvm",
    ):
        forbid(host, unsafe, "host authority expansion")

    package_rows = tuple(
        line for line in atspi_packages.splitlines() if line and not line.startswith("#")
    )
    if package_rows != (
        "at-spi2-core\t57324\t42c3567bef2bd3e868a072acbdef1c3b0416b2a127a2e0fa2cbc600cedcd2a9a\thttps://deb.debian.org/debian/pool/main/a/at-spi2-core/at-spi2-core_2.46.0-5_amd64.deb",
        "gsettings-desktop-schemas\t642864\t15cc7142c3ddea0551b834c53c4d3b5cd8f5485e695100966877f2be50def7af\thttps://deb.debian.org/debian/pool/main/g/gsettings-desktop-schemas/gsettings-desktop-schemas_43.0-1_all.deb",
    ):
        raise VerificationError("the exact AT-SPI package manifest changed")
    file_rows = tuple(
        line for line in atspi_files.splitlines() if line and not line.startswith("#")
    )
    if file_rows != (
        "usr/libexec/at-spi-bus-launcher\t31032\t755\t500\t10d7d226ec4fa8c21f325f362af0dae7ac2c7134c3b18bd33d542cb06b417316",
        "usr/libexec/at-spi2-registryd\t120824\t755\t500\t6998a81f0f04d8348f7e9879dbe5e02101c0f7e69744025d9aae735cc3304045",
        "usr/share/dbus-1/services/org.a11y.Bus.service\t111\t644\t400\t73272e74cbaa6d7cff1e3ffef190c5cdc2e2060012b2ca373749fd78ad3bbf8c",
        "usr/share/dbus-1/accessibility-services/org.a11y.atspi.Registry.service\t101\t644\t400\t1e3d75d456ba810e793879ea9d200dac54ff78d8b584a9506943deb95cfe1b36",
        "usr/share/defaults/at-spi2/accessibility.conf\t1363\t644\t400\t898a83a8ccf0eec4c96470f23c8755b9e3a8600a0eb9b0ab7855f8fe44e05b01",
    ):
        raise VerificationError("the exact minimal AT-SPI file manifest changed")
    require_order(
        atspi_prepare,
        (
            '[ "$(id -u)" -ne 0 ]',
            'findmnt -n -o OPTIONS --target "$INPUT_ROOT"',
            "offline input mount is writable",
            "declare -A expected_version=(",
            "[at-spi2-core]=2.46.0-5",
            "[gsettings-desktop-schemas]=43.0-1",
            'dpkg-deb --extract "$output" "$STAGING"',
            "extracted package closure contains a setuid or setgid file",
            "extracted package closure contains a special file",
            'glib-compile-schemas --strict --targetdir="$SCHEMA_A"',
            'glib-compile-schemas --strict --targetdir="$SCHEMA_B"',
            'cmp -s "$SCHEMA_A/gschemas.compiled" "$SCHEMA_B/gschemas.compiled"',
            "contract=rustdesk-flutter-peer-atspi-v1",
            'find "$TOOL_ROOT" -xdev -type d -exec chmod 0500 {} +',
            "offline preparation container opened a TCP listener",
            "offline preparation container retained a UDP socket",
            "ATSPI_TOOL_CLOSURE_OK",
        ),
        "minimal offline AT-SPI closure construction",
    )
    for forbidden_installer in ("apt-get", "apt ", "dpkg -i", "curl ", "wget "):
        forbid(atspi_prepare, forbidden_installer, "AT-SPI package installation or network acquisition")

    require_order(
        vm_outer,
        (
            'readonly FLUTTER_PEER_SOURCE="$SCRIPT_DIR/smoke-flutter-peer-presentation.sh"',
            'readonly FLUTTER_TOOLS_FINALIZER_SOURCE="$SCRIPT_DIR/finalize-flutter-tools-offline.sh"',
            'for source in "$OUTER_SOURCE" "$GUEST_SCRIPT"',
            '"$APPLE_CHECK_SOURCE" "$FLUTTER_PEER_SOURCE" "$FLUTTER_TOOLS_FINALIZER_SOURCE"',
            '"repo/scripts/smoke-flutter-peer-presentation.sh=$FLUTTER_PEER_SOURCE"',
            '"repo/scripts/finalize-flutter-tools-offline.sh=$FLUTTER_TOOLS_FINALIZER_SOURCE"',
            "VERIFIER_VM_FLUTTER_PEER_ENTRY=pass",
            '"$APPLE_CHECK_SOURCE" "$FLUTTER_PEER_SOURCE" "$FLUTTER_TOOLS_FINALIZER_SOURCE"',
        ),
        "outer no-NIC VM payload, receipt, and final source replay",
    )
    require_order(
        vm_outer,
        (
            "1:--flutter-peer-presentation)",
            "MODE=flutter-peer-presentation",
            "FLUTTER_PEER_SOURCE_COMMIT=",
            "focused Flutter peer requires the one checked-out master authority",
            "focused Flutter-peer source differs from pushed master",
            "git_closed -C \"$REPO_ROOT\" archive --format=tar \"$FLUTTER_PEER_SOURCE_COMMIT\"",
            "payload_identity=(-uid 1000 -gid 1000)",
            'guest_invocation+=" --flutter-peer-presentation',
            "FLUTTER_PEER_PRESENTATION_SMOKE_OK commit=",
            "FLUTTER_PEER_PRESENTATION_VM=pass commit=",
            "FLUTTER_PEER_PRESENTATION_VM_OUTER=pass",
        ),
        "focused no-NIC full-peer outer transaction",
    )
    require_order(
        vm_guest,
        (
            "smoke-flutter-peer-presentation.sh finalize-flutter-tools-offline.sh",
            'readonly FLUTTER_PEER_SCRIPT="$VERIFY_REPO/scripts/smoke-flutter-peer-presentation.sh"',
            "if /bin/bash \"$FLUTTER_PEER_SCRIPT\" --self-test-vm-authority",
            "setpriv --reuid=4001 --regid=4001 --clear-groups",
            "/usr/bin/env DOCKER_HOST=unix:///tmp/forbidden-docker.sock",
            "setpriv --reuid=4000 --regid=4000 --clear-groups",
            "FLUTTER_PEER_VM_AUTHORITY=pass uid=4000 gid=4000",
            "VERIFIER_VM_FLUTTER_PEER_ENTRY=pass uid=4000 gid=4000 root=refused foreign=refused caller=refused",
        ),
        "real guest authority decision matrix",
    )
    require_order(
        vm_guest,
        (
            "12:--flutter-peer-presentation)",
            "run_flutter_peer_presentation() {",
            "mount -t virtiofs -o ro,nodev,nosuid,noexec rustdesk-sealed-inputs",
            'mount -o remount,bind,ro,nodev,nosuid,noexec "$source_root"',
            'mount -o remount,bind,ro,nodev,nosuid,noexec "$source_root/online/inputs"',
            'cmp -s "$peer_script" "$FLUTTER_PEER_SCRIPT"',
            "--role devcheck",
            'loaded and verified devcheck $DEV_CHECK_IMAGE_ID',
            "--role deb-builder",
            'loaded and verified deb-builder $DEB_BUILDER_IMAGE_ID',
            '/bin/bash "$FLUTTER_PEER_SCRIPT" --self-test-vm-authority',
            "VM root passed the Flutter full-peer workload entry",
            "foreign principal passed the Flutter full-peer workload entry",
            "caller Docker authority passed the Flutter full-peer workload entry",
            'setpriv --reuid=1000 --regid=1000 --clear-groups',
            '"$DEV_CHECK_IMAGE_CONFIG_ID" "$DEB_BUILDER_CONFIG_ID"',
            "stop_docker_authority",
            "FLUTTER_PEER_PRESENTATION_VM=pass commit=",
            "run_flutter_peer_presentation",
        ),
        "real guest full-peer workload, refusal, image, and cleanup transaction",
    )
    require(
        sources["requirements"],
        'The transaction itself <span class="kw">MUST</span> be admitted only inside the authenticated no-NIC verifier VM',
        "normative VM-only full-peer authority",
    )

    require_order(
        stage,
        (
            "input-check)",
            'verify_archive "/online/rust-',
            'verify_archive "/online/flutter-',
            'verify_archive "/online/llvm-',
            "/source/scripts/online-input-provenance.py verify-subtree",
            '--tree /online/cargo-vendor --expected "$RUSTDESK_CARGO_VENDOR_SHA256"',
            "/source/scripts/online-cargo-tool-output.py check-complete",
            '"$(sha256sum /online/frb-tool/bin/flutter_rust_bridge_codegen | awk \'{print $1}\')" = \\\n      "$RUSTDESK_FRB_SHA256"',
            '--tree /online/vcpkg/installed/x64-linux',
            "verify_atspi_package_inputs",
            "FLUTTER_PEER_INPUTS_OK",
        ),
        "exact consumed-input validation",
    )
    require_order(
        stage,
        (
            "verify_atspi_package_inputs() {",
            "/source/scripts/smoke-atspi-packages.tsv",
            'package="/online/atspi-debs/$name.deb"',
            "AT-SPI package cardinality is not two",
            "verify_atspi_closure() {",
            "contract=rustdesk-flutter-peer-atspi-v1",
            "/atspi-root/usr/share/glib-2.0/schemas/gschemas.compiled",
            "sealed minimal AT-SPI runtime inventory differs",
            "atspi-check)",
            "verify_atspi_closure",
            "assert_loopback_only_interface",
            "start_xvfb :97 640x480x24",
            "org.a11y.Bus.GetAddress",
            "unix:path=/tmp/atspi-runtime/at-spi/bus_97",
            "org.a11y.atspi.Registry",
            "exact_executable_process_count /usr/libexec/at-spi-bus-launcher",
            "exact_executable_process_count /usr/libexec/at-spi2-registryd",
            "FLUTTER_PEER_ATSPI_RUNTIME_OK",
        ),
        "real private AT-SPI activation preflight",
    )
    if stage.count("    verify_atspi_closure") != 2:
        raise VerificationError("the AT-SPI preflight and viewer must both verify the closure")
    for pin_name in (
        "SHA256_PUB_CACHE_CLOSURE_V1",
        "SHA256_FLUTTER_PEER_VCPKG_X64_LINUX_CLOSURE_V1",
        "SHA256_FLUTTER_PEER_FRB_CODEGEN",
    ):
        if re.search(rf'(?m)^{pin_name}="[0-9a-f]{{64}}"(?:\s|$)', pins) is None:
            raise VerificationError(f"malformed exact input pin {pin_name}")
    if re.search(
        r'(?m)^SIZE_FLUTTER_PEER_FRB_CODEGEN="[1-9][0-9]*"(?:\s|$)', pins
    ) is None:
        raise VerificationError("malformed exact FRB executable size pin")
    require(pins, "This does not repin SHA256_ONLINE_CLOSURE_V1.", "full-online non-inference")
    require_order(
        stage,
        (
            "FLUTTER_PEER_CANONICAL_PUB_CACHE_OK",
            "cp -a /evidence-pub-cache /evidence-online/pub-cache",
            "check-complete --online /evidence-online",
            "FLUTTER_PEER_PUB_CACHE_PREPARED",
        ),
        "canonical Pub-cache copy and verification",
    )
    require(stage, "published=True", "published canonical Pub-cache inspection")
    require(stage, "source=canonical-pinned-online-copy semantics=current-three-git-lock", "Pub-cache provenance")
    require_order(
        stage,
        (
            'verify_archive "/online/rust-',
            'verify_archive "/online/flutter-',
            'verify_archive "/online/llvm-',
            "FRB codegen digest differs before executable projection",
            'install -m 0500 /online/frb-tool/bin/flutter_rust_bridge_codegen "$FRB_CODEGEN"',
            "private FRB executable projection digest differs",
            "dart pub get --offline --enforce-lockfile",
            '"$BUILD_SOURCE/scripts/finalize-flutter-tools-offline.sh"',
            '"$REAL_FLUTTER" pub get --offline --enforce-lockfile',
            '"$FRB_CODEGEN" --rust-input ./src/flutter_ffi.rs',
            "! grep -Fq '[SEVERE]'",
            "cargo build --locked --features flutter,unix-file-copy-paste",
            "--lib --example smoke_readiness --release",
            '"$REAL_FLUTTER" build linux --release --no-pub',
            "readelf --wide --dyn-syms",
            '"$BUILD_SOURCE/scripts/smoke-bind-loopback.c"',
            "-Wl,-z,relro,-z,now,-z,noexecstack",
            "FLUTTER_PEER_BUILD_OK",
        ),
        "exact offline full-product bundle build",
    )
    forbid(
        stage,
        "/online/frb-tool/bin:$PATH",
        "execution search path through the noexec persistent-input mount",
    )
    for token, label in (
        ("export PATH=/usr/bin:/bin", "fixed command authority"),
        ("LOCK_SHA256", "explicit lock-digest input"),
        ("Flutter-tools lockfile differs from its expected digest", "lock equality"),
        ('[ "$PUBSPEC" -ot "$LOCK" ]', "lock freshness"),
        ('[ "$PUBSPEC" -ot "$PACKAGE_CONFIG" ]', "package-config freshness"),
        ('/usr/bin/python3 -I -S - "$PACKAGE_CONFIG"', "package-root parser authority"),
        ("offline Pub package roots do not satisfy Flutter's freshness predicate", "package-root freshness refusal"),
        ("existing Flutter-tools freshness marker is not exact", "existing-marker refusal"),
        ("published Flutter-tools freshness marker is not exact", "published-marker finality"),
        ("FLUTTER_TOOLS_OFFLINE_FRESHNESS=pass", "exact freshness receipt"),
    ):
        require(flutter_tools_finalizer, token, label)
    require(stage, "cp -a /source/. \"$BUILD_SOURCE/\"", "private writable build copy")
    require(stage, "readonly PROBE=/out/smoke-readiness", "runtime readiness probe")
    require(stage, "export HOME CARGO_HOME CI=true PUB_CACHE=/evidence-online/pub-cache", "sealed Pub cache")
    require(stage, '[ -z "${LD_PRELOAD:-}" ]', "ambient preload refusal")
    require(stage, "assert_loopback_only_interface", "loopback-only inspection")
    require(stage, '[ "$interfaces" = lo ]', "sole loopback interface")
    require(stage, "0100007F:527E", "exact 127.0.0.1:21118 listener")
    require(stage, "verify_regular /out/smoke-bind-loopback.so", "manifested bind shim")
    require(stage, "verify_machine_identity", "private endpoint machine identity validation")
    if stage.count("    verify_machine_identity") != 2:
        raise VerificationError("both runtime endpoints must validate their machine identity")
    require(stage, '[ "$(udp_socket_count)" -eq 0 ]', "zero UDP runtime surface")
    require(stage, "pkg-config --cflags --libs x11 xtst atspi-2 gobject-2.0", "controller link")
    require(stage, '[ -n "${DBUS_SESSION_BUS_ADDRESS:-}" ]', "private accessibility session")
    require(stage, "FLUTTER_PEER_PASSWORD_PROMPT_OK accessible=true retired=true typed_via_xtest=true", "password prompt verdict")
    require_order(
        stage,
        (
            "export DISPLAY=:98 HOME=/tmp/server-home",
            "start_xvfb :98 640x480x24",
            '"$SOURCE_FIXTURE" >/tmp/source.log',
            'LD_PRELOAD="$BIND_SHIM" RUST_LOG=info exec "$APP" --server',
            'wait_process_maps_exact_file "$SERVER_PID" "$SERVER_START" "$BIND_SHIM"',
            '"$READY" --wait-typed-parked "$SERVER_PID" "$SERVER_START"',
            "--password-stdin",
            '"$READY" --wait-typed-user-server "$SERVER_PID" "$SERVER_START"',
            "listener_is_exact",
            'mv "$COORD/server.ready.tmp" "$COORD/server.ready"',
            'mv "$COORD/server.result.tmp" "$COORD/server.result"',
        ),
        "controlled-peer credential, listener, and finality",
    )
    require_order(
        stage,
        (
            '[ "${DISPLAY:-}" = :99 ]',
            '[ "${HOME:-}" = /tmp/viewer-home ]',
            '[ "${XDG_RUNTIME_DIR:-}" = /tmp/viewer-runtime ]',
            "/atspi-root/usr/share:/usr/local/share:/usr/share",
            "start_xvfb :99 1280x800x24",
            '(cd /out/bundle && RUST_LOG=info exec "$APP" --connect 127.0.0.1)',
            '"$CONTROLLER" :98 :99 "$VIEWER_PID"',
            "stable_connection=true",
            "viewer did not retire after its real remote window closed",
            'mv "$COORD/stop.tmp" "$COORD/stop"',
            "FLUTTER_PEER_VIEWER_RUNTIME_OK",
        ),
        "viewer prompt/pixel/lifecycle transaction",
    )
    require_order(
        stage,
        (
            "emit_runtime_logs() {",
            "runtime-log diagnostic selected a non-regular file",
            "runtime-log diagnostic file metadata differs",
            "runtime-log diagnostic exceeds its exact bounds",
            'cat -- "$path" >&2',
        ),
        "bounded owned runtime diagnostics",
    )
    forbid(stage, '"$APP" --connect 127.0.0.1 --password', "connect password argv")
    forbid(stage, "RUSTDESK_PASSWORD", "password environment variable")
    forbid(stage, "export LD_PRELOAD", "process-wide preload export")
    if stage.count('LD_PRELOAD="$BIND_SHIM"') != 1:
        raise VerificationError("the bind shim must be scoped to the controlled server launch")
    for unsafe in ("sudo ", "--privileged", "systemctl", "ufw ", "iptables", "nft "):
        forbid(stage, unsafe, "runtime authority expansion")

    for function, expected_state in (
        ("server_typed_parked() {", "parked"),
        ("server_typed_ready() {", '"$expected"'),
    ):
        require(ready, function, "typed readiness predicate")
        body = ready.split(function, 1)[1].split("\n}", 1)[0]
        require(body, 'ipc_surface_ready "$pid" "$uid"', "owned dual-IPC surface proof")
        require(body, f'typed_ipc_ready "$probe" {expected_state}', "typed IPC state proof")
        require(body, '"$(udp_socket_count)" = 0', "typed readiness zero-UDP proof")
        forbid(body, "grep ", "release-runner text-log dependency")
    require(ready, "--wait-typed-parked)", "typed parked CLI mode")
    require(ready, "--wait-typed-user-server)", "typed listening CLI mode")

    require_order(
        linux_runner,
        (
            "bool flutter_rustdesk_core_main(bool* should_start_ui)",
            "*should_start_ui = core_main();",
            "bool should_start_ui = false;",
            "if (!flutter_rustdesk_core_main(&should_start_ui))",
            "return EXIT_FAILURE;",
            "if (!should_start_ui)",
            "return EXIT_SUCCESS;",
            "g_application_run",
        ),
        "Linux runner handled-command contract",
    )
    forbid(linux_runner, "if (!flutter_rustdesk_core_main())", "handled command classified as loader failure")
    require(source, "The two independently colored halves encode one of 256", "source-state contract")
    require(source, "frame = (frame + 1U) & 255U;", "256-state source cadence")
    require(source, "attributes.override_redirect = True;", "source fixture isolation")
    require(source, "sigaction(SIGTERM", "source fixture teardown")
    require_order(
        bind_shim,
        (
            "addr->sa_family == AF_INET",
            "rewritten.sin_addr.s_addr == htonl(INADDR_ANY)",
            "ntohs(rewritten.sin_port) == 21118",
            "rewritten.sin_addr.s_addr = htonl(INADDR_LOOPBACK)",
            "return fn(sockfd, (const struct sockaddr *)&rewritten, sizeof(rewritten));",
            "return fn(sockfd, addr, addrlen);",
        ),
        "narrow loopback rewrite and passthrough",
    )
    if bind_shim.count("21118") != 1:
        raise VerificationError("the bind shim port match is not singular")

    require(controller, 'strstr(title, "127.0.0.1 - Remote Desktop")', "exact viewer title")
    if controller.count("pid != expected_pid") != 2:
        raise VerificationError("X11 and AT-SPI process identities must both be exact")
    require(controller, 'strcmp(hint.res_name, "rustdesk") != 0', "exact X11 instance")
    require(controller, 'strcmp(hint.res_class, "Rustdesk") != 0', "exact X11 class")
    if controller.count("XTestFakeKeyEvent") != 2:
        raise VerificationError("XTest key press/release calls are not exact")
    require(controller, 'static const char password[] = "rustdesk-peer-9f2a7c4e";', "test credential")
    require(controller, "atspi_init() != 0", "private AT-SPI initialization")
    require(controller, "atspi_get_desktop_count() != 1", "single accessibility desktop")
    if controller.count("role == ATSPI_ROLE_PASSWORD_TEXT") != 2:
        raise VerificationError("password-role accounting and readiness must both be exact")
    for state in (
        "ATSPI_STATE_EDITABLE", "ATSPI_STATE_ENABLED", "ATSPI_STATE_SENSITIVE",
        "ATSPI_STATE_VISIBLE", "ATSPI_STATE_FOCUSED", "ATSPI_STATE_FOCUSABLE",
    ):
        require(controller, state, f"password accessible {state}")
    forbid(controller, "ATSPI_STATE_SHOWING", "impossible obscured-password showing state")
    require(controller, "scan.password_nodes == 1U && scan.visible_passwords == 1U", "singular password field")
    require(controller, "scan.password_nodes == 0U", "password-field retirement")
    forbid(controller, "atspi_accessible_get_text", "accessible text/value disclosure")
    require(controller, "g_free(name);", "accessible-name release")
    forbid(controller, "PASSWORD_SETTLE_MS", "blind password-prompt delay")
    require(controller, "AUTH_WAIT_MS 30000U", "authentication deadline")
    require(controller, "FRESH_LIMIT_MS 1000U", "live-frame freshness bound")
    require(controller, "RECOVERY_LIMIT_MS 2500U", "focus-recovery bound")
    require_order(
        controller,
        (
            "wait_for_password_prompt((unsigned int)viewer_pid, &prompt_scan)",
            "type_password(display)",
            "wait_for_password_prompt_retirement((unsigned int)viewer_pid, &prompt_scan)",
            "atspi_exit() != 0",
            "wait_for_current_frames(source, display, &viewer, &history, AUTH_WAIT_MS",
            "read_connection_identity(&connection_before)",
            "sink = create_focus_sink(display)",
            "return_focus_with_pointer(display, &viewer)",
            "wait_for_current_frames(source, display, &viewer, &history, RECOVERY_LIMIT_MS",
            "read_connection_identity(&connection_after)",
            "same_connection(&connection_before, &connection_after)",
            "close_viewer(display, viewer.window)",
        ),
        "authenticated pixels, blur, pointer return, stable transport, and close",
    )
    require(controller, 'strcmp(remote, "0100007F:527E") == 0', "authenticated TCP tuple")
    require(controller, "left->inode == right->inode", "stable socket identity")
    require(controller, "WM_DELETE_WINDOW", "real viewer close")
    forbid(controller, "system(", "controller shell escape")
    forbid(controller, "Socket", "controller product-side probe socket")

    require(
        sources["verify"],
        "/usr/bin/python3 -I -S scripts/verify-flutter-peer-presentation.py --repo .",
        "shared fast source-contract wiring",
    )
    require(sources["readme"], "smoke-flutter-peer-presentation.sh", "harness README inventory")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    arguments = parser.parse_args()
    validate(load(arguments.repo.resolve()))
    print("flutter peer presentation source contract: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
