#!/usr/bin/env python3
"""Guard the one online-acquisition VM boundary and its container floor.

This is deliberately a compact source invariant. The authoritative behavior is
exercised by ``online-fetch.sh --self-test-vm-authority`` in a real QEMU guest;
this program only prevents an obvious host-Docker or host-listener fallback from
being added beside that tested path.
"""

import argparse
import pathlib
import re


class AuthorityError(Exception):
    pass


def require(source: str, token: str, label: str) -> None:
    if token not in source:
        raise AuthorityError(f"missing {label}")


def forbid(source: str, token: str, label: str) -> None:
    if token in source:
        raise AuthorityError(f"forbidden {label}")


def extract(source: str, start: str, end: str, label: str) -> str:
    if source.count(start) != 1:
        raise AuthorityError(f"{label} start cardinality differs")
    begin = source.index(start)
    finish = source.find(end, begin + len(start))
    if finish < 0:
        raise AuthorityError(f"{label} end is absent")
    return source[begin : finish + len(end)]


def validate(repo: pathlib.Path) -> None:
    online = (repo / "scripts/online-fetch.sh").read_text(encoding="utf-8")
    library = (repo / "scripts/lib.sh").read_text(encoding="utf-8")
    pins = (repo / "scripts/pins.env").read_text(encoding="utf-8")
    outer = (repo / "scripts/online-fetch-vm.sh").read_text(encoding="utf-8")
    guest = (repo / "scripts/online-fetch-vm-guest.sh").read_text(encoding="utf-8")
    preflight = (repo / "scripts/verify-online-fetch-vm-entry.sh").read_text(
        encoding="utf-8"
    )
    launcher = (repo / "scripts/launch-landlocked-virtiofsd.py").read_text(
        encoding="utf-8"
    )
    rename_probe = (
        repo / "scripts/verify-online-fetch-virtiofs-rename.py"
    ).read_text(encoding="utf-8")
    closure = (repo / "scripts/verify-private-tree-closure.py").read_text(
        encoding="utf-8"
    )
    provenance = (repo / "scripts/offline-image-provenance.py").read_text(
        encoding="utf-8"
    )

    devcheck_load = extract(
        online,
        "verify_or_load_devcheck_image() {",
        "\n}\n\nprepare_devcheck_build_context()",
        "devcheck online load",
    )
    devcheck_promotion = extract(
        online,
        "maintenance_promote_devcheck_image_candidate() {",
        "\n}\n\napple_check_image_spec_args()",
        "devcheck online promotion",
    )
    apple_load = extract(
        online,
        "verify_or_load_apple_check_image() {",
        "\n}\n\ndart_audit_contract_spec_args()",
        "Apple online load",
    )
    apple_builder = extract(
        online,
        "build_apple_check_image() {",
        "\n}\n\nmaintenance_build_apple_check_image_candidate()",
        "Apple online builder",
    )
    apple_build = extract(
        online,
        "maintenance_build_apple_check_image_candidate() {",
        "\n}\n\ncapture_apple_check_rebuild()",
        "Apple online candidate build",
    )
    apple_capture = extract(
        online,
        "capture_apple_check_rebuild() {",
        "\n}\n\nmaintenance_promote_apple_check_image_candidate()",
        "Apple online candidate capture",
    )
    apple_promotion = extract(
        online,
        "maintenance_promote_apple_check_image_candidate() {",
        "\n}\n\nprepare_dart_audit_build_context()",
        "Apple online promotion",
    )
    for source, label in (
        (devcheck_load, "devcheck load"),
        (devcheck_promotion, "devcheck promotion"),
        (apple_load, "Apple load"),
        (apple_capture, "Apple capture"),
        (apple_promotion, "Apple promotion"),
    ):
        require(
            source,
            "--publication-index-runtime",
            f"explicit containerd publication identity for {label}",
        )
    if apple_build.count('build_apple_check_image "$context" "$base_layout" "$tag"') != 2:
        raise AuthorityError(
            "Apple candidate transaction must perform two independent builds"
        )
    if apple_build.count('capture_apple_check_rebuild "$') != 2:
        raise AuthorityError(
            "Apple candidate transaction must capture both independent builds"
        )
    for token, label in (
        ("--network=default --pull=false --no-cache", "no-cache networked build"),
        ("--provenance=mode=max", "max provenance"),
        ("oci-layout://${base_layout}@${DEV_CHECK_IMAGE_MANIFEST_ID}", "local exact base"),
    ):
        require(apple_builder, token, f"Apple builder {label}")
    for token, label in (
        ('[ "$first_manifest:$first_config" = "$second_manifest:$second_config" ]', "runtime reproduction"),
        ('--source "$second_archive" --destination "$candidate"', "no-replace candidate publication"),
        ('/usr/bin/rm -f -- "$first_archive"', "first rebuild retirement"),
    ):
        require(apple_build, token, f"Apple candidate {label}")

    dispatch = 'if [ "${RUSTDESK_ONLINE_FETCH_VM_GUEST:-}" != 1 ]; then'
    require(online, dispatch, "outer VM dispatch")
    require(online, 'exec "$SCRIPT_DIR/online-fetch-vm.sh" "$@"', "sole outer entry")
    require(
        online,
        '"$SCRIPT_DIR/verify-online-fetch-vm-entry.sh"',
        "inner authority preflight",
    )
    if not online.index(dispatch) < online.index("readonly DOCKER_BIN=/usr/bin/docker"):
        raise AuthorityError("host VM dispatch does not precede Docker authority")
    if not online.index('if [ "${1:-}" = "--verifier-vm-inputs" ]') < online.index(
        dispatch
    ):
        raise AuthorityError("authenticated VM bootstrap is not isolated before dispatch")

    for token, label in (
        ("/var/run/docker.sock", "host Docker socket"),
        ("DOCKER_HOST", "host Docker environment"),
        (",hostfwd=", "QEMU host forwarding"),
        ("-netdev tap", "host TAP network"),
        ("-nic tap", "host TAP network"),
        ("-netdev bridge", "host bridge network"),
        ("-nic bridge", "host bridge network"),
        ("-virtfs", "legacy 9p export"),
        ("rustdesk-online-cache", "split active-cache export"),
        ("rustdesk-retired-cache", "split retired-cache export"),
    ):
        forbid(outer, token, label)
    if re.search(r"(?m)^\s*(?:/usr/bin/)?docker\s+(?:run|build|pull)\b", outer):
        raise AuthorityError("host Docker command exists in the outer VM orchestrator")
    for token, label in (
        ('[ "$HOST_UID" -ne 0 ]', "host-root refusal"),
        ('[ "$HOST_GID" -ne 0 ]', "host root-group refusal"),
        ('readonly BUILDX_BINARY="$INPUT_ROOT/buildx-v${VERIFIER_VM_BUILDX_VERSION}.linux-amd64"', "authenticated Buildx input path"),
        ('"$BUILDX_BINARY:$SIZE_VERIFIER_VM_BUILDX"', "Buildx input metadata admission"),
        ('verify_sha256 "$BUILDX_BINARY" "$SHA256_VERIFIER_VM_BUILDX"', "Buildx input digest admission"),
        ('readonly BUILDKIT_BUNDLE="$INPUT_ROOT/buildkit-v${VERIFIER_VM_BUILDKIT_VERSION}.linux-amd64.tar.gz"', "authenticated BuildKit input path"),
        ('"$BUILDKIT_BUNDLE:$SIZE_VERIFIER_VM_BUILDKIT"', "BuildKit input metadata admission"),
        ('verify_sha256 "$BUILDKIT_BUNDLE" "$SHA256_VERIFIER_VM_BUILDKIT"', "BuildKit input digest admission"),
        ("bundle create \"$SOURCE_BUNDLE\" refs/heads/master", "source Git bundle"),
        ("bundle verify \"$SOURCE_BUNDLE\"", "source-bundle verification"),
        ('"docker-buildx=$BUILDX_BINARY"', "authenticated Buildx payload"),
        ('"buildkit.tgz=$BUILDKIT_BUNDLE"', "authenticated BuildKit payload"),
        ('"git.deb=$GIT_PACKAGE"', "authenticated Git package payload"),
        ('retire_private_socket_path "$SERIAL_SOCKET"', "already-absent-safe serial cleanup"),
        ("-accel kvm", "KVM guest boundary"),
        (
            "-sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny",
            "QEMU seccomp sandbox",
        ),
        (
            "-netdev user,id=acquisition,ipv4=on,ipv6=off,net=10.0.2.0/24,host=10.0.2.2,dns=10.0.2.3,dhcpstart=10.0.2.15,restrict=off",
            "explicit unprivileged outbound-only network",
        ),
        (
            "-device virtio-net-pci,netdev=acquisition,mac=52:54:00:52:44:01",
            "fixed guest NIC",
        ),
        ("memory-backend-memfd,id=mem,size=${VM_MEMORY}M,share=on", "shared VM memory"),
        ("vhost-user-fs-pci,chardev=cache-state,tag=rustdesk-cache-state,queue-size=1024", "atomic virtiofs cache device"),
        ("vhost-user-fs-pci,chardev=systemd-cache,tag=rustdesk-systemd-cache,queue-size=1024", "systemd-cache virtiofs device"),
        ("vhost-user-fs-pci,chardev=result,tag=rustdesk-result,queue-size=1024", "bounded-result virtiofs device"),
        ('capture_listeners >"$LISTENERS_BEFORE"', "pre-run listener baseline"),
        ('capture_listeners >"$LISTENERS_DURING"', "live listener observation"),
        ('capture_listeners >"$LISTENERS_AFTER"', "post-run listener observation"),
        ("listeners=unchanged", "listener-invariance receipt"),
        ("udp=denied", "TCP-only acquisition receipt"),
        ("readonly SERIAL_LIMIT=16777216", "serial-output bound"),
        ("readonly SUCCESS_RECEIPT_LIMIT=65536", "success-receipt bound"),
        ('readonly RECEIPT_ROOT="$INPUT_ROOT/online-fetch-receipts"', "private success-receipt root"),
        ("online-fetch Buildx authority receipt is absent", "required Buildx result receipt"),
    ):
        require(outer, token, label)
    if outer.count(
        '/usr/bin/cmp -s "$LISTENERS_BEFORE" "$LISTENERS_DURING"'
    ) != 2:
        raise AuthorityError("complete live listener-inventory comparison differs")
    require(
        outer,
        '/usr/bin/cmp -s "$LISTENERS_BEFORE" "$LISTENERS_AFTER"',
        "complete final listener-inventory comparison",
    )
    if outer.count("vhost-user-fs-pci") != 3:
        raise AuthorityError("writable virtiofs device inventory differs")
    if outer.count("start_virtiofsd ") != 3:
        raise AuthorityError("Landlocked virtiofsd authority inventory differs")

    receipt_preparation = extract(
        outer,
        "prepare_success_receipt() {",
        "\n}\n\npublish_success_receipt() {",
        "success-receipt preparation",
    )
    receipt_publication = extract(
        outer,
        "publish_success_receipt() {",
        "\n}\n\ncleanup() {",
        "success-receipt publication",
    )
    cleanup = extract(outer, "cleanup() {", "\n}\ntrap cleanup EXIT", "outer cleanup")
    for token, label in (
        ("format=rustdesk-online-fetch-success-v2", "receipt format"),
        ("source_commit=$SOURCE_COMMIT", "receipt source commit"),
        ("source_tree=$SOURCE_TREE", "receipt source tree"),
        ("source_bundle_sha256=$SOURCE_BUNDLE_SHA256", "receipt source bundle"),
        ("listener_inventory_sha256=$listener_sha", "receipt listener digest"),
        ("serial_sha256=$serial_sha", "receipt serial digest"),
        ("transaction_stdout_sha256=$stdout_sha", "receipt stdout digest"),
        ("transaction_stderr_sha256=$stderr_sha", "receipt stderr digest"),
        ("buildx_receipt=$buildx_line", "receipt Buildx authority"),
        ('/usr/bin/chmod 0400 -- "$SUCCESS_RECEIPT_TMP"', "private receipt mode"),
        ('-le "$SUCCESS_RECEIPT_LIMIT"', "receipt size enforcement"),
    ):
        require(receipt_preparation, token, label)
    for token, label in (
        ('[ ! -e "$SUCCESS_RECEIPT_FINAL" ]', "no-replace precondition"),
        (
            '/usr/bin/mv -T --no-clobber -- "$SUCCESS_RECEIPT_TMP" "$SUCCESS_RECEIPT_FINAL"',
            "no-clobber receipt publication",
        ),
        ('= "$HOST_UID:$HOST_GID:400:1"', "published receipt metadata"),
        ('-le "$SUCCESS_RECEIPT_LIMIT"', "published receipt size enforcement"),
    ):
        require(receipt_publication, token, label)
    for token, label in (
        ('--remove-private-root "$RUN" --expected-identity "$RUN_ID"', "exact run-root retirement"),
        ("publish_success_receipt || cleanup_failed=1", "post-cleanup receipt publication"),
        ('if [ -n "$SUCCESS_RECEIPT_TMP" ]; then', "failed receipt-temporary retirement"),
        ("receipt=%s", "durable outer receipt path"),
    ):
        require(cleanup, token, label)
    if cleanup.index('--remove-private-root "$RUN"') > cleanup.index(
        "publish_success_receipt || cleanup_failed=1"
    ):
        raise AuthorityError("success receipt publishes before exact run-root retirement")
    bootstrap_operations = (
        "--maintenance-build-deb-builder-bootstrap-candidate",
        "--maintenance-build-android-builder-bootstrap-candidate",
        "--maintenance-build-win-helper-bootstrap-candidate",
        "--maintenance-promote-deb-builder-bootstrap-candidate",
        "--maintenance-promote-android-builder-bootstrap-candidate",
        "--maintenance-promote-win-helper-bootstrap-candidate",
    )
    for operation in bootstrap_operations:
        require(outer, f"1:{operation}", f"outer {operation} admission")
        require(guest, operation, f"guest {operation} admission")
    for operation in (
        "--maintenance-build-apple-check-image-candidate",
        "--maintenance-promote-apple-check-image-candidate",
    ):
        require(online, operation, f"inner {operation} admission")
        require(outer, f"1:{operation}", f"outer {operation} admission")
        require(guest, operation, f"guest {operation} admission")
    for retired in (
        "--maintenance-build-image-candidates",
        "--maintenance-capture-deb-builder-bootstrap-image",
        "--maintenance-capture-android-builder-bootstrap-image",
        "--maintenance-capture-win-helper-bootstrap-image",
        "--maintenance-capture-apple-check-image",
    ):
        forbid(online, retired, f"retired inner operation {retired}")
        forbid(outer, retired, f"retired outer operation {retired}")
        forbid(guest, retired, f"retired guest operation {retired}")
    require(library, 'ONLINE_STATE_ROOT="$REPO_ROOT/online"', "online state root")
    require(
        library,
        'ONLINE_DIR="${ONLINE_DIR:-$ONLINE_STATE_ROOT/inputs}"',
        "active-cache child layout",
    )
    require(
        online,
        'readonly RETIRED_ONLINE_INPUT_ROOT="$ONLINE_STATE_ROOT/retired"',
        "retired-cache sibling layout",
    )
    for token, label in (
        ('VERIFIER_VM_GIT_PACKAGE_VERSION="1:2.39.5-0+deb12u3"', "Git package version pin"),
        ('SHA256_VERIFIER_VM_GIT_PACKAGE="637a85ddd6247fab13bdd0592f2f39aff04ce4dbf0655d3ab553ac359a38ce6f"', "Git package pin"),
        ('SHA256_VERIFIER_VM_GIT_BINARY="2540879925a6881e3877ff7e3330746ba3027b04edf16a3a12dccd1644c4f32d"', "Git binary pin"),
        ('VERIFIER_VM_BUILDX_VERSION="0.20.0"', "Buildx version pin"),
        (
            'VERIFIER_VM_BUILDX_COMMIT="8e30c4669ca5aace9dd682650053c307f75fe5cc"',
            "Buildx commit pin",
        ),
        ('SIZE_VERIFIER_VM_BUILDX="65241240"', "Buildx size pin"),
        ('SHA256_VERIFIER_VM_BUILDX="8b21d3ce1011c4c072d64d4a7311c591cf1c2eb6b35bfdfe28f8e0b76e51621b"', "Buildx digest pin"),
        ('VERIFIER_VM_BUILDKIT_VERSION="0.18.2"', "BuildKit version pin"),
        (
            'VERIFIER_VM_BUILDKIT_COMMIT="e4da654b1251f91e914fab18eba33743aefd7080"',
            "BuildKit commit pin",
        ),
        ('SIZE_VERIFIER_VM_BUILDKIT="81953628"', "BuildKit size pin"),
        ('SHA256_VERIFIER_VM_BUILDKIT="5662f23cfa5e475ff50932dd2b71d2c5812928fad631d1e8c9f8f5592a4c1568"', "BuildKit digest pin"),
        ('SHA256_VERIFIER_VM_BUILDKITD="5597b69c910a58a7f49df8fde14d76a71f9a4e12f063ce9fe1397412f9a9815d"', "BuildKit daemon pin"),
        ('SHA256_VERIFIER_VM_BUILDKIT_RUNC="5e045d55319c523080a252890bd3a34818454701c6bc1629e57015e6934dc227"', "BuildKit runtime pin"),
        ('SHA256_VERIFIER_VM_BUILDKIT_CNI_BRIDGE="52511a6c4adf23020c9dd355ad6c0907960cb3063aea16e08aa8537a4131411a"', "BuildKit CNI bridge pin"),
        ('SHA256_VERIFIER_VM_BUILDKIT_CNI_FIREWALL="c200b885b2fcef736ec56e30abb93e4bcad0899702b60f2f875b99e1c132b6d8"', "BuildKit CNI firewall pin"),
        ('SHA256_VERIFIER_VM_BUILDKIT_CNI_HOST_LOCAL="4468298a67c16763ebe99b9d266b17fcff8ba45152d8c3de54694c8b334750de"', "BuildKit CNI host-local pin"),
        ('SHA256_VERIFIER_VM_BUILDKIT_CNI_LOOPBACK="534808f5a6671fc529eb143a7e5dcd353639cb24effd78bd9eb312adb857728d"', "BuildKit CNI loopback pin"),
        ('VERIFIER_VM_VIRTIOFSD_PACKAGE_VERSION="1.10.0-1ubuntu0.1"', "virtiofsd package version pin"),
        ('SHA256_VERIFIER_VM_VIRTIOFSD_PACKAGE="8069325e87cd4485fdb4dd2dde0e54dc68345847c92a1f5d9e9916dadd549b07"', "virtiofsd package pin"),
        ('SHA256_VERIFIER_VM_VIRTIOFSD_BINARY="e256a63975f3ba343d651ce001fdc1f1128a5967612f0f102ab1387727ead140"', "virtiofsd binary pin"),
    ):
        require(pins, token, label)

    for token, label in (
        ('[ "$(/usr/bin/id -u)" = 0 ]', "VM-local root bootstrap"),
        ('"$BUILDX_INPUT:$EXPECTED_BUILDX_SIZE"', "read-only Buildx guest input"),
        ('"$BUILDKIT_ARCHIVE:$EXPECTED_BUILDKIT_SIZE"', "read-only BuildKit guest input"),
        ('/usr/bin/install -m 0555 -- "$BUILDX_INPUT" "$BUILDX_SOURCE"', "root-owned fixed Buildx source"),
        ('fixed Buildx source identity differs', "fixed Buildx source verification"),
        ('install_buildkit_component "$BUILDKIT_EXTRACT/bin/buildkitd"', "pinned BuildKit daemon installation"),
        ('install_buildkit_component "$BUILDKIT_EXTRACT/bin/buildkit-runc"', "pinned BuildKit runtime installation"),
        ('install_buildkit_component "$BUILDKIT_EXTRACT/bin/buildkit-cni-bridge"', "pinned BuildKit CNI installation"),
        ('/usr/bin/dpkg-deb --extract "$GIT_PACKAGE" "$GIT_RUNTIME_ROOT"', "Git runtime extraction"),
        ('readonly GIT_BIN=$GIT_RUNTIME_ROOT/usr/bin/git', "fixed Git runtime"),
        ('GIT_ALLOW_PROTOCOL=file', "Git non-file protocol refusal"),
        ('bundle verify "$SOURCE_BUNDLE"', "guest source-bundle verification"),
        ("clone --no-hardlinks --no-tags", "source-bundle clone"),
        ("rustdesk-cache-state", "common cache-state export"),
        ("mount -t virtiofs", "virtiofs cache mount"),
        ('"$REPO/online/inputs"', "active-cache child"),
        ('"$REPO/online/retired"', "retired-cache child"),
        ("rustdesk-systemd-cache", "narrow systemd-cache export"),
        ("rustdesk-result", "bounded result export"),
        ('--host "unix://$SOCKET"', "guest Unix-only Docker endpoint"),
        ('readonly DAEMON_CONFIG=$ROOT/daemon.json', "fixed guest Docker daemon configuration"),
        ('{"features":{"containerd-snapshotter":true}}', "containerd image-store configuration"),
        ('--config-file "$DAEMON_CONFIG"', "explicit guest Docker daemon configuration"),
        ("'[[\"driver-type\",\"io.containerd.snapshotter.v1\"]]'", "containerd image-store runtime proof"),
        ("--bip 172.30.0.1/24", "fixed guest Docker bridge"),
        ('address = ["unix:///run/rustdesk-online-fetch-buildkit/buildkitd.sock"]', "fixed BuildKit Unix endpoint"),
        ('snapshotter = "overlayfs"', "BuildKit overlayfs snapshotter"),
        ('noProcessSandbox = false', "BuildKit process sandbox"),
        ('networkMode = "bridge"', "BuildKit CNI bridge network"),
        ('bridgeName = "rdbk0"', "fixed BuildKit bridge"),
        ('[worker.containerd]', "explicit BuildKit containerd-worker policy"),
        ('"$BUILDKIT_BIN/buildkitd" --config "$BUILDKIT_CONFIG"', "fixed BuildKit daemon launch"),
        ("--ip 127.0.0.1", "guest published-port loopback default"),
        ("--iptables=true", "guest-only firewall authority"),
        ("--ip-forward=true", "guest-only forwarding authority"),
        ("--ip-masq=true", "guest-only egress masquerade"),
        ("--dns-opt use-vc", "container DNS-over-TCP policy"),
        ("options use-vc", "guest DNS-over-TCP policy"),
        ("/usr/sbin/iptables --wait -I OUTPUT 1 -p udp -j REJECT", "guest UDP denial"),
        ("/usr/sbin/iptables --wait -I DOCKER-USER 1 -p udp -j REJECT", "container UDP denial"),
        ("/usr/sbin/iptables --wait -I FORWARD 1 -p udp -j REJECT", "BuildKit-worker UDP denial"),
        ("--userland-proxy=false", "Docker proxy refusal"),
        ("VM-local root passed the online-fetch entry preflight", "root negative test"),
        ("foreign VM principal passed", "foreign-principal negative test"),
        ("FOREIGN_PREFLIGHT_ROOT", "read-only foreign-principal preflight fixture"),
        ("--network=bridge --read-only", "real bridge-container probe"),
        ('--user "$ACQUISITION_UID:$ACQUISITION_GID"', "probe nonroot identity"),
        ("--cap-drop=ALL --security-opt=no-new-privileges", "probe privilege floor"),
        ("--pids-limit=64 --memory=256m --memory-swap=256m --cpus=1", "probe bounds"),
        ("https://files.pythonhosted.org/", "real pinned HTTPS probe"),
        ("543c7da2a7adadf21214938bb79c83ea12b473a4b6ee4ad4bf854e7715e13d1f", "probe digest"),
        ("online-fetch-vm-cache-transport-v1", "cache-transport observation"),
        ("VIRTIOFS_RENAME_CONTRACT=pass", "flagged-rename runtime receipt"),
        (
            "readonly ACQUISITION_NOFILE_LIMIT=524544",
            "private-workspace closure descriptor budget",
        ),
        (
            'ulimit -Hn "$ACQUISITION_NOFILE_LIMIT"',
            "exact hard descriptor limit before principal drop",
        ),
        (
            '[ "$(ulimit -Sn)" = "$1" ] && [ "$(ulimit -Hn)" = "$1" ]',
            "dropped-principal descriptor-limit replay",
        ),
        ("readonly RESULT_STREAM_LIMIT=16777216", "transaction-result byte bound"),
        ("bounded_result_reader() {", "bounded transaction-result reader"),
        (
            'count="$RESULT_STREAM_BLOCK_COUNT" iflag=fullblock',
            "full-block transaction-result ceiling",
        ),
        (
            '[ ! -s "$stdout_overflow" ] && [ ! -s "$stderr_overflow" ]',
            "transaction-result overflow refusal",
        ),
        (
            "local -a interpreters=()\n    verify_bounded_result_reader",
            "real transaction-result overflow smoke",
        ),
        ("verify_docker_daemon_generation", "Docker pre/post daemon-executable binding"),
        ("verify_buildkit_daemon_generation", "BuildKit pre/post daemon-executable binding"),
        ('mapfile -d \'\' -t buildkit_argv', "BuildKit root-owned argv binding"),
        ("stop_buildkit_daemon", "joined BuildKit shutdown"),
        ('[ "$daemon_status" -eq 1 ]', "pinned BuildKit signal-exit contract"),
        ('msg="stopping server"', "BuildKit graceful-stop marker"),
        (
            "buildkitd: got 1 SIGTERM/SIGINTs, forcing shutdown",
            "BuildKit signal-context marker",
        ),
        ("stop_docker_daemon", "joined Docker shutdown"),
    ):
        require(guest, token, label)
    if guest.count("/usr/bin/mount -t virtiofs") != 3:
        raise AuthorityError("guest writable virtiofs mount inventory differs")
    entry_limit = re.search(r"(?m)^TREE_ENTRY_LIMIT = ([0-9]+)$", closure)
    reserve = re.search(r"(?m)^RETAINED_DESCRIPTOR_RESERVE = ([0-9]+)$", closure)
    guest_limit = re.search(
        r"(?m)^readonly ACQUISITION_NOFILE_LIMIT=([0-9]+)$", guest
    )
    result_limit = re.search(
        r"(?m)^readonly RESULT_STREAM_LIMIT=([0-9]+)$", guest
    )
    result_block_size = re.search(
        r"(?m)^readonly RESULT_STREAM_BLOCK_SIZE=([0-9]+)$", guest
    )
    result_block_count = re.search(
        r"(?m)^readonly RESULT_STREAM_BLOCK_COUNT=([0-9]+)$", guest
    )
    if entry_limit is None or reserve is None or guest_limit is None:
        raise AuthorityError("private-workspace descriptor budget is not explicit")
    if int(guest_limit.group(1)) != int(entry_limit.group(1)) + int(reserve.group(1)):
        raise AuthorityError(
            "acquisition descriptor limit differs from the closure authority bound"
        )
    if result_limit is None \
       or result_block_size is None \
       or result_block_count is None:
        raise AuthorityError("transaction-result byte budget is not explicit")
    if int(result_limit.group(1)) != (
        int(result_block_size.group(1)) * int(result_block_count.group(1))
    ):
        raise AuthorityError(
            "transaction-result reader geometry differs from its byte bound"
        )
    forbid(guest, "ulimit -f", "process-wide transaction file-size limit")
    forbid(guest, "mount -t 9p", "legacy guest 9p mount")
    for token, label in (
        ("--host tcp", "guest Docker TCP endpoint"),
        ("--privileged", "privileged acquisition container"),
        ("--network=host", "host-network acquisition container"),
        ("--pid=host", "host-PID acquisition container"),
        ("--ipc=host", "host-IPC acquisition container"),
        ("--uts=host", "host-UTS acquisition container"),
        ("--cap-add", "added acquisition capability"),
        ("--publish", "published acquisition port"),
        ("--device", "guest-device grant"),
    ):
        forbid(guest, token, label)

    for token, label in (
        ("online-fetch VM entry refuses root", "inner root refusal"),
        ("caller is not the exact admitted acquisition principal", "principal binding"),
        ("kernel command line is not the acquisition-VM authority", "direct-boot proof"),
        ("guest Docker daemon generation differs", "daemon-generation proof"),
        ("guest Docker Unix-socket authority differs", "Unix-socket proof"),
        ("guest Docker image-store authority differs", "containerd image-store proof"),
        ("guest BuildKit daemon generation differs", "BuildKit generation proof"),
        ("guest BuildKit filesystem or socket authority differs", "BuildKit Unix-socket proof"),
        ("guest BuildKit daemon version differs", "BuildKit version proof"),
        ("guest-only BuildKit bridge identity differs", "BuildKit bridge proof"),
        ("fixed guest Buildx source identity differs", "Buildx source proof"),
        ("acquisition NIC identity is absent or ambiguous", "NIC proof"),
        ("cache export filesystem differs", "cache-boundary proof"),
        ("rustdesk-systemd-cache virtiofs noexec", "systemd-cache virtiofs proof"),
        ("rustdesk-result virtiofs noexec", "bounded-result virtiofs proof"),
        (
            "active and auxiliary cache roots do not share one atomic-rename filesystem",
            "same-mount replacement proof",
        ),
        ("admitted source identity changed", "source replay proof"),
        ("fixed Git runtime binary identity differs", "Git runtime identity proof"),
    ):
        require(preflight, token, label)

    for token, label in (
        ("Landlock ABI 8 or newer is required", "mandatory Landlock ABI"),
        ("HANDLED_NET = NET_BIND_TCP | NET_CONNECT_TCP", "TCP deny-by-default policy"),
        ('expect_landlock_denial("outside-file read"', "filesystem escape negative probe"),
        ('expect_landlock_denial("TCP bind"', "TCP bind negative probe"),
        ('expect_landlock_denial("TCP connect"', "TCP connect negative probe"),
        (
            'choices=("cache", "systemd-cache", "bounded-result", "sealed-input")',
            "enumerated filesystem authority",
        ),
        ('"--sandbox=none"', "explicit rootless backend mode"),
        ('"--seccomp=kill"', "virtiofsd seccomp floor"),
        ("os.execve(binary_fd", "descriptor-executed backend"),
    ):
        require(launcher, token, label)
    for token, label in (
        ("RENAME_NOREPLACE = 1", "no-clobber rename flag"),
        ("RENAME_EXCHANGE = 2", "exchange rename flag"),
        ("errno.EEXIST", "occupied-destination verdict"),
        ("noreplace=cross-parent collision=no-clobber exchange=nonempty", "behavioral rename receipt"),
    ):
        require(rename_probe, token, label)

    normalized_capture = extract(
        provenance,
        "def canonicalize_certified_builder_oci_export(",
        "\n\ndef canonicalize_bootstrap_capture_archive(",
        "certified OCI normalization",
    )
    bootstrap_normalization = extract(
        provenance,
        "def canonicalize_bootstrap_capture_archive(",
        "\n\ndef capture(",
        "bootstrap archive normalization",
    )
    image_capture = extract(
        provenance,
        "def capture(",
        "\n\ndef create_fixture_archive(",
        "image archive capture",
    )
    require(
        provenance,
        "CAPTURE_ARCHIVE_BYTE_LIMIT = 2_147_483_648",
        "independent image-archive byte bound",
    )
    for body, label in (
        (normalized_capture, "certified OCI normalization"),
        (bootstrap_normalization, "bootstrap archive normalization"),
        (image_capture, "image archive capture"),
    ):
        require(
            body,
            "BoundedDigestingWriter(",
            f"{label} bounded writer",
        )
        require(
            body,
            "CAPTURE_ARCHIVE_BYTE_LIMIT",
            f"{label} independent byte bound",
        )
    require(
        bootstrap_normalization,
        "allow_unreferenced_blobs=True",
        "discard-only source parsing",
    )
    require(
        bootstrap_normalization,
        "require_private=True",
        "strict normalized bootstrap verification",
    )
    forbid(
        image_capture,
        "stderr=subprocess.PIPE",
        "undrained Docker-save stderr pipe",
    )
    require(
        image_capture,
        "if private_archive:\n        validate_private_output_parent(output.parent)\n        save_ref = runtime_id",
        "private verified-runtime-ID archive capture",
    )
    forbid(
        image_capture,
        "cannot create fixed bootstrap capture tag",
        "bootstrap candidate compatibility tag",
    )

    for token, label in (
        ('readonly BUILDX_SOURCE=/opt/rustdesk-online-fetch-vm/docker-buildx', "fixed Buildx source"),
        ('readonly ONLINE_FETCH_BUILDX_PLUGIN="$ONLINE_FETCH_BUILDX_DIR/docker-buildx"', "private Buildx plugin"),
        ('install -m 0500 "$BUILDX_SOURCE" "$ONLINE_FETCH_BUILDX_PLUGIN"', "private Buildx installation"),
        ('"github.com/docker/buildx v${VERIFIER_VM_BUILDX_VERSION} ${VERIFIER_VM_BUILDX_COMMIT}"', "exact Buildx version"),
        ('readonly ONLINE_FETCH_BUILDKIT_ENDPOINT=unix:///run/rustdesk-online-fetch-buildkit/buildkitd.sock', "fixed BuildKit endpoint"),
        ('readonly ONLINE_FETCH_BUILDX_BUILDER=rustdesk-online-fetch', "fixed Buildx builder identity"),
        ('--name "$ONLINE_FETCH_BUILDX_BUILDER"', "named Buildx builder creation"),
        ('--driver remote "$ONLINE_FETCH_BUILDKIT_ENDPOINT"', "remote BuildKit driver binding"),
        ('--builder "$ONLINE_FETCH_BUILDX_BUILDER" inspect --bootstrap', "remote builder bootstrap inspection"),
        ('[ "$driver" = remote ]', "remote Buildx driver requirement"),
        ('if (key == "BuildKit version")', "Buildx 0.20 BuildKit-version field"),
        ('[ "$buildkit_version" = "v${VERIFIER_VM_BUILDKIT_VERSION}" ]', "remote BuildKit version requirement"),
        ("assert_online_fetch_containerd_image_store", "separate containerd image-store admission"),
        ('org.mobyproject.buildkit.worker.executor=oci', "OCI worker admission"),
        ('org.mobyproject.buildkit.worker.network=cni', "CNI network admission"),
        ('org.mobyproject.buildkit.worker.oci.process-mode=sandbox', "process-sandbox admission"),
        ('org.mobyproject.buildkit.worker.snapshotter=overlayfs', "overlayfs snapshotter admission"),
        ('grep -Fxc "$label" <<<"$worker_labels"', "unique worker-label admission"),
        ("^buildx_buildkit_", "managed builder-container refusal"),
        ('--builder "$ONLINE_FETCH_BUILDX_BUILDER" build "$@"', "sole remote Buildx build funnel"),
        ("driver=remote buildkit=%s endpoint=guest-unix", "remote BuildKit runtime receipt"),
        ('"rd-devcheck@${DEV_CHECK_IMAGE_ID}=oci-layout://${base_layout}@${DEV_CHECK_IMAGE_MANIFEST_ID}"', "Apple local OCI base context"),
    ):
        require(online, token, label)
    for token, label in (
        ("online_docker buildx build", "unbound Buildx build"),
        ("online_docker_without_vcs buildx build", "unbound VCS-free Buildx build"),
        ("docker-container", "Buildx container-driver fallback"),
    ):
        forbid(online, token, label)
    admission = (
        "assert_online_fetch_buildx_version\n"
        "create_online_fetch_buildx_builder\n"
        "assert_online_fetch_buildx_driver\n"
    )
    if online.index('if [ "$ONLINE_FETCH_VM_AUTHORITY_PROBE" -eq 1 ]') < online.index(
        admission
    ):
        raise AuthorityError("VM authority probe exits before Buildx runtime admission")

    for function_name, network, pids, memory in (
        ("online_docker_run", "bridge", "2048", "16g"),
        ("online_docker_run_offline", "none", "512", "4g"),
        ("online_docker_run_cargo_semantic", "none", "256", "4g"),
        ("online_docker_run_pub_semantic", "none", "512", "8g"),
        ("online_docker_run_archive_acquisition", "bridge", "256", "4g"),
    ):
        body = extract(
            online,
            f"{function_name}() {{",
            '        "$@"\n}',
            function_name,
        )
        for token, label in (
            ("--rm --pull=never", "ephemeral no-pull execution"),
            (f"--network={network}", "network profile"),
            ("--read-only", "read-only root"),
            ('--user "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID"', "numeric nonroot user"),
            ("--cap-drop=ALL --security-opt=no-new-privileges", "privilege floor"),
            (f"--pids-limit={pids}", "PID bound"),
            (f"--memory={memory} --memory-swap={memory}", "memory/no-swap bound"),
        ):
            require(body, token, f"{function_name} {label}")
        for forbidden in (
            "--privileged",
            "--network=host",
            "--cap-add",
            "--publish",
            "--device",
        ):
            forbid(body, forbidden, f"{function_name} {forbidden}")
    if re.search(r"(?m)^\s*docker\s+(?:run|build|pull|tag)\b", online):
        raise AuthorityError("ambient Docker command exists outside the fixed inner funnel")

    pub_resolution = extract(
        online,
        "verify_pub_cache_resolution() {",
        "\n}\n\nproduce_pub_cache_candidate() {",
        "offline Pub-cache semantic resolution",
    )
    for token, label in (
        (
            "source=$GRADLE_SOURCE_AUTHORITY,target=/authority,readonly,bind-recursive=disabled",
            "read-only source authority",
        ),
        (
            '--env "RUSTDESK_FLUTTER_VERSION=$FLUTTER_VERSION"',
            "pinned Flutter version",
        ),
        (
            '--env "RUSTDESK_FLUTTER_TOOLS_LOCK_SHA256=$SHA256_FLUTTER_TOOLS_LOCK"',
            "pinned Flutter-tools lock digest",
        ),
    ):
        require(pub_resolution, token, f"Pub-cache semantic resolution {label}")
    positions = tuple(
        pub_resolution.find(token)
        for token in (
            "dart pub get --offline --enforce-lockfile",
            "/authority/scripts/finalize-flutter-tools-offline.sh",
            "flutter pub get --offline --enforce-lockfile",
        )
    )
    if any(position < 0 for position in positions) or positions != tuple(sorted(positions)):
        raise AuthorityError(
            "Pub-cache semantic resolution does not finalize Flutter tools before Flutter"
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=".")
    args = parser.parse_args()
    repo = pathlib.Path(args.repo).resolve()
    try:
        validate(repo)
    except AuthorityError as exc:
        print(f"online-fetch VM authority: FAIL: {exc}")
        return 1
    print("online-fetch VM authority: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
