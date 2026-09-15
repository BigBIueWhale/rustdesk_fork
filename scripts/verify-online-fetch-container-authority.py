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
        ("docker run", "host Docker execution"),
        ("docker build", "host Docker build"),
        ("docker pull", "host Docker pull"),
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
    for token, label in (
        ('[ "$HOST_UID" -ne 0 ]', "host-root refusal"),
        ('[ "$HOST_GID" -ne 0 ]', "host root-group refusal"),
        ("bundle create \"$SOURCE_BUNDLE\" refs/heads/master", "source Git bundle"),
        ("bundle verify \"$SOURCE_BUNDLE\"", "source-bundle verification"),
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
    ):
        require(outer, token, label)
    if outer.count("vhost-user-fs-pci") != 3:
        raise AuthorityError("writable virtiofs device inventory differs")
    if outer.count("start_virtiofsd ") != 3:
        raise AuthorityError("Landlocked virtiofsd authority inventory differs")
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
    for retired in (
        "--maintenance-build-image-candidates",
        "--maintenance-capture-deb-builder-bootstrap-image",
        "--maintenance-capture-android-builder-bootstrap-image",
        "--maintenance-capture-win-helper-bootstrap-image",
    ):
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
        ('VERIFIER_VM_VIRTIOFSD_PACKAGE_VERSION="1.10.0-1ubuntu0.1"', "virtiofsd package version pin"),
        ('SHA256_VERIFIER_VM_VIRTIOFSD_PACKAGE="8069325e87cd4485fdb4dd2dde0e54dc68345847c92a1f5d9e9916dadd549b07"', "virtiofsd package pin"),
        ('SHA256_VERIFIER_VM_VIRTIOFSD_BINARY="e256a63975f3ba343d651ce001fdc1f1128a5967612f0f102ab1387727ead140"', "virtiofsd binary pin"),
    ):
        require(pins, token, label)

    for token, label in (
        ('[ "$(/usr/bin/id -u)" = 0 ]', "VM-local root bootstrap"),
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
        ("--bip 172.30.0.1/24", "fixed guest Docker bridge"),
        ("--ip 127.0.0.1", "guest published-port loopback default"),
        ("--iptables=true", "guest-only firewall authority"),
        ("--ip-forward=true", "guest-only forwarding authority"),
        ("--ip-masq=true", "guest-only egress masquerade"),
        ("--dns-opt use-vc", "container DNS-over-TCP policy"),
        ("options use-vc", "guest DNS-over-TCP policy"),
        ("/usr/sbin/iptables --wait -I OUTPUT 1 -p udp -j REJECT", "guest UDP denial"),
        ("/usr/sbin/iptables --wait -I DOCKER-USER 1 -p udp -j REJECT", "container UDP denial"),
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
        ("ulimit -f 32768", "transaction-output bound"),
        ("verify_daemon_generation", "root pre/post daemon-executable binding"),
    ):
        require(guest, token, label)
    if guest.count("/usr/bin/mount -t virtiofs") != 3:
        raise AuthorityError("guest writable virtiofs mount inventory differs")
    entry_limit = re.search(r"(?m)^TREE_ENTRY_LIMIT = ([0-9]+)$", closure)
    reserve = re.search(r"(?m)^RETAINED_DESCRIPTOR_RESERVE = ([0-9]+)$", closure)
    guest_limit = re.search(
        r"(?m)^readonly ACQUISITION_NOFILE_LIMIT=([0-9]+)$", guest
    )
    if entry_limit is None or reserve is None or guest_limit is None:
        raise AuthorityError("private-workspace descriptor budget is not explicit")
    if int(guest_limit.group(1)) != int(entry_limit.group(1)) + int(reserve.group(1)):
        raise AuthorityError(
            "acquisition descriptor limit differs from the closure authority bound"
        )
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
        ("acquisition NIC identity is absent or ambiguous", "NIC proof"),
        ("cache export filesystem differs", "cache-boundary proof"),
        ("rustdesk-systemd-cache virtiofs noexec", "systemd-cache virtiofs proof"),
        ("rustdesk-result virtiofs noexec", "bounded-result virtiofs proof"),
        (
            "active and retired cache roots do not share one atomic-rename filesystem",
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
        ('choices=("cache", "systemd-cache", "bounded-result")', "enumerated filesystem authority"),
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
