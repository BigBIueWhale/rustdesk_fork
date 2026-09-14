#!/usr/bin/env python3
"""Verify exact creator-owned libvirt lifecycle in Windows golden provisioning."""

import argparse
import re
import sys
from pathlib import Path


class VerificationError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise VerificationError(message)


def require_text(source, text, message):
    require(text in source, message)


def require_count(source, text, count, message):
    observed = source.count(text)
    require(
        observed == count,
        "{} (found {}, expected {})".format(message, observed, count),
    )


def require_order(source, tokens, message):
    positions = []
    offset = 0
    for token in tokens:
        position = source.find(token, offset)
        require(position >= 0, message)
        positions.append(position)
        offset = position + len(token)
    require(positions == sorted(positions), message)


def validate(sources):
    provision = sources["provision"]
    storage = sources["storage"]

    for text, label in (
        ("export LC_ALL=C", "fixed control-output locale"),
        ("CONTROL_TIMEOUT_SECONDS=30", "finite libvirt control deadline"),
        ("CREATE_TIMEOUT_SECONDS=300", "finite domain-creation deadline"),
        ("PROCESS_ADMISSION_SECONDS=10", "finite process-group admission deadline"),
        ("VM_TIMEOUT_SECONDS=7800", "finite complete-provision deadline"),
        ('PROVISION_DOMAIN_UUID=""', "retained domain UUID state"),
        ("PROVISION_DOMAIN_CREATION_STARTED=0", "creation-intent state"),
        (
            "PROVISION_DOMAIN_OWNERSHIP_COMMITTED=0",
            "pre-commit domain authority state",
        ),
        ('PROVISION_VIRT_PID=""', "retained virt-install PID state"),
        ('PROVISION_VIRT_START=""', "retained virt-install start identity"),
        (
            "require_cmd virt-install virsh qemu-img xorriso setsid timeout awk python3",
            "exact lifecycle command preflight",
        ),
        (
            '[[ "$DOMAIN" =~ ^[A-Za-z0-9._-]+$ ]]',
            "domain-name grammar",
        ),
        ('[ "${#DOMAIN}" -le 63 ]', "domain-name length bound"),
        (
            '[[ "$1" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-'
            '[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]]',
            "kernel UUID grammar",
        ),
        ('[ "$start" = "$PROVISION_VIRT_START" ]', "process start identity"),
        ('[ "$group" = "$PROVISION_VIRT_PID" ]', "process-group identity"),
        ('[ "$session" = "$PROVISION_VIRT_PID" ]', "process-session identity"),
        (
            "owned_virt_process_group_is_live() {",
            "complete owned process-group scanner",
        ),
        (
            "wait_for_owned_virt_process_group() {",
            "exact process-group admission",
        ),
        (
            "deadline=$(( $(monotonic_seconds) + PROCESS_ADMISSION_SECONDS ))",
            "monotonic process-group admission deadline",
        ),
        (
            '[ "$start" = "$PROVISION_VIRT_START" ] || return 1',
            "admission start-identity refusal",
        ),
        (
            '[ "$state" != Z ] && [ "$state" != X ] || return 1',
            "admission live-state refusal",
        ),
        (
            'if [ "$group" = "$PROVISION_VIRT_PID" ] \\\n'
            '            && [ "$session" = "$PROVISION_VIRT_PID" ]; then',
            "admission group/session proof",
        ),
        (
            "for path in /proc/[0-9]*/stat; do",
            "process-group member enumeration",
        ),
        (
            '&& [ "$session" = "$PROVISION_VIRT_PID" ] \\\n'
            '            && [ "$state" != Z ] && [ "$state" != X ]; then',
            "live group/session member proof",
        ),
        (
            'kill -TERM -- "-$PROVISION_VIRT_PID"',
            "exact owned process-group graceful stop",
        ),
        (
            'kill -KILL -- "-$PROVISION_VIRT_PID"',
            "exact owned process-group terminal stop",
        ),
        (
            'source "$SCRIPT_DIR/windows-libvirt-storage-pools.sh"',
            "shared private libvirt authority",
        ),
        (
            'windows_libvirt_virsh_bounded "$@"',
            "private session-libvirt control delegation",
        ),
        ('list --all --name', "fail-closed complete name enumeration"),
        ('list --all --uuid', "fail-closed complete UUID enumeration"),
        (
            'awk -v wanted="$DOMAIN" '
            "'$0 == wanted { found=1 } END { exit !found }'",
            "exact name collision comparison",
        ),
        (
            'awk -v wanted="$PROVISION_DOMAIN_UUID" '
            "'$0 == wanted { found=1 } END { exit !found }'",
            "exact UUID comparison",
        ),
        (
            "golden domain name already exists; refusing to mutate it",
            "pre-existing name refusal",
        ),
        (
            "cannot prove that the golden domain name is unused",
            "name-enumeration uncertainty refusal",
        ),
        (
            "cannot prove that the golden domain UUID is unused",
            "UUID-enumeration uncertainty refusal",
        ),
        (
            'actual_name="$(virsh_bounded domname "$PROVISION_DOMAIN_UUID"',
            "UUID-addressed secondary name proof",
        ),
        (
            "verify_owned_golden_domain_xml() {",
            "exact confined domain-XML proof",
        ),
        (
            '/usr/bin/setsid --wait "${WINDOWS_LIBVIRT_CLIENT_ENV[@]}" \\\n'
            "        /usr/bin/virt-install \\\n"
            "        --connect qemu:///session",
            "retained private-namespace process-group launch",
        ),
        ('--uuid "$PROVISION_DOMAIN_UUID"', "explicit libvirt UUID creation"),
        (
            'PROVISION_VIRT_START="$(process_start_time "$PROVISION_VIRT_PID")"',
            "post-launch process identity binding",
        ),
        (
            "wait_for_owned_virt_process_group \\\n"
            '        || die "could not prove virt-install process-group admission"',
            "post-launch process-group admission",
        ),
        (
            "while owned_virt_process_group_is_live; do",
            "complete provision-client group drain",
        ),
        (
            'virsh_bounded send-key "$PROVISION_DOMAIN_UUID"',
            "UUID-addressed boot-key injection",
        ),
        (
            'virsh_bounded destroy "$PROVISION_DOMAIN_UUID"',
            "UUID-addressed destroy",
        ),
        (
            'virsh_bounded undefine "$PROVISION_DOMAIN_UUID" --nvram',
            "UUID-addressed NVRAM undefine",
        ),
        (
            'state="$(virsh_bounded domstate "$PROVISION_DOMAIN_UUID")"',
            "UUID-addressed state polling",
        ),
        ('--network user,model=e1000e', "fixed user-mode guest network"),
        (
            '--graphics vnc,listen=127.0.0.1',
            "loopback-only diagnostic VNC",
        ),
        (
            'warn "provision UUID exists under an unexpected name; preserving it"',
            "ambiguous-name preservation",
        ),
        (
            'warn "uncommitted provision UUID exists after an ambiguous launch; preserving it"',
            "pre-commit UUID preservation",
        ),
        (
            "PROVISION_DOMAIN_OWNERSHIP_COMMITTED=1",
            "proved domain-ownership commit",
        ),
        (
            "completed golden domain could not be undefined safely",
            "successful terminal teardown requirement",
        ),
        (
            "could not prove exact terminal cleanup of the provision-owned domain",
            "cleanup uncertainty failure",
        ),
        (
            "windows_libvirt_transaction_close \\\n"
            '        || die "golden-provision libvirt authority did not retire after domain finality"',
            "successful transaction finality",
        ),
        ("trap '' HUP INT TERM", "terminal cleanup signal exclusion"),
        ("trap cleanup_provision EXIT", "terminal cleanup trap"),
        ("trap 'signal_exit 129' HUP", "HUP cleanup routing"),
        ("trap 'signal_exit 130' INT", "INT cleanup routing"),
        ("trap 'signal_exit 143' TERM", "TERM cleanup routing"),
    ):
        require_text(provision, text, label)

    for text, label in (
        (
            "/usr/bin/setsid --wait \\\n"
            '        /usr/bin/timeout --foreground --kill-after=2 "$CONTROL_TIMEOUT_SECONDS" \\\n'
            '        "$@" </dev/null',
            "bounded closed-input libvirt control",
        ),
        (
            '"${WINDOWS_LIBVIRT_CLIENT_ENV[@]}" \\\n'
            '        /usr/bin/virsh --connect qemu:///session "$@"',
            "private environment and absolute libvirt client",
        ),
    ):
        require_text(storage, text, label)

    domain_xml = provision[
        provision.index("verify_owned_golden_domain_xml() {"):
        provision.index("clear_provision_domain_authority() {")
    ]
    for text, label in (
        (
            'set -o noclobber; virsh_bounded dumpxml "$PROVISION_DOMAIN_UUID"',
            "UUID-addressed no-clobber domain XML capture",
        ),
        (
            '/usr/bin/python3 -I -S - "$xml" "$DOMAIN" "$PROVISION_DOMAIN_UUID"',
            "isolated absolute domain XML parser",
        ),
        (
            'stat.S_IMODE(before.st_mode) != 0o600',
            "owner-only domain XML mode",
        ),
        (
            'not 0 < before.st_size <= 1024 * 1024',
            "bounded domain XML size",
        ),
        (
            'root.findtext("name") != expected_name or root.findtext("uuid") != expected_uuid',
            "domain XML name and UUID proof",
        ),
        (
            'len(disks) != len(expected_disks)',
            "exact domain XML disk cardinality",
        ),
        (
            'source is None or "file" not in source.attrib',
            "non-file domain disk refusal",
        ),
        (
            'sorted(actual_disks) != sorted(expected_disk_devices)',
            "exact domain XML disk set and device roles",
        ),
        (
            'len(interfaces) != 1 or interfaces[0].get("type") != "user"',
            "single user-mode network interface",
        ),
        (
            'len(models) != 1 or models[0].get("type") != "e1000e"',
            "exact user-mode network model",
        ),
        (
            'interfaces[0].findall("./portForward")',
            "host-forwarding refusal",
        ),
        (
            'graphic.get("type") != "vnc" or graphic.get("listen") != "127.0.0.1"',
            "loopback VNC parent proof",
        ),
        (
            'listeners[0].get("address") != "127.0.0.1"',
            "loopback VNC child proof",
        ),
        (
            'root.findall("./devices/hostdev") or root.findall("./devices/filesystem")',
            "host-device and filesystem-passthrough refusal",
        ),
        (
            'element.tag.startswith(qemu_namespace) for element in root.iter()',
            "raw QEMU command-line refusal",
        ),
    ):
        require_text(domain_xml, text, label)

    require_count(
        provision,
        "require_domain_identity_absent",
        3,
        "two absence proofs plus function definition",
    )
    require_count(
        provision,
        "PROVISION_VM_DEADLINE=$(( $(monotonic_seconds) + VM_TIMEOUT_SECONDS ))",
        2,
        "independent first-shutdown and post-shutdown deadlines",
    )
    require_count(
        provision,
        "PROVISION_DOMAIN_OWNERSHIP_COMMITTED=0",
        2,
        "initial and terminally cleared pre-commit authority state",
    )
    require_count(
        provision,
        'stat="${stat##*) }"',
        2,
        "two robust proc-stat command boundaries",
    )
    require_count(
        provision,
        'virsh_bounded destroy "$PROVISION_DOMAIN_UUID"',
        1,
        "single exact UUID destroy site",
    )
    require_count(
        provision,
        'virsh_bounded undefine "$PROVISION_DOMAIN_UUID" --nvram',
        1,
        "single exact UUID undefine site",
    )

    for forbidden, label in (
        ('destroy "$DOMAIN"', "name-addressed destroy absence"),
        ('undefine "$DOMAIN"', "name-addressed undefine absence"),
        ('send-key "$DOMAIN"', "name-addressed boot-key absence"),
        ('domstate "$DOMAIN"', "name-addressed state-query absence"),
        ("virsh -c qemu:///session", "unbounded legacy virsh absence"),
        ("--no-pkttyagent", "post-libvirt-10 virsh option absence"),
        ("--remove-all-storage", "domain storage-removal absence"),
        ("--storage", "selected domain storage-removal absence"),
        ("--wipe-storage", "domain storage-wipe absence"),
        (
            "--delete-storage-volume-snapshots",
            "domain storage-snapshot-removal absence",
        ),
        ("hostfwd=", "guest-to-host forwarding absence"),
        ("listen=0.0.0.0", "non-loopback IPv4 VNC absence"),
        ("listen=::", "non-loopback IPv6 VNC absence"),
        ("|| true", "suppressed lifecycle error absence"),
    ):
        require(forbidden not in provision, label)

    require_order(
        provision,
        (
            'PROVISION_DOMAIN_UUID="$(</proc/sys/kernel/random/uuid)"',
            'assert_uuid "$PROVISION_DOMAIN_UUID"',
            "require_domain_identity_absent",
            'qemu-img create -f qcow2 "$GOLDEN" 80G',
            "require_domain_identity_absent",
            "PROVISION_DOMAIN_CREATION_STARTED=1",
            '/usr/bin/setsid --wait "${WINDOWS_LIBVIRT_CLIENT_ENV[@]}"',
            "/usr/bin/virt-install",
            '--uuid "$PROVISION_DOMAIN_UUID"',
            'PROVISION_VIRT_START="$(process_start_time "$PROVISION_VIRT_PID")"',
            "wait_for_owned_virt_process_group",
            "wait_for_owned_domain_creation",
            "verify_owned_golden_domain_xml",
            "windows_libvirt_require_targets_owned",
            "PROVISION_DOMAIN_OWNERSHIP_COMMITTED=1",
        ),
        "UUID absence, creation intent, launch, proof, and ownership-commit order",
    )
    cleanup = provision[
        provision.index("stop_and_undefine_owned_domain() {"):
        provision.index("seal_golden_read_only() {")
    ]
    require_order(
        cleanup,
        (
            'if [ "$PROVISION_DOMAIN_OWNERSHIP_COMMITTED" = 0 ]; then',
            "if domain_uuid_is_listed; then",
            "uncommitted provision UUID exists after an ambiguous launch; preserving it",
            "return 1",
            "clear_provision_domain_authority",
            "if ! prove_owned_domain; then",
        ),
        "pre-commit UUID preservation before committed-domain control",
    )
    require_order(
        provision,
        (
            "if ! stop_owned_virt_process; then",
            "preserving the domain because the owned virt-install process group",
            "elif ! stop_and_undefine_owned_domain; then",
            "windows_helper_authority_close",
        ),
        "process-before-domain-before-helper terminal cleanup",
    )
    require_order(
        provision,
        (
            '[ "$vi_status" = 0 ] || die "virt-install failed with exit $vi_status"',
            "PROVISION_VM_DEADLINE=$(( $(monotonic_seconds) + VM_TIMEOUT_SECONDS ))",
            'log "waiting for win-guest-setup to COMPLETE',
        ),
        "independent post-shutdown deadline",
    )
    completion = provision[provision.find("if golden_has_done_marker; then") :]
    require_order(
        completion,
        (
            "if golden_has_done_marker; then",
            'verify_sha256 "$GOLDEN" "${SHA256_WIN11_GOLDEN_QCOW2}"',
            "stop_and_undefine_owned_domain",
            "golden Win11 template built:",
        ),
        "marker, hash, terminal teardown, and success order",
    )


def load_sources(repo):
    paths = {
        "provision": "scripts/provision-windows-vm.sh",
        "storage": "scripts/windows-libvirt-storage-pools.sh",
    }
    return {
        key: (repo / relative).read_text(encoding="utf-8")
        for key, relative in paths.items()
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    args = parser.parse_args()
    sources = load_sources(args.repo.resolve())
    validate(sources)
    print("verify-windows-golden-domain-authority: ok")


if __name__ == "__main__":
    try:
        main()
    except (OSError, VerificationError) as exc:
        print(
            "verify-windows-golden-domain-authority: {}".format(exc),
            file=sys.stderr,
        )
        sys.exit(1)
