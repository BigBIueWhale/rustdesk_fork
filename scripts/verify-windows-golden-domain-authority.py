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


def extract_requirement(source, requirement_id):
    marker = '<span class="id">{}</span>'.format(requirement_id)
    start = source.find(marker)
    require(start >= 0, "{} requirement".format(requirement_id))
    start = source.rfind('<div class="req"', 0, start)
    require(start >= 0, "{} requirement boundary".format(requirement_id))
    end = source.find('<div class="req"', start + 1)
    require(end >= 0, "{} requirement terminal boundary".format(requirement_id))
    return source[start:end]


def validate(sources):
    provision = sources["provision"]

    for text, label in (
        ("export LC_ALL=C", "fixed control-output locale"),
        ("CONTROL_TIMEOUT_SECONDS=30", "finite libvirt control deadline"),
        ("CREATE_TIMEOUT_SECONDS=300", "finite domain-creation deadline"),
        ("PROCESS_ADMISSION_SECONDS=10", "finite process-group admission deadline"),
        ("VM_TIMEOUT_SECONDS=7800", "finite complete-provision deadline"),
        ('PROVISION_DOMAIN_UUID=""', "retained domain UUID state"),
        ("PROVISION_DOMAIN_CREATION_STARTED=0", "creation-intent state"),
        ('PROVISION_VIRT_PID=""', "retained virt-install PID state"),
        ('PROVISION_VIRT_START=""', "retained virt-install start identity"),
        (
            "require_cmd virt-install virsh qemu-img xorriso setsid timeout awk",
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
            'timeout --foreground --kill-after=2 "$CONTROL_TIMEOUT_SECONDS" \\\n'
            "        virsh --connect qemu:///session --no-pkttyagent \"$@\"",
            "bounded fixed session-libvirt control",
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
            'setsid --wait virt-install \\\n'
            "        --connect qemu:///session",
            "retained process-group launch",
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
        (
            'warn "provision UUID exists under an unexpected name; preserving it"',
            "ambiguous-name preservation",
        ),
        (
            "completed golden domain could not be undefined safely",
            "successful terminal teardown requirement",
        ),
        (
            "could not prove exact terminal cleanup of the provision-owned domain",
            "cleanup uncertainty failure",
        ),
        ("trap '' HUP INT TERM", "terminal cleanup signal exclusion"),
        ("trap cleanup_provision EXIT", "terminal cleanup trap"),
        ("trap 'signal_exit 129' HUP", "HUP cleanup routing"),
        ("trap 'signal_exit 130' INT", "INT cleanup routing"),
        ("trap 'signal_exit 143' TERM", "TERM cleanup routing"),
    ):
        require_text(provision, text, label)

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
        ("|| true", "suppressed lifecycle error absence"),
        (
            "independently name-owned pre-creation collision handling remains",
            "stale open-audit wording absence",
        ),
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
            "setsid --wait virt-install",
            '--uuid "$PROVISION_DOMAIN_UUID"',
            'PROVISION_VIRT_START="$(process_start_time "$PROVISION_VIRT_PID")"',
            "wait_for_owned_virt_process_group",
            "wait_for_owned_domain_creation",
        ),
        "UUID absence, creation intent, launch, and ownership order",
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

    requirement = extract_requirement(sources["requirements"], "R-S11dr")
    for text, label in (
        (
            "Windows golden provisioning owns one exact libvirt UUID and retires it terminally",
            "R-S11dr title",
        ),
        (
            "Any pre-existing name is an explicit operator-reconciliation failure",
            "pre-existing-name normative refusal",
        ),
        (
            "Creation intent <span class=\"kw\">MUST</span> be recorded only immediately before launch",
            "creation-intent normative boundary",
        ),
        (
            "one finite admission step",
            "process-group admission normative boundary",
        ),
        (
            "pre-admission exit, identity change, or deadline",
            "process-group admission failure boundary",
        ),
        (
            "every guest-specific <code>virsh</code> operation",
            "UUID-only normative control boundary",
        ),
        (
            "Domain cleanup <span class=\"kw\">MUST NOT</span> request storage deletion",
            "golden-storage preservation requirement",
        ),
        (
            "without invoking the provisioner, <code>virsh</code>, libvirt, KVM, a Windows VM",
            "source-only verification boundary",
        ),
    ):
        require_text(requirement, text, label)
    require_text(
        sources["requirements"],
        "<tr><td>271</td>",
        "Appendix C #271 disposition",
    )
    require_text(
        sources["requirements"],
        "<tr><td>291</td>",
        "Appendix C #291 disposition",
    )
    require_text(
        sources["hardening"],
        "R-S11dr/R-S11e-136 — Windows golden provisioner owns one exact libvirt UUID",
        "hardening-ledger disposition",
    )
    require_text(
        sources["hardening"],
        "R-S11dr/R-S11ds/R-S11e-170 — exact setsid process-group admission",
        "setsid-admission hardening ledger",
    )
    require_text(
        sources["verify"],
        "python3 scripts/verify-windows-golden-domain-authority.py --repo . --self-test",
        "shared source-gate wiring",
    )
    require_text(
        sources["workspace"],
        "def validate_windows_golden_domain_authority_contract(sources):",
        "independent workspace contract",
    )


def mutate(source, old, new, label):
    observed = source.count(old)
    require(
        observed == 1,
        "self-test fixture for {} occurs {} times".format(label, observed),
    )
    return source.replace(old, new, 1)


def run_self_test(sources):
    mutations = (
        (
            "provision",
            "export LC_ALL=C",
            "export LC_ALL=en_US.UTF-8",
            "fixed control-output locale",
        ),
        (
            "provision",
            "CONTROL_TIMEOUT_SECONDS=30",
            "CONTROL_TIMEOUT_SECONDS=0",
            "finite libvirt control deadline",
        ),
        (
            "provision",
            "PROCESS_ADMISSION_SECONDS=10",
            "PROCESS_ADMISSION_SECONDS=0",
            "finite process-group admission deadline",
        ),
        (
            "provision",
            "require_cmd virt-install virsh qemu-img xorriso setsid timeout awk",
            "require_cmd virt-install virsh qemu-img xorriso setsid timeout",
            "exact lifecycle command preflight",
        ),
        (
            "provision",
            'stat="$(<"/proc/$pid/stat")" || return 1\n'
            '    stat="${stat##*) }"',
            'stat="$(<"/proc/$pid/stat")" || return 1\n'
            '    stat="${stat#*) }"',
            "two robust proc-stat command boundaries",
        ),
        (
            "provision",
            'stat="$(<"$path")" || continue\n'
            '        stat="${stat##*) }"',
            'stat="$(<"$path")" || continue\n'
            '        stat="${stat#*) }"',
            "two robust proc-stat command boundaries",
        ),
        (
            "provision",
            'kill -TERM -- "-$PROVISION_VIRT_PID"',
            'kill -TERM -- "$PROVISION_VIRT_PID"',
            "exact owned process-group graceful stop",
        ),
        (
            "provision",
            "while owned_virt_process_group_is_live; do",
            "while owned_virt_process_is_live; do",
            "complete provision-client group drain",
        ),
        (
            "provision",
            "virsh --connect qemu:///session --no-pkttyagent",
            "virsh --connect qemu:///session",
            "bounded fixed session-libvirt control",
        ),
        (
            "provision",
            "list --all --name",
            'domuuid "$DOMAIN"',
            "fail-closed complete name enumeration",
        ),
        (
            "provision",
            "list --all --uuid",
            "list --uuid",
            "fail-closed complete UUID enumeration",
        ),
        (
            "provision",
            "golden domain name already exists; refusing to mutate it",
            "golden domain name already exists; destroying it",
            "pre-existing name refusal",
        ),
        (
            "provision",
            'PROVISION_DOMAIN_UUID="$(</proc/sys/kernel/random/uuid)"',
            'PROVISION_DOMAIN_UUID="00000000-0000-4000-8000-000000000000"',
            "UUID absence, creation intent, launch, and ownership order",
        ),
        (
            "provision",
            'assert_uuid "$PROVISION_DOMAIN_UUID"',
            "true # UUID grammar removed",
            "UUID absence, creation intent, launch, and ownership order",
        ),
        (
            "provision",
            "    require_domain_identity_absent\n"
            "    # NB no --tpm:",
            "    # first absence proof removed\n"
            "    # NB no --tpm:",
            "two absence proofs plus function definition",
        ),
        (
            "provision",
            "PROVISION_DOMAIN_CREATION_STARTED=1",
            "PROVISION_DOMAIN_CREATION_STARTED=0",
            "UUID absence, creation intent, launch, and ownership order",
        ),
        (
            "provision",
            "setsid --wait virt-install",
            "virt-install",
            "retained process-group launch",
        ),
        (
            "provision",
            '--uuid "$PROVISION_DOMAIN_UUID"',
            "# explicit UUID removed",
            "explicit libvirt UUID creation",
        ),
        (
            "provision",
            'PROVISION_VIRT_START="$(process_start_time "$PROVISION_VIRT_PID")"',
            'PROVISION_VIRT_START=""',
            "post-launch process identity binding",
        ),
        (
            "provision",
            "wait_for_owned_virt_process_group() {",
            "wait_for_unowned_virt_process_group() {",
            "exact process-group admission",
        ),
        (
            "provision",
            '[ "$start" = "$PROVISION_VIRT_START" ] || return 1',
            '[ -n "$start" ] || return 1',
            "admission start-identity refusal",
        ),
        (
            "provision",
            '[ "$state" != Z ] && [ "$state" != X ] || return 1',
            "true # terminal admission accepted",
            "admission live-state refusal",
        ),
        (
            "provision",
            "wait_for_owned_virt_process_group \\\n"
            '        || die "could not prove virt-install process-group admission"',
            "true # process-group admission omitted",
            "post-launch process-group admission",
        ),
        (
            "provision",
            'virsh_bounded send-key "$PROVISION_DOMAIN_UUID"',
            'virsh_bounded send-key "$DOMAIN"',
            "UUID-addressed boot-key injection",
        ),
        (
            "provision",
            'virsh_bounded destroy "$PROVISION_DOMAIN_UUID"',
            'virsh_bounded destroy "$DOMAIN"',
            "UUID-addressed destroy",
        ),
        (
            "provision",
            'virsh_bounded undefine "$PROVISION_DOMAIN_UUID" --nvram',
            'virsh_bounded undefine "$DOMAIN" --nvram',
            "UUID-addressed NVRAM undefine",
        ),
        (
            "provision",
            "stop_and_undefine_owned_domain \\\n"
            '                            || die "completed golden domain could not be undefined safely"',
            "true # successful terminal teardown removed",
            "successful terminal teardown requirement",
        ),
        (
            "provision",
            '[ "$vi_status" = 0 ] || die "virt-install failed with exit $vi_status"\n'
            "    # Preserve the old 130-minute allowance after the first guest shutdown,\n"
            "    # independently of the newly bounded install-to-first-shutdown phase.\n"
            "    PROVISION_VM_DEADLINE=$(( $(monotonic_seconds) + VM_TIMEOUT_SECONDS ))",
            '[ "$vi_status" = 0 ] || die "virt-install failed with exit $vi_status"',
            "independent first-shutdown and post-shutdown deadlines",
        ),
        (
            "provision",
            "elif ! stop_and_undefine_owned_domain; then",
            "if ! stop_and_undefine_owned_domain; then",
            "process-before-domain-before-helper terminal cleanup",
        ),
        (
            "provision",
            "trap 'signal_exit 143' TERM",
            "trap - TERM",
            "TERM cleanup routing",
        ),
        (
            "provision",
            "trap '' HUP INT TERM",
            "trap - HUP INT TERM",
            "terminal cleanup signal exclusion",
        ),
        (
            "requirements",
            '<span class="id">R-S11dr</span>',
            '<span class="id">R-S11dr-disabled</span>',
            "R-S11dr requirement",
        ),
        (
            "requirements",
            "Any pre-existing name is an explicit operator-reconciliation failure",
            "Any pre-existing name may be destroyed automatically",
            "pre-existing-name normative refusal",
        ),
        (
            "requirements",
            "one finite admission step",
            "an optional admission step",
            "process-group admission normative boundary",
        ),
        (
            "requirements",
            "<tr><td>271</td>",
            "<tr><td>271-disabled</td>",
            "Appendix C #271 disposition",
        ),
        (
            "requirements",
            "<tr><td>291</td>",
            "<tr><td>291-disabled</td>",
            "Appendix C #291 disposition",
        ),
        (
            "hardening",
            "R-S11dr/R-S11e-136 — Windows golden provisioner owns one exact libvirt UUID",
            "R-S11dr/R-S11e-136 — Windows golden provisioner owns a mutable name",
            "hardening-ledger disposition",
        ),
        (
            "hardening",
            "R-S11dr/R-S11ds/R-S11e-170 — exact setsid process-group admission",
            "R-S11dr/R-S11ds/R-S11e-170 — ambient setsid process-group admission",
            "setsid-admission hardening ledger",
        ),
        (
            "verify",
            "python3 scripts/verify-windows-golden-domain-authority.py --repo . --self-test",
            "true # golden domain authority gate removed",
            "shared source-gate wiring",
        ),
        (
            "workspace",
            "def validate_windows_golden_domain_authority_contract(sources):",
            "def validate_windows_golden_name_authority_contract(sources):",
            "independent workspace contract",
        ),
    )
    for key, old, new, expected in mutations:
        candidate = dict(sources)
        candidate[key] = mutate(candidate[key], old, new, expected)
        try:
            validate(candidate)
        except VerificationError as exc:
            require(
                expected in str(exc),
                "self-test wrong failure for {}: {}".format(expected, exc),
            )
        else:
            raise VerificationError(
                "self-test mutation unexpectedly accepted: {}".format(expected)
            )
    return len(mutations)


def load_sources(repo):
    paths = {
        "provision": "scripts/provision-windows-vm.sh",
        "requirements": "requirements.html",
        "hardening": "HARDENING_STATUS.md",
        "verify": "scripts/verify.sh",
        "workspace": "scripts/verify-verifier-workspace.py",
    }
    return {
        key: (repo / relative).read_text(encoding="utf-8")
        for key, relative in paths.items()
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    sources = load_sources(args.repo.resolve())
    validate(sources)
    count = run_self_test(sources) if args.self_test else 0
    if args.self_test:
        print(
            "verify-windows-golden-domain-authority: ok "
            "({} mutations)".format(count)
        )
    else:
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
