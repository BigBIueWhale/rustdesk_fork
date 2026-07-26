#!/usr/bin/env python3
"""Verify that generic cleanup has no guessed destructive ownership."""

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
    cleanup = sources["cleanup"]
    if re.search(r"(?i)\bdocker\b", cleanup):
        raise VerificationError("cleanup Docker authority absence")

    for forbidden, label in (
        ("clean_ephemeral", "cleanup legacy generic mutator absence"),
        ("HARNESS_PREFIX", "cleanup name-prefix ownership absence"),
        ("winvm", "cleanup legacy PID/socket namespace absence"),
        ("qemu:///session", "cleanup session-libvirt authority absence"),
        ("$STATE_DIR/overlays", "cleanup overlay-path authority absence"),
        ("monitor.sock", "cleanup guessed monitor-socket deletion absence"),
        ("tpm.sock", "cleanup guessed TPM-socket deletion absence"),
    ):
        require(forbidden not in cleanup, label)
    require(
        re.search(r"(^|[;&|\s])kill(?:\s|$)", cleanup) is None,
        "cleanup process-signal authority absence",
    )

    expected_report = (
        "report_transaction_owned_cleanup() {\n"
        '    log "no generic ephemeral cleanup performed; each creating transaction '
        "owns exact terminal cleanup (use explicit manifest-backed flags for "
        'recorded host state)"\n'
        "}"
    )
    require(
        cleanup.count("report_transaction_owned_cleanup() {") == 1,
        "cleanup no-argument reporter cardinality",
    )
    require_text(
        cleanup,
        expected_report,
        "cleanup no-argument nonmutating reporter",
    )
    require_text(
        cleanup,
        '        "")             report_transaction_owned_cleanup ;;',
        "cleanup default dispatch ownership report",
    )
    require_text(
        cleanup,
        "--build-host-network) cleanup_build_host_network",
        "cleanup explicit recorded-network mode",
    )
    require_text(
        cleanup,
        "--reverse-host) reverse_host",
        "cleanup explicit recorded-package mode",
    )

    readme = sources["readme"]
    for text, label in (
        (
            "the default cleanup mode does not infer ownership from a PID file, a\n"
            "domain-name prefix, or a directory pathname",
            "cleanup ownership documentation",
        ),
        (
            "Current build transactions close\n"
            "their exact retained process/domain/state identities themselves",
            "creator-owned terminal cleanup documentation",
        ),
        (
            "Legacy\n"
            "unowned leftovers require explicit operator reconciliation",
            "legacy ambiguous-state documentation",
        ),
    ):
        require_text(readme, text, label)

    requirement = extract_requirement(sources["requirements"], "R-S11dq")
    for text, label in (
        (
            "Generic cleanup has no PID-file, session-domain-name, or pathname-derived destructive ownership",
            "cleanup authority requirement title",
        ),
        (
            "MUST</span> perform no mutation",
            "cleanup no-argument no-mutation requirement",
        ),
        (
            "MUST NOT</span> read or act on a PID file, signal a process, enumerate/control a session-libvirt domain",
            "cleanup guessed-process/domain prohibition",
        ),
        (
            "golden-image provisioner's formerly name-owned collision path is independently closed by R-S11dr",
            "cleanup independent golden-provision boundary",
        ),
        (
            "without invoking cleanup, signaling a process, querying libvirt, deleting a file, or inspecting/mutating host state",
            "cleanup source-only verification boundary",
        ),
    ):
        require_text(requirement, text, label)

    require_text(
        sources["requirements"],
        "<tr><td>270</td>",
        "cleanup authority Appendix C row",
    )
    require_text(
        sources["hardening"],
        "R-S11dq/R-S11e-135 — generic cleanup has no PID-file, session-domain-name, or pathname-derived destructive ownership",
        "cleanup authority hardening ledger",
    )
    require_text(
        sources["verify"],
        "python3 scripts/verify-cleanup-authority.py --repo . --self-test",
        "cleanup focused gate wiring",
    )
    require_text(
        sources["workspace"],
        "def validate_cleanup_process_domain_path_authority_contract(sources):",
        "cleanup independent workspace contract",
    )


def mutate(source, old, new, label):
    require(old in source, "self-test fixture missing: {}".format(label))
    return source.replace(old, new, 1)


def run_self_test(sources):
    mutations = (
        (
            "cleanup",
            "report_transaction_owned_cleanup() {\n",
            "clean_ephemeral() {\n",
            "cleanup legacy generic mutator absence",
        ),
        (
            "cleanup",
            "report_transaction_owned_cleanup() {\n",
            'HARNESS_PREFIX="guessed"\nreport_transaction_owned_cleanup() {\n',
            "cleanup name-prefix ownership absence",
        ),
        (
            "cleanup",
            "report_transaction_owned_cleanup() {\n",
            'winvm="$STATE_DIR/winvm"\nreport_transaction_owned_cleanup() {\n',
            "cleanup legacy PID/socket namespace absence",
        ),
        (
            "cleanup",
            "report_transaction_owned_cleanup() {\n",
            "virsh --connect qemu:///session list --all\n"
            "report_transaction_owned_cleanup() {\n",
            "cleanup session-libvirt authority absence",
        ),
        (
            "cleanup",
            "report_transaction_owned_cleanup() {\n",
            'rm -f "$STATE_DIR/overlays/"*.qcow2\n'
            "report_transaction_owned_cleanup() {\n",
            "cleanup overlay-path authority absence",
        ),
        (
            "cleanup",
            "report_transaction_owned_cleanup() {\n",
            "kill 12345\nreport_transaction_owned_cleanup() {\n",
            "cleanup process-signal authority absence",
        ),
        (
            "cleanup",
            '    log "no generic ephemeral cleanup performed; each creating transaction '
            "owns exact terminal cleanup (use explicit manifest-backed flags for "
            'recorded host state)"',
            "    true",
            "cleanup no-argument nonmutating reporter",
        ),
        (
            "cleanup",
            '        "")             report_transaction_owned_cleanup ;;',
            '        "")             true ;;',
            "cleanup default dispatch ownership report",
        ),
        (
            "readme",
            "the default cleanup mode does not infer ownership from a PID file, a\n"
            "domain-name prefix, or a directory pathname",
            "the default cleanup mode may infer ownership from a PID file, a\n"
            "domain-name prefix, or a directory pathname",
            "cleanup ownership documentation",
        ),
        (
            "requirements",
            '<span class="id">R-S11dq</span>',
            '<span class="id">R-S11dq-disabled</span>',
            "R-S11dq requirement",
        ),
        (
            "requirements",
            "MUST</span> perform no mutation",
            "MAY</span> perform mutation",
            "cleanup no-argument no-mutation requirement",
        ),
        (
            "requirements",
            "MUST NOT</span> read or act on a PID file, signal a process, enumerate/control a session-libvirt domain",
            "MAY</span> read or act on a PID file, signal a process, enumerate/control a session-libvirt domain",
            "cleanup guessed-process/domain prohibition",
        ),
        (
            "requirements",
            "<tr><td>270</td>",
            "<tr><td>270-disabled</td>",
            "cleanup authority Appendix C row",
        ),
        (
            "hardening",
            "R-S11dq/R-S11e-135 — generic cleanup has no PID-file, session-domain-name, or pathname-derived destructive ownership",
            "R-S11dq/R-S11e-135 — generic cleanup retains guessed destructive ownership",
            "cleanup authority hardening ledger",
        ),
        (
            "verify",
            "python3 scripts/verify-cleanup-authority.py --repo . --self-test",
            "true # cleanup authority gate removed",
            "cleanup focused gate wiring",
        ),
        (
            "workspace",
            "def validate_cleanup_process_domain_path_authority_contract(sources):",
            "validate_cleanup_guessed_authority_contract",
            "cleanup independent workspace contract",
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
        "cleanup": "scripts/cleanup.sh",
        "readme": "scripts/README.md",
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
        print("verify-cleanup-authority: ok ({} mutations)".format(count))
    else:
        print("verify-cleanup-authority: ok")


if __name__ == "__main__":
    try:
        main()
    except (OSError, VerificationError) as exc:
        print("verify-cleanup-authority: {}".format(exc), file=sys.stderr)
        sys.exit(1)
