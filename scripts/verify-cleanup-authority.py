#!/usr/bin/env python3
"""Supplementary source invariant for generic cleanup's authority boundary."""

import argparse
import re
import sys
from pathlib import Path


class VerificationError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise VerificationError(message)


def validate(cleanup):
    require(
        re.search(r"(?i)\bdocker\b", cleanup) is None,
        "cleanup Docker authority absence",
    )
    for forbidden, label in (
        ("clean_ephemeral", "legacy generic mutator"),
        ("HARNESS_PREFIX", "name-prefix ownership"),
        ("winvm", "legacy PID/socket namespace"),
        ("qemu:///session", "session-libvirt authority"),
        ("$STATE_DIR/overlays", "overlay-path authority"),
        ("monitor.sock", "guessed monitor-socket deletion"),
        ("tpm.sock", "guessed TPM-socket deletion"),
    ):
        require(forbidden not in cleanup, "cleanup contains " + label)
    require(
        re.search(r"(^|[;&|\s])kill(?:\s|$)", cleanup) is None,
        "cleanup process-signal authority absence",
    )

    report = (
        "report_transaction_owned_cleanup() {\n"
        '    log "no generic ephemeral cleanup performed; each creating transaction '
        "owns exact terminal cleanup (use explicit manifest-backed flags for "
        'recorded host state)"\n'
        "}"
    )
    require(cleanup.count("report_transaction_owned_cleanup() {") == 1,
            "cleanup reporter cardinality")
    require(report in cleanup, "cleanup nonmutating reporter")
    require(
        '        "")             report_transaction_owned_cleanup ;;' in cleanup,
        "cleanup default dispatch",
    )
    require(
        "--build-host-network) cleanup_build_host_network" in cleanup,
        "cleanup explicit recorded-network mode",
    )
    require(
        "--reverse-host) reverse_host" in cleanup,
        "cleanup explicit recorded-package mode",
    )
    require(cleanup.rstrip().endswith('main "$@"'), "cleanup entrypoint")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    args = parser.parse_args()
    cleanup = (args.repo.resolve() / "scripts/cleanup.sh").read_text(encoding="utf-8")
    validate(cleanup)
    print("verify-cleanup-authority: ok (source only)")


if __name__ == "__main__":
    try:
        main()
    except (OSError, VerificationError) as exc:
        print("verify-cleanup-authority: {}".format(exc), file=sys.stderr)
        sys.exit(1)
