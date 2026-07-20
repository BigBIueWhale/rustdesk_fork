#!/usr/bin/env python3
"""Mutation-bind Rust advisory freshness, finality, and Docker authority."""

import argparse
from pathlib import Path
import re
import sys


class ContractError(RuntimeError):
    pass


class Mutation:
    def __init__(self, source, old, new, label):
        self.source = source
        self.old = old
        self.new = new
        self.label = label


def require(condition, message):
    if not condition:
        raise ContractError(message)


def require_all(source, tokens, label):
    for token in tokens:
        require(token in source, "{}: missing {!r}".format(label, token))


def run_block(shell, start_token, end_token):
    start_anchor = shell.index(start_token)
    start = shell.index("run_bounded_docker run ", start_anchor)
    end = shell.index(end_token, start) + len(end_token)
    return shell[start:end]


def validate_run(block, label):
    require_all(
        block,
        (
            "--rm",
            "--pull=never",
            "--network=none",
            "--read-only",
            '--user "$(id -u):$(id -g)"',
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--pids-limit=",
            "--memory=",
            "--memory-swap=",
            "--cpus=",
            "noexec,nosuid,nodev",
            '"$IMAGE_ID"',
        ),
        label,
    )
    for forbidden in (
        "docker.sock",
        "--privileged",
        "--cap-add",
        "--pid=host",
        "--pid host",
        "--ipc=host",
        "--ipc host",
        "--uts=host",
        "--uts host",
        "--network=host",
        "--network host",
        "--publish",
        "--expose",
        "--volume",
        "-v ",
        "--pull=always",
        '"$RUST_AUDIT_IMAGE_ID" /bin/bash',
        "2>/dev/null",
    ):
        require(forbidden not in block, "{} has forbidden authority {!r}".format(label, forbidden))
    docker_arguments = block[: block.index('"$IMAGE_ID"')]
    require(
        re.search(r"(?:^|\s)-p(?:\s|=)", docker_arguments) is None,
        "{} publishes a port".format(label),
    )


def validate_contract(sources):
    shell = sources["shell"]
    policy = sources["policy"]
    pins = sources["pins"]
    provenance = sources["provenance"]
    verify = sources["verify"]
    requirements = sources["requirements"]
    hardening = sources["hardening"]
    validator = sources["validator"]

    require(shell.count("run_bounded_docker run ") == 3, "Rust audit must have exactly three Docker launches")
    require(
        shell.count('ulimit -Sf "$MAX_SCANNER_OUTPUT_BLOCKS"') == 2,
        "Rust audit must cap both unlimited and overly broad scanner output limits",
    )
    require(
        shell.count("scripts/online-input-provenance.py verify-subtree") == 2,
        "Rust audit must verify the vendor closure before and after scanner use",
    )
    require_all(
        shell,
        (
            "source \"$SCRIPT_DIR/lib.sh\"",
            "load_pins",
            "readonly DOCKER_BIN=/usr/bin/docker",
            "readonly PYTHON_BIN=/usr/bin/python3",
            "readonly MAX_SCANNER_OUTPUT_BLOCKS=65536",
            'current_limit="$(ulimit -Sf)"',
            'if (( current_limit > MAX_SCANNER_OUTPUT_BLOCKS )); then',
            'ulimit -Sf "$MAX_SCANNER_OUTPUT_BLOCKS"',
            'exec "$DOCKER_BIN" "$@"',
            '[ "$(id -u)" -ne 0 ] || audit_die "refuses host or container-root execution"',
            '[ "$(id -g)" -ne 0 ] || audit_die "refuses a root primary group"',
            '[ -f "$LOCKFILE" ] && [ ! -L "$LOCKFILE" ]',
            '[ -f "$POLICY" ] && [ ! -L "$POLICY" ]',
            '[ -d "$VENDOR_DIR" ] && [ ! -L "$VENDOR_DIR" ]',
            'AUDIT_TMP="$(umask 077 && mktemp -d /tmp/rustdesk-rust-audit.XXXXXXXXXX)"',
            'AUDIT_TMP_ID="$(/usr/bin/stat -c \'%d:%i\' -- "$AUDIT_TMP")"',
            '--remove-private-root "$AUDIT_TMP" --expected-identity "$AUDIT_TMP_ID"',
            "scripts/rust-audit-policy.py prepare",
            "scripts/rust-audit-policy.py check-freshness",
            '--max-age-days "$ADVISORY_DB_MAX_AGE_DAYS"',
            "scripts/online-input-provenance.py verify-subtree",
            '--expected "$SHA256_CARGO_VENDOR_CLOSURE_V1"',
            "IMAGE_ID=\"$($DOCKER_BIN image inspect --format '{{.Id}}' \"$RUST_AUDIT_IMAGE_ID\")\"",
            '[ "$IMAGE_ID" = "$RUST_AUDIT_IMAGE_ID" ]',
            "SHA256_RUST_AUDIT_CARGO_AUDIT",
            "SHA256_RUST_AUDIT_CARGO_DENY",
            "git -c safe.directory=/opt/advisory-db",
            'mapfile -t IGNORE_IDS <"$AUDIT_TMP/accepted-ids.txt"',
            'IGNORE_FLAGS+=(--ignore "$advisory_id")',
            "scripts/rust-audit-policy.py validate-audit-result",
            '--expected-db-commit "$ADVISORY_DB_COMMIT"',
            "scripts/rust-audit-policy.py validate-deny-result",
            'AUDIT_SUCCESS_MESSAGE="VERIFY-AUDIT: green',
        ),
        "Rust audit shell authority",
    )
    require(
        shell.index("scripts/rust-audit-policy.py prepare")
        < shell.index("scripts/rust-audit-policy.py check-freshness")
        < shell.index("$DOCKER_BIN image inspect"),
        "policy/freshness must precede Docker authority",
    )
    require(
        shell.rindex("scripts/online-input-provenance.py verify-subtree")
        < shell.index('AUDIT_SUCCESS_MESSAGE="VERIFY-AUDIT: green'),
        "vendor postcondition must precede green",
    )
    for forbidden in (
        "$DOCKER_BIN build",
        "docker build",
        "Dockerfile.audit",
        "rd-cargo-cache",
        "rd-cargo-git-cache",
        "|| true",
        "IMG=rd-audit",
    ):
        require(forbidden not in shell, "Rust audit retained forbidden path {!r}".format(forbidden))

    preflight = run_block(shell, "IMAGE_PREFLIGHT_OUT=", "IMAGE_PREFLIGHT_STATUS=$?")
    audit = run_block(shell, "AUDIT_RESULT=", "CARGO_AUDIT_STATUS=$?")
    deny = run_block(shell, "DENY_OUTPUT=", "CARGO_DENY_STATUS=$?")
    validate_run(preflight, "Rust audit image preflight")
    validate_run(audit, "cargo-audit launch")
    validate_run(deny, "cargo-deny launch")
    require_all(
        preflight,
        (
            "--pids-limit=32",
            "--memory=256m",
            "--memory-swap=256m",
            "--cpus=1",
            "--tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777,size=16m",
        ),
        "Rust audit image preflight resources",
    )
    require_all(
        audit,
        (
            "--pids-limit=64",
            "--memory=512m",
            "--memory-swap=512m",
            "--cpus=2",
            "--tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777,size=32m",
        ),
        "cargo-audit resources",
    )
    require_all(
        deny,
        (
            "--pids-limit=256",
            "--memory=2g",
            "--memory-swap=2g",
            "--cpus=2",
            "--tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777,size=512m",
        ),
        "cargo-deny resources",
    )
    require(preflight.count("--mount ") == 0, "image preflight must have no bind mount")
    require(audit.count("--mount ") == 1, "cargo-audit must have exactly one bind mount")
    require(deny.count("--mount ") == 3, "cargo-deny must have exactly three bind mounts")
    require_all(
        audit,
        (
            '--mount "type=bind,source=$AUDIT_TMP,target=/audit,readonly"',
            "cargo-audit audit --file /audit/Cargo.lock --db /opt/advisory-db --no-fetch --deny warnings --json",
            '"${IGNORE_FLAGS[@]}" >"$AUDIT_RESULT" 2>"$AUDIT_ERROR"',
        ),
        "cargo-audit exact input/result",
    )
    require_all(
        deny,
        (
            "--tmpfs /work/.cargo:rw,noexec,nosuid,nodev,mode=0700,size=1m",
            "--tmpfs /work/.git:rw,noexec,nosuid,nodev,mode=0700,size=1m",
            "--tmpfs /work/.harness-state:rw,noexec,nosuid,nodev,mode=0700,size=1m",
            "--tmpfs /work/online:rw,noexec,nosuid,nodev,mode=0700,size=1m",
            "--tmpfs /work/target:rw,noexec,nosuid,nodev,mode=0700,size=1m",
            "--tmpfs /work/flutter/.dart_tool:rw,noexec,nosuid,nodev,mode=0700,size=1m",
            "--tmpfs /work/flutter/build:rw,noexec,nosuid,nodev,mode=0700,size=1m",
            '--mount "type=bind,source=$REPO_ROOT,target=/work,readonly"',
            '--mount "type=bind,source=$AUDIT_TMP,target=/audit,readonly"',
            '--mount "type=bind,source=$REPO_ROOT/$VENDOR_DIR,target=/vendor,readonly"',
            "cp -a -- /opt/advisory-db \"$db\"",
            'cp -- /audit/cargo.config.toml /tmp/cargo-home/config.toml',
            "cargo-deny --format json --locked --offline",
            "check -c /audit/deny.runtime.toml advisories --disable-fetch",
            '>"$DENY_OUTPUT" 2>"$DENY_ERROR"',
        ),
        "cargo-deny exact input/result",
    )

    require_all(
        pins,
        (
            'ADVISORY_DB_COMMIT="4ea955aed4d1b1214badc01f9d029bb12ef9e8e4"',
            'ADVISORY_DB_COMMIT_EPOCH="1764461716"',
            'ADVISORY_DB_MAX_AGE_DAYS="90"',
            'RUST_AUDIT_IMAGE_ID="sha256:6dbb956dd764140aa3a75bbae9280ac91e3b1efe7552d7d97f33ef59dcf06bcc"',
            'SHA256_CARGO_VENDOR_CLOSURE_V1="96c8e717dc14458e3ddf0a4a7c26a1d3567f67e2557b6438ef6331afcdd4f503"',
            'SHA256_CARGO_VENDOR_CONFIG="f64f7237f0e67631bbc7c620bea9d5dafe89a07f50caf1f6a54e07757a2145d6"',
        ),
        "Rust audit pins",
    )
    require_all(
        policy,
        (
            "metadata.st_nlink == 1",
            "metadata.st_mtime_ns",
            'advisories.get("db-urls") == EXPECTED_DB_URLS',
            'set(entry) == {"id", "reason"}',
            "advisory_id not in seen",
            'advisories.get("yanked") == "warn"',
            'enabled = false',
            'update_index = false',
            'yanked = "allow"',
            'directory = "/vendor"',
            'offline = true',
            'maximum_days == 90',
            'age <= maximum_days * 86400',
            'result_status == 0',
            'database["last-commit"] in (None, expected_db_commit)',
            'sorted(result_ignores) == accepted',
            'vulnerabilities.get("found") is (count != 0)',
            'value.get("warnings") == {}',
            'code == "advisory-not-detected" and severity == "warning"',
            'advisories["errors"] == 0',
            "require(checks == 20",
        ),
        "Rust audit policy/result authority",
    )
    require(
        policy.count("result_status == 0") == 2,
        "both Rust scanners must require exact status zero",
    )
    require_all(
        provenance,
        (
            "def verify_subtree(tree: Path, expected: str) -> Result:",
            'subparsers.add_parser("verify-subtree")',
            'elif args.command == "verify-subtree":',
            "verify_subtree(tree, original.root)",
        ),
        "vendor subtree provenance",
    )
    require_all(
        verify,
        (
            "python3 scripts/rust-audit-policy.py --self-test",
            "python3 scripts/verify-rust-audit-authority.py --repo . --self-test",
            'ADVISORY_DB_MAX_AGE_DAYS="90"',
        ),
        "shared verifier wiring",
    )
    require('<span class="id">R-S11bf</span>' in requirements, "requirements are missing R-S11bf")
    require("<tr><td>183</td>" in requirements, "requirements are missing Appendix C #183")
    require("currently pinned 2025-11-30 RustSec snapshot is stale" in requirements, "stale DB release status is missing")
    require(
        "R-S11bf/R-S11e-72 — Rust advisory freshness, result finality, and scanner authority" in hardening,
        "hardening ledger is missing the Rust audit closure",
    )
    require("neither this item nor the overall release is claimed complete" in hardening, "ledger overclaims completion")

    mutation_text = validator[validator.index("\nMUTATIONS = (") : validator.index("\n)\n\n\ndef mutate_once")]
    require_all(
        mutation_text,
        (
            'Mutation("shell", "--network=none", "--network=bridge"',
            'Mutation("shell", \'ulimit -Sf "$MAX_SCANNER_OUTPUT_BLOCKS"\'',
            'Mutation("shell", "scripts/rust-audit-policy.py check-freshness"',
            'Mutation("shell", "--deny warnings --json", "--json"',
            'Mutation("policy", "maximum_days == 90", "maximum_days >= 90"',
            'Mutation("policy", "metadata.st_mtime_ns", "opened.st_mtime_ns"',
            'Mutation("policy", \'value.get("warnings") == {}\'',
            'Mutation("policy", \'code == "advisory-not-detected" and severity == "warning"\'',
            'Mutation("verify", "python3 scripts/verify-rust-audit-authority.py --repo . --self-test"',
            'Mutation("requirements", \'<span class="id">R-S11bf</span>\'',
            'Mutation("hardening", "R-S11bf/R-S11e-72 — Rust advisory freshness, result finality, and scanner authority"',
        ),
        "Rust audit validator mutation coverage",
    )


MUTATIONS = (
    Mutation("shell", '[ "$(id -u)" -ne 0 ]', '[ "$(id -u)" -ge 0 ]', "UID-root refusal"),
    Mutation("shell", '[ "$(id -g)" -ne 0 ]', '[ "$(id -g)" -ge 0 ]', "GID-root refusal"),
    Mutation("shell", '[ ! -L "$LOCKFILE" ]', '[ -e "$LOCKFILE" ]', "lockfile link refusal"),
    Mutation("shell", '[ ! -L "$POLICY" ]', '[ -e "$POLICY" ]', "policy link refusal"),
    Mutation("shell", "scripts/rust-audit-policy.py prepare", "printf 34 # prepare", "private policy staging"),
    Mutation("shell", "scripts/rust-audit-policy.py check-freshness", "printf fresh # check-freshness", "DB freshness"),
    Mutation("shell", '--max-age-days "$ADVISORY_DB_MAX_AGE_DAYS"', '--max-age-days 9999', "freshness pin use"),
    Mutation("shell", '$DOCKER_BIN image inspect --format', 'printf sha256: # $DOCKER_BIN image inspect --format', "image identity"),
    Mutation("shell", '[ "$IMAGE_ID" = "$RUST_AUDIT_IMAGE_ID" ]', '[ -n "$IMAGE_ID" ]', "content-ID equality"),
    Mutation("shell", 'ulimit -Sf "$MAX_SCANNER_OUTPUT_BLOCKS"', ': # output limit', "host output bound"),
    Mutation("shell", "--pull=never", "--pull=always", "pull refusal"),
    Mutation("shell", "--network=none", "--network=bridge", "network isolation"),
    Mutation("shell", "--read-only", "--hostname=rust-audit", "read-only root"),
    Mutation("shell", '--user "$(id -u):$(id -g)"', '--user 0:0', "nonroot container"),
    Mutation("shell", "--cap-drop=ALL", "--cap-add=SYS_ADMIN", "capability drop"),
    Mutation("shell", "--security-opt=no-new-privileges", "--security-opt=label=disable", "no-new-privileges"),
    Mutation("shell", "--pids-limit=32", "--pids-limit=-1", "PID bound"),
    Mutation("shell", "--memory=256m", "--memory=0", "memory bound"),
    Mutation("shell", "--memory-swap=256m", "--memory-swap=-1", "swap bound"),
    Mutation("shell", "noexec,nosuid,nodev", "exec,suid,dev", "tmpfs hardening"),
    Mutation("shell", '--mount "type=bind,source=$AUDIT_TMP,target=/audit,readonly"', '-v "$PWD:/audit:rw"', "audit input mount"),
    Mutation("shell", '--mount "type=bind,source=$REPO_ROOT,target=/work,readonly"', '-v "$PWD:/work:rw"', "source mount"),
    Mutation("shell", "cargo-audit audit --file /audit/Cargo.lock", "cargo-audit audit --file /work/Cargo.lock", "exact lock scan"),
    Mutation("shell", "--deny warnings --json", "--json", "cargo-audit warning finality"),
    Mutation("shell", "cargo-deny --format json --locked --offline", "cargo-deny --format json", "locked offline deny"),
    Mutation("shell", "scripts/rust-audit-policy.py validate-audit-result", "true # validate-audit-result", "audit result finality"),
    Mutation("shell", "scripts/rust-audit-policy.py validate-deny-result", "true # validate-deny-result", "deny result finality"),
    Mutation("shell", "scripts/online-input-provenance.py verify-subtree", "true # verify-subtree", "vendor closure"),
    Mutation("policy", "metadata.st_nlink == 1", "metadata.st_nlink >= 1", "hardlink refusal"),
    Mutation("policy", "metadata.st_mtime_ns", "opened.st_mtime_ns", "open-race stability"),
    Mutation("policy", 'set(entry) == {"id", "reason"}', 'set(entry) >= {"id"}', "reason-bearing policy"),
    Mutation("policy", "maximum_days == 90", "maximum_days >= 90", "exact freshness policy"),
    Mutation("policy", "age <= maximum_days * 86400", "age >= 0", "stale refusal"),
    Mutation("policy", "result_status == 0", "result_status >= 0", "scanner status finality"),
    Mutation("policy", 'sorted(result_ignores) == accepted', 'set(result_ignores) >= set(accepted)', "exact accepts"),
    Mutation("policy", 'value.get("warnings") == {}', 'isinstance(value.get("warnings"), dict)', "audit warning finality"),
    Mutation("policy", 'code == "advisory-not-detected" and severity == "warning"', 'severity == "warning"', "deny diagnostic allowlist"),
    Mutation("policy", 'advisories["errors"] == 0', 'advisories["errors"] >= 0', "deny zero errors"),
    Mutation("policy", "require(checks == 20", "require(checks >= 0", "behavioral self-test count"),
    Mutation("pins", 'ADVISORY_DB_MAX_AGE_DAYS="90"', 'ADVISORY_DB_MAX_AGE_DAYS="900"', "freshness pin"),
    Mutation("pins", 'RUST_AUDIT_IMAGE_ID="sha256:6dbb956d', 'RUST_AUDIT_IMAGE_ID="rd-audit-', "image content pin"),
    Mutation("provenance", "def verify_subtree(tree: Path, expected: str) -> Result:", "def ignored_subtree(tree: Path, expected: str) -> Result:", "subtree verifier"),
    Mutation("verify", "python3 scripts/verify-rust-audit-authority.py --repo . --self-test", "python3 scripts/verify-rust-audit-authority.py --repo .", "shared mutation gate"),
    Mutation("requirements", '<span class="id">R-S11bf</span>', '<span class="id">R-S11bf-disabled</span>', "normative requirement"),
    Mutation("requirements", "<tr><td>183</td>", "<tr><td>183-disabled</td>", "Appendix disposition"),
    Mutation("hardening", "R-S11bf/R-S11e-72 — Rust advisory freshness, result finality, and scanner authority", "R-S11bf/R-S11e-72 — Rust audit deferred", "hardening ledger"),
)


def mutate_once(sources, mutation):
    source = sources[mutation.source]
    require(mutation.old in source, "self-test mutation {!r} matched zero times".format(mutation.label))
    changed = dict(sources)
    changed[mutation.source] = source.replace(mutation.old, mutation.new, 1)
    return changed


def load_sources(repo):
    return {
        "shell": (repo / "scripts/audit.sh").read_text(encoding="utf-8"),
        "policy": (repo / "scripts/rust-audit-policy.py").read_text(encoding="utf-8"),
        "pins": (repo / "scripts/pins.env").read_text(encoding="utf-8"),
        "provenance": (repo / "scripts/online-input-provenance.py").read_text(encoding="utf-8"),
        "verify": (repo / "scripts/verify.sh").read_text(encoding="utf-8"),
        "requirements": (repo / "requirements.html").read_text(encoding="utf-8"),
        "hardening": (repo / "HARDENING_STATUS.md").read_text(encoding="utf-8"),
        "validator": (repo / "scripts/verify-rust-audit-authority.py").read_text(encoding="utf-8"),
    }


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path("."))
    parser.add_argument("--self-test", action="store_true")
    arguments = parser.parse_args(argv)
    try:
        sources = load_sources(arguments.repo.resolve())
        validate_contract(sources)
        if arguments.self_test:
            for mutation in MUTATIONS:
                try:
                    validate_contract(mutate_once(sources, mutation))
                except ContractError:
                    continue
                raise ContractError("self-test mutation was accepted: {}".format(mutation.label))
            print(
                "verify-rust-audit-authority: ok ({} deliberate mutations rejected)".format(
                    len(MUTATIONS)
                )
            )
        else:
            print("verify-rust-audit-authority: ok")
        return 0
    except (ContractError, OSError, UnicodeError, ValueError) as exc:
        print("verify-rust-audit-authority: {}".format(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
