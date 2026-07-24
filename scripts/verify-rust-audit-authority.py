#!/usr/bin/env python3
"""Mutation-bind Rust advisory freshness, finality, and Docker authority."""

import argparse
import hashlib
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


def validate_dockerfile(dockerfile):
    require_all(
        dockerfile,
        (
            "ARG RUST_AUDIT_RUST_VERSION=1.88",
            "ARG CARGO_AUDIT_VERSION=0.22.2",
            "ARG CARGO_DENY_VERSION=0.20.2",
            "FROM rust:${RUST_AUDIT_RUST_VERSION}-bookworm@${BASE_DIGEST} AS builder",
            "FROM rust:${RUST_AUDIT_RUST_VERSION}-bookworm@${BASE_DIGEST} AS runtime",
            'cargo install --root "$AUDIT_TOOLS" --locked',
            '--version "$CARGO_AUDIT_VERSION" cargo-audit',
            '--version "$CARGO_DENY_VERSION" cargo-deny',
            'git -c protocol.version=2 -C "$ADVISORY_DB" fetch -q --depth=1 origin "$ADVISORY_DB_SHA"',
            'git -C "$ADVISORY_DB" checkout -q --detach FETCH_HEAD',
            "COPY --from=builder --chown=1000:1000",
            'org.rustdesk.audit.run-user="1000:1000"',
        ),
        "Rust audit acquisition recipe",
    )
    require(dockerfile.count("\nFROM ") == 2, "Rust audit recipe must have exactly two stages")
    require(dockerfile.count("\nUSER 1000:1000\n") == 2, "both audit-image stages must set numeric nonroot user")
    require(dockerfile.count("\nRUN ") == 5, "Rust audit recipe must have exactly five rootless RUN instructions")
    require(dockerfile.count("--locked") == 2, "both scanner installs must use packaged lockfiles")
    copy_lines = [line for line in dockerfile.splitlines() if line.startswith("COPY ")]
    require(len(copy_lines) == 2, "runtime image must have exactly two COPY instructions")
    require(
        all(line == "COPY --from=builder --chown=1000:1000 \\" for line in copy_lines),
        "runtime image may copy only from the rootless builder stage",
    )
    for stage_number, stage in enumerate(dockerfile.split("\nFROM ")[1:], 1):
        require("\nUSER 1000:1000\n" in stage, "stage {} lacks numeric user".format(stage_number))
        user_position = stage.index("\nUSER 1000:1000\n")
        for run in re.finditer(r"(?m)^RUN ", stage):
            require(run.start() > user_position, "stage {} executes RUN before USER".format(stage_number))
    for forbidden in (
        "apt-get",
        "sudo",
        "USER root",
        "USER 0",
        "RUN --mount",
        "ADD ",
        "COPY .",
        "COPY scripts",
        "EXPOSE ",
        "ENTRYPOINT ",
        "--privileged",
        "--cap-add",
    ):
        require(forbidden not in dockerfile, "Rust audit recipe has forbidden authority {!r}".format(forbidden))


def validate_contract(sources):
    shell = sources["shell"]
    dockerfile = sources["dockerfile"]
    policy = sources["policy"]
    pins = sources["pins"]
    provenance = sources["provenance"]
    verify = sources["verify"]
    requirements = sources["requirements"]
    hardening = sources["hardening"]
    validator = sources["validator"]

    validate_dockerfile(dockerfile)

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
            "readonly AUDIT_IMAGE_ROOT=/var/tmp/rustdesk-rust-audit",
            'readonly AUDIT_IMAGE_DB="$AUDIT_IMAGE_ROOT/advisory-db"',
            'readonly AUDIT_IMAGE_CARGO_AUDIT="$AUDIT_IMAGE_ROOT/tools/bin/cargo-audit"',
            'readonly AUDIT_IMAGE_CARGO_DENY="$AUDIT_IMAGE_ROOT/tools/bin/cargo-deny"',
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
            "IMAGE_METADATA=\"$($DOCKER_BIN image inspect --format",
            'EXPECTED_IMAGE_METADATA="$IMAGE_ID|linux|amd64|1000:1000|rust:${RUST_AUDIT_RUST_VERSION}-bookworm@${RUST_AUDIT_BASE_IMAGE_DIGEST}',
            '[ "$IMAGE_METADATA" = "$EXPECTED_IMAGE_METADATA" ]',
            "RUST_AUDIT_TOOLCHAIN",
            "SHA256_RUST_AUDIT_CARGO_AUDIT",
            "SHA256_RUST_AUDIT_CARGO_DENY",
            'git -c safe.directory="$ADVISORY_DB"',
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
            "--memory=3g",
            "--memory-swap=3g",
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
            '"$AUDIT_IMAGE_CARGO_AUDIT" audit --file /audit/Cargo.lock --db "$AUDIT_IMAGE_DB" --no-fetch --deny warnings --json',
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
            "--tmpfs /work/target:rw,noexec,nosuid,nodev,mode=0700,size=8m",
            "--tmpfs /work/flutter/.dart_tool:rw,noexec,nosuid,nodev,mode=0700,size=1m",
            "--tmpfs /work/flutter/build:rw,noexec,nosuid,nodev,mode=0700,size=1m",
            '--mount "type=bind,source=$REPO_ROOT,target=/work,readonly"',
            '--mount "type=bind,source=$AUDIT_TMP,target=/audit,readonly"',
            '--mount "type=bind,source=$REPO_ROOT/$VENDOR_DIR,target=/vendor,readonly"',
            "--env CARGO_TARGET_DIR=/work/target --env CARGO_DENY_DB_PATH=/tmp/advisory-dbs",
            'cp -a -- "$ADVISORY_DB" "$db"',
            'cp -- /audit/cargo.config.toml /tmp/cargo-home/config.toml',
            '"$AUDIT_TOOLS/bin/cargo-deny" --format json --locked --offline',
            "--config /audit/deny.runtime.toml check advisories",
            '>"$DENY_OUTPUT" 2>"$DENY_ERROR"',
        ),
        "cargo-deny exact input/result",
    )

    require_all(
        pins,
        (
            'ADVISORY_DB_COMMIT="b5fc89b8be99e96f79194d8a6f11e9b4143b99f0"',
            'ADVISORY_DB_COMMIT_EPOCH="1784303558"',
            'ADVISORY_DB_MAX_AGE_DAYS="90"',
            'RUST_AUDIT_RUST_VERSION="1.88"',
            'RUST_AUDIT_RUSTC_VERSION="1.88.0"',
            'RUST_AUDIT_TOOLCHAIN="1.88.0-x86_64-unknown-linux-gnu"',
            'CARGO_AUDIT_VERSION="0.22.2"',
            'CARGO_DENY_VERSION="0.20.2"',
            'RUST_AUDIT_IMAGE_ID="sha256:c8ef1aae7df528285a50bbf55d80bc6807d0beb75126f8a33e37e7bec5b862b9"',
            'SHA256_RUST_AUDIT_CARGO_AUDIT="bcd015b7b140f87024349670d1fd4cae09415049394a96d8f82776032f9a76e0"',
            'SHA256_RUST_AUDIT_CARGO_DENY="5e4a31300be4ee99625751025b4c1a0c3965b747c60fecaebd7454f17dc944ad"',
            'SHA256_RUST_AUDIT_DOCKERFILE="1daf24e5f6be11d832d2c1ab01b09906fa479b0c086fc44238ac39942c3366e7"',
            'RUST_AUDIT_BASE_IMAGE_DIGEST="sha256:af306cfa71d987911a781c37b59d7d67d934f49684058f96cf72079c3626bfe0"',
            'SHA256_CARGO_VENDOR_CLOSURE_V1="fb63f7daefc2c26fb73c04a7d77e9cb8a7658e3c899352e851bb1ebbacdc8c04"',
            'SHA256_CARGO_VENDOR_CONFIG="18a946aa319d64fa07e9616801981b1794c01764f9d870090de593cec412d62f"',
        ),
        "Rust audit pins",
    )
    dockerfile_pin = re.search(r'^SHA256_RUST_AUDIT_DOCKERFILE="([0-9a-f]{64})"', pins, re.MULTILINE)
    require(dockerfile_pin is not None, "Rust audit Dockerfile hash pin is malformed")
    require(
        hashlib.sha256(dockerfile.encode("utf-8")).hexdigest() == dockerfile_pin.group(1),
        "Rust audit Dockerfile does not match its acquisition pin",
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
    require(
        "exact 2026-07-17 RustSec snapshot was reviewed on 2026-07-22" in requirements,
        "current RustSec review status is missing",
    )
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
            'Mutation("dockerfile", "USER 1000:1000", "USER 0:0"',
            'Mutation("dockerfile", "COPY --from=builder --chown=1000:1000"',
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
    Mutation("dockerfile", "USER 1000:1000", "USER 0:0", "rootless acquisition stage"),
    Mutation("dockerfile", "--locked", "--force", "locked scanner acquisition"),
    Mutation("dockerfile", "--depth=1", "--depth=100", "bounded exact DB acquisition"),
    Mutation("dockerfile", "COPY --from=builder --chown=1000:1000", "COPY .", "empty-context runtime copy"),
    Mutation("dockerfile", "-bookworm@${BASE_DIGEST}", "-bookworm", "digest-pinned acquisition base"),
    Mutation("shell", '[ "$(id -u)" -ne 0 ]', '[ "$(id -u)" -ge 0 ]', "UID-root refusal"),
    Mutation("shell", '[ "$(id -g)" -ne 0 ]', '[ "$(id -g)" -ge 0 ]', "GID-root refusal"),
    Mutation("shell", '[ ! -L "$LOCKFILE" ]', '[ -e "$LOCKFILE" ]', "lockfile link refusal"),
    Mutation("shell", '[ ! -L "$POLICY" ]', '[ -e "$POLICY" ]', "policy link refusal"),
    Mutation("shell", "scripts/rust-audit-policy.py prepare", "printf 34 # prepare", "private policy staging"),
    Mutation("shell", "scripts/rust-audit-policy.py check-freshness", "printf fresh # check-freshness", "DB freshness"),
    Mutation("shell", '--max-age-days "$ADVISORY_DB_MAX_AGE_DAYS"', '--max-age-days 9999', "freshness pin use"),
    Mutation("shell", '$DOCKER_BIN image inspect --format', 'printf sha256: # $DOCKER_BIN image inspect --format', "image identity"),
    Mutation("shell", '[ "$IMAGE_ID" = "$RUST_AUDIT_IMAGE_ID" ]', '[ -n "$IMAGE_ID" ]', "content-ID equality"),
    Mutation("shell", '[ "$IMAGE_METADATA" = "$EXPECTED_IMAGE_METADATA" ]', '[ -n "$IMAGE_METADATA" ]', "image metadata equality"),
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
    Mutation("shell", '"$AUDIT_IMAGE_CARGO_AUDIT" audit --file /audit/Cargo.lock', '"$AUDIT_IMAGE_CARGO_AUDIT" audit --file /work/Cargo.lock', "exact lock scan"),
    Mutation("shell", "--deny warnings --json", "--json", "cargo-audit warning finality"),
    Mutation("shell", '"$AUDIT_TOOLS/bin/cargo-deny" --format json --locked --offline', '"$AUDIT_TOOLS/bin/cargo-deny" --format json', "locked offline deny"),
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
    Mutation("pins", 'RUST_AUDIT_IMAGE_ID="sha256:c8ef1aae', 'RUST_AUDIT_IMAGE_ID="rd-audit-', "image content pin"),
    Mutation("pins", 'SHA256_RUST_AUDIT_DOCKERFILE="1daf24e5', 'SHA256_RUST_AUDIT_DOCKERFILE="00000000', "acquisition recipe pin"),
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
        "dockerfile": (repo / "scripts/Dockerfile.audit").read_text(encoding="utf-8"),
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
