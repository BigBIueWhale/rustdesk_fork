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


def function_block(shell, name, next_name):
    start = shell.index("{}() {{".format(name))
    end = shell.index("{}() {{".format(next_name), start)
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
            (
                "ARG BASE_DIGEST=sha256:"
                "af306cfa71d987911a781c37b59d7d67d934f49684058f96cf72079c3626bfe0"
            ),
            "ARG CARGO_AUDIT_VERSION=0.22.2",
            "ARG CARGO_DENY_VERSION=0.20.2",
            "ARG CARGO_AUDIT_TAG_OBJECT",
            "ARG CARGO_AUDIT_SOURCE_COMMIT",
            "ARG CARGO_AUDIT_SOURCE_TREE",
            "ARG SHA256_CARGO_AUDIT_SOURCE_ARCHIVE",
            "ARG CARGO_DENY_TAG_OBJECT",
            "ARG CARGO_DENY_SOURCE_COMMIT",
            "ARG CARGO_DENY_SOURCE_TREE",
            "ARG SHA256_CARGO_DENY_SOURCE_ARCHIVE",
            "FROM rust:${RUST_AUDIT_RUST_VERSION}-bookworm@${BASE_DIGEST} AS builder",
            "FROM rust:${RUST_AUDIT_RUST_VERSION}-bookworm@${BASE_DIGEST} AS runtime",
            "COPY <<EOF /etc/passwd",
            (
                "rustdesk-audit:x:1000:1000:RustDesk audit builder:"
                "/var/tmp/rustdesk-rust-audit/home:/usr/sbin/nologin"
            ),
            "RUN --network=default fetch_scanner_source() {",
            "https://github.com/RustSec/rustsec.git",
            '"refs/tags/cargo-audit/v${CARGO_AUDIT_VERSION}"',
            'git -C "$repository" rev-parse "$tag^{commit}"',
            'git -C "$repository" rev-parse "$commit^{tree}"',
            'git -C "$repository" archive --format=tar',
            'sha256sum "$archive"',
            "ecdsa-sha2-nistp256 "
            "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTY"
            "AAABBBAdyFjfzdhqQVdamlsu8LFAVGipsMdsd4r6K/FmhCbqkY"
            "HATxXBmBveLv7HeDF9QpB44OWzkiX76g/Q3NR9jGso=",
            "verify-tag --raw",
            (
                'Good "git" signature for dirkjan@ochtman.nl with ECDSA key '
                "SHA256:Nek/oTQkBpjde4wx0GVl9zJkmMae8M65edoqmLdafUE"
            ),
            "https://github.com/EmbarkStudios/cargo-deny.git",
            '"refs/tags/${CARGO_DENY_VERSION}"',
            'cargo fetch --locked --manifest-path "$CARGO_AUDIT_SOURCE/Cargo.toml"',
            'cargo fetch --locked --manifest-path "$CARGO_DENY_SOURCE/Cargo.toml"',
            'chmod -R a-w "$AUDIT_ROOT/scanner-sources"',
            'RUN --network=none export CARGO_TARGET_DIR="$AUDIT_ROOT/cargo-target"',
            'cargo install --root "$AUDIT_TOOLS" --locked --offline',
            '--path "$CARGO_AUDIT_SOURCE/cargo-audit"',
            '--path "$CARGO_DENY_SOURCE"',
            'git -c protocol.version=2 -C "$ADVISORY_DB" fetch -q --depth=1 origin "$ADVISORY_DB_SHA"',
            'git -C "$ADVISORY_DB" checkout -q --detach FETCH_HEAD',
            "COPY --from=builder --chown=1000:1000",
            'org.rustdesk.audit.cargo-audit-source="${CARGO_AUDIT_SOURCE_COMMIT}"',
            'org.rustdesk.audit.cargo-audit-source-tree="${CARGO_AUDIT_SOURCE_TREE}"',
            'org.rustdesk.audit.cargo-deny-source="${CARGO_DENY_SOURCE_COMMIT}"',
            'org.rustdesk.audit.cargo-deny-source-tree="${CARGO_DENY_SOURCE_TREE}"',
            'org.rustdesk.audit.run-user="1000:1000"',
            'RUN --network=none [ "$(id -u)" = 1000 ]',
            'RUN --network=default git init -q "$ADVISORY_DB"',
            'RUN --network=none ln -s "$ADVISORY_DB"',
        ),
        "Rust audit acquisition recipe",
    )
    require(dockerfile.count("\nFROM ") == 2, "Rust audit recipe must have exactly two stages")
    require(dockerfile.count("\nUSER 1000:1000\n") == 2, "both audit-image stages must set numeric nonroot user")
    require(dockerfile.count("\nRUN ") == 6, "Rust audit recipe must have exactly six rootless RUN instructions")
    require(
        dockerfile.count("\nRUN --network=none ") == 4,
        "Rust audit recipe must have exactly four networkless RUN instructions",
    )
    require(
        dockerfile.count("\nRUN --network=default ") == 2,
        "Rust audit recipe must have exactly two acquisition-network RUN instructions",
    )
    require(
        dockerfile.count("--locked") == 4,
        "scanner dependency acquisition and compilation must use committed lockfiles",
    )
    require(
        dockerfile.count("--offline") == 2
        and dockerfile.count("--path ") == 2,
        "both scanner compilations must be offline and exact-source path based",
    )
    require(
        "--version \"$CARGO_AUDIT_VERSION\" cargo-audit" not in dockerfile
        and "--version \"$CARGO_DENY_VERSION\" cargo-deny" not in dockerfile,
        "scanner root packages must not come from the registry",
    )
    copy_lines = [line for line in dockerfile.splitlines() if line.startswith("COPY ")]
    require(
        copy_lines == [
            "COPY <<EOF /etc/passwd",
            "COPY --from=builder --chown=1000:1000 \\",
            "COPY --from=builder --chown=1000:1000 \\",
        ],
        "audit image may only construct the reviewed passwd file and copy "
        "the two exact rootless-builder outputs",
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
        "--network=host",
    ):
        require(forbidden not in dockerfile, "Rust audit recipe has forbidden authority {!r}".format(forbidden))


def validate_contract(sources):
    shell = sources["shell"]
    dockerfile = sources["dockerfile"]
    policy = sources["policy"]
    pins = sources["pins"]
    provenance = sources["provenance"]
    image_provenance = sources["image_provenance"]
    online_fetch = sources["online_fetch"]
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
            'CARGO_AUDIT_TAG_OBJECT="78bd4d48923d207898e94827cbd79d73903a85fa"',
            'CARGO_AUDIT_SOURCE_COMMIT="281452c35cf0870969042374110f099a411bc185"',
            'CARGO_AUDIT_SOURCE_TREE="62833baf6c7ae4ac676f00bb52687e62cd5bed4c"',
            (
                'SHA256_CARGO_AUDIT_SOURCE_ARCHIVE="'
                '457562cec67c15aebd76da04d0e7a632efb82d1425d973cbd4c67f6c5ca18044"'
            ),
            (
                'CARGO_AUDIT_SIGNING_KEY_FINGERPRINT="'
                'SHA256:Nek/oTQkBpjde4wx0GVl9zJkmMae8M65edoqmLdafUE"'
            ),
            'CARGO_DENY_TAG_OBJECT="87da103c554376c89a641116f835a41073a9d774"',
            'CARGO_DENY_SOURCE_COMMIT="bca0dde53651ee946720e4540b5ce2610bec8f06"',
            'CARGO_DENY_SOURCE_TREE="fbfc96f028b5f197ca062ddce1301395578feded"',
            (
                'SHA256_CARGO_DENY_SOURCE_ARCHIVE="'
                '3a719d0cf4785e646a39fbf97fbdc75ab832c7eafde91ba3d56d16d410ce6bc9"'
            ),
            'RUST_AUDIT_IMAGE_ID="sha256:ef686dadbe8b0846ddd5565c7dff251d84467337bf2a2efe6caab54eb92dc689"',
            'RUST_AUDIT_IMAGE_CONFIG_ID="sha256:d6ab0e782795da49e1acb415f14fcc57dc83fa4d9433b59617be57a865073389"',
            'RUST_AUDIT_IMAGE_MANIFEST_ID="sha256:eddb729aa817300721bd4ffd62f968761f8dda18c445870f356630330de04eb8"',
            'SHA256_RUST_AUDIT_IMAGE_ARCHIVE="d7ad706d15fa41770f105a628ced93172102aa205d558af26e2b6753e5b0a152"',
            'SIZE_RUST_AUDIT_IMAGE_ARCHIVE="563327519"',
            'SHA256_RUST_AUDIT_CARGO_AUDIT="6c64582f03d560e747bbbb74af46fac217691a098e2d5c622abdded14b220f5c"',
            'SHA256_RUST_AUDIT_CARGO_DENY="acbde16ebe1fe780e80b45b2b51df335389d19398401f725449498af93fe5e47"',
            'SHA256_RUST_AUDIT_DOCKERFILE="dad88247654a87fe49cff73b23f16047ecc8f2fd3cbd1c8617c9af16d05874bf"',
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
        image_provenance,
        (
            "class RustAuditSpec:",
            "def validate_rust_audit_attestation(",
            "def create_rust_audit_fixture_archive(",
            'if args.role == "rust-audit":',
            'if isinstance(spec, RustAuditSpec):',
            "cargo_audit_tag_object: str",
            "cargo_audit_source_commit: str",
            "cargo_audit_source_tree: str",
            "cargo_audit_source_archive_sha256: str",
            "cargo_audit_signing_key_fingerprint: str",
            "cargo_deny_tag_object: str",
            "cargo_deny_source_commit: str",
            "cargo_deny_source_tree: str",
            "cargo_deny_source_archive_sha256: str",
            '"User": "1000:1000"',
            '"Shell": ["/bin/bash", "-euo", "pipefail", "-c"]',
            '"pkg:docker/rd-rust-audit-candidate@provenance-v1"',
            'statement.get("_type") != "https://in-toto.io/Statement/v1"',
            '"image.resolvemode": "pull"',
            "source_runs = dockerfile_run_contract(embedded_dockerfile)",
            'execution_networks = (2, 2, None, 2, None, 2)',
            'if operations[position].get("exec") != expected_execution:',
            '"local://dockerfile"',
            'if hashlib.sha256(dockerfile).hexdigest() != spec.dockerfile_sha256:',
            "RUST_AUDIT_PASSWD = (",
            'if not isinstance(history, list) or len(history) != 29:',
            "def requires_private_archive(spec: ImageSpec) -> bool:",
            "if rust_checks != 40:",
        ),
        "Rust audit image archive/provenance authority",
    )
    private_archive_start = image_provenance.index(
        "def requires_private_archive(spec: ImageSpec) -> bool:"
    )
    private_archive_end = image_provenance.index(
        "\n\n\ndef fail(message: str) -> None:", private_archive_start
    )
    private_archive = image_provenance[
        private_archive_start:private_archive_end
    ]
    require_all(
        private_archive,
        (
            "CertifiedBuilderSpec",
            "VerifierSpec",
            "AppleCheckSpec",
            "DartAuditSpec",
            "RustAuditSpec",
        ),
        "private image archive classification",
    )
    provenance_capture_start = image_provenance.index(
        "def capture(output: Path, spec: ImageSpec) -> tuple[str, int]:"
    )
    provenance_capture_end = image_provenance.index(
        "\n\n\ndef create_fixture_archive(path: Path, spec: Spec) -> str:",
        provenance_capture_start,
    )
    provenance_capture = image_provenance[
        provenance_capture_start:provenance_capture_end
    ]
    require_all(
        provenance_capture,
        (
            "if requires_private_archive(spec):",
            "save_ref = spec.image_id",
        ),
        "private image archive capture",
    )
    require(
        image_provenance.count("requires_private_archive(spec)") == 6,
        "Rust audit archive must share every strict modern-image boundary",
    )
    spec_block = function_block(
        online_fetch,
        "rust_audit_image_spec_args",
        "require_rust_audit_image_pins",
    )
    require_block = function_block(
        online_fetch,
        "require_rust_audit_image_pins",
        "verify_or_load_rust_audit_image",
    )
    load_block = function_block(
        online_fetch,
        "verify_or_load_rust_audit_image",
        "maintenance_capture_rust_audit_image",
    )
    capture_block = function_block(
        online_fetch,
        "maintenance_capture_rust_audit_image",
        "build_deb_builder_bootstrap_image",
    )
    build_block = function_block(
        online_fetch,
        "maintenance_build_rust_audit_image_candidate",
        "maintenance_capture_deb_builder_bootstrap_image",
    )
    require_all(
        spec_block,
        (
            "--role rust-audit",
            '--expected-id "$RUST_AUDIT_IMAGE_ID"',
            '--config-id "$RUST_AUDIT_IMAGE_CONFIG_ID"',
            '--manifest-id "$RUST_AUDIT_IMAGE_MANIFEST_ID"',
            '--cargo-audit-tag-object "$CARGO_AUDIT_TAG_OBJECT"',
            '--cargo-audit-source-commit "$CARGO_AUDIT_SOURCE_COMMIT"',
            '--cargo-audit-source-tree "$CARGO_AUDIT_SOURCE_TREE"',
            '--cargo-audit-source-archive-sha "$SHA256_CARGO_AUDIT_SOURCE_ARCHIVE"',
            (
                '--cargo-audit-signing-key-fingerprint '
                '"$CARGO_AUDIT_SIGNING_KEY_FINGERPRINT"'
            ),
            '--cargo-deny-tag-object "$CARGO_DENY_TAG_OBJECT"',
            '--cargo-deny-source-commit "$CARGO_DENY_SOURCE_COMMIT"',
            '--cargo-deny-source-tree "$CARGO_DENY_SOURCE_TREE"',
            '--cargo-deny-source-archive-sha "$SHA256_CARGO_DENY_SOURCE_ARCHIVE"',
            '--cargo-audit-sha "$SHA256_RUST_AUDIT_CARGO_AUDIT"',
            '--cargo-deny-sha "$SHA256_RUST_AUDIT_CARGO_DENY"',
            '--advisory-db-sha "$ADVISORY_DB_COMMIT"',
            '--advisory-db-epoch "$ADVISORY_DB_COMMIT_EPOCH"',
        ),
        "Rust audit image specification",
    )
    require_all(
        require_block,
        (
            "RUST_AUDIT_IMAGE_CONFIG_ID",
            "RUST_AUDIT_IMAGE_MANIFEST_ID",
            "SHA256_RUST_AUDIT_DOCKERFILE",
            "CARGO_AUDIT_TAG_OBJECT",
            "CARGO_AUDIT_SOURCE_COMMIT",
            "CARGO_AUDIT_SOURCE_TREE",
            "SHA256_CARGO_AUDIT_SOURCE_ARCHIVE",
            "CARGO_AUDIT_SIGNING_KEY_FINGERPRINT",
            "CARGO_DENY_TAG_OBJECT",
            "CARGO_DENY_SOURCE_COMMIT",
            "CARGO_DENY_SOURCE_TREE",
            "SHA256_CARGO_DENY_SOURCE_ARCHIVE",
            'sha256sum "$SCRIPT_DIR/Dockerfile.audit"',
        ),
        "Rust audit image pin preflight",
    )
    require_all(
        load_block,
        (
            "SHA256_RUST_AUDIT_IMAGE_ARCHIVE",
            "SIZE_RUST_AUDIT_IMAGE_ARCHIVE",
            "online_image_provenance verify-load",
            'verifier-images/rust-audit.docker.tar.gz"',
            '--archive-size "$SIZE_RUST_AUDIT_IMAGE_ARCHIVE"',
        ),
        "Rust audit image archive recovery",
    )
    require_all(
        capture_block,
        (
            '"$directory/rust-audit.docker.tar.gz"',
            "current-user-private mode 0700",
            '"$FLOCK_BIN" --exclusive --nonblock',
            "online_image_provenance maintenance-capture",
        ),
        "Rust audit image archive capture",
    )
    require_all(
        build_block,
        (
            'local tag="rd-rust-audit-candidate:provenance-v1"',
            'local context="$ONLINE_FETCH_TMP/rust-audit-build-context"',
            '/usr/bin/install -m 0400',
            '"$SCRIPT_DIR/Dockerfile.audit" "$context/Dockerfile.audit"',
            '-type f | /usr/bin/wc -l)" -eq 1',
            "--network=default --pull=true --no-cache",
            "--platform=linux/amd64 --provenance=mode=max --load",
            '--build-arg "BASE_DIGEST=${RUST_AUDIT_BASE_IMAGE_DIGEST}"',
            '--build-arg "CARGO_AUDIT_TAG_OBJECT=${CARGO_AUDIT_TAG_OBJECT}"',
            (
                '--build-arg "CARGO_AUDIT_SOURCE_COMMIT='
                '${CARGO_AUDIT_SOURCE_COMMIT}"'
            ),
            '--build-arg "CARGO_AUDIT_SOURCE_TREE=${CARGO_AUDIT_SOURCE_TREE}"',
            (
                '--build-arg "SHA256_CARGO_AUDIT_SOURCE_ARCHIVE='
                '${SHA256_CARGO_AUDIT_SOURCE_ARCHIVE}"'
            ),
            '--build-arg "CARGO_DENY_TAG_OBJECT=${CARGO_DENY_TAG_OBJECT}"',
            (
                '--build-arg "CARGO_DENY_SOURCE_COMMIT='
                '${CARGO_DENY_SOURCE_COMMIT}"'
            ),
            '--build-arg "CARGO_DENY_SOURCE_TREE=${CARGO_DENY_SOURCE_TREE}"',
            (
                '--build-arg "SHA256_CARGO_DENY_SOURCE_ARCHIVE='
                '${SHA256_CARGO_DENY_SOURCE_ARCHIVE}"'
            ),
            "online_image_provenance verify-local",
        ),
        "Rust audit maintenance candidate build",
    )
    for forbidden in (
        "--privileged",
        "--cap-add",
        "--network=host",
        "--pid=host",
        "--ipc=host",
        "--uts=host",
        "--publish",
        "--expose",
        "docker.sock",
        "$REPO_ROOT,target=",
    ):
        require(
            forbidden not in build_block,
            "Rust audit candidate build has forbidden authority {!r}".format(
                forbidden
            ),
        )
    require_all(
        online_fetch,
        (
            "--maintenance-build-rust-audit-image-candidate)",
            "--maintenance-capture-rust-audit-image)",
            "--rust-audit-image)",
            "verify_or_load_rust_audit_image",
        ),
        "Rust audit online acquisition wiring",
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
            'Mutation("dockerfile", "RUN --network=none", "RUN --network=default"',
            'Mutation("dockerfile", "RUN --network=default", "RUN --network=none"',
            'Mutation("dockerfile", "COPY --from=builder --chown=1000:1000"',
            'Mutation("shell", \'ulimit -Sf "$MAX_SCANNER_OUTPUT_BLOCKS"\'',
            'Mutation("shell", "scripts/rust-audit-policy.py check-freshness"',
            'Mutation("shell", "--deny warnings --json", "--json"',
            'Mutation("policy", "maximum_days == 90", "maximum_days >= 90"',
            'Mutation("policy", "metadata.st_mtime_ns", "opened.st_mtime_ns"',
            'Mutation("policy", \'value.get("warnings") == {}\'',
            'Mutation("policy", \'code == "advisory-not-detected" and severity == "warning"\'',
            'Mutation("image_provenance", "class RustAuditSpec:"',
            'Mutation("image_provenance", \'statement.get("_type") != "https://in-toto.io/Statement/v1"\'',
            'Mutation("dockerfile", "https://github.com/RustSec/rustsec.git"',
            'Mutation("dockerfile", "verify-tag --raw"',
            'Mutation("dockerfile", \'Good "git" signature for dirkjan@ochtman.nl\'',
            'Mutation("dockerfile", "https://github.com/EmbarkStudios/cargo-deny.git"',
            'Mutation("dockerfile", \'--offline \\\\\\n        --path "$CARGO_AUDIT_SOURCE/cargo-audit"\'',
            'Mutation("pins", \'CARGO_AUDIT_TAG_OBJECT="78bd4d48\'',
            'Mutation("pins", \'CARGO_DENY_TAG_OBJECT="87da103c\'',
            'Mutation("image_provenance", "cargo_audit_tag_object: str"',
            'Mutation("image_provenance", "source_runs = dockerfile_run_contract(embedded_dockerfile)"',
            'Mutation("image_provenance", "execution_networks = (2, 2, None, 2, None, 2)"',
            '"Rust private archive classification"',
            'Mutation("online_fetch", \'--archive "$ONLINE_DIR/verifier-images/rust-audit.docker.tar.gz"\'',
            '"Rust image candidate network authority"',
            'Mutation("verify", "python3 scripts/verify-rust-audit-authority.py --repo . --self-test"',
            'Mutation("requirements", \'<span class="id">R-S11bf</span>\'',
            'Mutation("hardening", "R-S11bf/R-S11e-72 — Rust advisory freshness, result finality, and scanner authority"',
        ),
        "Rust audit validator mutation coverage",
    )


MUTATIONS = (
    Mutation("dockerfile", "USER 1000:1000", "USER 0:0", "rootless acquisition stage"),
    Mutation("dockerfile", "RUN --network=none", "RUN --network=default", "networkless acquisition setup"),
    Mutation("dockerfile", "RUN --network=default", "RUN --network=none", "scoped acquisition network"),
    Mutation("dockerfile", "https://github.com/RustSec/rustsec.git", "https://example.invalid/rustsec.git", "cargo-audit source repository"),
    Mutation("dockerfile", '"refs/tags/cargo-audit/v${CARGO_AUDIT_VERSION}"', '"refs/heads/main"', "cargo-audit exact tag"),
    Mutation("dockerfile", "verify-tag --raw", "show --show-signature", "cargo-audit signed-tag verification"),
    Mutation("dockerfile", 'Good "git" signature for dirkjan@ochtman.nl', 'Good "git" signature for unknown@example.invalid', "cargo-audit signer identity"),
    Mutation("dockerfile", "SHA256:Nek/oTQkBpjde4wx0GVl9zJkmMae8M65edoqmLdafUE", "SHA256:0000000000000000000000000000000000000000000", "cargo-audit signer fingerprint"),
    Mutation("dockerfile", "https://github.com/EmbarkStudios/cargo-deny.git", "https://example.invalid/cargo-deny.git", "cargo-deny source repository"),
    Mutation("dockerfile", '"refs/tags/${CARGO_DENY_VERSION}"', '"refs/heads/main"', "cargo-deny exact tag"),
    Mutation("dockerfile", 'git -C "$repository" rev-parse "$tag^{commit}"', 'git -C "$repository" rev-parse FETCH_HEAD', "tag-to-commit binding"),
    Mutation("dockerfile", 'git -C "$repository" rev-parse "$commit^{tree}"', 'git -C "$repository" rev-parse HEAD^{tree}', "commit-to-tree binding"),
    Mutation("dockerfile", 'sha256sum "$archive"', 'wc -c "$archive"', "canonical source archive hash"),
    Mutation("dockerfile", 'chmod -R a-w "$AUDIT_ROOT/scanner-sources"', 'chmod -R u+w "$AUDIT_ROOT/scanner-sources"', "read-only authenticated sources"),
    Mutation("dockerfile", "--locked", "--force", "locked scanner acquisition"),
    Mutation("dockerfile", '--offline \\\n        --path "$CARGO_AUDIT_SOURCE/cargo-audit"', '--version "$CARGO_AUDIT_VERSION" cargo-audit', "offline cargo-audit source build"),
    Mutation("dockerfile", '--offline \\\n        --path "$CARGO_DENY_SOURCE"', '--version "$CARGO_DENY_VERSION" cargo-deny', "offline cargo-deny source build"),
    Mutation("dockerfile", 'org.rustdesk.audit.cargo-audit-source="${CARGO_AUDIT_SOURCE_COMMIT}"', 'org.rustdesk.audit.cargo-audit-source="unknown"', "cargo-audit source label"),
    Mutation("dockerfile", 'org.rustdesk.audit.cargo-deny-source="${CARGO_DENY_SOURCE_COMMIT}"', 'org.rustdesk.audit.cargo-deny-source="unknown"', "cargo-deny source label"),
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
    Mutation("pins", 'CARGO_AUDIT_TAG_OBJECT="78bd4d48', 'CARGO_AUDIT_TAG_OBJECT="00000000', "cargo-audit tag-object pin"),
    Mutation("pins", 'CARGO_AUDIT_SOURCE_COMMIT="281452c3', 'CARGO_AUDIT_SOURCE_COMMIT="00000000', "cargo-audit source-commit pin"),
    Mutation("pins", 'CARGO_AUDIT_SOURCE_TREE="62833baf', 'CARGO_AUDIT_SOURCE_TREE="00000000', "cargo-audit source-tree pin"),
    Mutation("pins", 'SHA256_CARGO_AUDIT_SOURCE_ARCHIVE="457562ce', 'SHA256_CARGO_AUDIT_SOURCE_ARCHIVE="00000000', "cargo-audit source-archive pin"),
    Mutation("pins", 'CARGO_AUDIT_SIGNING_KEY_FINGERPRINT="SHA256:Nek/', 'CARGO_AUDIT_SIGNING_KEY_FINGERPRINT="SHA256:000/', "cargo-audit signer pin"),
    Mutation("pins", 'CARGO_DENY_TAG_OBJECT="87da103c', 'CARGO_DENY_TAG_OBJECT="00000000', "cargo-deny tag-object pin"),
    Mutation("pins", 'CARGO_DENY_SOURCE_COMMIT="bca0dde5', 'CARGO_DENY_SOURCE_COMMIT="00000000', "cargo-deny source-commit pin"),
    Mutation("pins", 'CARGO_DENY_SOURCE_TREE="fbfc96f0', 'CARGO_DENY_SOURCE_TREE="00000000', "cargo-deny source-tree pin"),
    Mutation("pins", 'SHA256_CARGO_DENY_SOURCE_ARCHIVE="3a719d0c', 'SHA256_CARGO_DENY_SOURCE_ARCHIVE="00000000', "cargo-deny source-archive pin"),
    Mutation("pins", 'RUST_AUDIT_IMAGE_ID="sha256:ef686dad', 'RUST_AUDIT_IMAGE_ID="rd-audit-', "image content pin"),
    Mutation("pins", 'RUST_AUDIT_IMAGE_CONFIG_ID="sha256:d6ab0e78', 'RUST_AUDIT_IMAGE_CONFIG_ID="sha256:00000000', "image config pin"),
    Mutation("pins", 'RUST_AUDIT_IMAGE_MANIFEST_ID="sha256:eddb729a', 'RUST_AUDIT_IMAGE_MANIFEST_ID="sha256:00000000', "image manifest pin"),
    Mutation("pins", 'SHA256_RUST_AUDIT_IMAGE_ARCHIVE="d7ad706d', 'SHA256_RUST_AUDIT_IMAGE_ARCHIVE="00000000', "image archive pin"),
    Mutation("pins", 'SIZE_RUST_AUDIT_IMAGE_ARCHIVE="563327519"', 'SIZE_RUST_AUDIT_IMAGE_ARCHIVE="1"', "image archive length pin"),
    Mutation("pins", 'SHA256_RUST_AUDIT_DOCKERFILE="dad88247', 'SHA256_RUST_AUDIT_DOCKERFILE="00000000', "acquisition recipe pin"),
    Mutation("provenance", "def verify_subtree(tree: Path, expected: str) -> Result:", "def ignored_subtree(tree: Path, expected: str) -> Result:", "subtree verifier"),
    Mutation("image_provenance", "class RustAuditSpec:", "class IgnoredRustAuditSpec:", "Rust image specification"),
    Mutation("image_provenance", 'statement.get("_type") != "https://in-toto.io/Statement/v1"', "False", "attested in-toto statement type"),
    Mutation("image_provenance", "cargo_audit_tag_object: str", "ignored: str", "cargo-audit provenance tag object"),
    Mutation("image_provenance", "cargo_deny_source_archive_sha256: str", "ignored: str", "cargo-deny provenance archive"),
    Mutation("image_provenance", "source_runs = dockerfile_run_contract(embedded_dockerfile)", "source_runs = []", "Dockerfile-derived command contract"),
    Mutation("image_provenance", "execution_networks = (2, 2, None, 2, None, 2)", "execution_networks = (None, None, None, None, None, None)", "attested build network graph"),
    Mutation("image_provenance", "RUST_AUDIT_PASSWD = (", "IGNORED_PASSWD = (", "attested passwd identity"),
    Mutation("image_provenance", "if rust_checks != 40:", "if rust_checks < 0:", "Rust image behavioral self-test count"),
    Mutation(
        "image_provenance",
        (
            "def requires_private_archive(spec: ImageSpec) -> bool:\n"
            "    return isinstance(\n"
            "        spec,\n"
            "        (\n"
            "            CertifiedBuilderSpec,\n"
            "            VerifierSpec,\n"
            "            AppleCheckSpec,\n"
            "            DartAuditSpec,\n"
            "            RustAuditSpec,\n"
            "        ),\n"
            "    )"
        ),
        (
            "def requires_private_archive(spec: ImageSpec) -> bool:\n"
            "    return isinstance(\n"
            "        spec,\n"
            "        (\n"
            "            CertifiedBuilderSpec,\n"
            "            VerifierSpec,\n"
            "            AppleCheckSpec,\n"
            "            DartAuditSpec,\n"
            "        ),\n"
            "    )"
        ),
        "Rust private archive classification",
    ),
    Mutation("online_fetch", '--archive "$ONLINE_DIR/verifier-images/rust-audit.docker.tar.gz"', '--archive "$ONLINE_DIR/verifier-images/other.docker.tar.gz"', "Rust image archive recovery path"),
    Mutation(
        "online_fetch",
        (
            "    online_docker buildx build \\\n"
            "        --network=default --pull=true --no-cache"
        ),
        (
            "    online_docker buildx build \\\n"
            "        --network=host --pull=true --no-cache"
        ),
        "Rust image candidate network authority",
    ),
    Mutation("online_fetch", '"$SCRIPT_DIR/Dockerfile.audit" "$context/Dockerfile.audit"', '"$REPO_ROOT" "$context/repository"', "Dockerfile-only candidate context"),
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
        "image_provenance": (
            repo / "scripts/offline-image-provenance.py"
        ).read_text(encoding="utf-8"),
        "online_fetch": (repo / "scripts/online-fetch.sh").read_text(
            encoding="utf-8"
        ),
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
