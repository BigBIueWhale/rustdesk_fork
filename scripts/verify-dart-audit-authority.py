#!/usr/bin/env python3
"""Bind Dart advisory freshness/finality to one immutable confined scan."""

import argparse
from pathlib import Path
import re
import sys


IMAGE_ID = "sha256:1cdfd518d52738f17f2724a8424acb0530eaa69e38e1a053a7bead82aae77a65"
CONFIG_ID = "sha256:a1833b5698aef708a1c5485776aea2264b966f978db7923881b7c1e9e70a54fd"
MANIFEST_ID = "sha256:8b09349196d4c32a90072f055840952c0e702be8c2a03ab54586211558217b33"
ARCHIVE_SHA256 = "f6afc51f31b0c85c15e1497adfdaa18fe3736150f7149823298a6584d3b811b9"
ARCHIVE_SIZE = "45818346"
DOCKERFILE_SHA256 = "ced57c69244532025697db580ddd54dc9475cd98dd076a47571de5ce2c3a068f"
SCANNER_SIZE = "56676514"
SCANNER_SHA256 = "15314940c10d26af9c6649f150b8a47c1262e8fc7e17b1d1029b0e479e8ed8a0"
DATABASE_SHA256 = "5fdd3db5059b4f935a507385cb93cab3c35ba3d632332a5c8f5deb604f95a5c0"
DATABASE_CAPTURE_EPOCH = "1783494618"
DATABASE_GENERATION = "1783494617999513"
DATABASE_MAX_AGE_DAYS = "30"


class ContractError(RuntimeError):
    pass


class Mutation(object):
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


def require_once(source, token, label):
    count = source.count(token)
    require(count == 1, "{}: expected one occurrence, found {}".format(label, count))


def extract_between(source, start_token, end_token, label, offset=0):
    start = source.find(start_token, offset)
    require(start >= 0, "{}: missing start token".format(label))
    end = source.find(end_token, start)
    require(end >= 0, "{}: missing end token".format(label))
    return source[start : end + len(end_token)], end + len(end_token)


def require_container_floor(block, label):
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
            "--memory-swap=",
            "--cpus=",
            "--tmpfs /tmp:rw,noexec,nosuid,nodev",
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
        "$PWD",
        '"$IMG"',
        "2>/dev/null",
    ):
        require(forbidden not in block, "{} has forbidden authority {!r}".format(label, forbidden))
    require(
        re.search(r"(?:^|\s)-p(?:\s|=)", block) is None,
        "{} publishes a port".format(label),
    )


def validate_contract(sources):
    shell = sources["shell"]
    result = sources["result"]
    pins = sources["pins"]
    dockerfile = sources["dockerfile"]
    verify = sources["verify"]
    requirements = sources["requirements"]
    hardening = sources["hardening"]
    validator = sources["validator"]
    online_fetch = sources["online_fetch"]
    provenance = sources["provenance"]
    input_validator = sources["input_validator"]
    fixed_helper = sources["fixed_helper"]

    require_all(
        shell,
        (
            'source "$SCRIPT_DIR/lib.sh"',
            "load_pins",
            "readonly DOCKER_BIN=/usr/bin/docker",
            "readonly PYTHON_BIN=/usr/bin/python3",
            "readonly MAX_SCANNER_OUTPUT_BLOCKS=65536",
            "run_bounded_docker() (",
            'current_limit="$(ulimit -Sf)"',
            'exec "$DOCKER_BIN" "$@"',
            '[ "$(id -u)" -ne 0 ] || dart_audit_die "refuses host or container-root execution"',
            '[ "$(id -g)" -ne 0 ] || dart_audit_die "refuses a root primary group"',
            '[ -f "$LOCKFILE" ] && [ ! -L "$LOCKFILE" ]',
            '[ -f "$IGNORES_FILE" ] && [ ! -L "$IGNORES_FILE" ]',
            ': "${DART_AUDIT_IMAGE_ID:?dart-audit.sh: DART_AUDIT_IMAGE_ID unset in pins.env}"',
            '[[ "$DART_AUDIT_IMAGE_ID" =~ ^sha256:[0-9a-f]{64}$ ]]',
            'AUDIT_TMP="$(umask 077 && mktemp -d /tmp/rustdesk-dart-audit.XXXXXXXXXX)"',
            'AUDIT_TMP_ID="$(/usr/bin/stat -c \'%d:%i\' -- "$AUDIT_TMP")"',
            '--remove-private-root "$AUDIT_TMP" --expected-identity "$AUDIT_TMP_ID"',
            "scripts/dart-audit-result.py prepare",
            '--policy "$IGNORES_FILE" --lockfile "$LOCKFILE" --output "$AUDIT_TMP"',
            "scripts/dart-audit-result.py check-freshness",
            '--capture-epoch "$OSV_DB_PUB_CAPTURE_EPOCH"',
            '--max-age-days "$OSV_DB_PUB_MAX_AGE_DAYS"',
            'SOURCE_LOCK_SHA="$(/usr/bin/sha256sum -- "$LOCKFILE"',
            'SOURCE_POLICY_SHA="$(/usr/bin/sha256sum -- "$IGNORES_FILE"',
            'IMAGE_ID="$($DOCKER_BIN image inspect --format \'{{.Id}}\' "$DART_AUDIT_IMAGE_ID")"',
            '[ "$IMAGE_ID" = "$DART_AUDIT_IMAGE_ID" ]',
            'printf "%s  %s\\n" "$5" /usr/local/bin/osv-scanner',
            'printf "%s  %s\\n" "$6" /opt/osv-db/osv-scanner/Pub/all.zip',
            "sha256sum --check --strict --status -",
            'stat -c "%F:%s:%Y:%a:%u:%g:%h" /opt/osv-db/osv-scanner/Pub/all.zip',
            '[ "$IMAGE_PREFLIGHT_STATUS" -eq 0 ]',
            '[ ! -s "$IMAGE_PREFLIGHT_OUT" ]',
            '[ ! -s "$IMAGE_PREFLIGHT_ERR" ]',
            'case "$SCANNER_STATUS" in\n  0|1) ;;',
            'scripts/dart-audit-result.py evaluate',
            '--result "$RESULT_FILE" --stderr "$ERROR_FILE"',
            '--scanner-status "$SCANNER_STATUS" --lockfile "$LOCKFILE"',
            '[ "$RESULT_BYTES" -le 67108864 ]',
            '[ "$ERROR_BYTES" -le 1048576 ]',
            'sha256sum -- "$AUDIT_TMP/pubspec.lock"',
            'sha256sum -- "$AUDIT_TMP/policy.txt"',
            'AUDIT_SUCCESS_MESSAGE="VERIFY-DART-AUDIT: green',
        ),
        "Dart audit shell authority",
    )
    require(shell.count("scripts/dart-audit-result.py check-freshness") == 2, "freshness must be checked before and after scanning")
    require(shell.count('--capture-epoch "$OSV_DB_PUB_CAPTURE_EPOCH"') == 2, "both freshness checks must use the pinned capture epoch")
    require(shell.count('--max-age-days "$OSV_DB_PUB_MAX_AGE_DAYS"') == 2, "both freshness checks must use the pinned age ceiling")
    require(shell.count("run_bounded_docker run --rm") == 2, "Dart audit must have exactly preflight and scanner containers")
    require("$DOCKER_BIN run" not in shell, "Dart audit bypasses the bounded Docker wrapper")
    for forbidden in (
        "$DOCKER_BIN build",
        "docker build",
        "TAG_IMAGE_ID",
        "readonly IMG=",
        "rd-dart-audit",
        "--pull=always",
        "--network=bridge",
        "curl ",
        "wget ",
        "apt-get",
        "https://",
        "http://",
        "|| true",
        'data.get("results", [])',
    ):
        require(forbidden not in shell, "Dart audit retained forbidden acquisition/fail-open path {!r}".format(forbidden))

    prepare_index = shell.index("scripts/dart-audit-result.py prepare")
    freshness_index = shell.index("scripts/dart-audit-result.py check-freshness")
    inspect_index = shell.index("IMAGE_ID=\"$($DOCKER_BIN image inspect")
    preflight_index = shell.index("run_bounded_docker run --rm")
    scan_index = shell.index("run_bounded_docker run --rm", preflight_index + 1)
    evaluate_index = shell.index("scripts/dart-audit-result.py evaluate")
    postcondition_index = shell.rindex('sha256sum -- "$AUDIT_TMP/pubspec.lock"')
    require(
        prepare_index < freshness_index < inspect_index < preflight_index < scan_index < evaluate_index < postcondition_index,
        "Dart audit transaction order is not prepare/freshness/bind/preflight/scan/evaluate/postcondition",
    )

    preflight, preflight_end = extract_between(
        shell,
        "run_bounded_docker run --rm",
        '>"$IMAGE_PREFLIGHT_OUT" 2>"$IMAGE_PREFLIGHT_ERR"',
        "Dart audit image preflight",
    )
    scanner, _ = extract_between(
        shell,
        "run_bounded_docker run --rm",
        '>"$RESULT_FILE" 2>"$ERROR_FILE"',
        "Dart audit scanner",
        preflight_end,
    )
    require_container_floor(preflight, "Dart audit image preflight")
    require_container_floor(scanner, "Dart audit scanner")
    require_all(
        preflight,
        (
            "--pids-limit=32 --memory=256m --memory-swap=256m --cpus=1",
            "--tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777,size=16m",
            '--env HOME=/tmp --env LC_ALL=C',
            '"$IMAGE_ID" /bin/bash --noprofile --norc -c',
            '"$OSV_SCANNER_SHA256" "$OSV_DB_PUB_SHA256"',
            '"$OSV_DB_PUB_SIZE" "$OSV_DB_PUB_CAPTURE_EPOCH"',
        ),
        "Dart audit image preflight",
    )
    require("--mount " not in preflight, "Dart audit image preflight must have no mount")
    require_all(
        scanner,
        (
            "--pids-limit=64 --memory=512m --memory-swap=512m --cpus=2",
            "--tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777,size=64m",
            '--env HOME=/tmp/audit-home --env LC_ALL=C',
            "--env OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/opt/osv-db",
            '--mount "type=bind,source=$STAGED_LOCKFILE_PATH,target=/work/$LOCKFILE,readonly"',
            '--workdir /work "$IMAGE_ID"',
            'osv-scanner --offline --format=json --lockfile="$LOCKFILE"',
        ),
        "Dart audit scanner",
    )
    require(scanner.count("--mount ") == 1, "Dart audit scanner must have exactly one mount")

    require_all(
        result,
        (
            "ALLOWED_SCANNER_STATUSES = frozenset((0, 1))",
            "EXPECTED_DB_MAX_AGE_DAYS = 30",
            "MAX_RESULT_BYTES = 64 * 1024 * 1024",
            "MAX_STDERR_BYTES = 1024 * 1024",
            "def stable_read(path, maximum_bytes=None):",
            "metadata.st_nlink == 1",
            'flags |= os.O_NOFOLLOW',
            "def prepare(policy_path, lockfile_path, output):",
            'output / "pubspec.lock"',
            'output / "policy.txt"',
            "def require_fresh(capture_epoch, maximum_days, now_epoch):",
            "maximum_days == EXPECTED_DB_MAX_AGE_DAYS",
            "def validate_scanner_stderr(path, expected_source):",
            'len(lines) == 4',
            'lines[0] == "Starting filesystem walk for root: /"',
            '"Loaded Pub local db from {}".format(EXPECTED_SCANNER_DATABASE)',
            'results = data.get("results")',
            "len(results) <= 1",
            'source.get("path") == expected_source and source.get("type") == "lockfile"',
            'package.get("ecosystem") == "Pub"',
            "scanner_status in ALLOWED_SCANNER_STATUSES",
            "OSV status 0 disagrees with nonempty vulnerability results",
            "OSV status 1 has no vulnerability result",
            "require(checks == 31",
            "--capture-epoch",
            "--stderr",
            "--self-test",
        ),
        "Dart audit result authority",
    )
    require_once(result, "def evaluate(policy_path, result_path, stderr_path, scanner_status, lockfile):", "result evaluator")
    require_once(result, "def run_self_test():", "result behavioral self-test")
    require('data.get("results", [])' not in result, "Dart result parser defaults a missing results field")

    require_all(
        pins,
        (
            'OSV_SCANNER_VERSION="2.4.0"',
            'OSV_SCALIBR_VERSION="0.4.5"',
            'OSV_SCANNER_COMMIT="b56b5191101d5f27d4787d5583d8d01e9518a7af"',
            'OSV_SCANNER_BUILT_AT="2026-06-18T12:55:27Z"',
            'OSV_SCANNER_SIZE="{}"'.format(SCANNER_SIZE),
            'OSV_SCANNER_SHA256="{}"'.format(SCANNER_SHA256),
            'OSV_DB_PUB_SHA256="{}"'.format(DATABASE_SHA256),
            'OSV_DB_PUB_SIZE="19448"',
            'OSV_DB_PUB_CAPTURE_EPOCH="{}"'.format(DATABASE_CAPTURE_EPOCH),
            'OSV_DB_PUB_GENERATION="{}"'.format(DATABASE_GENERATION),
            'OSV_DB_PUB_MD5_BASE64="yOWu6VS64jMQQPA8ZzScvQ=="',
            'OSV_DB_PUB_CRC32C_BASE64="W78GeA=="',
            'OSV_DB_PUB_RECORDS="13"',
            'OSV_DB_PUB_UNCOMPRESSED_BYTES="47209"',
            'OSV_DB_PUB_MAX_AGE_DAYS="{}"'.format(DATABASE_MAX_AGE_DAYS),
            'DART_AUDIT_IMAGE_ID="{}"'.format(IMAGE_ID),
            'SHA256_DART_AUDIT_DOCKERFILE="{}"'.format(DOCKERFILE_SHA256),
            'DART_AUDIT_IMAGE_CONFIG_ID="{}"'.format(CONFIG_ID),
            'DART_AUDIT_IMAGE_MANIFEST_ID="{}"'.format(MANIFEST_ID),
            'SHA256_DART_AUDIT_IMAGE_ARCHIVE="{}"'.format(ARCHIVE_SHA256),
            'SIZE_DART_AUDIT_IMAGE_ARCHIVE="{}"'.format(ARCHIVE_SIZE),
        ),
        "Dart advisory immutable pins",
    )
    require_all(
        dockerfile,
        (
            "scripts/online-fetch.sh acquires those standalone files by exact URL, size, and",
            "scripts/dart-audit.sh never invokes",
            "ARG BASE_DIGEST=sha256:152dc042452c496007f07ca9127571cb9c29697f42acbfad72324b2bb2e43c98",
            "USER 65532:65532",
            "COPY --chown=65532:65532 --chmod=0755 osv-scanner /inputs/osv-scanner",
            "COPY --chown=65532:65532 --chmod=0644 Pub-all.zip /inputs/all.zip",
            "sha256sum --check --strict --status",
            "touch -d \"@${OSV_DB_PUB_CAPTURE_EPOCH}\"",
            "org.rustdesk.dart-audit-input.contract",
            "COPY --from=validated-inputs --chown=0:0 --chmod=0755",
            "COPY --from=validated-inputs --chown=0:0 --chmod=0644",
        ),
        "Dart advisory acquisition separation",
    )
    for forbidden in ("apt-get", "curl ", "wget ", "https://", "http://"):
        require(
            forbidden not in dockerfile,
            "Dart advisory Dockerfile retained live acquisition {!r}".format(
                forbidden
            ),
        )

    require_all(
        input_validator,
        (
            "MAX_SCANNER_BYTES = 64 * 1024 * 1024",
            "MAX_DATABASE_BYTES = 16 * 1024 * 1024",
            "metadata_identity(before) == metadata_identity(opened)",
            "metadata_identity(opened) == metadata_identity(closed)",
            "metadata_identity(closed) == metadata_identity(after)",
            "before.st_nlink == 1",
            "stat.S_IMODE(before.st_mode) == 0o400",
            "flags |= os.O_NOFOLLOW",
            "actual == expected_sha256",
            "actual_md5 == expected_md5",
            "actual_crc32c == expected_crc32c",
            "len(members) == expected_records",
            "total == expected_uncompressed_bytes",
            "match = ADVISORY_FILE.fullmatch(name)",
            "record.get(\"id\") == match.group(1)",
            "data.startswith(b\"\\x7fELF\")",
            "require(checks == 11",
        ),
        "Dart advisory standalone input validator",
    )
    require_all(
        fixed_helper,
        (
            "if len(specs) == 2:",
            '"dart-audit-inputs/Pub-all.zip"',
            '"dart-audit-inputs/osv-scanner"',
            "Dart-audit self-test publication omitted an input",
        ),
        "Dart advisory fixed-input transaction profile",
    )
    require_all(
        online_fetch,
        (
            "readonly -a DART_AUDIT_FIXED_INPUT_ARGS=(",
            (
                "https://storage.googleapis.com/storage/v1/b/"
                "osv-vulnerabilities/o/Pub%2Fall.zip?alt=media"
                "&generation=${OSV_DB_PUB_GENERATION}"
            ),
            (
                "https://github.com/google/osv-scanner/releases/download/"
                "v${OSV_SCANNER_VERSION}/osv-scanner_linux_amd64"
            ),
            'dart-audit) archive_args=("${DART_AUDIT_FIXED_INPUT_ARGS[@]}")',
            "stage_dart_audit_inputs() {",
            'stage_archive_bundle dart-audit "$ONLINE_DIR" .rustdesk-dart-audit-inputs',
            "validate_dart_audit_inputs",
            "--database-md5 \"$OSV_DB_PUB_MD5_BASE64\"",
            "--database-crc32c \"$OSV_DB_PUB_CRC32C_BASE64\"",
            "--database-records \"$OSV_DB_PUB_RECORDS\"",
            "--database-uncompressed-bytes \"$OSV_DB_PUB_UNCOMPRESSED_BYTES\"",
            "maintenance_build_dart_audit_image_candidate() {",
            'local context="$ONLINE_FETCH_TMP/dart-audit-build-context"',
            '/usr/bin/install -d -m 0700 "$context"',
            '"$SCRIPT_DIR/Dockerfile.dart-audit" "$context/Dockerfile.dart-audit"',
            '"$ONLINE_DIR/dart-audit-inputs/osv-scanner" "$context/osv-scanner"',
            '"$ONLINE_DIR/dart-audit-inputs/Pub-all.zip" "$context/Pub-all.zip"',
            '"$context" -mindepth 1 -maxdepth 1 -type f',
            "--network=none --pull=false --no-cache",
            "--platform=linux/amd64 --provenance=mode=max --load",
            '--build-arg "DART_AUDIT_DOCKERFILE_SHA256=${SHA256_DART_AUDIT_DOCKERFILE}"',
            'local tag="rd-dart-audit-candidate:provenance-v1"',
            "online_image_provenance verify-local",
            "dart_audit_image_spec_args() {",
            "require_dart_audit_image_pins() {",
            "verify_or_load_dart_audit_image() {",
            "maintenance_capture_dart_audit_image() {",
            '--archive "$ONLINE_DIR/verifier-images/dart-audit.docker.tar.gz"',
            '--archive-sha "$SHA256_DART_AUDIT_IMAGE_ARCHIVE"',
            '--archive-size "$SIZE_DART_AUDIT_IMAGE_ARCHIVE"',
            (
                'online_image_provenance maintenance-capture \\\n'
                '            --output "$directory/dart-audit.docker.tar.gz"'
            ),
            '--output "$directory/dart-audit.docker.tar.gz"',
            "--maintenance-capture-dart-audit-image",
            "--dart-audit-image",
        ),
        "Dart advisory acquisition, build, archive, and recovery authority",
    )
    candidate = extract_between(
        online_fetch,
        "maintenance_build_dart_audit_image_candidate() {",
        '\n}\n\ncapture_builder_image()',
        "Dart advisory candidate build",
    )[0]
    require_all(
        candidate,
        (
            "online_docker buildx build",
            "--network=none --pull=false --no-cache",
            "--platform=linux/amd64 --provenance=mode=max --load",
        ),
        "Dart advisory candidate build",
    )
    for forbidden in (
        "docker pull",
        "online_docker pull",
        "--network=host",
        "--privileged",
        "--cap-add",
        "--publish",
        "source=$REPO_ROOT",
        "source=$SCRIPT_DIR",
    ):
        require(
            forbidden not in candidate,
            "Dart advisory candidate build retained forbidden authority {!r}".format(
                forbidden
            ),
        )
    private_archive, _ = extract_between(
        provenance,
        "def requires_private_archive(spec: ImageSpec) -> bool:",
        "\n\n\ndef fail(message: str) -> None:",
        "private image archive classification",
    )
    require_all(
        private_archive,
        (
            "CertifiedAndroidBuilderSpec",
            "VerifierSpec",
            "AppleCheckSpec",
            "DartAuditSpec",
            "RustAuditSpec",
        ),
        "private image archive classification",
    )
    capture, _ = extract_between(
        provenance,
        "def capture(output: Path, spec: ImageSpec) -> tuple[str, int]:",
        "\n\n\ndef create_fixture_archive(path: Path, spec: Spec) -> str:",
        "private image archive capture",
    )
    require_all(
        capture,
        (
            "if requires_private_archive(spec):",
            "save_ref = spec.image_id",
        ),
        "private image archive capture",
    )
    require(
        provenance.count("requires_private_archive(spec)") == 6,
        "every private image archive boundary must use the shared classification",
    )
    require_all(
        provenance,
        (
            "class DartAuditSpec:",
            "DART_AUDIT_CONTRACT = \"rustdesk-dart-audit-image-v1\"",
            (
                "def contains_vcs_authority(value: object) -> bool:\n"
                "        if isinstance(value, dict):\n"
                "            return any(\n"
                "                isinstance(key, str)"
            ),
            "contains undeclared VCS authority",
            '"build-arg:DART_AUDIT_DOCKERFILE_SHA256"',
            '"force-network-mode": "none"',
            '"no-cache": ""',
            (
                '"local.followpaths": '
                '\'["Pub-all.zip","osv-scanner"]\''
            ),
            "source_operations != expected_sources",
            (
                "[set(operation) for operation in operations] != "
                "["
            ),
            'executions[0].get("mounts") != [{"dest": "/"}]',
            (
                "DART_AUDIT_VALIDATION_COMMAND_SHA256 = (\n"
                '    "e8c2ad1bc895b67920107e76caf327c54'
                'a740ab84f4b40018f59b5948cf46a47"'
            ),
            'execution_meta.get("user") != "65532:65532"',
            'executions[0].get("network") != 2',
            "base64.b64decode(source_info[\"data\"], validate=True)",
            "provenance Dockerfile differs from its pin",
            "root descriptor has undeclared annotations",
            "create_dart_audit_fixture_archive(",
            "add_extra_source=True",
            "if dart_checks != 21:",
        ),
        "Dart advisory image provenance and recoverable archive contract",
    )

    require_once(verify, "python3 scripts/dart-audit-result.py --self-test", "Dart audit result self-test wiring")
    require_once(
        verify,
        "/usr/bin/python3 -I -S scripts/dart-audit-image-input.py --self-test",
        "Dart advisory fixed-input self-test wiring",
    )
    require_once(
        verify,
        "/usr/bin/python3 -I -S scripts/offline-image-provenance.py --self-test",
        "Dart advisory image archive self-test wiring",
    )
    require_once(
        verify,
        "python3 scripts/verify-dart-audit-authority.py --repo . --self-test",
        "Dart audit authority self-test wiring",
    )
    require('<span class="id">R-S11be</span>' in requirements, "requirements are missing R-S11be")
    require("<tr><td>182</td>" in requirements, "requirements are missing Appendix C #182")
    require_all(
        requirements,
        (
            "never build, pull, or resolve an image tag",
            "exact immutable local image content ID",
            "exactly 30 days",
            "stable private copies",
            "bounded stderr telemetry",
            "generation-specific GCS media object",
            "current-user-private three-file context",
            "VCS-free BuildKit provenance statement",
            "single-link, mode-0400, untagged OCI archive",
            "Recovery remains outside the verdict path",
        ),
        "Dart advisory normative closure",
    )
    require(
        "R-S11be/R-S11e-71 — Dart advisory result and scanner authority" in hardening,
        "hardening ledger is missing the Dart audit closure",
    )
    require_all(
        hardening,
        (
            "RECOVERABLE\n  IMAGE DISTRIBUTION CLOSED/GATED",
            "exact 30-day capture-age ceiling",
            IMAGE_ID,
            CONFIG_ID,
            MANIFEST_ID,
            ARCHIVE_SHA256,
            "Networkless construction and distribution:",
            "31 policy/freshness/status/schema decisions",
            "199 packages reported",
        ),
        "Dart advisory hardening evidence",
    )

    mutation_start = validator.index("\nMUTATIONS = (") + 1
    mutation_end = validator.index("\n)\n\n\ndef mutate_once", mutation_start)
    validator_mutations = validator[mutation_start:mutation_end]
    require_all(
        validator_mutations,
        (
            'Mutation("shell", "--network=none", "--network=bridge"',
            'Mutation("shell", \'case "$SCANNER_STATUS" in\\n  0|1) ;;\'',
            'Mutation("result", "EXPECTED_DB_MAX_AGE_DAYS = 30"',
            'Mutation("pins", \'DART_AUDIT_IMAGE_ID="{}"\''.format(IMAGE_ID),
            '"networkless candidate build"',
            '"VCS-attribution rejection"',
            '"standalone input immutability"',
            '"Dart private archive classification"',
            'Mutation("requirements", \'<span class="id">R-S11be</span>\'',
            'Mutation("hardening", "Networkless construction and distribution:"',
        ),
        "Dart audit authority validator mutation coverage",
    )


MUTATIONS = (
    Mutation("shell", '[ "$(id -u)" -ne 0 ]', '[ "$(id -u)" -ge 0 ]', "UID-root refusal"),
    Mutation("shell", '[ "$(id -g)" -ne 0 ]', '[ "$(id -g)" -ge 0 ]', "GID-root refusal"),
    Mutation("shell", '[ ! -L "$LOCKFILE" ]', '[ -e "$LOCKFILE" ]', "lockfile symlink refusal"),
    Mutation("shell", '[ ! -L "$IGNORES_FILE" ]', '[ -e "$IGNORES_FILE" ]', "policy symlink refusal"),
    Mutation(
        "shell",
        'AUDIT_TMP="$(umask 077 && mktemp -d /tmp/rustdesk-dart-audit.XXXXXXXXXX)"',
        'AUDIT_TMP="/tmp/rustdesk-dart-audit"',
        "private workspace",
    ),
    Mutation(
        "shell",
        '--remove-private-root "$AUDIT_TMP" --expected-identity "$AUDIT_TMP_ID"',
        'rm -rf -- "$AUDIT_TMP"',
        "descriptor-safe cleanup",
    ),
    Mutation("shell", "readonly MAX_SCANNER_OUTPUT_BLOCKS=65536", "readonly MAX_SCANNER_OUTPUT_BLOCKS=999999", "output file limit"),
    Mutation("shell", "scripts/dart-audit-result.py prepare", "scripts/dart-audit-result.py validate-policy", "stable preparation"),
    Mutation("shell", '--capture-epoch "$OSV_DB_PUB_CAPTURE_EPOCH"', '--capture-epoch "$(date +%s)"', "capture freshness"),
    Mutation("shell", '--max-age-days "$OSV_DB_PUB_MAX_AGE_DAYS"', '--max-age-days 99999', "age ceiling"),
    Mutation("shell", '"$DART_AUDIT_IMAGE_ID")"', '"rd-dart-audit")"', "exact image inspection"),
    Mutation("shell", '[[ "$DART_AUDIT_IMAGE_ID" =~ ^sha256:[0-9a-f]{64}$ ]]', '[ -n "$DART_AUDIT_IMAGE_ID" ]', "image ID syntax"),
    Mutation("shell", '[ "$IMAGE_ID" = "$DART_AUDIT_IMAGE_ID" ]', 'true # exact image identity', "image ID equality"),
    Mutation("shell", "--pull=never", "--pull=always", "pull refusal"),
    Mutation("shell", "--network=none", "--network=bridge", "network isolation"),
    Mutation("shell", "--read-only", "--hostname=dart-audit", "read-only root"),
    Mutation("shell", '--user "$(id -u):$(id -g)"', '--user 0:0', "nonroot user"),
    Mutation("shell", "--cap-drop=ALL", "--cap-add=SYS_ADMIN", "capability drop"),
    Mutation("shell", "--security-opt=no-new-privileges", "--security-opt=label=disable", "no-new-privileges"),
    Mutation("shell", "--pids-limit=32", "--pids-limit=-1", "preflight PID bound"),
    Mutation("shell", "--pids-limit=64", "--pids-limit=-1", "scanner PID bound"),
    Mutation("shell", "--memory=256m", "--memory=0", "preflight memory bound"),
    Mutation("shell", "--memory=512m", "--memory=0", "scanner memory bound"),
    Mutation("shell", "--memory-swap=256m", "--memory-swap=-1", "preflight swap bound"),
    Mutation("shell", "--memory-swap=512m", "--memory-swap=-1", "scanner swap bound"),
    Mutation("shell", "--cpus=1", "--cpuset-cpus=0-255", "preflight CPU bound"),
    Mutation("shell", "--cpus=2", "--cpuset-cpus=0-255", "scanner CPU bound"),
    Mutation("shell", "size=16m", "size=1g", "preflight tmpfs bound"),
    Mutation("shell", "size=64m", "size=1g", "scanner tmpfs bound"),
    Mutation("shell", '"$OSV_SCANNER_SHA256" "$OSV_DB_PUB_SHA256"', '"bad" "$OSV_DB_PUB_SHA256"', "scanner byte pin"),
    Mutation("shell", '"$OSV_DB_PUB_SIZE" "$OSV_DB_PUB_CAPTURE_EPOCH"', '"0" "$OSV_DB_PUB_CAPTURE_EPOCH"', "database metadata pin"),
    Mutation("shell", '[ "$IMAGE_PREFLIGHT_STATUS" -eq 0 ]', '[ "$IMAGE_PREFLIGHT_STATUS" -ge 0 ]', "preflight finality"),
    Mutation("shell", '[ ! -s "$IMAGE_PREFLIGHT_ERR" ]', 'true # preflight stderr', "preflight diagnostics"),
    Mutation(
        "shell",
        '--mount "type=bind,source=$STAGED_LOCKFILE_PATH,target=/work/$LOCKFILE,readonly"',
        '-v "$PWD:/work:rw"',
        "exact private input",
    ),
    Mutation("shell", 'case "$SCANNER_STATUS" in\n  0|1) ;;', 'case "$SCANNER_STATUS" in\n  0|1|127) ;;', "status classification"),
    Mutation("shell", '--scanner-status "$SCANNER_STATUS"', '--scanner-status 0', "status/result binding"),
    Mutation("shell", '[ "$RESULT_BYTES" -le 67108864 ]', '[ "$RESULT_BYTES" -ge 0 ]', "result size bound"),
    Mutation("shell", '[ "$ERROR_BYTES" -le 1048576 ]', '[ "$ERROR_BYTES" -ge 0 ]', "stderr size bound"),
    Mutation("shell", 'sha256sum -- "$AUDIT_TMP/pubspec.lock"', 'sha256sum -- "$LOCKFILE"', "staged lock postcondition"),
    Mutation("shell", 'sha256sum -- "$AUDIT_TMP/policy.txt"', 'sha256sum -- "$IGNORES_FILE"', "staged policy postcondition"),
    Mutation("result", "ALLOWED_SCANNER_STATUSES = frozenset((0, 1))", "ALLOWED_SCANNER_STATUSES = frozenset((0, 1, 127, 128))", "allowed statuses"),
    Mutation("result", "EXPECTED_DB_MAX_AGE_DAYS = 30", "EXPECTED_DB_MAX_AGE_DAYS = 90", "freshness policy"),
    Mutation("result", "metadata.st_nlink == 1", "metadata.st_nlink >= 1", "hardlink refusal"),
    Mutation("result", 'results = data.get("results")', 'results = data.get("results", [])', "required results field"),
    Mutation("result", "len(results) <= 1", "len(results) >= 0", "single source"),
    Mutation("result", 'source.get("path") == expected_source and source.get("type") == "lockfile"', 'source.get("type") == "lockfile"', "exact result source"),
    Mutation("result", 'package.get("ecosystem") == "Pub"', 'bool(package.get("ecosystem"))', "Pub ecosystem"),
    Mutation("result", "len(lines) == 4", "len(lines) >= 0", "stderr telemetry finality"),
    Mutation("result", 'lines[0] == "Starting filesystem walk for root: /"', "True # walk diagnostic", "stderr telemetry grammar"),
    Mutation("result", 'require(not findings, "OSV status 0 disagrees with nonempty vulnerability results")', "pass # status 0 agreement", "clean-status agreement"),
    Mutation("result", 'require(bool(findings), "OSV status 1 has no vulnerability result")', "pass # status 1 agreement", "finding-status agreement"),
    Mutation("result", "require(checks == 31", "require(checks >= 0", "behavioral self-test count"),
    Mutation("pins", 'DART_AUDIT_IMAGE_ID="sha256:1cdfd518d52738f17f2724a8424acb0530eaa69e38e1a053a7bead82aae77a65"', 'DART_AUDIT_IMAGE_ID="sha256:0000000000000000000000000000000000000000000000000000000000000000"', "image content pin"),
    Mutation("pins", 'DART_AUDIT_IMAGE_CONFIG_ID="sha256:a1833b5698aef708a1c5485776aea2264b966f978db7923881b7c1e9e70a54fd"', 'DART_AUDIT_IMAGE_CONFIG_ID="sha256:0000000000000000000000000000000000000000000000000000000000000000"', "image config pin"),
    Mutation("pins", 'DART_AUDIT_IMAGE_MANIFEST_ID="sha256:8b09349196d4c32a90072f055840952c0e702be8c2a03ab54586211558217b33"', 'DART_AUDIT_IMAGE_MANIFEST_ID="sha256:0000000000000000000000000000000000000000000000000000000000000000"', "image manifest pin"),
    Mutation("pins", 'SHA256_DART_AUDIT_IMAGE_ARCHIVE="f6afc51f31b0c85c15e1497adfdaa18fe3736150f7149823298a6584d3b811b9"', 'SHA256_DART_AUDIT_IMAGE_ARCHIVE="0000000000000000000000000000000000000000000000000000000000000000"', "image archive pin"),
    Mutation("pins", 'OSV_DB_PUB_CAPTURE_EPOCH="1783494618"', 'OSV_DB_PUB_CAPTURE_EPOCH="9999999999"', "capture epoch pin"),
    Mutation("pins", 'OSV_DB_PUB_MAX_AGE_DAYS="30"', 'OSV_DB_PUB_MAX_AGE_DAYS="90"', "capture age pin"),
    Mutation("pins", 'OSV_DB_PUB_SHA256="5fdd3db5059b4f935a507385cb93cab3c35ba3d632332a5c8f5deb604f95a5c0"', 'OSV_DB_PUB_SHA256="0000000000000000000000000000000000000000000000000000000000000000"', "database byte pin"),
    Mutation("dockerfile", "USER 65532:65532", "USER 0:0", "nonroot build validation"),
    Mutation(
        "online_fetch",
        (
            "    online_docker buildx build \\\n"
            "        --network=none --pull=false --no-cache"
        ),
        (
            "    online_docker buildx build \\\n"
            "        --network=default --pull=true --no-cache"
        ),
        "networkless candidate build",
    ),
    Mutation(
        "online_fetch",
        'local context="$ONLINE_FETCH_TMP/dart-audit-build-context"',
        'local context="$REPO_ROOT"',
        "private candidate context",
    ),
    Mutation(
        "online_fetch",
        'online_image_provenance maintenance-capture \\\n'
        '            --output "$directory/dart-audit.docker.tar.gz"',
        'online_image_provenance verify-local \\\n'
        '            --output "$directory/dart-audit.docker.tar.gz"',
        "archive capture authority",
    ),
    Mutation(
        "online_fetch",
        '--archive "$ONLINE_DIR/verifier-images/dart-audit.docker.tar.gz"',
        '--archive "$ONLINE_DIR/dart-audit.docker.tar.gz"',
        "private archive namespace",
    ),
    Mutation(
        "provenance",
        (
            "def contains_vcs_authority(value: object) -> bool:\n"
            "        if isinstance(value, dict):\n"
            "            return any(\n"
            "                isinstance(key, str)"
        ),
        (
            "def contains_vcs_authority_removed(value: object) -> bool:\n"
            "        if isinstance(value, dict):\n"
            "            return any(\n"
            "                isinstance(key, str)"
        ),
        "VCS-attribution rejection",
    ),
    Mutation(
        "provenance",
        'execution_meta.get("user") != "65532:65532"',
        'execution_meta.get("user") != "0:0"',
        "attested nonroot validation",
    ),
    Mutation(
        "provenance",
        'executions[0].get("network") != 2',
        'executions[0].get("network") != 0',
        "attested networkless validation",
    ),
    Mutation(
        "provenance",
        "source_operations != expected_sources",
        "False",
        "attested exact source inventory",
    ),
    Mutation(
        "provenance",
        "if dart_checks != 21:",
        "if dart_checks < 1:",
        "Dart image behavioral coverage",
    ),
    Mutation(
        "provenance",
        (
            "def requires_private_archive(spec: ImageSpec) -> bool:\n"
            "    return isinstance(\n"
            "        spec,\n"
            "        (\n"
            "            CertifiedAndroidBuilderSpec,\n"
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
            "            CertifiedAndroidBuilderSpec,\n"
            "            VerifierSpec,\n"
            "            AppleCheckSpec,\n"
            "            RustAuditSpec,\n"
            "        ),\n"
            "    )"
        ),
        "Dart private archive classification",
    ),
    Mutation(
        "input_validator",
        "stat.S_IMODE(before.st_mode) == 0o400",
        "stat.S_IMODE(before.st_mode) in (0o400, 0o600)",
        "standalone input immutability",
    ),
    Mutation(
        "input_validator",
        "metadata_identity(closed) == metadata_identity(after)",
        "metadata_identity(closed) != metadata_identity(after)",
        "standalone input path stability",
    ),
    Mutation(
        "input_validator",
        "before.st_nlink == 1",
        "before.st_nlink >= 1",
        "standalone input hardlink refusal",
    ),
    Mutation(
        "input_validator",
        "actual == expected_sha256",
        "len(actual) == 64",
        "standalone input SHA-256 equality",
    ),
    Mutation(
        "input_validator",
        "actual_md5 == expected_md5",
        "len(actual_md5) == 24",
        "standalone input publisher MD5 equality",
    ),
    Mutation(
        "input_validator",
        "actual_crc32c == expected_crc32c",
        "len(actual_crc32c) == 8",
        "standalone input publisher CRC32C equality",
    ),
    Mutation(
        "input_validator",
        "match = ADVISORY_FILE.fullmatch(name)",
        "match = ADVISORY_FILE.search(name)",
        "standalone input member-name grammar",
    ),
    Mutation(
        "input_validator",
        'record.get("id") == match.group(1)',
        'record.get("id") is not None',
        "standalone input record identity",
    ),
    Mutation(
        "input_validator",
        'data.startswith(b"\\x7fELF")',
        "bool(data)",
        "standalone scanner format",
    ),
    Mutation(
        "fixed_helper",
        "if len(specs) == 2:",
        "if len(specs) == 3:",
        "closed fixed-input profile",
    ),
    Mutation(
        "verify",
        "/usr/bin/python3 -I -S scripts/dart-audit-image-input.py --self-test",
        "true # Dart advisory input self-test removed",
        "standalone input self-test",
    ),
    Mutation("verify", "python3 scripts/verify-dart-audit-authority.py --repo . --self-test", "python3 scripts/verify-dart-audit-authority.py --repo .", "shared semantic gate"),
    Mutation("requirements", '<span class="id">R-S11be</span>', '<span class="id">R-S11be-disabled</span>', "normative requirement"),
    Mutation("requirements", "<tr><td>182</td>", "<tr><td>182-disabled</td>", "Appendix disposition"),
    Mutation("hardening", "Networkless construction and distribution:", "Networked construction and mutable distribution:", "hardening acquisition record"),
)


def mutate_once(sources, mutation):
    source = sources[mutation.source]
    count = source.count(mutation.old)
    require(count >= 1, "self-test mutation {!r} is absent".format(mutation.label))
    changed = dict(sources)
    changed[mutation.source] = source.replace(mutation.old, mutation.new, 1)
    return changed


def load_sources(repo):
    return {
        "shell": (repo / "scripts/dart-audit.sh").read_text(encoding="utf-8"),
        "result": (repo / "scripts/dart-audit-result.py").read_text(encoding="utf-8"),
        "pins": (repo / "scripts/pins.env").read_text(encoding="utf-8"),
        "dockerfile": (repo / "scripts/Dockerfile.dart-audit").read_text(encoding="utf-8"),
        "verify": (repo / "scripts/verify.sh").read_text(encoding="utf-8"),
        "requirements": (repo / "requirements.html").read_text(encoding="utf-8"),
        "hardening": (repo / "HARDENING_STATUS.md").read_text(encoding="utf-8"),
        "validator": (repo / "scripts/verify-dart-audit-authority.py").read_text(encoding="utf-8"),
        "online_fetch": (repo / "scripts/online-fetch.sh").read_text(encoding="utf-8"),
        "provenance": (repo / "scripts/offline-image-provenance.py").read_text(encoding="utf-8"),
        "input_validator": (repo / "scripts/dart-audit-image-input.py").read_text(encoding="utf-8"),
        "fixed_helper": (repo / "scripts/online-fixed-archive-output.py").read_text(encoding="utf-8"),
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
                "verify-dart-audit-authority: ok ({} deliberate mutations rejected)".format(
                    len(MUTATIONS)
                )
            )
        else:
            print("verify-dart-audit-authority: ok")
        return 0
    except (ContractError, OSError, UnicodeError, ValueError) as exc:
        print("verify-dart-audit-authority: {}".format(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
