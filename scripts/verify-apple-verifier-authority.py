#!/usr/bin/env python3
"""Validate the Apple source-conformance verifier's input and container authority."""

import argparse
import hashlib
import pathlib
import re
from typing import Dict, NamedTuple, Tuple


class AuthorityError(Exception):
    pass


class Mutation(NamedTuple):
    source: str
    old: str
    new: str
    label: str


def require(source: str, token: str, label: str) -> None:
    if token not in source:
        raise AuthorityError("missing {}".format(label))


def require_count(source: str, token: str, count: int, label: str) -> None:
    observed = source.count(token)
    if observed != count:
        raise AuthorityError("{} count is {}, expected {}".format(label, observed, count))


def forbid(source: str, token: str, label: str) -> None:
    if token in source:
        raise AuthorityError("forbidden {}".format(label))


def require_order(source: str, tokens: Tuple[str, ...], label: str) -> None:
    positions = []
    cursor = 0
    for token in tokens:
        position = source.find(token, cursor)
        if position < 0:
            raise AuthorityError("{} is missing {!r}".format(label, token))
        positions.append(position)
        cursor = position + len(token)
    if positions != sorted(positions) or len(set(positions)) != len(positions):
        raise AuthorityError("{} is incomplete or misordered".format(label))


def extract(source: str, start: str, end: str, label: str) -> str:
    if source.count(start) != 1:
        raise AuthorityError("{} start cardinality differs".format(label))
    begin = source.index(start)
    finish = source.find(end, begin + len(start))
    if finish < 0:
        raise AuthorityError("{} end is missing".format(label))
    return source[begin : finish + len(end)]


def forbid_container_authority(source: str, label: str) -> None:
    for token, description in (
        ("--privileged", "privileged container"),
        ("--cap-add", "added capability"),
        ("--network=host", "host network namespace"),
        ("--network host", "host network namespace"),
        ("--pid=host", "host PID namespace"),
        ("--pid host", "host PID namespace"),
        ("--ipc=host", "host IPC namespace"),
        ("--ipc host", "host IPC namespace"),
        ("--uts=host", "host UTS namespace"),
        ("--uts host", "host UTS namespace"),
        ("--publish", "published port"),
        ("--expose", "exposed port"),
        ("/var/run/docker.sock:/var/run/docker.sock", "Docker socket volume"),
        ("source=/var/run/docker.sock", "Docker socket mount"),
    ):
        forbid(source, token, "{} {}".format(label, description))
    if re.search(r"(?:^|\s)-p(?:\s|=)", source):
        raise AuthorityError("forbidden {} short published port".format(label))


def validate(sources: Dict[str, str]) -> None:
    apple = sources["apple"]
    pins = sources["pins"]
    provenance = sources["offline_provenance"]
    online_fetch = sources["online_fetch"]
    dockerfile_digest = hashlib.sha256(
        sources["dockerfile"].encode("utf-8")
    ).hexdigest()
    require(
        pins,
        'SHA256_APPLE_CHECK_DOCKERFILE="{}"'.format(dockerfile_digest),
        "Apple acquisition-recipe content pin",
    )

    cleanup = extract(
        apple,
        "cleanup_apple_check_tmp() {",
        "}\ntrap cleanup_apple_check_tmp EXIT",
        "private Apple workspace cleanup",
    )
    require_order(
        cleanup,
        (
            'trap - EXIT HUP INT TERM',
            'if ! /usr/bin/python3 -I -S "$REPO/scripts/restore-private-directory-modes.py"',
            '--root "$APPLE_CHECK_TMP"',
            '--expected-identity "$APPLE_CHECK_TMP_IDENTITY"',
            '--owner "$APPLE_CHECK_TMP_UID"',
            '--group "$APPLE_CHECK_TMP_GID"',
            'echo "apple-conform-check: failed to restore private workspace directory modes: $APPLE_CHECK_TMP" >&2',
            "status=1",
            'if ! rm -rf -- "$APPLE_CHECK_TMP"',
            'echo "apple-conform-check: failed to remove private workspace: $APPLE_CHECK_TMP" >&2',
            'status=1',
        ),
        "identity-bound directory restoration before private workspace removal",
    )

    classifier = extract(
        apple,
        "apple_sdk_boundary_after_successful_workspace_anchor() {",
        "}\n\napple_sdk_boundary_self_test() {",
        "Apple SDK boundary classifier",
    )
    for token, label in (
        ("rust_error_line = NR", "first prior Rust diagnostic capture"),
        ('$0 !~ /^[[:space:]]*error: failed to run custom build command for `[^`]+`$/',
         "exact Cargo custom-build wrapper exception"),
        ("boundary_line = NR", "first SDK boundary capture"),
        ("boundary_line > 0", "SDK boundary presence"),
        ("rust_error_line == 0 || rust_error_line > boundary_line",
         "no Rust diagnostic before accepted boundary"),
    ):
        require(classifier, token, label)

    for token, label in (
        ('readonly APPLE_CHECK_TMP_IDENTITY="$(stat -c \'%d:%i\' -- "$APPLE_CHECK_TMP")"',
         "private workspace retained identity"),
        ('readonly APPLE_CHECK_TMP_UID="$(id -u)"',
         "private workspace retained owner"),
        ('readonly APPLE_CHECK_TMP_GID="$(id -g)"',
         "private workspace retained group"),
        ("readonly DOCKER_BIN=/usr/bin/docker", "fixed Docker client"),
        ("readonly APPLE_DOCKER_HOST=unix:///var/run/docker.sock", "fixed local Docker endpoint"),
        ('readonly APPLE_DOCKER_CONFIG="$APPLE_CHECK_TMP/docker-config"',
         "private Docker configuration path"),
        ('[ "$BUILD_UID" -ne 0 ] || die "refusing host or container-root execution"',
         "host-root refusal"),
        ('[ "$BUILD_GID" -ne 0 ] || die "refusing a root primary group"',
         "root-primary-group refusal"),
        ('[ "$(stat -c \'%u:%g:%a:%h\' -- "$DOCKER_BIN")" = "0:0:755:1" ]',
         "trusted Docker client metadata"),
        ('[ -S /var/run/docker.sock ]', "fixed Docker socket type"),
        ("for name in DOCKER_CONFIG DOCKER_CONTEXT DOCKER_CERT_PATH DOCKER_TLS_VERIFY DOCKER_TLS",
         "caller Docker authority rejection"),
        ('[ -z "${APPLE_TARGET:-}" ] && [ -z "${APPLE_TARGETS:-}" ]',
         "target override rejection"),
        ('[ -z "${MACOS_SDK_DIR:-}" ]', "SDK override rejection"),
        ('env -i \\\n    PATH=/usr/bin:/bin', "closed Docker client environment"),
        ('--host "$APPLE_DOCKER_HOST"', "explicit Docker endpoint"),
        ('--config "$APPLE_DOCKER_CONFIG"', "explicit Docker configuration"),
        ('[ "$(cat "$APPLE_DOCKER_CONFIG/config.json")" = "{}" ]',
         "empty Docker configuration bytes"),
        ("readonly SELECTED_APPLE_TARGETS=(\n  aarch64-apple-darwin\n"
         "  x86_64-apple-darwin\n  aarch64-apple-ios\n)",
         "exact three-target matrix"),
        ('readonly IMG="$APPLE_CHECK_IMAGE_ID"', "immutable image selection"),
        ('[[ "$IMG" =~ ^sha256:[0-9a-f]{64}$ ]]', "content-ID syntax"),
        ('IMAGE_ID="$(apple_docker image inspect --format \'{{.Id}}\' "$IMG")"',
         "local exact-image inspection"),
        ('[ "$IMAGE_ID" = "$IMG" ]', "exact-image equality"),
        ('/usr/bin/python3 "$REPO/scripts/offline-image-provenance.py"',
         "fixed offline image provenance verifier"),
        ('apple_image_provenance verify-local',
         "exact Apple image provenance verification"),
        ('--image-ref "$IMAGE_ID" "${APPLE_IMAGE_SPEC[@]}"',
         "content-addressed Apple provenance arguments"),
        ('[ "$(sha256sum scripts/Dockerfile.apple-check',
         "reviewed acquisition-recipe pin"),
        ('archive_current_source >"$APPLE_SOURCE_ARCHIVE"', "private source snapshot"),
        ('SOURCE_DIGEST="$(sha256sum "$APPLE_SOURCE_ARCHIVE"', "source precondition digest"),
        ('chmod -R a-w "$APPLE_SOURCE"', "read-only source snapshot"),
        ("snapshot-subtree-create", "private vendor snapshot"),
        ('--expected "$SHA256_CARGO_VENDOR_CLOSURE_V1"', "vendor closure pin"),
        ("sed 's#directory = .*#directory = \"/vendor\"#' online/cargo-vendor-config.toml",
         "private Cargo source map"),
        ('chmod 0400 "$APPLE_CARGO_CONFIG"', "read-only Cargo source map"),
        ('"${APPLE_READ_RUN[@]}" python3 -', "confined metadata parser"),
        ("cargo check --locked --offline --config /tmp/cargo-config.toml --jobs 1",
         "locked offline Apple cross-check"),
        ("check --locked --offline --config /tmp/cargo-config.toml --jobs 1 \\\n"
         '  --package hbb_common --target "$target"',
         "locked serialized workspace anchor command"),
        ("check --locked --offline --config /tmp/cargo-config.toml --jobs 1 \\\n"
         '  --target "$target" --features "$features"',
         "locked serialized full Cargo command"),
        ('--package hbb_common --target "$target"',
         "deterministic workspace anchor package"),
        ('if [ "$anchor_rc" -ne 0 ]',
         "workspace anchor success requirement"),
        ('apple_sdk_boundary_after_successful_workspace_anchor "$log"',
         "post-anchor SDK-boundary classifier"),
        ("apple_sdk_boundary_self_test()", "SDK-boundary classifier self-test"),
        ("\napple_sdk_boundary_self_test\n\n# ---- preflight ----",
         "SDK-boundary classifier self-test invocation"),
        ('die "Apple SDK classifier accepted a log without an SDK boundary"',
         "missing-boundary negative fixture"),
        ('die "Apple SDK classifier accepted a prior coded Rust diagnostic"',
         "coded Rust diagnostic negative fixture"),
        ('die "Apple SDK classifier accepted a prior uncoded Rust diagnostic"',
         "uncoded Rust diagnostic negative fixture"),
        ('die "Apple SDK classifier accepted an inexact Cargo wrapper diagnostic"',
         "inexact Cargo wrapper negative fixture"),
        ("boundary_line > 0", "SDK boundary presence"),
        ('SOURCE_DIGEST_AFTER="$(archive_current_source | sha256sum',
         "real-source postcondition digest"),
        ('[ "$SOURCE_DIGEST_AFTER" = "$SOURCE_DIGEST" ]',
         "real-source stability proof"),
        ('FINAL_IMAGE_ID="$(apple_docker image inspect --format \'{{.Id}}\' "$IMAGE_ID")"',
         "final exact-image inspection"),
        ('[ "$FINAL_IMAGE_ID" = "$IMAGE_ID" ]', "final exact-image equality"),
        ("verify_apple_docker_authority\n\n", "final Docker authority proof"),
    ):
        require(apple, token, label)

    require_count(apple, "snapshot-subtree-create", 1, "vendor snapshot creation")
    require_count(
        apple,
        '--expected "$SHA256_CARGO_VENDOR_CLOSURE_V1"',
        2,
        "vendor create/final verification",
    )
    require_count(apple, "APPLE_READ_RUN=(", 1, "metadata launch definition")
    require_count(apple, "COMMON_CHECK=(", 1, "cross-check launch definition")
    require_count(
        apple,
        "apple_image_provenance verify-local",
        1,
        "offline image provenance invocation",
    )
    require_count(
        apple,
        'env -i \\\n    PATH=/usr/bin:/bin',
        2,
        "closed Docker/provenance environment inventory",
    )
    require_count(apple, '"${APPLE_READ_RUN[@]}"', 1, "metadata launch use")
    require_count(apple, '"${COMMON_CHECK[@]}"', 2, "workspace-anchor/full-matrix launch sites")
    require_count(apple, "apple_docker run", 3, "complete Docker run inventory")

    require_order(
        apple,
        (
            'install -d -m 0700 "$APPLE_DOCKER_CONFIG"',
            'IMAGE_ID="$(apple_docker image inspect',
            "apple_image_provenance verify-local",
            'archive_current_source >"$APPLE_SOURCE_ARCHIVE"',
            "snapshot-subtree-create",
            "apple_docker run --rm --pull=never",
            "APPLE_READ_RUN=(",
            "COMMON_CHECK=(",
            '"${APPLE_READ_RUN[@]}" python3 -',
            'for target in "${SELECTED_APPLE_TARGETS[@]}"; do',
            '"${COMMON_CHECK[@]}"',
            '--package hbb_common --target "$target"',
            'anchor_rc=$?',
            'if [ "$anchor_rc" -ne 0 ]',
            "continue",
            '"${COMMON_CHECK[@]}"',
            'apple_sdk_boundary_after_successful_workspace_anchor "$log"',
            "verify-subtree",
            'SOURCE_DIGEST_AFTER="$(archive_current_source',
            'FINAL_IMAGE_ID="$(apple_docker image inspect',
            "verify_apple_docker_authority",
        ),
        "Apple verifier setup, execution, and postconditions",
    )

    preflight = extract(
        apple,
        "apple_docker run --rm --pull=never --network=none --read-only",
        "' >\"$IMAGE_PREFLIGHT_OUT\" 2>\"$IMAGE_PREFLIGHT_ERR\"",
        "image preflight",
    )
    for token, label in (
        ('--user "$BUILD_UID:$BUILD_GID"', "numeric nonroot identity"),
        ("--cap-drop=ALL", "complete capability drop"),
        ("--security-opt=no-new-privileges", "no-new-privileges"),
        ("--pids-limit=32", "PID ceiling"),
        ("--memory=256m", "memory ceiling"),
        ("--memory-swap=256m", "no-swap expansion"),
        ("--cpus=1", "CPU ceiling"),
        ("--tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777,size=16m", "bounded scratch"),
        ('"$IMAGE_ID"', "exact image"),
    ):
        require(preflight, token, "preflight {}".format(label))
    forbid(preflight, "--mount ", "preflight host mount")
    forbid_container_authority(preflight, "preflight")

    read_run = extract(apple, "APPLE_READ_RUN=(", '  "$IMAGE_ID")', "metadata parser launch")
    for token, label in (
        ("--pull=never", "no-pull policy"),
        ("--network=none", "networkless policy"),
        ("--read-only", "read-only root"),
        ('--user "$BUILD_UID:$BUILD_GID"', "numeric nonroot identity"),
        ("--cap-drop=ALL", "complete capability drop"),
        ("--security-opt=no-new-privileges", "no-new-privileges"),
        ("--pids-limit=64", "PID ceiling"),
        ("--memory=512m", "memory ceiling"),
        ("--memory-swap=512m", "no-swap expansion"),
        ("--cpus=1", "CPU ceiling"),
        ("--tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777,size=64m", "bounded scratch"),
        ('--mount "type=bind,source=$APPLE_SOURCE,target=/work,readonly"',
         "read-only private source"),
    ):
        require(read_run, token, "metadata parser {}".format(label))
    require_count(read_run, "--mount ", 1, "metadata parser mount inventory")
    forbid_container_authority(read_run, "metadata parser")

    cross = extract(apple, "COMMON_CHECK=(", "  --workdir /work)", "cross-check launch")
    for token, label in (
        ("--pull=never", "no-pull policy"),
        ("--network=none", "networkless policy"),
        ("--read-only", "read-only root"),
        ('--user "$BUILD_UID:$BUILD_GID"', "numeric nonroot identity"),
        ("--cap-drop=ALL", "complete capability drop"),
        ("--security-opt=no-new-privileges", "no-new-privileges"),
        ("--pids-limit=512", "PID ceiling"),
        ("--memory=12g", "memory ceiling"),
        ("--memory-swap=12g", "no-swap expansion"),
        ("--cpus=4", "CPU ceiling"),
        ("--tmpfs /tmp:rw,exec,nosuid,nodev,mode=1777,size=2g", "bounded scratch"),
        ('--mount "type=bind,source=$APPLE_SOURCE,target=/work,readonly"',
         "read-only private source"),
        ('--mount "type=bind,source=$APPLE_VENDOR,target=/vendor,readonly"',
         "read-only private vendor"),
        ('--mount "type=bind,source=$APPLE_TARGET,target=/build"', "private target"),
        ('--mount "type=bind,source=$APPLE_CARGO_CONFIG,target=/tmp/cargo-config.toml,readonly"',
         "read-only Cargo source map"),
        ("--env CARGO_NET_OFFLINE=true", "Cargo offline policy"),
        ('--env PATH="$APPLE_CHECK_PATH"', "exact direct Apple toolchain path"),
    ):
        require(cross, token, "cross-check {}".format(label))
    require_count(cross, "--mount ", 4, "cross-check mount inventory")
    forbid_container_authority(cross, "cross-check")

    for token, label in (
        ("docker build", "image build fallback"),
        ("docker pull", "image pull fallback"),
        ("\nBASE_IMG=", "mutable base tag"),
        ("\nIMG=rd-apple-check", "mutable Apple tag"),
        ("rd-cargo-cache", "persistent Cargo cache"),
        ("rd-git-cache", "persistent Git cache"),
        ("rd-apple-target", "persistent target cache"),
        ('$REPO:/work', "real checkout short bind"),
        ("source=$REPO,target=/work", "real checkout bind"),
        ("source=$REPO/online", "real online tree bind"),
        ("source=$MACOS_SDK_DIR", "caller SDK bind"),
        ("source=$SDK_DIR", "ambient SDK bind"),
        ("rustfmt --emit", "undeclared rustfmt pseudo-gate"),
    ):
        forbid(apple, token, label)

    for token, label in (
        ('APPLE_CHECK_IMAGE_ID="sha256:', "Apple image content pin"),
        ('APPLE_CHECK_IMAGE_CONFIG_ID="sha256:', "Apple image config pin"),
        ('APPLE_CHECK_IMAGE_MANIFEST_ID="sha256:', "Apple platform manifest pin"),
        ('SHA256_APPLE_CHECK_IMAGE_ARCHIVE="', "Apple image archive pin"),
        ('SIZE_APPLE_CHECK_IMAGE_ARCHIVE="', "Apple image archive size"),
        ('SHA256_APPLE_CHECK_DOCKERFILE="', "Apple acquisition-recipe pin"),
        ('SHA256_APPLE_CHECK_CARGO="', "Apple Cargo binary pin"),
        ('SHA256_APPLE_CHECK_RUSTC="', "Apple rustc binary pin"),
        ('SHA256_APPLE_CHECK_DPKG_MANIFEST="', "Apple package-manifest pin"),
        ('SHA256_APPLE_TOOLCHAIN_RELEASE_HELPER="',
         "Apple release-helper content pin"),
        ('SHA256_APPLE_TOOLCHAIN_PROVENANCE_HELPER="',
         "Apple provenance-helper content pin"),
        ('SHA256_APPLE_RUST_RELEASE_MANIFEST="',
         "signed Rust release manifest pin"),
        ('APPLE_TOOLCHAIN_TREE_SHA256="', "Apple toolchain tree pin"),
    ):
        require(pins, token, label)
    for token, label in (
        (
            'APPLE_CHECK_IMAGE_ID="sha256:'
            '1845e16ca1b255cc41dc57736b50263304937699d5e23e1353b843c00a2ea15f"',
            "exact Apple OCI index pin",
        ),
        (
            'APPLE_CHECK_IMAGE_CONFIG_ID="sha256:'
            'f75a07a3808620ebbc2188b5a4e7fb3d1de64dbeb534a9ec11f48f070067320c"',
            "exact Apple image config pin",
        ),
        (
            'APPLE_CHECK_IMAGE_MANIFEST_ID="sha256:'
            'eb08db4dd16ba120a2fbb2957ea38a319203931de699d3b47c43ae7e9e6274cc"',
            "exact reproducible Apple platform manifest pin",
        ),
        (
            'SHA256_APPLE_CHECK_IMAGE_ARCHIVE="'
            '9f675754d52962952a2bfc1d74e98d1a37b1b0d220e670780dca78f653d8a7cc"',
            "exact Apple archive digest pin",
        ),
        (
            'SIZE_APPLE_CHECK_IMAGE_ARCHIVE="1122604778"',
            "exact Apple archive size pin",
        ),
        (
            'APPLE_TOOLCHAIN_TREE_SHA256="'
            '74f49c84298a448e020a5c5251ce59bf7b0cbda9ce75055986f5ecb19523e757"',
            "exact Apple toolchain tree pin",
        ),
    ):
        require(pins, token, label)

    for token, label in (
        ("class AppleCheckSpec:", "Apple archive provenance specification"),
        (
            "def validate_apple_check_attestation(",
            "Apple SLSA provenance validator",
        ),
        (
            "pkg:docker/rd-apple-check@authenticated-v1",
            "Apple exact attestation subject",
        ),
        (
            'pkg:docker/rd-devcheck?"',
            "Apple exact attested base dependency",
        ),
        (
            '\'["apple-toolchain-provenance.py",\'',
            "Apple private helper context",
        ),
        (
            "source_runs = [\n"
            "        (network, command.lstrip())\n"
            "        for network, command in dockerfile_run_contract(dockerfile)",
            "Apple exact Dockerfile command normalization",
        ),
        (
            '"default",\n        "none",\n        "none",',
            "Apple one-networked/two-networkless build contract",
        ),
        (
            '"user": "1000:1000"',
            "Apple attested numeric nonroot execution",
        ),
        (
            '"buildkit/rewritten-timestamp"',
            "Apple layer timestamp rewrite proof",
        ),
        (
            "create_apple_check_fixture_archive(",
            "Apple archive behavioral fixture",
        ),
        (
            "if apple_checks != 33:",
            "Apple archive behavioral decision count",
        ),
        (
            "networkless-acquisition-apple-check-image.tar.gz",
            "Apple acquisition-network negative fixture",
        ),
        (
            "networked-install-apple-check-image.tar.gz",
            "Apple install-network negative fixture",
        ),
        (
            "root-helper-copy-apple-check-image.tar.gz",
            "Apple helper-owner negative fixture",
        ),
        (
            "broad-context-apple-check-image.tar.gz",
            "Apple context-authority negative fixture",
        ),
        (
            "unattested-apple-check-image.tar.gz",
            "Apple missing-attestation negative fixture",
        ),
    ):
        require(provenance, token, label)

    for token, label in (
        (
            "apple_check_image_spec_args() {",
            "Apple online image specification",
        ),
        (
            "verify_or_load_apple_check_image() {",
            "Apple verified archive recovery",
        ),
        (
            '        --archive "$ONLINE_DIR/verifier-images/apple-check.docker.tar.gz"',
            "Apple exact offline archive path",
        ),
        (
            '        --archive-sha "$SHA256_APPLE_CHECK_IMAGE_ARCHIVE"',
            "Apple offline archive digest wiring",
        ),
        (
            '        --archive-size "$SIZE_APPLE_CHECK_IMAGE_ARCHIVE"',
            "Apple offline archive size wiring",
        ),
        (
            "maintenance_build_apple_check_image_candidate() {",
            "Apple explicit candidate acquisition",
        ),
        (
            'local context="$ONLINE_FETCH_TMP/apple-check-build-context"',
            "Apple private three-file context",
        ),
        (
            "--platform=linux/amd64 --provenance=mode=max",
            "Apple maximum BuildKit provenance",
        ),
        (
            "--output=type=docker,rewrite-timestamp=true",
            "Apple reproducible runtime export",
        ),
        (
            '        --network=default --pull=false --no-cache',
            "Apple explicit candidate acquisition policy",
        ),
        (
            '            --output "$directory/apple-check.docker.tar.gz"',
            "Apple explicit canonical archive capture",
        ),
        (
            "--maintenance-build-apple-check-image-candidate",
            "Apple candidate acquisition entry point",
        ),
        (
            "--maintenance-capture-apple-check-image",
            "Apple canonical capture entry point",
        ),
        (
            "--apple-check-image",
            "Apple archive recovery entry point",
        ),
    ):
        require(online_fetch, token, label)
    candidate = extract(
        online_fetch,
        "maintenance_build_apple_check_image_candidate() {",
        "\n}\n\nmaintenance_build_dart_audit_image_candidate() {",
        "Apple maintenance candidate acquisition",
    )
    forbid_container_authority(candidate, "Apple maintenance candidate")
    for token, label in (
        ("--privileged", "privileged execution"),
        ("--cap-add", "added capability"),
        ("--network=host", "host network"),
        ("--publish", "published port"),
        ("source=$REPO", "repository mount"),
        ("source=$SCRIPT_DIR", "script-tree mount"),
        ("/var/run/docker.sock", "nested Docker socket"),
    ):
        forbid(candidate, token, f"Apple maintenance candidate {label}")

    require(
        sources["verify"],
        "/usr/bin/python3 -I -S scripts/verify-apple-verifier-authority.py --repo . --self-test",
        "shared focused-verifier wiring",
    )
    require(sources["requirements"], '<span class="id">R-S11ci</span>', "R-S11ci requirement")
    require(sources["requirements"], "<tr><td>228</td>", "Appendix C #228 disposition")
    require(
        sources["requirements"],
        "This closes the independently archived and provenance-verified "
        "Apple checker-image input;",
        "Apple image-provenance requirement disposition",
    )
    require(
        sources["hardening"],
        "R-S11ci/R-S11e-101 — Apple conformance verifier authority",
        "hardening-ledger disposition",
    )
    require(
        sources["hardening"],
        "`9f675754d52962952a2bfc1d74e98d1a37b1b0d220e670780dca78f653d8a7cc`",
        "Apple canonical archive ledger evidence",
    )
    require(
        sources["workspace"],
        '"apple_verifier_authority_verifier"',
        "workspace-verifier source ownership",
    )
    require(
        sources["workspace"],
        "Apple conformance focused authority verifier",
        "workspace-verifier semantic binding",
    )


MUTATIONS: Tuple[Mutation, ...] = (
    Mutation("apple", "readonly DOCKER_BIN=/usr/bin/docker", "DOCKER_BIN=docker",
             "fixed Docker client"),
    Mutation("apple", "readonly APPLE_DOCKER_HOST=unix:///var/run/docker.sock",
             "readonly APPLE_DOCKER_HOST=tcp://127.0.0.1:2375", "fixed local Docker endpoint"),
    Mutation("apple", '"$BUILD_UID" -ne 0', '"$BUILD_UID" -ge 0', "host-root refusal"),
    Mutation("apple", '"$BUILD_GID" -ne 0', '"$BUILD_GID" -ge 0', "root-group refusal"),
    Mutation(
        "apple",
        "apple_docker() {\n"
        "  local status=0\n"
        "  verify_apple_docker_authority\n"
        "  env -i \\\n"
        "    PATH=/usr/bin:/bin",
        "apple_docker() {\n"
        "  local status=0\n"
        "  verify_apple_docker_authority\n"
        "  env \\\n"
        '    PATH="$PATH"',
        "closed Docker client environment",
    ),
    Mutation("apple", "--host \"$APPLE_DOCKER_HOST\"", "--host \"$DOCKER_HOST\"",
             "explicit Docker endpoint"),
    Mutation("apple", "--config \"$APPLE_DOCKER_CONFIG\"", "--config \"$HOME/.docker\"",
             "private Docker configuration"),
    Mutation("apple", '[ "$(cat "$APPLE_DOCKER_CONFIG/config.json")" = "{}" ]', "true",
             "empty Docker configuration proof"),
    Mutation("apple", "  x86_64-apple-darwin\n  aarch64-apple-ios",
             "  x86_64-apple-darwin", "exact three-target matrix"),
    Mutation("apple", 'readonly IMG="$APPLE_CHECK_IMAGE_ID"', "readonly IMG=rd-apple-check",
             "immutable image selection"),
    Mutation("apple", '[ "$IMAGE_ID" = "$IMG" ]', "true", "image identity equality"),
    Mutation(
        "apple",
        "apple_image_provenance verify-local",
        "true # image provenance verification removed",
        "offline Apple image provenance verification",
    ),
    Mutation("apple", "archive_current_source >\"$APPLE_SOURCE_ARCHIVE\"",
             "tar -cf \"$APPLE_SOURCE_ARCHIVE\" .", "private source snapshot"),
    Mutation("apple", "chmod -R a-w \"$APPLE_SOURCE\"", "chmod -R a+w \"$APPLE_SOURCE\"",
             "read-only source snapshot"),
    Mutation("apple", "snapshot-subtree-create", "verify-subtree", "private vendor snapshot"),
    Mutation(
        "apple",
        '  --mount "type=bind,source=$APPLE_SOURCE,target=/work,readonly"\n'
        '  --mount "type=bind,source=$APPLE_VENDOR,target=/vendor,readonly"',
        '  --mount "type=bind,source=$APPLE_SOURCE,target=/work"\n'
        '  --mount "type=bind,source=$APPLE_VENDOR,target=/vendor,readonly"',
        "read-only source mount",
    ),
    Mutation("apple", 'target=/vendor,readonly"', 'target=/vendor"', "read-only vendor mount"),
    Mutation("apple", 'target=/tmp/cargo-config.toml,readonly"',
             'target=/tmp/cargo-config.toml"', "read-only Cargo source map"),
    Mutation(
        "apple",
        "COMMON_CHECK=(apple_docker run --rm --interactive --pull=never --network=none --read-only",
        "COMMON_CHECK=(apple_docker run --rm --interactive --pull=always --network=none --read-only",
        "no-pull policy",
    ),
    Mutation(
        "apple",
        "COMMON_CHECK=(apple_docker run --rm --interactive --pull=never --network=none --read-only",
        "COMMON_CHECK=(apple_docker run --rm --interactive --pull=never --network=host --read-only",
        "networkless policy",
    ),
    Mutation(
        "apple",
        "COMMON_CHECK=(apple_docker run --rm --interactive --pull=never --network=none --read-only",
        "COMMON_CHECK=(apple_docker run --rm --interactive --pull=never --network=none",
        "read-only root",
    ),
    Mutation(
        "apple",
        "COMMON_CHECK=(apple_docker run --rm --interactive --pull=never --network=none --read-only\n"
        '  --user "$BUILD_UID:$BUILD_GID"',
        "COMMON_CHECK=(apple_docker run --rm --interactive --pull=never --network=none --read-only\n"
        "  --user 0:0",
        "numeric nonroot identity",
    ),
    Mutation(
        "apple",
        'COMMON_CHECK=(apple_docker run --rm --interactive --pull=never --network=none --read-only\n'
        '  --user "$BUILD_UID:$BUILD_GID"\n'
        "  --cap-drop=ALL --security-opt=no-new-privileges",
        'COMMON_CHECK=(apple_docker run --rm --interactive --pull=never --network=none --read-only\n'
        '  --user "$BUILD_UID:$BUILD_GID"\n'
        "  --cap-drop=NET_RAW --security-opt=no-new-privileges",
        "complete capability drop",
    ),
    Mutation(
        "apple",
        'COMMON_CHECK=(apple_docker run --rm --interactive --pull=never --network=none --read-only\n'
        '  --user "$BUILD_UID:$BUILD_GID"\n'
        "  --cap-drop=ALL --security-opt=no-new-privileges",
        'COMMON_CHECK=(apple_docker run --rm --interactive --pull=never --network=none --read-only\n'
        '  --user "$BUILD_UID:$BUILD_GID"\n'
        "  --cap-drop=ALL --security-opt=seccomp=unconfined",
        "no-new-privileges",
    ),
    Mutation("apple", "--pids-limit=512", "--pids-limit=-1", "cross-check PID ceiling"),
    Mutation("apple", "--memory=12g", "--memory=0", "cross-check memory ceiling"),
    Mutation("apple", "--memory-swap=12g", "--memory-swap=-1", "cross-check no-swap policy"),
    Mutation("apple", "--cpus=4", "--cpus=0", "cross-check CPU ceiling"),
    Mutation("apple", "size=2g", "size=20g", "cross-check scratch bound"),
    Mutation("apple", "--env CARGO_NET_OFFLINE=true", "--env CARGO_NET_OFFLINE=false",
             "Cargo offline policy"),
    Mutation(
        "apple",
        "check --locked --offline --config /tmp/cargo-config.toml --jobs 1 \\\n"
        '  --package hbb_common --target "$target"',
        "check --config /tmp/cargo-config.toml --jobs 4 \\\n"
        '  --package hbb_common --target "$target"',
        "locked serialized workspace anchor",
    ),
    Mutation(
        "apple",
        "check --locked --offline --config /tmp/cargo-config.toml --jobs 1 \\\n"
        '  --target "$target" --features "$features"',
        "check --config /tmp/cargo-config.toml --jobs 4 \\\n"
        '  --target "$target" --features "$features"',
        "locked serialized full Cargo check",
    ),
    Mutation(
        "apple",
        'if ! /usr/bin/python3 -I -S "$REPO/scripts/restore-private-directory-modes.py" \\\n'
        '      --root "$APPLE_CHECK_TMP"',
        'if ! true \\\n'
        '      --root "$APPLE_CHECK_TMP"',
        "private workspace directory restoration",
    ),
    Mutation(
        "apple",
        '--expected-identity "$APPLE_CHECK_TMP_IDENTITY" \\\n'
        '      --owner "$APPLE_CHECK_TMP_UID"',
        '--expected-identity "0:1" \\\n'
        '      --owner "$APPLE_CHECK_TMP_UID"',
        "private workspace cleanup identity",
    ),
    Mutation(
        "apple",
        'echo "apple-conform-check: failed to restore private workspace directory modes: $APPLE_CHECK_TMP" >&2\n'
        "    status=1",
        'echo "apple-conform-check: failed to restore private workspace directory modes: $APPLE_CHECK_TMP" >&2',
        "private workspace restoration failure status",
    ),
    Mutation(
        "apple",
        '--package hbb_common --target "$target"',
        '--package coreaudio-sys --target "$target"',
        "workspace anchor package",
    ),
    Mutation(
        "apple",
        'if [ "$anchor_rc" -ne 0 ]; then',
        "if false; then",
        "workspace anchor success requirement",
    ),
    Mutation("apple", "accepted = boundary_line > 0", "accepted = boundary_line >= 0",
             "SDK boundary presence"),
    Mutation(
        "apple",
        "rust_error_line == 0 || rust_error_line > boundary_line",
        "rust_error_line >= 0",
        "prior Rust diagnostic refusal",
    ),
    Mutation(
        "apple",
        '$0 !~ /^[[:space:]]*error: failed to run custom build command for `[^`]+`$/',
        '$0 !~ /error: failed/',
        "exact Cargo custom-build wrapper exception",
    ),
    Mutation(
        "apple",
        "\napple_sdk_boundary_self_test\n\n# ---- preflight ----",
        "\ntrue # Apple SDK boundary self-test removed\n\n# ---- preflight ----",
        "SDK boundary classifier self-test invocation",
    ),
    Mutation("apple", '[ "$SOURCE_DIGEST_AFTER" = "$SOURCE_DIGEST" ]', "true",
             "real-source stability proof"),
    Mutation("apple", '[ "$FINAL_IMAGE_ID" = "$IMAGE_ID" ]', "true",
             "final image stability proof"),
    Mutation("pins", 'APPLE_CHECK_IMAGE_ID="sha256:', 'APPLE_CHECK_IMAGE_ID="tag:',
             "Apple image content pin"),
    Mutation(
        "pins",
        'APPLE_CHECK_IMAGE_MANIFEST_ID="sha256:',
        'APPLE_CHECK_IMAGE_MANIFEST_ID="tag:',
        "Apple image manifest pin",
    ),
    Mutation(
        "pins",
        'SHA256_APPLE_CHECK_IMAGE_ARCHIVE="'
        '9f675754d52962952a2bfc1d74e98d1a37b1b0d220e670780dca78f653d8a7cc"',
        'SHA256_APPLE_CHECK_IMAGE_ARCHIVE="'
        '8f675754d52962952a2bfc1d74e98d1a37b1b0d220e670780dca78f653d8a7cc"',
        "Apple archive digest pin",
    ),
    Mutation(
        "offline_provenance",
        "if apple_checks != 33:",
        "if apple_checks != 32:",
        "Apple archive behavioral decision count",
    ),
    Mutation(
        "online_fetch",
        "--output=type=docker,rewrite-timestamp=true",
        "--output=type=docker,rewrite-timestamp=false",
        "Apple reproducible runtime export",
    ),
    Mutation(
        "online_fetch",
        '        --archive "$ONLINE_DIR/verifier-images/apple-check.docker.tar.gz"',
        '        --archive "$ONLINE_DIR/verifier-images/unreviewed.docker.tar.gz"',
        "Apple exact offline archive path",
    ),
    Mutation(
        "dockerfile",
        "This is an acquisition recipe, never a verdict-time fallback.",
        "This is an unreviewed acquisition recipe.",
        "Apple acquisition-recipe content pin",
    ),
    Mutation("verify", "/usr/bin/python3 -I -S scripts/verify-apple-verifier-authority.py --repo . --self-test",
             "true # Apple verifier authority gate removed", "shared focused-verifier wiring"),
    Mutation("requirements", '<span class="id">R-S11ci</span>',
             '<span class="id">R-S11ci-disabled</span>', "R-S11ci requirement"),
    Mutation("requirements", "<tr><td>228</td>", "<tr><td>228-disabled</td>",
             "Appendix C #228 disposition"),
    Mutation(
        "requirements",
        "This closes the independently archived and provenance-verified "
        "Apple checker-image input;",
        "The Apple checker-image input remains open;",
        "Apple image-provenance requirement disposition",
    ),
    Mutation("hardening", "R-S11ci/R-S11e-101 — Apple conformance verifier authority",
             "R-S11ci/R-S11e-101 — Apple ambient verifier authority",
             "hardening-ledger disposition"),
    Mutation(
        "hardening",
        "`9f675754d52962952a2bfc1d74e98d1a37b1b0d220e670780dca78f653d8a7cc`",
        "`8f675754d52962952a2bfc1d74e98d1a37b1b0d220e670780dca78f653d8a7cc`",
        "Apple canonical archive ledger evidence",
    ),
)


def load_sources(repo: pathlib.Path) -> Dict[str, str]:
    return {
        "apple": (repo / "scripts/apple-conform-check.sh").read_text(encoding="utf-8"),
        "dockerfile": (repo / "scripts/Dockerfile.apple-check").read_text(encoding="utf-8"),
        "pins": (repo / "scripts/pins.env").read_text(encoding="utf-8"),
        "offline_provenance": (
            repo / "scripts/offline-image-provenance.py"
        ).read_text(encoding="utf-8"),
        "online_fetch": (repo / "scripts/online-fetch.sh").read_text(encoding="utf-8"),
        "verify": (repo / "scripts/verify.sh").read_text(encoding="utf-8"),
        "requirements": (repo / "requirements.html").read_text(encoding="utf-8"),
        "hardening": (repo / "HARDENING_STATUS.md").read_text(encoding="utf-8"),
        "workspace": (repo / "scripts/verify-verifier-workspace.py").read_text(encoding="utf-8"),
    }


def run_mutations(sources: Dict[str, str]) -> None:
    for mutation in MUTATIONS:
        original = sources[mutation.source]
        count = original.count(mutation.old)
        if count != 1:
            raise AuthorityError(
                "mutation target for {} occurs {} times".format(mutation.label, count)
            )
        changed = dict(sources)
        changed[mutation.source] = original.replace(mutation.old, mutation.new, 1)
        try:
            validate(changed)
        except AuthorityError:
            continue
        raise AuthorityError("mutation was accepted: {}".format(mutation.label))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=pathlib.Path, default=pathlib.Path("."))
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    sources = load_sources(args.repo.resolve())
    validate(sources)
    if args.self_test:
        run_mutations(sources)
    print(
        "verify-apple-verifier-authority: OK"
        + (" ({} mutations)".format(len(MUTATIONS)) if args.self_test else "")
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AuthorityError, OSError) as error:
        print("verify-apple-verifier-authority: {}".format(error))
        raise SystemExit(1)
