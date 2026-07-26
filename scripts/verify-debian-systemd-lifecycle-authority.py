#!/usr/bin/env python3
"""Validate the Debian systemd-lifecycle child's fixed Docker authority."""

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
        raise AuthorityError(
            "{} count is {}, expected {}".format(label, observed, count)
        )


def forbid(source: str, token: str, label: str) -> None:
    if token in source:
        raise AuthorityError("forbidden {}".format(label))


def require_order(source: str, tokens: Tuple[str, ...], label: str) -> None:
    try:
        positions = tuple(source.index(token) for token in tokens)
    except ValueError as error:
        raise AuthorityError("{} is incomplete or misordered".format(label)) from error
    if positions != tuple(sorted(positions)) or len(set(positions)) != len(positions):
        raise AuthorityError("{} is incomplete or misordered".format(label))


def extract(source: str, start: str, end: str, label: str) -> str:
    try:
        begin = source.index(start)
        finish = source.index(end, begin)
    except ValueError as error:
        raise AuthorityError("missing {}".format(label)) from error
    return source[begin:finish]


def pin_value(pins: str, name: str) -> str:
    match = re.search(
        r'^{}="([^"]+)"'.format(re.escape(name)),
        pins,
        flags=re.MULTILINE,
    )
    if match is None:
        raise AuthorityError("missing {} pin".format(name))
    return match.group(1)


def validate_shared_authority(lib: str) -> None:
    for token, label in (
        (
            "DOCKER_HOST DOCKER_CONTEXT DOCKER_CONFIG DOCKER_CERT_PATH DOCKER_TLS_VERIFY DOCKER_TLS",
            "complete Docker routing/configuration/TLS refusal",
        ),
        (
            "DOCKER_API_VERSION DOCKER_DEFAULT_PLATFORM DOCKER_CONTENT_TRUST",
            "Docker API/platform/content-trust refusal",
        ),
        (
            "DOCKER_CONTENT_TRUST_SERVER DOCKER_CUSTOM_HEADERS",
            "Docker trust-server/custom-header refusal",
        ),
        (
            "[ -f /usr/bin/docker ] && [ ! -L /usr/bin/docker ] && [ -x /usr/bin/docker ]",
            "fixed Docker client shape",
        ),
        (
            "case \"$(/usr/bin/stat -c '%u:%g:%a:%h' -- /usr/bin/docker 2>/dev/null)\" in\n"
            "        0:0:755:1) ;;",
            "fixed Docker client metadata",
        ),
        (
            "[ -S /var/run/docker.sock ] && [ ! -L /var/run/docker.sock ]",
            "fixed local Docker socket shape",
        ),
        (
            "case \"$(/usr/bin/stat -c '%u:%h' -- /var/run/docker.sock 2>/dev/null)\" in\n"
            "        0:1) ;;",
            "fixed local Docker socket metadata",
        ),
        (
            "(umask 077 && set -o noclobber && printf '{}\\n' >\"$config/config.json\")",
            "canonical no-clobber Docker configuration",
        ),
        (
            'LOCAL_DOCKER_AUTHORITY_PARENT_ID="$(/usr/bin/stat -c',
            "Docker-authority parent identity binding",
        ),
        (
            'LOCAL_DOCKER_AUTHORITY_CONFIG_ID="$(/usr/bin/stat -c',
            "Docker-configuration identity binding",
        ),
        (
            'LOCAL_DOCKER_AUTHORITY_CONFIG_FILE_ID="$(/usr/bin/stat -c',
            "Docker-configuration file identity binding",
        ),
        (
            'LOCAL_DOCKER_AUTHORITY_CLIENT_ID="$(/usr/bin/stat -c',
            "Docker-client identity binding",
        ),
        (
            'LOCAL_DOCKER_AUTHORITY_SOCKET_ID="$(/usr/bin/stat -c',
            "Docker-socket identity binding",
        ),
        (
            '/usr/bin/cmp -s -- "$LOCAL_DOCKER_AUTHORITY_CONFIG/config.json" '
            "<(printf '{}\\n')",
            "Docker-configuration byte recheck",
        ),
        (
            '/usr/bin/rm -- "$LOCAL_DOCKER_AUTHORITY_CONFIG/config.json" || return 125',
            "exact Docker-configuration file retirement",
        ),
        (
            '/usr/bin/rmdir -- "$LOCAL_DOCKER_AUTHORITY_CONFIG" || return 125',
            "exact Docker-configuration directory retirement",
        ),
    ):
        require(lib, token, label)

    initializer = extract(
        lib,
        "initialize_local_docker_authority() {",
        "\n}\n\nassert_local_docker_authority() {",
        "shared Docker authority initializer",
    )
    require_order(
        initializer,
        (
            'local config="$1" label="$2" parent variable',
            "[ -f /usr/bin/docker ]",
            "[ -S /var/run/docker.sock ]",
            "for variable in",
            "/usr/bin/install -d -m 0700",
            "LOCAL_DOCKER_AUTHORITY_PARENT_ID=",
            "LOCAL_DOCKER_AUTHORITY_CLIENT_ID=",
            "LOCAL_DOCKER_AUTHORITY_SOCKET_ID=",
            "LOCAL_DOCKER_AUTHORITY_INITIALIZED=1",
            "assert_local_docker_authority",
        ),
        "shared Docker authority construction",
    )

    assertion = extract(
        lib,
        "assert_local_docker_authority() {",
        "\n}\n\nlocal_docker() {",
        "shared Docker authority assertion",
    )
    for token, label in (
        ("LOCAL_DOCKER_AUTHORITY_PARENT_ID", "authority-parent recheck"),
        ("LOCAL_DOCKER_AUTHORITY_CONFIG_ID", "configuration-directory recheck"),
        ("LOCAL_DOCKER_AUTHORITY_CONFIG_FILE_ID", "configuration-file recheck"),
        ("LOCAL_DOCKER_AUTHORITY_CLIENT_ID", "client recheck"),
        ("LOCAL_DOCKER_AUTHORITY_SOCKET_ID", "socket recheck"),
        ("config.json bytes changed", "configuration-byte failure"),
    ):
        require(assertion, token, label)

    launcher = extract(
        lib,
        "local_docker() {",
        "\n}\n\nlocal_docker_image_provenance() {",
        "shared fixed Docker launcher",
    )
    for token, label in (
        ("/usr/bin/env -i", "empty Docker-client environment"),
        ("PATH=/usr/bin:/bin", "fixed Docker-client PATH"),
        ('HOME="$LOCAL_DOCKER_AUTHORITY_PARENT"', "private Docker-client HOME"),
        ("DOCKER_HOST=unix:///var/run/docker.sock", "fixed local Docker host"),
        (
            'DOCKER_CONFIG="$LOCAL_DOCKER_AUTHORITY_CONFIG"',
            "private Docker client configuration",
        ),
        ("/usr/bin/docker", "absolute Docker client"),
        ("--host unix:///var/run/docker.sock", "explicit local Docker endpoint"),
        (
            '--config "$LOCAL_DOCKER_AUTHORITY_CONFIG"',
            "explicit private Docker configuration",
        ),
    ):
        require(launcher, token, label)
    require_count(
        launcher,
        "assert_local_docker_authority",
        2,
        "Docker launch pre/post authority proofs",
    )

    provenance = extract(
        lib,
        "local_docker_image_provenance() {",
        "\n}\n\nremove_local_docker_authority() {",
        "shared fixed Docker provenance wrapper",
    )
    for token, label in (
        ("/usr/bin/env -i", "empty provenance environment"),
        ("PATH=/usr/bin:/bin", "fixed provenance PATH"),
        ('HOME="$LOCAL_DOCKER_AUTHORITY_PARENT"', "private provenance HOME"),
        ("DOCKER_HOST=unix:///var/run/docker.sock", "fixed provenance endpoint"),
        (
            'DOCKER_CONFIG="$LOCAL_DOCKER_AUTHORITY_CONFIG"',
            "private provenance configuration",
        ),
        (
            '/usr/bin/python3 -I -S "$LIB_DIR/offline-image-provenance.py"',
            "fixed isolated provenance interpreter",
        ),
    ):
        require(provenance, token, label)
    require_count(
        provenance,
        "assert_local_docker_authority",
        2,
        "provenance pre/post authority proofs",
    )


def validate(sources: Dict[str, str]) -> None:
    host = sources["host"]
    lib = sources["lib"]
    pins = sources["pins"]
    dockerfile = sources["dockerfile"]
    verify = sources["verify"]
    android_gate = sources["android_gate"]
    workspace_gate = sources["workspace_gate"]
    requirements = sources["requirements"]
    hardening = sources["hardening"]

    validate_shared_authority(lib)

    for token, label in (
        ("set -euo pipefail\numask 077", "strict mode and private umask"),
        ("export PATH=/usr/bin:/bin", "fixed host command path"),
        ('readonly HOST_UID="$(/usr/bin/id -u)"', "absolute host UID capture"),
        ('readonly HOST_GID="$(/usr/bin/id -g)"', "absolute host GID capture"),
        ('[ "$HOST_UID" -ne 0 ]', "host UID-root refusal"),
        ('[ "$HOST_GID" -ne 0 ]', "host primary-GID-root refusal"),
        (
            "Debian systemd VM smoke refuses host or container-root execution",
            "host-root refusal diagnostic",
        ),
        (
            "Debian systemd VM smoke refuses a root primary group",
            "root-primary-group refusal diagnostic",
        ),
        (
            'readonly SCRIPT_DIR="$(cd "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")" '
            "&& /usr/bin/pwd -P)\"",
            "physical script directory resolution",
        ),
        ('source "$SCRIPT_DIR/lib.sh"', "shared authority source"),
        (
            'initialize_local_docker_authority "$WORK/docker-config" '
            '"debian-systemd-lifecycle"',
            "lifecycle-owned fixed Docker authority",
        ),
        (
            'local_docker_image_provenance verify-local \\\n    --role devcheck',
            "isolated immutable devcheck provenance",
        ),
        ('--expected-id "$DEV_CHECK_IMAGE_ID"', "exact provenance image ID"),
        ('--image-ref "$DEV_CHECK_IMAGE_ID"', "content-ID-only provenance lookup"),
        (
            '--base "rust:1.75-slim@${DEV_CHECK_BASE_IMAGE_ID}"',
            "exact devcheck base identity",
        ),
        (
            '--dockerfile-sha "$SHA256_DEV_CHECK_DOCKERFILE"',
            "devcheck recipe digest",
        ),
        (
            '--dpkg-sha "$SHA256_DEV_CHECK_DPKG_MANIFEST"',
            "devcheck package manifest digest",
        ),
        ('--cargo-sha "$SHA256_DEV_CHECK_CARGO"', "devcheck Cargo digest"),
        ('--rustc-sha "$SHA256_DEV_CHECK_RUSTC"', "devcheck rustc digest"),
        (
            '--source-commit "$DEV_CHECK_SOURCE_COMMIT"',
            "devcheck source commit",
        ),
        (
            '--source-repository "$DEV_CHECK_SOURCE_REPOSITORY"',
            "devcheck source repository",
        ),
        (
            '--config-id "$DEV_CHECK_IMAGE_CONFIG_ID"',
            "devcheck configuration identity",
        ),
        (
            '--manifest-id "$DEV_CHECK_IMAGE_MANIFEST_ID"',
            "devcheck manifest identity",
        ),
        (
            'git --no-replace-objects merge-base --is-ancestor '
            '"$DEV_CHECK_SOURCE_COMMIT" HEAD',
            "devcheck source ancestry proof",
        ),
        (
            '"$DEV_CHECK_SOURCE_COMMIT:scripts/Dockerfile.devcheck"',
            "historical devcheck recipe proof",
        ),
        (
            '[ "$(sha256sum "$SCRIPT_DIR/Dockerfile.devcheck" | awk '
            '\'{print $1}\')" =',
            "current devcheck recipe proof",
        ),
        (
            "local_docker run --rm --pull=never --network=none --read-only",
            "sole no-pull networkless read-only launch",
        ),
        (
            "--pids-limit=64 --memory=1g --memory-swap=1g --cpus=1",
            "process/memory/no-swap/CPU bounds",
        ),
        (
            "--ulimit nofile=4096:4096 --ulimit fsize=268435456:268435456",
            "descriptor/file-size bounds",
        ),
        (
            "--tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777,size=32m",
            "bounded non-executable scratch",
        ),
        (
            "--cap-drop=ALL --security-opt=no-new-privileges",
            "capability and privilege confinement",
        ),
        ('--user "$HOST_UID:$HOST_GID"', "numeric non-root container identity"),
        (
            "source=$BINARY,target=/work/rustdesk-lifecycle-input,"
            "readonly,bind-recursive=disabled",
            "exact read-only executable input",
        ),
        (
            "source=$LIBS,target=/out,bind-recursive=disabled",
            "sole writable dependency output",
        ),
        (
            '"$DEV_CHECK_IMAGE_ID" /bin/bash --noprofile --norc',
            "immutable image and fixed inner shell",
        ),
        (
            "runtime dependency output contains a non-regular or nested entry",
            "regular top-level output enforcement",
        ),
        (
            '[ "$library_count" -ge 60 ] && [ "$library_count" -le 256 ]',
            "bounded dependency count predicate",
        ),
        (
            "runtime dependency bundle count is outside 60..256",
            "bounded dependency count",
        ),
        (
            '[ "$(stat -c \'%u:%g:%h\' -- "$library")" = '
            '"$HOST_UID:$HOST_GID:1" ]',
            "dependency owner/link predicate",
        ),
        (
            "runtime dependency output has wrong owner or link count",
            "dependency owner/link enforcement",
        ),
        (
            '[ "$library_bytes" -le 1073741824 ]',
            "bounded dependency byte predicate",
        ),
        (
            "runtime dependency bundle exceeds 1 GiB",
            "bounded dependency bytes",
        ),
        ("-nic none", "networkless KVM guest"),
    ):
        require(host, token, label)

    require_order(
        host,
        (
            'readonly HOST_UID="$(/usr/bin/id -u)"',
            'readonly HOST_GID="$(/usr/bin/id -g)"',
            '[ "$HOST_UID" -ne 0 ]',
            '[ "$HOST_GID" -ne 0 ]',
            'readonly SCRIPT_DIR="$(cd "$(/usr/bin/dirname',
            'source "$SCRIPT_DIR/lib.sh"',
            "load_pins",
            'WORK=$(mktemp -d "$STATE_DIR/run.XXXXXXXXXX")',
            'initialize_local_docker_authority "$WORK/docker-config"',
            "local_docker_image_provenance verify-local",
            "local_docker run --rm --pull=never",
        ),
        "root refusal, repository load, private authority, provenance, and launch order",
    )

    cleanup = extract(
        host,
        "cleanup() {",
        "\n}\n\ntrap cleanup EXIT",
        "lifecycle cleanup",
    )
    require_order(
        cleanup,
        (
            "remove_local_docker_authority",
            "preserving changed private Debian systemd-lifecycle Docker authority",
            'elif [ -n "$WORK" ] && [ -d "$WORK" ]',
            'chmod -R u+rwX "$WORK"',
            'rm -rf -- "$WORK"',
        ),
        "exact Docker-before-workspace cleanup",
    )

    stage = extract(
        host,
        "local_docker run --rm --pull=never",
        "\n[ \"$(stat -c '%u:%g:%a:%h' -- \"$LIBS\")\"",
        "runtime dependency staging launch",
    )
    require_count(
        host,
        "local_docker run --rm --pull=never",
        1,
        "sole lifecycle Docker launch",
    )
    require_count(stage, "--mount ", 2, "two exact staging mounts")
    for token, label in (
        ("--publish", "published Docker port"),
        ("--network=host", "host Docker network"),
        ("--pid=host", "host PID namespace"),
        ("--ipc=host", "host IPC namespace"),
        ("--uts=host", "host UTS namespace"),
        ("--privileged", "privileged container"),
        ("/var/run/docker.sock", "Docker socket mount"),
        ("$PWD:/work", "whole repository mount"),
        ("$EXTRACTED:/artifact-root", "whole extracted artifact mount"),
    ):
        forbid(stage, token, label)

    for token, label in (
        ("SYSTEMD_SMOKE_DEV_IMAGE", "mutable lifecycle dev-image input"),
        ("DEV_IMAGE", "mutable lifecycle dev-image alias"),
        ("assert_private_docker_config", "bespoke Docker configuration assertion"),
        ("export DOCKER_CONFIG", "process-global Docker configuration"),
        ("docker image inspect", "direct Docker image inspection"),
        ("\ndocker run", "direct Docker launch"),
        ("docker_mounts", "broad Docker mount array"),
        ("container_binary", "broad container path selection"),
        ('-v "$PWD:/work:ro"', "whole repository short bind"),
        ('-v "$EXTRACTED:/artifact-root:ro"', "whole artifact-tree short bind"),
        ("trap - EXIT HUP INT TERM\nrm -rf -- \"$WORK\"", "cleanup bypass"),
    ):
        forbid(host, token, label)

    for name in (
        "DEV_CHECK_IMAGE_ID",
        "DEV_CHECK_BASE_IMAGE_ID",
        "DEV_CHECK_IMAGE_CONFIG_ID",
        "DEV_CHECK_IMAGE_MANIFEST_ID",
    ):
        value = pin_value(pins, name)
        if re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None:
            raise AuthorityError("{} is not an immutable image identity".format(name))
    for name in (
        "SHA256_DEV_CHECK_DOCKERFILE",
        "SHA256_DEV_CHECK_DPKG_MANIFEST",
        "SHA256_DEV_CHECK_CARGO",
        "SHA256_DEV_CHECK_RUSTC",
    ):
        value = pin_value(pins, name)
        if re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise AuthorityError("{} is not a SHA-256 digest".format(name))
    if hashlib.sha256(dockerfile.encode("utf-8")).hexdigest() != pin_value(
        pins, "SHA256_DEV_CHECK_DOCKERFILE"
    ):
        raise AuthorityError("current devcheck Dockerfile bytes differ from pins.env")

    for token, label in (
        (
            "python3 scripts/verify-debian-systemd-lifecycle-authority.py "
            "--repo . --self-test",
            "focused lifecycle authority gate wiring",
        ),
        (
            "R-S11e-130 Debian systemd-lifecycle dependency staging uses exact "
            "devcheck provenance and one independent fixed local Docker authority",
            "shared lifecycle authority disposition",
        ),
    ):
        require(verify, token, label)

    for token, label in (
        (
            '"systemd_authority": read_regular(',
            "Android gate lifecycle-authority source loading",
        ),
        (
            "verify-debian-systemd-lifecycle-authority.py",
            "Android gate lifecycle-focused delegation",
        ),
        (
            'initialize_local_docker_authority "$WORK/docker-config" '
            '"debian-systemd-lifecycle"',
            "Android integration gate lifecycle authority",
        ),
    ):
        require(android_gate, token, label)

    for token, label in (
        (
            '"systemd_lifecycle_authority": (\n'
            '                repo / "scripts/verify-debian-systemd-lifecycle-authority.py"\n'
            "            ).read_text",
            "independent lifecycle verifier source catalog",
        ),
        (
            "validate_debian_systemd_lifecycle_authority_contract(sources)",
            "independent lifecycle authority validation",
        ),
        (
            "R-S11n through R-S11dv",
            "independent requirement range",
        ),
        ("Appendix C #192–#275", "independent Appendix range"),
    ):
        require(workspace_gate, token, label)

    require(
        requirements,
        '<span class="id">R-S11dl</span>',
        "R-S11dl normative requirement",
    )
    require(
        requirements,
        "<tr><td>265</td>",
        "Appendix C #265 disposition",
    )
    require(
        hardening,
        "R-S11dl/R-S11e-130 — Debian systemd-lifecycle Docker client, daemon,\n"
        "  configuration, image, and mount authority",
        "R-S11e-130 hardening ledger",
    )


MUTATIONS = (
    Mutation(
        "host",
        'readonly HOST_UID="$(/usr/bin/id -u)"',
        'readonly HOST_UID="$(id -u)"',
        "absolute host UID capture",
    ),
    Mutation(
        "host",
        '[ "$HOST_UID" -ne 0 ] \\\n'
        '    || { echo "Debian systemd VM smoke refuses host or container-root execution"',
        'true # host UID root accepted\n'
        '    || { echo "Debian systemd VM smoke refuses host or container-root execution"',
        "host UID-root refusal",
    ),
    Mutation(
        "host",
        '[ "$HOST_GID" -ne 0 ] \\\n'
        '    || { echo "Debian systemd VM smoke refuses a root primary group"',
        'true # host root primary group accepted\n'
        '    || { echo "Debian systemd VM smoke refuses a root primary group"',
        "host GID-root refusal",
    ),
    Mutation(
        "host",
        'source "$SCRIPT_DIR/lib.sh"',
        "source scripts/lib.sh",
        "physical shared-library source",
    ),
    Mutation(
        "host",
        'initialize_local_docker_authority "$WORK/docker-config" '
        '"debian-systemd-lifecycle"',
        "true # local Docker authority omitted",
        "lifecycle authority initialization",
    ),
    Mutation(
        "host",
        "local_docker_image_provenance verify-local",
        "/usr/bin/python3 scripts/offline-image-provenance.py verify-local",
        "isolated image provenance",
    ),
    Mutation(
        "host",
        '--image-ref "$DEV_CHECK_IMAGE_ID"',
        "--image-ref rd-devcheck",
        "immutable provenance lookup",
    ),
    Mutation(
        "host",
        'git --no-replace-objects merge-base --is-ancestor "$DEV_CHECK_SOURCE_COMMIT" HEAD',
        "true # devcheck source ancestry unchecked",
        "devcheck source ancestry",
    ),
    Mutation(
        "host",
        '"$DEV_CHECK_SOURCE_COMMIT:scripts/Dockerfile.devcheck"',
        '"HEAD:scripts/Dockerfile.devcheck"',
        "historical devcheck recipe",
    ),
    Mutation(
        "host",
        "local_docker run --rm --pull=never --network=none --read-only",
        "local_docker run --rm --network=none --read-only",
        "no implicit image pull",
    ),
    Mutation(
        "host",
        "--pids-limit=64 --memory=1g --memory-swap=1g --cpus=1",
        "--pids-limit=64 --memory=1g --cpus=1",
        "no-swap resource bound",
    ),
    Mutation(
        "host",
        "--ulimit nofile=4096:4096 --ulimit fsize=268435456:268435456",
        "--ulimit nofile=4096:4096",
        "file-size resource bound",
    ),
    Mutation(
        "host",
        "--tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777,size=32m",
        "--tmpfs /tmp:rw,exec,nosuid,nodev,mode=1777,size=32m",
        "non-executable staging scratch",
    ),
    Mutation(
        "host",
        "--cap-drop=ALL --security-opt=no-new-privileges",
        "--security-opt=no-new-privileges",
        "capability drop",
    ),
    Mutation(
        "host",
        '--user "$HOST_UID:$HOST_GID"',
        "--user 0:0",
        "numeric non-root staging identity",
    ),
    Mutation(
        "host",
        "source=$BINARY,target=/work/rustdesk-lifecycle-input,"
        "readonly,bind-recursive=disabled",
        "source=$PWD,target=/work,readonly",
        "narrow executable input mount",
    ),
    Mutation(
        "host",
        "source=$LIBS,target=/out,bind-recursive=disabled",
        "source=$LIBS,target=/out",
        "recursive output-bind exclusion",
    ),
    Mutation(
        "host",
        '"$DEV_CHECK_IMAGE_ID" /bin/bash --noprofile --norc',
        'rd-devcheck /bin/bash --noprofile --norc',
        "immutable staging image",
    ),
    Mutation(
        "host",
        "runtime dependency output contains a non-regular or nested entry",
        "runtime dependency output shape accepted",
        "regular-only output",
    ),
    Mutation(
        "host",
        '[ "$library_count" -ge 60 ] && [ "$library_count" -le 256 ]',
        '[ "$library_count" -ge 1 ]',
        "bounded output count",
    ),
    Mutation(
        "host",
        '[ "$(stat -c \'%u:%g:%h\' -- "$library")" = "$HOST_UID:$HOST_GID:1" ]',
        "true # output ownership and links unchecked",
        "output ownership and link count",
    ),
    Mutation(
        "host",
        '[ "$library_bytes" -le 1073741824 ]',
        "true # output bytes unbounded",
        "bounded output bytes",
    ),
    Mutation(
        "host",
        "&& ! remove_local_docker_authority; then",
        "&& false; then",
        "exact Docker authority cleanup",
    ),
    Mutation(
        "host",
        'elif [ -n "$WORK" ] && [ -d "$WORK" ]; then',
        'if [ -n "$WORK" ] && [ -d "$WORK" ]; then',
        "changed-authority workspace preservation",
    ),
    Mutation(
        "lib",
        "DOCKER_HOST DOCKER_CONTEXT DOCKER_CONFIG DOCKER_CERT_PATH DOCKER_TLS_VERIFY DOCKER_TLS",
        "DOCKER_HOST DOCKER_CONFIG DOCKER_CERT_PATH DOCKER_TLS_VERIFY DOCKER_TLS",
        "ambient Docker context refusal",
    ),
    Mutation(
        "lib",
        "DOCKER_API_VERSION DOCKER_DEFAULT_PLATFORM DOCKER_CONTENT_TRUST",
        "DOCKER_DEFAULT_PLATFORM DOCKER_CONTENT_TRUST",
        "ambient Docker API-version refusal",
    ),
    Mutation(
        "lib",
        "case \"$(/usr/bin/stat -c '%u:%g:%a:%h' -- /usr/bin/docker 2>/dev/null)\" in\n"
        "        0:0:755:1) ;;",
        "case \"$(/usr/bin/stat -c '%u:%g:%a:%h' -- /usr/bin/docker 2>/dev/null)\" in\n"
        "        *:0:755:1) ;;",
        "root-owned Docker client",
    ),
    Mutation(
        "lib",
        "case \"$(/usr/bin/stat -c '%u:%h' -- /var/run/docker.sock 2>/dev/null)\" in\n"
        "        0:1) ;;",
        "case \"$(/usr/bin/stat -c '%u:%h' -- /var/run/docker.sock 2>/dev/null)\" in\n"
        "        *:1) ;;",
        "root-owned local Docker socket",
    ),
    Mutation(
        "lib",
        "(umask 077 && set -o noclobber && printf '{}\\n' >\"$config/config.json\")",
        "(umask 077 && printf '{}\\n' >\"$config/config.json\")",
        "Docker config no-clobber creation",
    ),
    Mutation(
        "lib",
        'LOCAL_DOCKER_AUTHORITY_PARENT_ID="$(/usr/bin/stat -c '
        '\'%d:%i:%u:%g:%a\' -- "$parent")"',
        "LOCAL_DOCKER_AUTHORITY_PARENT_ID=unchecked",
        "Docker parent identity binding",
    ),
    Mutation(
        "lib",
        'LOCAL_DOCKER_AUTHORITY_CONFIG_FILE_ID="$(/usr/bin/stat -c '
        '\'%d:%i:%u:%g:%a:%h\' -- "$config/config.json")"',
        "LOCAL_DOCKER_AUTHORITY_CONFIG_FILE_ID=unchecked",
        "Docker config-file identity binding",
    ),
    Mutation(
        "lib",
        'LOCAL_DOCKER_AUTHORITY_CLIENT_ID="$(/usr/bin/stat -c '
        '\'%d:%i:%u:%g:%a:%h\' -- /usr/bin/docker)"',
        "LOCAL_DOCKER_AUTHORITY_CLIENT_ID=unchecked",
        "Docker client identity binding",
    ),
    Mutation(
        "lib",
        'LOCAL_DOCKER_AUTHORITY_SOCKET_ID="$(/usr/bin/stat -c '
        '\'%d:%i:%u:%g:%a:%h\' -- /var/run/docker.sock)"',
        "LOCAL_DOCKER_AUTHORITY_SOCKET_ID=unchecked",
        "Docker socket identity binding",
    ),
    Mutation(
        "lib",
        '/usr/bin/cmp -s -- "$LOCAL_DOCKER_AUTHORITY_CONFIG/config.json" '
        "<(printf '{}\\n')",
        "true # Docker configuration bytes unchecked",
        "Docker configuration byte recheck",
    ),
    Mutation(
        "lib",
        "local_docker() {\n    local status=0\n"
        "    assert_local_docker_authority || return 1\n    /usr/bin/env -i",
        "local_docker() {\n    local status=0\n"
        "    assert_local_docker_authority || return 1\n    /usr/bin/env",
        "empty Docker client environment",
    ),
    Mutation(
        "lib",
        "--host unix:///var/run/docker.sock",
        "--host tcp://127.0.0.1:2375",
        "explicit fixed local Docker endpoint",
    ),
    Mutation(
        "lib",
        "local_docker_image_provenance() {\n    local status=0\n"
        "    assert_local_docker_authority || return 1\n    /usr/bin/env -i",
        "local_docker_image_provenance() {\n    local status=0\n"
        "    assert_local_docker_authority || return 1\n    /usr/bin/env",
        "empty provenance environment",
    ),
    Mutation(
        "lib",
        '/usr/bin/rm -- "$LOCAL_DOCKER_AUTHORITY_CONFIG/config.json" || return 125',
        "true # Docker configuration retained",
        "exact Docker configuration retirement",
    ),
    Mutation(
        "pins",
        'DEV_CHECK_IMAGE_ID="sha256:da876c1f',
        'DEV_CHECK_IMAGE_ID="rd-devcheck-',
        "devcheck content identity pin",
    ),
    Mutation(
        "pins",
        'SHA256_DEV_CHECK_DOCKERFILE="a2c6a501',
        'SHA256_DEV_CHECK_DOCKERFILE="00000000',
        "devcheck recipe pin",
    ),
    Mutation(
        "verify",
        "python3 scripts/verify-debian-systemd-lifecycle-authority.py "
        "--repo . --self-test",
        "true # lifecycle authority gate removed",
        "shared focused-gate wiring",
    ),
    Mutation(
        "requirements",
        '<span class="id">R-S11dl</span>',
        '<span class="id">R-S11dl-disabled</span>',
        "R-S11dl requirement",
    ),
    Mutation(
        "requirements",
        "<tr><td>265</td>",
        "<tr><td>265-disabled</td>",
        "Appendix C #265",
    ),
    Mutation(
        "hardening",
        "R-S11dl/R-S11e-130 — Debian systemd-lifecycle Docker client, daemon,\n"
        "  configuration, image, and mount authority",
        "R-S11dl/R-S11e-XXX — Debian lifecycle Docker authority deferred",
        "R-S11e-130 hardening ledger",
    ),
)


def run_mutations(sources: Dict[str, str]) -> None:
    for mutation in MUTATIONS:
        original = sources[mutation.source]
        count = original.count(mutation.old)
        if count != 1:
            raise AuthorityError(
                "mutation '{}' expected one source token, found {}".format(
                    mutation.label, count
                )
            )
        changed = dict(sources)
        changed[mutation.source] = original.replace(mutation.old, mutation.new, 1)
        try:
            validate(changed)
        except AuthorityError:
            continue
        raise AuthorityError("mutation survived: {}".format(mutation.label))


def read_regular(repo: pathlib.Path, relative: str) -> str:
    path = repo / relative
    if path.is_symlink() or not path.is_file():
        raise AuthorityError("required source is not a regular file: {}".format(relative))
    return path.read_text(encoding="utf-8")


def load_sources(repo: pathlib.Path) -> Dict[str, str]:
    return {
        "host": read_regular(repo, "scripts/smoke-debian-systemd-lifecycle.sh"),
        "lib": read_regular(repo, "scripts/lib.sh"),
        "pins": read_regular(repo, "scripts/pins.env"),
        "dockerfile": read_regular(repo, "scripts/Dockerfile.devcheck"),
        "verify": read_regular(repo, "scripts/verify.sh"),
        "android_gate": read_regular(repo, "scripts/verify-android-builder-authority.py"),
        "workspace_gate": read_regular(repo, "scripts/verify-verifier-workspace.py"),
        "requirements": read_regular(repo, "requirements.html"),
        "hardening": read_regular(repo, "HARDENING_STATUS.md"),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=".")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    sources = load_sources(pathlib.Path(args.repo).resolve())
    validate(sources)
    if args.self_test:
        run_mutations(sources)
    print(
        "DEBIAN-SYSTEMD-LIFECYCLE-AUTHORITY: pre-source root refusal, exact "
        "devcheck provenance, fixed local Docker authority, narrow mounts, "
        "bounded staging, and exact cleanup are GREEN ({} mutations)".format(
            len(MUTATIONS) if args.self_test else 0
        )
    )


if __name__ == "__main__":
    try:
        main()
    except (AuthorityError, OSError, UnicodeError) as error:
        raise SystemExit(
            "verify-debian-systemd-lifecycle-authority: {}".format(error)
        )
