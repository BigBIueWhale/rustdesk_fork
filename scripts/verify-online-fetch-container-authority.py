#!/usr/bin/env python3
"""Validate the online acquisition containers' execution authority."""

import argparse
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
        ("--privileged", "privileged mode"),
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
        ("--publish-all", "published ports"),
        ("--expose", "exposed port"),
        ("--device", "host device"),
        ("/var/run/docker.sock:/var/run/docker.sock", "Docker socket volume"),
        ("source=/var/run/docker.sock", "Docker socket mount"),
    ):
        forbid(source, token, "{} {}".format(label, description))
    if re.search(r"^\s+-(?:p|P)(?:\s|=)", source, re.MULTILINE):
        raise AuthorityError("forbidden {} short published port".format(label))


def validate(sources: Dict[str, str]) -> None:
    shell = sources["shell"]
    for token, label in (
        ("readonly DOCKER_BIN=/usr/bin/docker", "fixed Docker client"),
        ("readonly ONLINE_FETCH_DOCKER_HOST=unix:///var/run/docker.sock",
         "fixed local Docker endpoint"),
        ('[ "$ONLINE_FETCH_UID" -ne 0 ]', "host-root refusal"),
        ('[ "$ONLINE_FETCH_GID" -ne 0 ]', "root-primary-group refusal"),
        ('[ "$(stat -c \'%u:%g:%a:%h\' -- "$DOCKER_BIN")" = "0:0:755:1" ]',
         "trusted Docker client metadata"),
        ("for variable in DOCKER_CONFIG DOCKER_CONTEXT DOCKER_CERT_PATH DOCKER_TLS_VERIFY DOCKER_TLS",
         "caller Docker authority rejection"),
        ("ONLINE_FETCH_TMP=\"$(umask 077 && mktemp -d /tmp/rustdesk-online-fetch.",
         "private workspace"),
        ("trap cleanup_online_fetch_tmp EXIT", "private workspace cleanup"),
        ('readonly ONLINE_FETCH_DOCKER_CONFIG="$ONLINE_FETCH_TMP/docker-config"',
         "private Docker configuration"),
        ("printf '{}\\n' >\"$ONLINE_FETCH_DOCKER_CONFIG/config.json\"",
         "canonical empty Docker configuration"),
        ('[ "$(cat "$ONLINE_FETCH_DOCKER_CONFIG/config.json")" = "{}" ]',
         "Docker configuration byte proof"),
        ("env -i \\\n        PATH=/usr/bin:/bin", "closed Docker client environment"),
        ('--host "$ONLINE_FETCH_DOCKER_HOST"', "explicit Docker endpoint"),
        ('--config "$ONLINE_FETCH_DOCKER_CONFIG"', "explicit Docker configuration"),
        ("online_image_provenance()", "confined image-provenance funnel"),
        ("require_online_fetch_builder_image()", "verified immutable-image funnel"),
        ('--image-ref "$WIN_HELPER_IMAGE_ID"',
         "exact certified Windows-helper verification"),
        ('stage_archive_bundle wix "$ONLINE_DIR" .rustdesk-wix-nuget-packages',
         "exact WiX package acquisition funnel"),
    ):
        require(shell, token, label)
    forbid(
        shell,
        "mcr.microsoft.com/dotnet/sdk:8.0",
        "mutable WiX cache producer",
    )

    docker_client = extract(
        shell,
        "online_docker() {",
        '    return "$status"\n}',
        "Docker client funnel",
    )
    require(
        docker_client,
        "env -i \\\n        PATH=/usr/bin:/bin",
        "Docker client funnel closed environment",
    )
    require(
        docker_client,
        '--host "$ONLINE_FETCH_DOCKER_HOST"',
        "Docker client funnel fixed endpoint",
    )
    require(
        docker_client,
        '--config "$ONLINE_FETCH_DOCKER_CONFIG"',
        "Docker client funnel private configuration",
    )

    no_vcs_docker_client = extract(
        shell,
        "online_docker_without_vcs() {",
        '    return "$status"\n}',
        "VCS-suppressed Docker client funnel",
    )
    for token, label in (
        (
            "env -i \\\n        PATH=/usr/bin:/bin",
            "closed environment",
        ),
        (
            "BUILDX_GIT_INFO=false",
            "unverified VCS suppression",
        ),
        (
            '--host "$ONLINE_FETCH_DOCKER_HOST"',
            "fixed endpoint",
        ),
        (
            '--config "$ONLINE_FETCH_DOCKER_CONFIG"',
            "private configuration",
        ),
    ):
        require(
            no_vcs_docker_client,
            token,
            "VCS-suppressed Docker client funnel {}".format(label),
        )

    run = extract(
        shell,
        "online_docker_run() {",
        '        "$@"\n}',
        "online acquisition launch funnel",
    )
    for token, label in (
        ("online_docker run --rm", "ephemeral container"),
        ("--pull=never", "no-pull policy"),
        ("--network=bridge", "intentional isolated bridge egress"),
        ("--read-only", "read-only root"),
        ('--user "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID"', "numeric nonroot identity"),
        ("--cap-drop=ALL", "complete capability drop"),
        ("--security-opt=no-new-privileges", "no-new-privileges"),
        ("--pids-limit=2048", "PID ceiling"),
        ("--memory=16g", "memory ceiling"),
        ("--memory-swap=16g", "no-swap expansion"),
        ("--cpus=4", "CPU ceiling"),
        ("--tmpfs /tmp:rw,exec,nosuid,nodev,mode=1777,size=12g",
         "bounded scratch"),
    ):
        require(run, token, "launch funnel {}".format(label))
    forbid_container_authority(run, "launch funnel")

    offline_run = extract(
        shell,
        "online_docker_run_offline() {",
        '        "$@"\n}',
        "networkless archive launch funnel",
    )
    for token, label in (
        ("online_docker run --rm", "ephemeral container"),
        ("--pull=never", "no-pull policy"),
        ("--network=none", "network removal"),
        ("--read-only", "read-only root"),
        ('--user "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID"',
         "numeric nonroot identity"),
        ("--cap-drop=ALL", "complete capability drop"),
        ("--security-opt=no-new-privileges", "no-new-privileges"),
        ("--pids-limit=512", "PID ceiling"),
        ("--memory=4g", "memory ceiling"),
        ("--memory-swap=4g", "no-swap expansion"),
        ("--cpus=2", "CPU ceiling"),
        ("--tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777,size=256m",
         "bounded non-executable scratch"),
    ):
        require(
            offline_run,
            token,
            "networkless archive launch funnel {}".format(label),
        )
    forbid_container_authority(
        offline_run,
        "networkless archive launch funnel",
    )

    cargo_semantic_run = extract(
        shell,
        "online_docker_run_cargo_semantic() {",
        '        "$@"\n}',
        "networkless Cargo semantic launch funnel",
    )
    for token, label in (
        ("online_docker run --rm", "ephemeral container"),
        ("--pull=never", "no-pull policy"),
        ("--network=none", "network removal"),
        ("--read-only", "read-only root"),
        ('--user "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID"',
         "numeric nonroot identity"),
        ("--cap-drop=ALL", "complete capability drop"),
        ("--security-opt=no-new-privileges", "no-new-privileges"),
        ("--pids-limit=256", "PID ceiling"),
        ("--memory=4g", "memory ceiling"),
        ("--memory-swap=4g", "no-swap expansion"),
        ("--cpus=2", "CPU ceiling"),
        ("--tmpfs /tmp:rw,exec,nosuid,nodev,mode=1777,size=4g",
         "bounded executable scratch"),
    ):
        require(
            cargo_semantic_run,
            token,
            "networkless Cargo semantic launch funnel {}".format(label),
        )
    forbid_container_authority(
        cargo_semantic_run,
        "networkless Cargo semantic launch funnel",
    )

    acquisition_run = extract(
        shell,
        "online_docker_run_archive_acquisition() {",
        '        "$@"\n}',
        "networked archive acquisition launch funnel",
    )
    for token, label in (
        ("online_docker run --rm", "ephemeral container"),
        ("--pull=never", "no-pull policy"),
        ("--network=bridge", "isolated acquisition egress"),
        ("--read-only", "read-only root"),
        ('--user "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID"',
         "numeric nonroot identity"),
        ("--cap-drop=ALL", "complete capability drop"),
        ("--security-opt=no-new-privileges", "no-new-privileges"),
        ("--pids-limit=256", "PID ceiling"),
        ("--memory=4g", "memory ceiling"),
        ("--memory-swap=4g", "no-swap expansion"),
        ("--cpus=2", "CPU ceiling"),
        ("--tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777,size=256m",
         "bounded non-executable scratch"),
    ):
        require(
            acquisition_run,
            token,
            "networked archive acquisition launch funnel {}".format(label),
        )
    forbid_container_authority(
        acquisition_run,
        "networked archive acquisition launch funnel",
    )

    provenance = extract(
        shell,
        "online_image_provenance() {",
        '    return "$status"\n}',
        "image-provenance funnel",
    )
    require_count(
        provenance,
        "assert_online_fetch_docker_authority",
        2,
        "image-provenance Docker authority proofs",
    )
    require(
        provenance,
        '/usr/bin/python3 "$LIB_DIR/offline-image-provenance.py" "$@"',
        "fixed image-provenance program",
    )
    require(
        provenance,
        "env -i \\\n        PATH=/usr/bin:/bin \\\n        HOME=\"$ONLINE_FETCH_TMP\" \\\n"
        "        DOCKER_HOST=\"$ONLINE_FETCH_DOCKER_HOST\" \\\n"
        "        DOCKER_CONFIG=\"$ONLINE_FETCH_DOCKER_CONFIG\"",
        "closed image-provenance environment",
    )

    require_count(shell, "online_docker_run ", 8, "ordinary acquisition launch inventory")
    require_count(
        shell,
        "stage_cargo_installed_tool ",
        2,
        "closed Cargo-tool producer invocations",
    )
    require(
        shell,
        'stage_cargo_installed_tool frb "$builder"',
        "FRB typed producer invocation",
    )
    require(
        shell,
        'stage_cargo_installed_tool cargo-ndk "$builder"',
        "cargo-ndk typed producer invocation",
    )
    semantic = extract(
        shell,
        "online_docker_run_pub_semantic() {",
        "\n}\n\n# Exact archive acquisition",
        "Pub-cache networkless semantic funnel",
    )
    for token, label in (
        ("online_docker run --rm --pull=never --network=none --read-only",
         "ephemeral no-pull networkless read-only launch"),
        ('--user "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID"', "numeric nonroot identity"),
        ("--cap-drop=ALL --security-opt=no-new-privileges",
         "privilege confinement"),
        ("--pids-limit=512 --memory=8g --memory-swap=8g --cpus=4",
         "resource ceilings"),
        ("--tmpfs /tmp:rw,exec,nosuid,nodev,mode=1777,size=5g",
         "bounded scratch"),
    ):
        require(semantic, token, "Pub-cache semantic {}".format(label))
    forbid_container_authority(semantic, "Pub-cache semantic funnel")
    resolution = extract(
        shell,
        "verify_pub_cache_resolution() {",
        "\n}\n\nstage_pub_cache() {",
        "Pub-cache networkless semantic launch",
    )
    require(
        resolution,
        "online_docker_run_pub_semantic \\",
        "Pub-cache semantic funnel use",
    )
    forbid_container_authority(resolution, "Pub-cache semantic launch")

    require_count(
        shell,
        "online_docker run ",
        5,
        "ordinary, archive-expansion, Cargo/Pub semantic, and networked archive Docker primitives",
    )
    require_count(
        shell,
        "--pull=never",
        5,
        "five runtime launch no-pull policies",
    )
    require_count(
        shell,
        "online_docker buildx build \\\n"
        "        --network=none --pull=false --no-cache",
        1,
        "Dart advisory networkless no-pull candidate build",
    )
    require_count(
        shell,
        "online_docker buildx build \\\n"
        "        --network=default --pull=true --no-cache",
        1,
        "Rust advisory networked pull-enabled candidate build",
    )
    for token, label in (
        ("--read-only", "root-filesystem policy"),
        ("--user ", "container identity"),
        ("--cap-drop=", "capability policy"),
        ("--security-opt=", "security policy"),
        ("--pids-limit=", "PID policy"),
        ("--memory=", "memory policy"),
        ("--memory-swap=", "swap policy"),
        ("--cpus=", "CPU policy"),
        ("--tmpfs ", "scratch policy"),
    ):
        require_count(shell, token, 5, "five-launch {}".format(label))
    require_count(
        shell,
        'local builder="$DEB_BUILDER_IMAGE_ID"',
        5,
        "exact Debian builder consumers",
    )
    require_count(
        shell,
        'local builder="$ANDROID_BUILDER_IMAGE_ID"',
        9,
        "exact Android builder consumers",
    )
    require_count(
        shell,
        "require_online_fetch_builder_image ",
        13,
        "per-launch-site exact-image verification",
    )

    for token, label in (
        ("compatibility_tag", "compatibility-tag API"),
        ('"$builder" bash', "legacy mutable launch shape"),
        ("online_docker_run \"$@\"", "external Docker option passthrough"),
        ("online_docker_run ${", "environment-selected Docker option passthrough"),
        ("online_docker_run ubuntu:", "public Ubuntu runtime tag"),
        ("online_docker_run mcr.microsoft.com", "public .NET runtime tag"),
        ("apt-get update -qq", "live package installation in an ordinary producer"),
    ):
        forbid(shell, token, label)
    if re.search(r"(?m)^\s*docker\s+(?:run|tag)\b", shell):
        raise AuthorityError("forbidden ambient Docker run/tag primitive")
    forbid_container_authority(shell, "ordinary online-fetch source")

    require(
        sources["verify"],
        "/usr/bin/python3 -I -S scripts/verify-online-fetch-container-authority.py --repo . --self-test",
        "shared focused-verifier wiring",
    )
    require(sources["requirements"], '<span class="id">R-S11cj</span>', "R-S11cj requirement")
    require(sources["requirements"], "<tr><td>229</td>", "Appendix C #229 disposition")
    require(
        sources["hardening"],
        "R-S11cj/R-S11e-102 — online acquisition container execution authority",
        "hardening-ledger disposition",
    )
    require(
        sources["workspace"],
        '"online_fetch_container_authority_verifier"',
        "workspace-verifier source ownership",
    )
    require(
        sources["workspace"],
        "Online acquisition container authority focused verifier",
        "workspace-verifier semantic binding",
    )


MUTATIONS: Tuple[Mutation, ...] = (
    Mutation("shell", "readonly DOCKER_BIN=/usr/bin/docker", "DOCKER_BIN=docker",
             "fixed Docker client"),
    Mutation("shell", "readonly ONLINE_FETCH_DOCKER_HOST=unix:///var/run/docker.sock",
             "readonly ONLINE_FETCH_DOCKER_HOST=tcp://127.0.0.1:2375",
             "fixed local Docker endpoint"),
    Mutation("shell", '"$ONLINE_FETCH_UID" -ne 0', '"$ONLINE_FETCH_UID" -ge 0',
             "host-root refusal"),
    Mutation("shell", '"$ONLINE_FETCH_GID" -ne 0', '"$ONLINE_FETCH_GID" -ge 0',
             "root-primary-group refusal"),
    Mutation(
        "shell",
        "online_docker() {\n    local status=0\n    assert_online_fetch_docker_authority\n"
        "    env -i \\\n        PATH=/usr/bin:/bin",
        "online_docker() {\n    local status=0\n    assert_online_fetch_docker_authority\n"
        "    env \\\n        PATH=\"$PATH\"",
        "closed Docker environment",
    ),
    Mutation(
        "shell",
        '        DOCKER_CONFIG="$ONLINE_FETCH_DOCKER_CONFIG" \\\n'
        '        "$DOCKER_BIN" \\\n'
        '        --host "$ONLINE_FETCH_DOCKER_HOST"',
        '        DOCKER_CONFIG="$ONLINE_FETCH_DOCKER_CONFIG" \\\n'
        '        "$DOCKER_BIN" \\\n'
        '        --host "$DOCKER_HOST"',
        "ordinary Docker fixed endpoint use",
    ),
    Mutation(
        "shell",
        '        DOCKER_CONFIG="$ONLINE_FETCH_DOCKER_CONFIG" \\\n'
        '        "$DOCKER_BIN" \\\n'
        '        --host "$ONLINE_FETCH_DOCKER_HOST" \\\n'
        '        --config "$ONLINE_FETCH_DOCKER_CONFIG"',
        '        DOCKER_CONFIG="$ONLINE_FETCH_DOCKER_CONFIG" \\\n'
        '        "$DOCKER_BIN" \\\n'
        '        --host "$ONLINE_FETCH_DOCKER_HOST" \\\n'
        '        --config "$HOME/.docker"',
        "ordinary Docker private configuration use",
    ),
    Mutation(
        "shell",
        '        BUILDX_GIT_INFO=false \\\n'
        '        "$DOCKER_BIN" \\\n'
        '        --host "$ONLINE_FETCH_DOCKER_HOST"',
        '        BUILDX_GIT_INFO=false \\\n'
        '        "$DOCKER_BIN" \\\n'
        '        --host "$DOCKER_HOST"',
        "VCS-suppressed Docker fixed endpoint use",
    ),
    Mutation(
        "shell",
        '        BUILDX_GIT_INFO=false \\\n'
        '        "$DOCKER_BIN" \\\n'
        '        --host "$ONLINE_FETCH_DOCKER_HOST" \\\n'
        '        --config "$ONLINE_FETCH_DOCKER_CONFIG"',
        '        BUILDX_GIT_INFO=false \\\n'
        '        "$DOCKER_BIN" \\\n'
        '        --host "$ONLINE_FETCH_DOCKER_HOST" \\\n'
        '        --config "$HOME/.docker"',
        "VCS-suppressed Docker private configuration use",
    ),
    Mutation(
        "shell",
        "        BUILDX_GIT_INFO=false \\\n"
        '        "$DOCKER_BIN"',
        "        BUILDX_GIT_INFO=true \\\n"
        '        "$DOCKER_BIN"',
        "unverified VCS suppression",
    ),
    Mutation("shell", '[ "$(cat "$ONLINE_FETCH_DOCKER_CONFIG/config.json")" = "{}" ]',
             "true", "empty Docker configuration proof"),
    Mutation(
        "shell",
        "online_image_provenance() {\n    local status=0\n    assert_online_fetch_docker_authority",
        "online_image_provenance() {\n    local status=0\n    true",
        "image-provenance Docker authority proofs",
    ),
    Mutation(
        "shell",
        "online_image_provenance() {\n    local status=0\n"
        "    assert_online_fetch_docker_authority\n    env -i",
        "online_image_provenance() {\n    local status=0\n"
        "    assert_online_fetch_docker_authority\n    env",
        "closed image-provenance environment",
    ),
    Mutation(
        "shell",
        "online_docker_run() {\n"
        "    online_docker run --rm --pull=never --network=bridge --read-only",
        "online_docker_run() {\n"
        "    online_docker run --rm --pull=always --network=bridge --read-only",
        "no-pull policy",
    ),
    Mutation(
        "shell",
        "online_docker_run() {\n"
        "    online_docker run --rm --pull=never --network=bridge",
        "online_docker_run() {\n"
        "    online_docker run --rm --pull=never --network=host",
        "isolated acquisition network",
    ),
    Mutation(
        "shell",
        "online_docker_run() {\n"
        "    online_docker run --rm --pull=never --network=bridge --read-only",
        "online_docker_run() {\n"
        "    online_docker run --rm --pull=never --network=bridge "
        "--hostname=online-fetch",
        "read-only root",
    ),
    Mutation(
        "shell",
        'online_docker_run() {\n'
        '    online_docker run --rm --pull=never --network=bridge --read-only \\\n'
        '        --user "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID"',
        'online_docker_run() {\n'
        '    online_docker run --rm --pull=never --network=bridge --read-only \\\n'
        "        --user 0:0",
        "numeric nonroot identity",
    ),
    Mutation(
        "shell",
        "--cap-drop=ALL --security-opt=no-new-privileges \\\n"
        "        --pids-limit=2048",
        "--cap-drop=NET_RAW --security-opt=no-new-privileges \\\n"
        "        --pids-limit=2048",
        "complete capability drop",
    ),
    Mutation(
        "shell",
        "--cap-drop=ALL --security-opt=no-new-privileges \\\n"
        "        --pids-limit=2048",
        "--cap-drop=ALL --security-opt=seccomp=unconfined \\\n"
        "        --pids-limit=2048",
        "no-new-privileges",
    ),
    Mutation("shell", "--pids-limit=2048", "--pids-limit=-1", "PID ceiling"),
    Mutation("shell", "--memory=16g", "--memory=0", "memory ceiling"),
    Mutation("shell", "--memory-swap=16g", "--memory-swap=-1", "swap ceiling"),
    Mutation(
        "shell",
        "--memory-swap=16g --cpus=4",
        "--memory-swap=16g --cpus=0",
        "CPU ceiling",
    ),
    Mutation("shell", "size=12g", "size=120g", "scratch ceiling"),
    Mutation(
        "shell",
        "online_docker_run_offline() {\n"
        "    online_docker run --rm --pull=never --network=none --read-only",
        "online_docker_run_offline() {\n"
        "    online_docker run --rm --pull=never --network=bridge --read-only",
        "networkless archive network removal",
    ),
    Mutation(
        "shell",
        "--pids-limit=512 --memory=4g --memory-swap=4g --cpus=2",
        "--pids-limit=-1 --memory=4g --memory-swap=4g --cpus=2",
        "networkless archive PID ceiling",
    ),
    Mutation(
        "shell",
        "online_docker_run_offline() {\n"
        "    online_docker run --rm --pull=never --network=none --read-only \\\n"
        '        --user "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID" \\\n'
        "        --cap-drop=ALL --security-opt=no-new-privileges \\\n"
        "        --pids-limit=512 --memory=4g --memory-swap=4g --cpus=2 \\\n"
        "        --tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777,size=256m",
        "online_docker_run_offline() {\n"
        "    online_docker run --rm --pull=never --network=none --read-only \\\n"
        '        --user "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID" \\\n'
        "        --cap-drop=ALL --security-opt=no-new-privileges \\\n"
        "        --pids-limit=512 --memory=4g --memory-swap=4g --cpus=2 \\\n"
        "        --tmpfs /tmp:rw,exec,nosuid,nodev,mode=1777,size=256m",
        "networkless archive non-executable scratch",
    ),
    Mutation(
        "shell",
        "online_docker_run_cargo_semantic() {\n"
        "    online_docker run --rm --pull=never --network=none --read-only",
        "online_docker_run_cargo_semantic() {\n"
        "    online_docker run --rm --pull=never --network=bridge --read-only",
        "Cargo semantic network removal",
    ),
    Mutation(
        "shell",
        "online_docker_run_cargo_semantic() {\n"
        "    online_docker run --rm --pull=never --network=none --read-only \\\n"
        '        --user "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID"',
        "online_docker_run_cargo_semantic() {\n"
        "    online_docker run --rm --pull=never --network=none --read-only \\\n"
        "        --user 0:0",
        "Cargo semantic numeric nonroot identity",
    ),
    Mutation(
        "shell",
        "online_docker_run_cargo_semantic() {\n"
        "    online_docker run --rm --pull=never --network=none --read-only \\\n"
        '        --user "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID" \\\n'
        "        --cap-drop=ALL --security-opt=no-new-privileges \\\n"
        "        --pids-limit=256 --memory=4g --memory-swap=4g --cpus=2 \\\n"
        "        --tmpfs /tmp:rw,exec,nosuid,nodev,mode=1777,size=4g",
        "online_docker_run_cargo_semantic() {\n"
        "    online_docker run --rm --pull=never --network=none --read-only \\\n"
        '        --user "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID" \\\n'
        "        --cap-drop=ALL --security-opt=no-new-privileges \\\n"
        "        --pids-limit=256 --memory=4g --memory-swap=4g --cpus=2 \\\n"
        "        --tmpfs /tmp:rw,exec,nosuid,nodev,mode=1777,size=40g",
        "Cargo semantic scratch ceiling",
    ),
    Mutation(
        "shell",
        "online_docker_run_archive_acquisition() {\n"
        "    online_docker run --rm --pull=never --network=bridge --read-only",
        "online_docker_run_archive_acquisition() {\n"
        "    online_docker run --rm --pull=never --network=host --read-only",
        "networked archive isolated bridge",
    ),
    Mutation(
        "shell",
        "online_docker_run_archive_acquisition() {\n"
        "    online_docker run --rm --pull=never --network=bridge --read-only \\\n"
        '        --user "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID" \\\n'
        "        --cap-drop=ALL --security-opt=no-new-privileges \\\n"
        "        --pids-limit=256 --memory=4g --memory-swap=4g --cpus=2",
        "online_docker_run_archive_acquisition() {\n"
        "    online_docker run --rm --pull=never --network=bridge --read-only \\\n"
        '        --user "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID" \\\n'
        "        --cap-drop=ALL --security-opt=no-new-privileges \\\n"
        "        --pids-limit=-1 --memory=4g --memory-swap=4g --cpus=2",
        "networked archive PID ceiling",
    ),
    Mutation(
        "shell",
        "online_docker_run_archive_acquisition() {\n"
        "    online_docker run --rm --pull=never --network=bridge --read-only \\\n"
        '        --user "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID" \\\n'
        "        --cap-drop=ALL --security-opt=no-new-privileges \\\n"
        "        --pids-limit=256 --memory=4g --memory-swap=4g --cpus=2 \\\n"
        "        --tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777,size=256m",
        "online_docker_run_archive_acquisition() {\n"
        "    online_docker run --rm --pull=never --network=bridge --read-only \\\n"
        '        --user "$ONLINE_FETCH_UID:$ONLINE_FETCH_GID" \\\n'
        "        --cap-drop=ALL --security-opt=no-new-privileges \\\n"
        "        --pids-limit=256 --memory=4g --memory-swap=4g --cpus=2 \\\n"
        "        --tmpfs /tmp:rw,exec,nosuid,nodev,mode=1777,size=256m",
        "networked archive non-executable scratch",
    ),
    Mutation(
        "shell",
        "online_docker_run_pub_semantic() {\n"
        "    online_docker run --rm --pull=never --network=none --read-only",
        "online_docker_run_pub_semantic() {\n"
        "    online_docker run --rm --pull=never --network=bridge --read-only",
        "Pub-cache semantic network removal",
    ),
    Mutation(
        "shell",
        "online_docker buildx build \\\n"
        "        --network=none --pull=false --no-cache",
        "online_docker buildx build \\\n"
        "        --network=bridge --pull=true --no-cache",
        "Dart advisory candidate build authority",
    ),
    Mutation(
        "shell",
        "online_docker buildx build \\\n"
        "        --network=default --pull=true --no-cache",
        "online_docker buildx build \\\n"
        "        --network=none --pull=false --no-cache",
        "Rust advisory candidate build authority",
    ),
    Mutation("shell", 'build_frb_codegen() {\n    local builder="$DEB_BUILDER_IMAGE_ID"',
             'build_frb_codegen() {\n    local builder="ubuntu:18.04"',
             "exact Debian image"),
    Mutation("shell", 'stage_vcpkg_natives_arm64() {\n    local builder="$ANDROID_BUILDER_IMAGE_ID"',
             'stage_vcpkg_natives_arm64() {\n    local builder="ubuntu:24.04"',
             "exact Android image"),
    Mutation("shell", '--image-ref "$WIN_HELPER_IMAGE_ID"',
             '--image-ref "$WIN_HELPER_BOOTSTRAP_IMAGE_ID"',
             "exact loaded-image verification"),
    Mutation(
        "shell",
        'stage_archive_bundle wix "$ONLINE_DIR" .rustdesk-wix-nuget-packages',
        'stage_archive_bundle toolchain "$ONLINE_DIR" .rustdesk-wix-nuget-packages',
        "exact WiX package acquisition funnel",
    ),
    Mutation(
        "verify",
        "/usr/bin/python3 -I -S scripts/verify-online-fetch-container-authority.py --repo . --self-test",
        "true # online-fetch authority gate removed",
        "shared focused-verifier wiring",
    ),
    Mutation("requirements", '<span class="id">R-S11cj</span>',
             '<span class="id">R-S11cj-disabled</span>', "R-S11cj requirement"),
    Mutation("requirements", "<tr><td>229</td>", "<tr><td>229-disabled</td>",
             "Appendix C #229 disposition"),
    Mutation(
        "hardening",
        "R-S11cj/R-S11e-102 — online acquisition container execution authority",
        "R-S11cj/R-S11e-102 — ambient online acquisition authority",
        "hardening-ledger disposition",
    ),
)


def load_sources(repo: pathlib.Path) -> Dict[str, str]:
    return {
        "shell": (repo / "scripts/online-fetch.sh").read_text(encoding="utf-8"),
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
    arguments = parser.parse_args()
    sources = load_sources(arguments.repo.resolve())
    validate(sources)
    if arguments.self_test:
        run_mutations(sources)
    print(
        "verify-online-fetch-container-authority: OK"
        + (" ({} mutations)".format(len(MUTATIONS)) if arguments.self_test else "")
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AuthorityError, OSError) as error:
        print("verify-online-fetch-container-authority: {}".format(error))
        raise SystemExit(1)
