#!/usr/bin/env python3
"""Validate Android signing-identity generation and publication authority."""

import argparse
import pathlib
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
    positions = tuple(source.index(token) for token in tokens)
    if positions != tuple(sorted(positions)) or len(set(positions)) != len(positions):
        raise AuthorityError("{} is incomplete or misordered".format(label))


def extract(source: str, start: str, end: str, label: str) -> str:
    try:
        begin = source.index(start)
        finish = source.index(end, begin)
    except ValueError as exc:
        raise AuthorityError("missing {}".format(label)) from exc
    return source[begin:finish]


def validate(sources: Dict[str, str]) -> None:
    generate = sources["generate"]
    lib = sources["lib"]
    inner = sources["inner"]

    for token, label in (
        ("set -euo pipefail\numask 077", "private host-created state umask"),
        ("export PATH=/usr/bin:/bin", "closed host command path"),
        ('readonly BUILD_UID="$(/usr/bin/id -u)"', "absolute host UID source"),
        ('readonly BUILD_GID="$(/usr/bin/id -g)"', "absolute host GID source"),
        ('[ "$BUILD_UID" -ne 0 ]', "host UID-root refusal"),
        ('[ "$BUILD_GID" -ne 0 ]', "host GID-root refusal"),
        ("source \"$SCRIPT_DIR/lib.sh\"", "shared authority source"),
        ("load_pins", "pinned manifest load"),
        ('readonly IMAGE_ID="$ANDROID_BUILDER_IMAGE_ID"', "immutable Android image identity"),
        ("readonly KEY_ALIAS=rustdesk-fork", "fixed Android signing alias"),
        ("refuses host or container-root execution", "root execution refusal"),
        ("refuses a root primary group", "root primary-group refusal"),
        ('[ "$(readlink -m -- "$value")" = "$value" ]',
         "canonical no-symlink signing paths"),
        ("must not contain a Docker mount delimiter", "Docker-mount delimiter refusal"),
        ('[ "$SIGNING_DIR" = "$PASS_DIR" ]', "shared private signing directory"),
        ('metadata" = "$BUILD_UID:700"', "private signing-directory ownership"),
        ('"$BUILD_UID:600:1:"', "single-link secret ownership"),
        ('[ ! -e "$OUT_JKS" ] && [ ! -L "$OUT_JKS" ]',
         "existing-keystore no-clobber refusal"),
        ('mktemp -d "$SIGNING_DIR/.rustdesk-keystore.XXXXXXXXXX"',
         "same-filesystem private staging"),
        ('install -m 0400 -- "$INNER_SOURCE"', "private inner-program snapshot"),
        ('initialize_local_docker_authority "$STAGE_ROOT/docker-config" "android-keystore"',
         "fixed local Docker authority initialization"),
        ('if [ "$LOCAL_DOCKER_AUTHORITY_INITIALIZED" -eq 1 ]',
         "fixed local Docker authority cleanup admission"),
        ("&& ! remove_local_docker_authority; then",
         "exact local Docker authority cleanup"),
        ("preserving changed private Android keystore Docker authority",
         "changed local Docker authority preservation"),
        ('require_pinned_builder_image android-builder "$IMAGE_ID"',
         "immutable builder provenance verification"),
        ("android_keystore_docker_run() {", "single container-confinement wrapper"),
        ("local_docker run --rm --pull=never --network=none --read-only",
         "no-pull networkless read-only-root launch"),
        ('--user "$BUILD_UID:$BUILD_GID"', "numeric nonroot container identity"),
        ("--cap-drop=ALL --security-opt=no-new-privileges",
         "capability and privilege confinement"),
        ("--pids-limit=32 --memory=256m --memory-swap=256m --cpus=1",
         "password-generator resource bounds"),
        ("--pids-limit=64 --memory=1g --memory-swap=1g --cpus=1",
         "key-generator resource bounds"),
        ("--pids-limit=32 --memory=512m --memory-swap=512m --cpus=1",
         "key-verifier resource bounds"),
        ("--tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777,size=32m",
         "password-generator bounded scratch"),
        ("--tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777,size=256m",
         "key-generator bounded scratch"),
        ("--tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777,size=128m",
         "key-verifier bounded scratch"),
        ('source=$STAGE_ROOT/output,target=/out"', "private narrow writable output mount"),
        ('source=$PASS_INPUT,target=/authority/pass,readonly"',
         "read-only password-file mount"),
        ('source=$STAGED_KEYSTORE,target=/authority/keystore.jks,readonly"',
         "read-only independent-verification keystore mount"),
        ('target=/authority/android-keystore-generate.sh,readonly"',
         "read-only private worker mount"),
        ('mv -- "$STAGE_ROOT/output/pass" "$STAGE_ROOT/secret/pass"',
         "generated-password isolation before key generation"),
        ("PASS_STATE_BEFORE=", "password identity/metadata snapshot"),
        ("PASS_SHA_BEFORE=", "password byte snapshot"),
        ("KEYSTORE_STATE_BEFORE=", "keystore identity/metadata snapshot"),
        ("KEYSTORE_SHA_BEFORE=", "keystore byte snapshot"),
        ("password bytes changed during key generation", "password byte postcondition"),
        ("keystore bytes changed during verification", "keystore byte postcondition"),
        ('[[ "$verification" =~ ^ANDROID_KEYSTORE_CERT_SHA256=[0-9A-F]{64}$ ]]',
         "canonical independent certificate result"),
        ('ln -- "$PASS_INPUT" "$PASS_FILE"', "atomic no-clobber password publication"),
        ('ln -- "$STAGED_KEYSTORE" "$OUT_JKS"', "atomic no-clobber keystore publication"),
        ('sync -f -- "$OUT_JKS" "$PASS_FILE"', "durable signing-identity publication"),
        ("published Android signing password differs", "published-password byte proof"),
        ("published Android keystore differs", "published-keystore byte proof"),
    ):
        require(generate, token, label)

    require_count(
        generate,
        "local_docker run --rm --pull=never --network=none --read-only",
        1,
        "single fixed local Docker launch funnel",
    )
    require_order(
        generate,
        (
            'readonly BUILD_UID="$(/usr/bin/id -u)"',
            'readonly BUILD_GID="$(/usr/bin/id -g)"',
            "refuses host or container-root execution",
            "refuses a root primary group",
            'source "$SCRIPT_DIR/lib.sh"',
            "load_pins",
            'mktemp -d "$SIGNING_DIR/.rustdesk-keystore.XXXXXXXXXX"',
            'initialize_local_docker_authority "$STAGE_ROOT/docker-config" "android-keystore"',
            'require_pinned_builder_image android-builder "$IMAGE_ID"',
            "local_docker run --rm --pull=never --network=none --read-only",
        ),
        "root refusal, shared authority, provenance, and launch order",
    )
    cleanup = extract(
        generate,
        "cleanup_stage() {",
        "\n}\ntrap cleanup_stage EXIT",
        "Android keystore stage cleanup",
    )
    require_order(
        cleanup,
        (
            "remove_local_docker_authority",
            'elif [ -d "$STAGE_ROOT" ]',
            'chmod -R u+rwX "$STAGE_ROOT"',
            'rm -rf -- "$STAGE_ROOT"',
        ),
        "Docker-before-stage cleanup order",
    )

    for token, label in (
        ("initialize_local_docker_authority() {", "shared Docker authority initializer"),
        (
            "DOCKER_HOST DOCKER_CONTEXT DOCKER_CONFIG DOCKER_CERT_PATH DOCKER_TLS_VERIFY DOCKER_TLS",
            "shared Docker ambient-input refusal",
        ),
        (
            "DOCKER_API_VERSION DOCKER_DEFAULT_PLATFORM DOCKER_CONTENT_TRUST",
            "shared Docker API/platform/trust-input refusal",
        ),
        (
            "DOCKER_CONTENT_TRUST_SERVER DOCKER_CUSTOM_HEADERS",
            "shared Docker trust-server/header-input refusal",
        ),
        (
            "[ -f /usr/bin/docker ] && [ ! -L /usr/bin/docker ] && [ -x /usr/bin/docker ]",
            "shared absolute Docker-client shape proof",
        ),
        (
            "case \"$(/usr/bin/stat -c '%u:%g:%a:%h' -- /usr/bin/docker 2>/dev/null)\" in\n"
            "        0:0:755:1) ;;",
            "shared root-owned Docker-client metadata proof",
        ),
        (
            "[ -S /var/run/docker.sock ] && [ ! -L /var/run/docker.sock ]",
            "shared local Docker-socket shape proof",
        ),
        (
            "case \"$(/usr/bin/stat -c '%u:%h' -- /var/run/docker.sock 2>/dev/null)\" in\n"
            "        0:1) ;;",
            "shared root-owned Docker-socket metadata proof",
        ),
        (
            "(umask 077 && set -o noclobber && printf '{}\\n' >\"$config/config.json\")",
            "shared Docker canonical no-clobber configuration",
        ),
        (
            'LOCAL_DOCKER_AUTHORITY_PARENT_ID="$(/usr/bin/stat',
            "shared Docker-authority parent identity binding",
        ),
        (
            'LOCAL_DOCKER_AUTHORITY_CONFIG_ID="$(/usr/bin/stat',
            "shared Docker-config directory identity binding",
        ),
        (
            'LOCAL_DOCKER_AUTHORITY_CONFIG_FILE_ID="$(/usr/bin/stat',
            "shared Docker-config file identity binding",
        ),
        (
            'LOCAL_DOCKER_AUTHORITY_CLIENT_ID="$(/usr/bin/stat',
            "shared Docker-client identity binding",
        ),
        (
            'LOCAL_DOCKER_AUTHORITY_SOCKET_ID="$(/usr/bin/stat',
            "shared Docker-socket identity binding",
        ),
        ("local_docker() {", "shared fixed Docker launcher"),
        ("local_docker_image_provenance() {", "shared fixed Docker provenance wrapper"),
        ("/usr/bin/env -i", "shared empty Docker environment"),
        ("DOCKER_HOST=unix:///var/run/docker.sock", "shared fixed local Docker endpoint"),
        ('--config "$LOCAL_DOCKER_AUTHORITY_CONFIG"', "shared private Docker configuration"),
        ("remove_local_docker_authority() {", "shared exact Docker cleanup"),
        (
            '/usr/bin/rm -- "$LOCAL_DOCKER_AUTHORITY_CONFIG/config.json"',
            "shared exact Docker-config leaf removal",
        ),
        (
            '/usr/bin/rmdir -- "$LOCAL_DOCKER_AUTHORITY_CONFIG"',
            "shared exact Docker-config directory removal",
        ),
        (
            'local_docker_image_provenance "${args[@]}"',
            "builder provenance shared-authority routing",
        ),
    ):
        require(lib, token, label)
    asserted_authority = extract(
        lib,
        "assert_local_docker_authority() {",
        "\n}\n\nlocal_docker() {",
        "shared Docker authority assertion",
    )
    for token, label in (
        ("LOCAL_DOCKER_AUTHORITY_PARENT_ID", "shared Docker parent identity recheck"),
        ("LOCAL_DOCKER_AUTHORITY_CONFIG_ID", "shared Docker-config identity recheck"),
        (
            "LOCAL_DOCKER_AUTHORITY_CONFIG_FILE_ID",
            "shared Docker-config file identity recheck",
        ),
        ("LOCAL_DOCKER_AUTHORITY_CLIENT_ID", "shared Docker-client identity recheck"),
        ("LOCAL_DOCKER_AUTHORITY_SOCKET_ID", "shared Docker-socket identity recheck"),
        (
            '/usr/bin/cmp -s -- "$LOCAL_DOCKER_AUTHORITY_CONFIG/config.json" <(printf \'{}\\n\')',
            "shared Docker-config byte recheck",
        ),
    ):
        require(asserted_authority, token, label)
    local_docker = extract(
        lib,
        "local_docker() {",
        "\n}\n\nlocal_docker_image_provenance() {",
        "shared fixed Docker launcher",
    )
    require_count(
        local_docker,
        "assert_local_docker_authority",
        2,
        "shared Docker pre/post authority proof",
    )
    for token, label in (
        ("/usr/bin/env -i", "shared Docker launcher empty environment"),
        ("/usr/bin/docker", "shared Docker launcher absolute client"),
        ("--host unix:///var/run/docker.sock", "shared Docker launcher endpoint"),
        ('--config "$LOCAL_DOCKER_AUTHORITY_CONFIG"', "shared Docker launcher configuration"),
    ):
        require(local_docker, token, label)
    docker_provenance = extract(
        lib,
        "local_docker_image_provenance() {",
        "\n}\n\nremove_local_docker_authority() {",
        "shared fixed Docker provenance wrapper",
    )
    require_count(
        docker_provenance,
        "assert_local_docker_authority",
        2,
        "shared Docker provenance pre/post authority proof",
    )
    for token, label in (
        ("/usr/bin/env -i", "shared Docker provenance empty environment"),
        ("/usr/bin/python3 -I -S", "shared absolute isolated provenance interpreter"),
        ('"$LIB_DIR/offline-image-provenance.py"', "shared fixed provenance program"),
    ):
        require(docker_provenance, token, label)

    require_count(
        generate,
        "        /authority/android-keystore-generate.sh password",
        1,
        "single password-generator operation",
    )
    require_count(
        generate,
        "    /authority/android-keystore-generate.sh keystore",
        1,
        "single key-generator operation",
    )
    require_count(
        generate,
        "        /authority/android-keystore-generate.sh verify",
        1,
        "single independent key-verifier operation",
    )
    require_count(generate, "target=/out\"", 2, "two narrow writable output mounts")
    require_count(
        generate, "target=/authority/pass,readonly", 2, "two read-only password mounts"
    )
    require_count(
        generate,
        "target=/authority/keystore.jks,readonly",
        1,
        "one read-only verification-keystore mount",
    )
    require_order(
        generate,
        (
            'mv -- "$STAGE_ROOT/output/pass" "$STAGE_ROOT/secret/pass"',
            "PASS_STATE_BEFORE=",
            "/authority/android-keystore-generate.sh keystore",
            "KEYSTORE_STATE_BEFORE=",
            "/authority/android-keystore-generate.sh verify",
            "password bytes changed during key generation",
            "keystore bytes changed during verification",
            'ln -- "$PASS_INPUT" "$PASS_FILE"',
            'ln -- "$STAGED_KEYSTORE" "$OUT_JKS"',
            'sync -f -- "$OUT_JKS" "$PASS_FILE"',
            "published Android keystore differs",
        ),
        "password/key generation, verification, and publication authority",
    )

    for token, label in (
        ("HARNESS_PREFIX", "mutable harness-prefix image selection"),
        ("android-builder\"", "mutable Android builder image name"),
        ("openssl rand", "host password generator"),
        ("docker image inspect", "ad hoc image-name inspection"),
        ("\ndocker run", "PATH-selected Docker invocation"),
        ("/usr/bin/docker run", "direct ambient Docker invocation"),
        ('"$DOCKER_BIN" run', "obsolete direct Docker client invocation"),
        ("readonly DOCKER_BIN=", "obsolete direct Docker client binding"),
        ("DOCKER_HOST", "generator-owned Docker endpoint environment"),
        ("DOCKER_CONFIG", "generator-owned Docker configuration environment"),
        ("assert_private_docker_config", "obsolete private Docker-config abstraction"),
        ('printf \'{}\\n\' > "$STAGE_ROOT/docker-config/config.json"',
         "duplicate Docker-config creation"),
        (" -v ", "short broad volume mount"),
        ("source=$SIGNING_DIR,target=/out", "final signing-directory writable mount"),
        ("source=$PASS_DIR,target=/out", "password-directory writable mount"),
        ("--privileged", "privileged container"),
        ("--cap-add", "added capability"),
        ("--network=host", "host network namespace"),
        ("--pid=host", "host PID namespace"),
        ("--ipc=host", "host IPC namespace"),
        ("--uts=host", "host UTS namespace"),
        ("--name ", "daemon-global container name"),
        ("/var/run/docker.sock:/var/run/docker.sock", "Docker socket volume"),
        ("source=/var/run/docker.sock", "Docker socket mount"),
        ("--publish", "port publication"),
        ("-p ", "short port publication"),
        ("docker build", "image build fallback"),
        ("docker pull", "image pull fallback"),
        ("--user 0:0", "container-root identity"),
        ("ANDROID_KEYSTORE_PASS=", "password environment value"),
    ):
        forbid(generate, token, label)

    for token, label in (
        ("set -euo pipefail\numask 077", "inner private umask"),
        ("dd if=/dev/urandom", "container-local kernel CSPRNG read"),
        ("bs=33 count=1", "fixed random-password entropy"),
        ("base64 -w 0", "single-line random-password encoding"),
        ("chmod 0600 /out/pass", "generated-password private mode"),
        ("keytool -J-Duser.language=en -J-Duser.country=US -genkeypair -noprompt",
         "noninteractive fixed key generation"),
        ("-keystore /out/keystore.jks -alias rustdesk-fork",
         "fixed output and signing alias"),
        ("-keyalg RSA -keysize 4096 -sigalg SHA256withRSA -validity 10000",
         "fixed R-B2 key properties"),
        ("-storepass:file /authority/pass -keypass:file /authority/pass",
         "file-only key-generation password inputs"),
        ("-keystore /authority/keystore.jks -alias rustdesk-fork",
         "independent fixed-alias key inspection"),
        ("-storepass:file /authority/pass 2>/dev/null",
         "file-only verification password input"),
        ("Signature algorithm name:[[:space:]]*SHA256withRSA",
         "certificate-algorithm verification"),
        ("4096-bit RSA key", "RSA-size verification"),
        ("ANDROID_KEYSTORE_CERT_SHA256=", "public certificate result"),
    ):
        require(inner, token, label)
    for token, label in (
        ('pw="$(cat', "password shell variable"),
        ('-storepass "$', "password argv expansion"),
        ('-keypass "$', "key-password argv expansion"),
        ("rustdesk-fork-harness", "mutable image knowledge"),
        ("docker", "nested Docker authority"),
        ("curl", "network client"),
        ("wget", "network client"),
    ):
        forbid(inner, token, label)

    require(
        sources["verify"],
        "python3 scripts/verify-android-keystore-authority.py --repo . --self-test",
        "shared focused-verifier wiring",
    )
    require(
        sources["requirements"],
        '<span class="id">R-S11cg</span>',
        "R-S11cg requirement",
    )
    require(
        sources["requirements"], "<tr><td>226</td>", "Appendix C #226 disposition"
    )
    require(
        sources["hardening"],
        "R-S11cg/R-S11e-99 — Android signing-identity generation authority",
        "hardening-ledger disposition",
    )
    require(
        sources["requirements"],
        '<span class="id">R-S11di</span>',
        "R-S11di requirement",
    )
    require(
        sources["requirements"],
        "<tr><td>262</td>",
        "Appendix C #262 disposition",
    )
    require(
        sources["hardening"],
        "R-S11di/R-S11e-127 — Android signing-identity Docker client, daemon, and configuration authority",
        "Docker-authority hardening-ledger disposition",
    )
    require(
        sources["workspace"],
        '"android_keystore_authority_verifier"',
        "workspace-verifier source ownership",
    )
    require(
        sources["workspace"],
        "Android keystore focused authority verifier",
        "workspace-verifier semantic binding",
    )
    require(
        sources["readme"],
        "`gen-android-keystore.sh`",
        "operator documentation",
    )


MUTATIONS: Tuple[Mutation, ...] = (
    Mutation("generate", "set -euo pipefail\numask 077", "set -euo pipefail\numask 022",
             "private state umask"),
    Mutation("generate", 'readonly BUILD_UID="$(/usr/bin/id -u)"',
             'readonly BUILD_UID="$(id -u)"', "absolute host UID source"),
    Mutation("generate", 'readonly BUILD_GID="$(/usr/bin/id -g)"',
             'readonly BUILD_GID="$(id -g)"', "absolute host GID source"),
    Mutation("generate", 'readonly IMAGE_ID="$ANDROID_BUILDER_IMAGE_ID"',
             'readonly IMAGE_ID="${HARNESS_PREFIX}-android-builder"', "immutable image identity"),
    Mutation("generate", '[ "$BUILD_UID" -ne 0 ]', '[ "$BUILD_UID" -eq 0 ]',
             "root execution refusal"),
    Mutation("generate", '[ "$BUILD_GID" -ne 0 ]', '[ "$BUILD_GID" -eq 0 ]',
             "root primary-group refusal"),
    Mutation("generate", '[ "$(readlink -m -- "$value")" = "$value" ]', "true",
             "canonical signing paths"),
    Mutation("generate", 'metadata" = "$BUILD_UID:700"', 'metadata" = "$BUILD_UID:755"',
             "private signing directory"),
    Mutation("generate", '"$BUILD_UID:600:1:"', '"$BUILD_UID:644:1:"',
             "private secret file"),
    Mutation("generate", 'mktemp -d "$SIGNING_DIR/.rustdesk-keystore.XXXXXXXXXX"',
             "mktemp -d /tmp/rustdesk-keystore.XXXXXXXXXX", "same-filesystem staging"),
    Mutation(
        "generate",
        'initialize_local_docker_authority "$STAGE_ROOT/docker-config" "android-keystore"',
        "true # fixed local Docker authority disabled",
        "fixed local Docker authority initialization",
    ),
    Mutation(
        "generate",
        'if [ "$LOCAL_DOCKER_AUTHORITY_INITIALIZED" -eq 1 ] \\\n'
        '        && ! remove_local_docker_authority; then',
        "if false; then",
        "fixed local Docker authority cleanup",
    ),
    Mutation("generate", 'require_pinned_builder_image android-builder "$IMAGE_ID"', "true",
             "builder provenance verification"),
    Mutation("generate", "local_docker run --rm --pull=never --network=none --read-only",
             "/usr/bin/docker run --rm --pull=never --network=none --read-only",
             "fixed local Docker launch funnel"),
    Mutation(
        "lib",
        "DOCKER_HOST DOCKER_CONTEXT DOCKER_CONFIG DOCKER_CERT_PATH DOCKER_TLS_VERIFY DOCKER_TLS",
        "DOCKER_HOST DOCKER_CONFIG DOCKER_CERT_PATH DOCKER_TLS_VERIFY DOCKER_TLS",
        "ambient Docker-authority refusal",
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
        "root-owned Docker-client identity",
    ),
    Mutation(
        "lib",
        "case \"$(/usr/bin/stat -c '%u:%h' -- /var/run/docker.sock 2>/dev/null)\" in\n"
        "        0:1) ;;",
        "case \"$(/usr/bin/stat -c '%u:%h' -- /var/run/docker.sock 2>/dev/null)\" in\n"
        "        *:1) ;;",
        "root-owned Docker-socket identity",
    ),
    Mutation(
        "lib",
        "(umask 077 && set -o noclobber && printf '{}\\n' >\"$config/config.json\")",
        "(umask 077 && printf '{}\\n' >\"$config/config.json\")",
        "private Docker config no-clobber creation",
    ),
    Mutation(
        "lib",
        'LOCAL_DOCKER_AUTHORITY_PARENT_ID="$(/usr/bin/stat -c \'%d:%i:%u:%g:%a\' -- "$parent")"',
        'LOCAL_DOCKER_AUTHORITY_PARENT_ID=unchecked',
        "Docker-authority parent identity binding",
    ),
    Mutation(
        "lib",
        'LOCAL_DOCKER_AUTHORITY_CONFIG_ID="$(/usr/bin/stat -c \'%d:%i:%u:%g:%a:%h\' -- "$config")"',
        'LOCAL_DOCKER_AUTHORITY_CONFIG_ID=unchecked',
        "Docker-config directory identity binding",
    ),
    Mutation(
        "lib",
        'LOCAL_DOCKER_AUTHORITY_CONFIG_FILE_ID="$(/usr/bin/stat -c \'%d:%i:%u:%g:%a:%h\' -- "$config/config.json")"',
        'LOCAL_DOCKER_AUTHORITY_CONFIG_FILE_ID=unchecked',
        "Docker-config file identity binding",
    ),
    Mutation(
        "lib",
        'LOCAL_DOCKER_AUTHORITY_CLIENT_ID="$(/usr/bin/stat -c \'%d:%i:%u:%g:%a:%h\' -- /usr/bin/docker)"',
        'LOCAL_DOCKER_AUTHORITY_CLIENT_ID=unchecked',
        "Docker-client identity binding",
    ),
    Mutation(
        "lib",
        'LOCAL_DOCKER_AUTHORITY_SOCKET_ID="$(/usr/bin/stat -c \'%d:%i:%u:%g:%a:%h\' -- /var/run/docker.sock)"',
        'LOCAL_DOCKER_AUTHORITY_SOCKET_ID=unchecked',
        "Docker-socket identity binding",
    ),
    Mutation(
        "lib",
        '/usr/bin/cmp -s -- "$LOCAL_DOCKER_AUTHORITY_CONFIG/config.json" <(printf \'{}\\n\')',
        "true # Docker config bytes unchecked",
        "Docker-config byte recheck",
    ),
    Mutation(
        "lib",
        "local_docker() {\n    local status=0\n    assert_local_docker_authority || return 1\n    /usr/bin/env -i",
        "local_docker() {\n    local status=0\n    assert_local_docker_authority || return 1\n    /usr/bin/env",
        "empty Docker client environment",
    ),
    Mutation(
        "lib",
        "--host unix:///var/run/docker.sock",
        "--host tcp://127.0.0.1:2375",
        "fixed local Docker endpoint",
    ),
    Mutation(
        "lib",
        'local_docker_image_provenance "${args[@]}"',
        'python3 "$LIB_DIR/offline-image-provenance.py" "${args[@]}"',
        "builder provenance shared-authority routing",
    ),
    Mutation(
        "lib",
        '/usr/bin/rm -- "$LOCAL_DOCKER_AUTHORITY_CONFIG/config.json" || return 125',
        "true # Docker configuration retained",
        "exact Docker-authority cleanup",
    ),
    Mutation("generate", '--user "$BUILD_UID:$BUILD_GID"', "--user 0:0",
             "numeric nonroot identity"),
    Mutation("generate", "--cap-drop=ALL --security-opt=no-new-privileges",
             "--cap-drop=NET_RAW", "privilege confinement"),
    Mutation("generate", "--memory=1g --memory-swap=1g", "--memory=1g --memory-swap=-1",
             "key-generator no-swap bound"),
    Mutation(
        "generate",
        '--mount "type=bind,source=$STAGE_ROOT/output,target=/out" \\\n'
        '    --mount "type=bind,source=$PASS_INPUT,target=/authority/pass,readonly"',
        '--mount "type=bind,source=$STAGE_ROOT/output,target=/out" \\\n'
        '    --mount "type=bind,source=$PASS_INPUT,target=/authority/pass"',
        "read-only password mount",
    ),
    Mutation("generate", 'mv -- "$STAGE_ROOT/output/pass" "$STAGE_ROOT/secret/pass"',
             "true # password remains in writable output", "generated-password isolation"),
    Mutation("generate", "password bytes changed during key generation",
             "password bytes were not checked", "password byte postcondition"),
    Mutation("generate", "keystore bytes changed during verification",
             "keystore bytes were not checked", "keystore byte postcondition"),
    Mutation("generate", 'ln -- "$PASS_INPUT" "$PASS_FILE"',
             'cp -- "$PASS_INPUT" "$PASS_FILE"', "atomic password publication"),
    Mutation("generate", 'ln -- "$STAGED_KEYSTORE" "$OUT_JKS"',
             'cp -- "$STAGED_KEYSTORE" "$OUT_JKS"', "atomic keystore publication"),
    Mutation("generate", 'sync -f -- "$OUT_JKS" "$PASS_FILE"', "true",
             "durable publication"),
    Mutation("inner", "dd if=/dev/urandom", "printf predictable-randomness",
             "kernel CSPRNG"),
    Mutation("inner", "-keystore /out/keystore.jks -alias rustdesk-fork",
             "-keystore /out/keystore.jks -alias \"$2\"", "fixed signing alias"),
    Mutation("inner", "-keysize 4096", "-keysize 2048", "RSA key size"),
    Mutation("inner", "-storepass:file /authority/pass -keypass:file /authority/pass",
             "-storepass password -keypass password", "file-only password input"),
    Mutation("inner", "Signature algorithm name:[[:space:]]*SHA256withRSA",
             "Signature algorithm name:", "signature-algorithm verification"),
    Mutation("verify", "python3 scripts/verify-android-keystore-authority.py --repo . --self-test",
             "true # Android keystore authority verifier removed", "shared verifier wiring"),
    Mutation("requirements", '<span class="id">R-S11cg</span>',
             '<span class="id">R-S11cg-disabled</span>', "R-S11cg requirement"),
    Mutation("requirements", "<tr><td>226</td>", "<tr><td>226-disabled</td>",
             "Appendix C #226 disposition"),
    Mutation("hardening", "R-S11cg/R-S11e-99 — Android signing-identity generation authority",
             "R-S11cg/R-S11e-99 — Android ambient identity generation authority",
             "hardening ledger"),
    Mutation("requirements", '<span class="id">R-S11di</span>',
             '<span class="id">R-S11di-disabled</span>', "R-S11di requirement"),
    Mutation("requirements", "<tr><td>262</td>", "<tr><td>262-disabled</td>",
             "Appendix C #262 disposition"),
    Mutation(
        "hardening",
        "R-S11di/R-S11e-127 — Android signing-identity Docker client, daemon, and configuration authority",
        "R-S11di/R-S11e-XXX — Android signing-identity Docker authority deferred",
        "Docker-authority hardening ledger",
    ),
)


def load_sources(repo: pathlib.Path) -> Dict[str, str]:
    return {
        "generate": (repo / "scripts/gen-android-keystore.sh").read_text(encoding="utf-8"),
        "lib": (repo / "scripts/lib.sh").read_text(encoding="utf-8"),
        "inner": (repo / "scripts/android-keystore-generate.sh").read_text(encoding="utf-8"),
        "verify": (repo / "scripts/verify.sh").read_text(encoding="utf-8"),
        "requirements": (repo / "requirements.html").read_text(encoding="utf-8"),
        "hardening": (repo / "HARDENING_STATUS.md").read_text(encoding="utf-8"),
        "workspace": (repo / "scripts/verify-verifier-workspace.py").read_text(encoding="utf-8"),
        "readme": (repo / "scripts/README.md").read_text(encoding="utf-8"),
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
    parser.add_argument("--repo", default=".")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        sources = load_sources(pathlib.Path(args.repo))
        validate(sources)
        if args.self_test:
            run_mutations(sources)
    except (AuthorityError, OSError, UnicodeError) as exc:
        print("android keystore authority: FAIL: {}".format(exc))
        return 1
    if args.self_test:
        print(
            "android keystore authority: PASS ({} deliberate mutations rejected)".format(
                len(MUTATIONS)
            )
        )
    else:
        print("android keystore authority: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
