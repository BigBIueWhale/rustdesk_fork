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


def validate(sources: Dict[str, str]) -> None:
    generate = sources["generate"]
    inner = sources["inner"]

    for token, label in (
        ("set -euo pipefail\numask 077", "private host-created state umask"),
        ("load_pins", "pinned manifest load"),
        ("export PATH=/usr/bin:/bin", "closed host command path"),
        ("readonly DOCKER_BIN=/usr/bin/docker", "fixed Docker client"),
        ('readonly IMAGE_ID="$ANDROID_BUILDER_IMAGE_ID"', "immutable Android image identity"),
        ("readonly KEY_ALIAS=rustdesk-fork", "fixed Android signing alias"),
        ("refuses host or container-root execution", "root execution refusal"),
        ("refuses a root primary group", "root primary-group refusal"),
        ("DOCKER_CONTEXT DOCKER_CERT_PATH DOCKER_TLS_VERIFY DOCKER_TLS DOCKER_CONFIG",
         "ambient Docker-authority refusal"),
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
        ('printf \'{}\\n\' > "$STAGE_ROOT/docker-config/config.json"',
         "empty private Docker configuration"),
        ("assert_private_docker_config()", "private Docker-config postcondition"),
        ("must remain the empty canonical configuration", "empty Docker-config byte proof"),
        ('install -m 0400 -- "$INNER_SOURCE"', "private inner-program snapshot"),
        ('require_pinned_builder_image android-builder "$IMAGE_ID"',
         "immutable builder provenance verification"),
        ("android_keystore_docker_run() {", "single container-confinement wrapper"),
        ('"$DOCKER_BIN" run --rm --pull=never --network=none --read-only',
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
        ("docker run", "PATH-selected Docker invocation"),
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
    Mutation("generate", "readonly DOCKER_BIN=/usr/bin/docker", "DOCKER_BIN=docker",
             "fixed Docker client"),
    Mutation("generate", 'readonly IMAGE_ID="$ANDROID_BUILDER_IMAGE_ID"',
             'readonly IMAGE_ID="${HARNESS_PREFIX}-android-builder"', "immutable image identity"),
    Mutation("generate", "refuses host or container-root execution",
             "permits host root execution", "root execution refusal"),
    Mutation("generate", "DOCKER_CONTEXT DOCKER_CERT_PATH DOCKER_TLS_VERIFY DOCKER_TLS DOCKER_CONFIG",
             "DOCKER_CERT_PATH DOCKER_TLS_VERIFY DOCKER_TLS", "ambient Docker-authority refusal"),
    Mutation("generate", '[ "$(readlink -m -- "$value")" = "$value" ]', "true",
             "canonical signing paths"),
    Mutation("generate", 'metadata" = "$BUILD_UID:700"', 'metadata" = "$BUILD_UID:755"',
             "private signing directory"),
    Mutation("generate", '"$BUILD_UID:600:1:"', '"$BUILD_UID:644:1:"',
             "private secret file"),
    Mutation("generate", 'mktemp -d "$SIGNING_DIR/.rustdesk-keystore.XXXXXXXXXX"',
             "mktemp -d /tmp/rustdesk-keystore.XXXXXXXXXX", "same-filesystem staging"),
    Mutation("generate", 'require_pinned_builder_image android-builder "$IMAGE_ID"', "true",
             "builder provenance verification"),
    Mutation("generate", '"$DOCKER_BIN" run --rm --pull=never --network=none --read-only',
             '"$DOCKER_BIN" run --rm', "container launch confinement"),
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
)


def load_sources(repo: pathlib.Path) -> Dict[str, str]:
    return {
        "generate": (repo / "scripts/gen-android-keystore.sh").read_text(encoding="utf-8"),
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
