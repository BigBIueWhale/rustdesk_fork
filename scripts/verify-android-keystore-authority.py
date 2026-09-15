#!/usr/bin/env python3
"""Compact source gate for Android signing generation and verifier-VM authority."""

from __future__ import annotations

import argparse
import pathlib


class ContractError(RuntimeError):
    pass


def require(source: str, token: str, label: str) -> None:
    if token not in source:
        raise ContractError(f"missing {label}")


def require_count(source: str, token: str, count: int, label: str) -> None:
    observed = source.count(token)
    if observed != count:
        raise ContractError(f"{label} count is {observed}, expected {count}")


def forbid(source: str, token: str, label: str) -> None:
    if token in source:
        raise ContractError(f"forbidden {label}")


def require_order(source: str, tokens: tuple[str, ...], label: str) -> None:
    position = -1
    for token in tokens:
        next_position = source.find(token, position + 1)
        if next_position < 0 or next_position <= position:
            raise ContractError(f"{label} is incomplete or misordered")
        position = next_position


def section(source: str, start: str, end: str, label: str) -> str:
    begin = source.find(start)
    finish = source.find(end, begin + len(start)) if begin >= 0 else -1
    if begin < 0 or finish < 0:
        raise ContractError(f"missing {label}")
    return source[begin:finish]


def read(repo: pathlib.Path, relative: str) -> str:
    return (repo / relative).read_text(encoding="utf-8")


def validate(repo: pathlib.Path) -> None:
    generator = read(repo, "scripts/gen-android-keystore.sh")
    inner = read(repo, "scripts/android-keystore-generate.sh")
    verify = read(repo, "scripts/verify.sh")
    outer = read(repo, "scripts/smoke-verifier-vm-authority.sh")
    guest = read(repo, "scripts/smoke-verifier-vm-authority-guest.sh")

    require_order(
        generator,
        (
            'readonly BUILD_UID="$(/usr/bin/id -u)"',
            'readonly BUILD_GID="$(/usr/bin/id -g)"',
            '[ "$BUILD_UID" -ne 0 ]',
            '[ "$BUILD_GID" -ne 0 ]',
            "readonly VERIFIER_VM_ENTRY_PREFLIGHT=",
            '/usr/bin/bash "$VERIFIER_VM_ENTRY_PREFLIGHT"',
            'source "$SCRIPT_DIR/lib.sh"',
            "load_pins",
        ),
        "root refusal, VM admission, and repository-source order",
    )
    for token, label in (
        ("set -euo pipefail\numask 077", "private-state shell mode"),
        ("export PATH=/usr/bin:/bin", "closed command path"),
        ("refuses host or container-root execution", "UID-root refusal"),
        ("refuses a root primary group", "GID-root refusal"),
        ("verify-vm-entry-preflight.sh", "verifier-VM admission source"),
        ("'%a:%h'", "entry-preflight metadata check"),
        ('readonly IMAGE_ID="$ANDROID_BUILDER_IMAGE_ID"', "immutable image ID"),
        ("readonly KEY_ALIAS=rustdesk-fork", "fixed signing alias"),
        ("readonly VERIFIER_VM_AUTHORITY_ROOT=/run/rustdesk-verifier-vm", "fixed VM authority root"),
        ("readonly VERIFIER_VM_DOCKER_CLIENT=/usr/bin/docker", "fixed guest client"),
        ("docker.sock", "fixed guest Unix channel"),
        ("docker-config", "fixed guest configuration"),
        ('"docker=$VERIFIER_VM_DOCKER_VERSION"', "repository Docker-version pin"),
    ):
        require(generator, token, label)

    docker_wrapper = section(
        generator,
        "verifier_vm_docker() {",
        "\n}\n\nverifier_vm_image_provenance() {",
        "guest Docker wrapper",
    )
    provenance_wrapper = section(
        generator,
        "verifier_vm_image_provenance() {",
        "\n}\n\nrequire_verifier_vm_android_builder() {",
        "guest provenance wrapper",
    )
    for wrapper, label in (
        (docker_wrapper, "Docker wrapper"),
        (provenance_wrapper, "provenance wrapper"),
    ):
        require_count(
            wrapper,
            '/usr/bin/bash "$VERIFIER_VM_ENTRY_PREFLIGHT" >/dev/null',
            2,
            f"{label} pre/post admission replay",
        )
        for token, token_label in (
            ("/usr/bin/env -i", "empty environment"),
            ("PATH=/usr/bin:/bin LC_ALL=C HOME=/nonexistent", "closed process environment"),
            ('DOCKER_HOST="unix://$VERIFIER_VM_DOCKER_SOCKET"', "fixed guest endpoint"),
            ('DOCKER_CONFIG="$VERIFIER_VM_DOCKER_CONFIG"', "fixed guest configuration"),
            ('|| status=$?', "operation-status preservation"),
            ('return "$status"', "post-replay result return"),
        ):
            require(wrapper, token, f"{label} {token_label}")
    for token, label in (
        ('"$VERIFIER_VM_DOCKER_CLIENT"', "absolute guest Docker client"),
        ('--host "unix://$VERIFIER_VM_DOCKER_SOCKET"', "explicit guest endpoint"),
        ('--config "$VERIFIER_VM_DOCKER_CONFIG"', "explicit guest configuration"),
    ):
        require(docker_wrapper, token, label)
    require(
        provenance_wrapper,
        '/usr/bin/python3 -I -S "$SCRIPT_DIR/offline-image-provenance.py"',
        "isolated immutable provenance program",
    )

    builder = section(
        generator,
        "require_verifier_vm_android_builder() {",
        "\n}\n\ncase \"$#\" in",
        "Android builder provenance contract",
    )
    for token, label in (
        ("verifier_vm_image_provenance verify-local", "guest-only provenance route"),
        ("--role android-builder", "Android builder role"),
        ('--expected-id "$ANDROID_BUILDER_IMAGE_ID"', "expected image content ID"),
        ('--image-ref "$IMAGE_ID"', "content-ID image reference"),
        ('--base "ubuntu:24.04@$SHA256_BASEIMAGE_UBUNTU_2404"', "immutable base"),
        ('--dockerfile-sha "$SHA256_ANDROID_BUILDER_CERTIFICATION_DOCKERFILE"', "certification recipe"),
        ('--recipe-sha "$SHA256_ANDROID_BUILDER_DOCKERFILE"', "builder recipe"),
        ('--dpkg-sha "$SHA256_ANDROID_BUILDER_DPKG_MANIFEST"', "package manifest"),
        ('--bootstrap-image-id "$ANDROID_BUILDER_BOOTSTRAP_IMAGE_ID"', "bootstrap image"),
        ('--bootstrap-manifest-id "$ANDROID_BUILDER_BOOTSTRAP_MANIFEST_ID"', "bootstrap manifest"),
        ('--source-date-epoch "$SOURCE_DATE_EPOCH_PIN"', "build epoch"),
        ('--config-id "$ANDROID_BUILDER_CONFIG_ID"', "image configuration"),
        ('--manifest-id "$ANDROID_BUILDER_MANIFEST_ID"', "image manifest"),
    ):
        require(builder, token, label)

    self_test = section(
        generator,
        "case \"$#\" in",
        "\n    0)",
        "VM-authority self-test branch",
    )
    for token, label in (
        ('[ "$1" = --self-test-vm-authority ]', "single explicit self-test selector"),
        ("verifier_vm_docker version", "real guest Docker request"),
        ("{{.Client.Version}}|{{.Server.Version}}", "client/server version proof"),
        ("ANDROID_KEYSTORE_VM_AUTHORITY=pass", "authority receipt"),
        ("identity=untouched", "identity non-access receipt"),
        ("exit 0", "early self-test completion"),
    ):
        require(self_test, token, label)
    require_order(
        generator,
        (
            "case \"$#\" in",
            "ANDROID_KEYSTORE_VM_AUTHORITY=pass",
            "exit 0",
            'OUT_JKS="$DEFAULT_ANDROID_KEYSTORE"',
            '[ -f "$INNER_SOURCE" ]',
            'mktemp -d "$SIGNING_DIR/.rustdesk-keystore.XXXXXXXXXX"',
        ),
        "self-test before default signing paths, signing inputs, and scratch",
    )

    for token, label in (
        ('[ "$(readlink -m -- "$value")" = "$value" ]', "canonical signing paths"),
        ('[ "$SIGNING_DIR" = "$PASS_DIR" ]', "single protected signing directory"),
        ('metadata" = "$BUILD_UID:700"', "private directory ownership"),
        ('"$BUILD_UID:600:1:"', "private single-link secret ownership"),
        ('[ ! -e "$OUT_JKS" ] && [ ! -L "$OUT_JKS" ]', "keystore no-clobber admission"),
        ('mktemp -d "$SIGNING_DIR/.rustdesk-keystore.XXXXXXXXXX"', "same-filesystem private stage"),
        ('install -m 0400 -- "$INNER_SOURCE"', "read-only worker snapshot"),
        ("require_verifier_vm_android_builder", "provenance before execution"),
        ("verifier_vm_docker run --rm --pull=never --network=none --read-only", "single guest launch funnel"),
        ('--user "$BUILD_UID:$BUILD_GID"', "numeric nonroot container identity"),
        ("--cap-drop=ALL --security-opt=no-new-privileges", "container privilege confinement"),
        ("--memory=256m --memory-swap=256m", "password no-swap bound"),
        ("--memory=1g --memory-swap=1g", "key-generation no-swap bound"),
        ("--memory=512m --memory-swap=512m", "verification no-swap bound"),
        ('source=$PASS_INPUT,target=/authority/pass,readonly', "read-only password mounts"),
        ('source=$STAGED_KEYSTORE,target=/authority/keystore.jks,readonly', "read-only verification keystore"),
        ('mv -- "$STAGE_ROOT/output/pass" "$STAGE_ROOT/secret/pass"', "generated-password isolation"),
        ("password bytes changed during key generation", "password byte postcondition"),
        ("keystore bytes changed during verification", "keystore byte postcondition"),
        ('ln -- "$PASS_INPUT" "$PASS_FILE"', "atomic password publication"),
        ('ln -- "$STAGED_KEYSTORE" "$OUT_JKS"', "atomic keystore publication"),
        ('sync -f -- "$OUT_JKS" "$PASS_FILE"', "durable identity publication"),
        ("published Android signing password differs", "published password byte proof"),
        ("published Android keystore differs", "published keystore byte proof"),
    ):
        require(generator, token, label)
    require_count(generator, "verifier_vm_docker run --rm", 1, "guest Docker launch funnel")
    require_count(generator, "/authority/android-keystore-generate.sh password", 1, "password operation")
    require_count(generator, "/authority/android-keystore-generate.sh keystore", 1, "keystore operation")
    require_count(generator, "/authority/android-keystore-generate.sh verify", 1, "verification operation")
    require_order(
        generator,
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
        ),
        "secret generation, verification, and publication",
    )
    for token, label in (
        ("/var/run/docker.sock", "host Docker socket"),
        ("local_docker", "host-Docker helper"),
        ("initialize_local_docker_authority", "host-Docker authority initialization"),
        ("remove_local_docker_authority", "host-Docker authority cleanup"),
        ("docker build", "image-build fallback"),
        ("docker pull", "image-pull fallback"),
        ("--privileged", "privileged container"),
        ("--cap-add", "added capability"),
        ("--network=host", "host network namespace"),
        ("--pid=host", "host PID namespace"),
        ("--ipc=host", "host IPC namespace"),
        ("--uts=host", "host UTS namespace"),
        ("--publish", "published port"),
        ("-p ", "short published port"),
        ("source=/run/rustdesk-verifier-vm/docker.sock", "Docker socket mount"),
        ("ANDROID_KEYSTORE_PASS=", "password environment value"),
    ):
        forbid(generator, token, label)

    for token, label in (
        ("dd if=/dev/urandom", "kernel CSPRNG"),
        ("bs=33 count=1", "password entropy size"),
        ("-keystore /out/keystore.jks -alias rustdesk-fork", "fixed key destination and alias"),
        ("-keyalg RSA -keysize 4096 -sigalg SHA256withRSA -validity 10000", "fixed key properties"),
        ("-storepass:file /authority/pass -keypass:file /authority/pass", "file-only generation secrets"),
        ("-keystore /authority/keystore.jks -alias rustdesk-fork", "fixed verification alias"),
        ("Signature algorithm name:[[:space:]]*SHA256withRSA", "signature check"),
        ("4096-bit RSA key", "key-size check"),
        ("ANDROID_KEYSTORE_CERT_SHA256=", "certificate receipt"),
    ):
        require(inner, token, label)
    for token, label in (
        ('pw="$(cat', "password shell variable"),
        ('-storepass "$', "password argv expansion"),
        ('-keypass "$', "key-password argv expansion"),
        ("docker", "nested Docker authority"),
        ("curl", "network client"),
        ("wget", "network client"),
    ):
        forbid(inner, token, label)

    require(
        verify,
        "python3 scripts/verify-android-keystore-authority.py --repo .",
        "main verifier wiring",
    )
    forbid(
        verify,
        "python3 scripts/verify-android-keystore-authority.py --repo . --self-test",
        "obsolete mutation-suite invocation",
    )
    for token, label in (
        ('readonly ANDROID_KEYSTORE_SOURCE="$SCRIPT_DIR/gen-android-keystore.sh"', "outer source binding"),
        ('readonly ANDROID_KEYSTORE_CHECKER="$SCRIPT_DIR/verify-android-keystore-authority.py"', "outer checker binding"),
        ('repo/scripts/gen-android-keystore.sh=$ANDROID_KEYSTORE_SOURCE', "generator payload"),
        ('repo/scripts/verify-android-keystore-authority.py=$ANDROID_KEYSTORE_CHECKER', "checker payload"),
        ("VERIFIER_VM_ANDROID_KEYSTORE_ENTRY=pass", "outer runtime receipt"),
        ("VERIFIER_VM_ANDROID_KEYSTORE_SOURCE_GATE=pass", "outer source-gate receipt"),
    ):
        require(outer, token, label)
    for token, label in (
        ('readonly ANDROID_KEYSTORE_SCRIPT=$VERIFY_REPO/scripts/gen-android-keystore.sh', "guest entry binding"),
        ("root-android-keystore-entry", "root-refusal execution"),
        ("foreign-android-keystore-entry", "foreign-refusal execution"),
        ('/bin/bash "$ANDROID_KEYSTORE_SCRIPT" --self-test-vm-authority', "authorized real entry execution"),
        ("ANDROID_KEYSTORE_VM_AUTHORITY=pass", "guest entry receipt"),
        ("VERIFIER_VM_ANDROID_KEYSTORE_ENTRY=pass", "guest aggregate receipt"),
        ('"$VERIFY_REPO/scripts/verify-android-keystore-authority.py"', "guest compact source gate"),
        ("VERIFIER_VM_ANDROID_KEYSTORE_SOURCE_GATE=pass", "guest source-gate receipt"),
    ):
        require(guest, token, label)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=pathlib.Path, default=pathlib.Path("."))
    args = parser.parse_args()
    try:
        validate(args.repo.resolve())
    except (ContractError, OSError, UnicodeError) as exc:
        print(f"verify-android-keystore-authority: FAIL: {exc}")
        return 1
    print("verify-android-keystore-authority: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
