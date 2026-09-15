#!/usr/bin/env python3
"""Compact source complement for the Android builder's verifier-VM authority."""

from __future__ import annotations

import argparse
import pathlib


class ContractError(RuntimeError):
    pass


def read(repo: pathlib.Path, relative: str) -> str:
    path = repo / relative
    if path.is_symlink() or not path.is_file():
        raise ContractError(f"required source is not a regular file: {relative}")
    return path.read_text(encoding="utf-8")


def require(source: str, token: str, label: str) -> None:
    if token not in source:
        raise ContractError(f"missing {label}")


def forbid(source: str, token: str, label: str) -> None:
    if token in source:
        raise ContractError(f"forbidden {label}")


def require_count(source: str, token: str, count: int, label: str) -> None:
    observed = source.count(token)
    if observed != count:
        raise ContractError(f"{label} count is {observed}, expected {count}")


def require_order(source: str, tokens: tuple[str, ...], label: str) -> None:
    position = -1
    for token in tokens:
        position = source.find(token, position + 1)
        if position < 0:
            raise ContractError(f"{label} is incomplete or misordered")


def section(source: str, start: str, end: str, label: str) -> str:
    begin = source.find(start)
    finish = source.find(end, begin + len(start)) if begin >= 0 else -1
    if begin < 0 or finish < 0:
        raise ContractError(f"missing {label}")
    return source[begin:finish]


def validate(repo: pathlib.Path) -> None:
    builder = read(repo, "scripts/build-android.sh")
    pins = read(repo, "scripts/pins.env")
    verify = read(repo, "scripts/verify.sh")
    outer = read(repo, "scripts/smoke-verifier-vm-authority.sh")
    guest = read(repo, "scripts/smoke-verifier-vm-authority-guest.sh")

    require_order(
        builder,
        (
            'readonly BUILD_UID="$(/usr/bin/id -u)"',
            'readonly BUILD_GID="$(/usr/bin/id -g)"',
            '[ "$BUILD_UID" -ne 0 ]',
            '[ "$BUILD_GID" -ne 0 ]',
            "readonly VERIFIER_VM_ENTRY_PREFLIGHT=",
            '/usr/bin/bash "$VERIFIER_VM_ENTRY_PREFLIGHT"',
            'source "$SCRIPT_DIR/lib.sh"',
            "load_pins",
            "if [ \"$#\" -eq 1 ] && [ \"$1\" = --self-test-vm-authority ]; then",
            "ANDROID_BUILDER_VM_AUTHORITY=pass",
            "exit 0",
            'OUT_DIR="${OUT_DIR:-$REPO_ROOT/dist}"',
            'KEYSTORE="${ANDROID_KEYSTORE:-$DEFAULT_ANDROID_KEYSTORE}"',
        ),
        "root refusal, VM admission, authority-only exit, and sensitive defaults",
    )
    for token, label in (
        ("set -euo pipefail\numask 077", "private-state shell mode"),
        ("export PATH=/usr/bin:/bin", "closed command path"),
        ("refuses host or container-root execution", "UID-root refusal"),
        ("refuses a root primary group", "GID-root refusal"),
        ("verify-vm-entry-preflight.sh", "verifier-VM admission source"),
        ("'%a:%h'", "entry-preflight metadata check"),
        (
            "readonly VERIFIER_VM_AUTHORITY_ROOT=/run/rustdesk-verifier-vm",
            "fixed VM authority root",
        ),
        ("readonly VERIFIER_VM_DOCKER_CLIENT=/usr/bin/docker", "fixed guest client"),
        ("docker.sock", "fixed guest Unix channel"),
        ("docker-config", "fixed guest configuration"),
        ('"docker=$VERIFIER_VM_DOCKER_VERSION"', "repository Docker-version pin"),
    ):
        require(builder, token, label)

    docker_wrapper = section(
        builder,
        "verifier_vm_docker() {",
        "\n}\n\nverifier_vm_image_provenance() {",
        "guest Docker wrapper",
    )
    provenance_wrapper = section(
        builder,
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
            ("PATH=/usr/bin:/bin LC_ALL=C HOME=/nonexistent", "closed environment"),
            ('DOCKER_HOST="unix://$VERIFIER_VM_DOCKER_SOCKET"', "guest endpoint"),
            ('DOCKER_CONFIG="$VERIFIER_VM_DOCKER_CONFIG"', "guest configuration"),
            ("|| status=$?", "operation status preservation"),
            ('return "$status"', "post-replay result return"),
        ):
            require(wrapper, token, f"{label} {token_label}")
    for token, label in (
        ('"$VERIFIER_VM_DOCKER_CLIENT"', "absolute guest client"),
        ('--host "unix://$VERIFIER_VM_DOCKER_SOCKET"', "explicit guest endpoint"),
        ('--config "$VERIFIER_VM_DOCKER_CONFIG"', "explicit guest configuration"),
    ):
        require(docker_wrapper, token, label)
    require(
        provenance_wrapper,
        '/usr/bin/python3 -I -S "$SCRIPT_DIR/offline-image-provenance.py"',
        "isolated provenance program",
    )

    provenance = section(
        builder,
        "require_verifier_vm_android_builder() {",
        "\n}\n\nif [ \"$#\" -eq 1 ]",
        "Android builder provenance",
    )
    for token, label in (
        ("verifier_vm_image_provenance verify-local", "guest-only provenance route"),
        ("--role android-builder", "closed builder role"),
        ('--expected-id "$ANDROID_BUILDER_IMAGE_ID"', "expected image ID"),
        ('--image-ref "$IMAGE_ID"', "content-ID image reference"),
        ('--base "ubuntu:24.04@$SHA256_BASEIMAGE_UBUNTU_2404"', "immutable base"),
        (
            '--dockerfile-sha "$SHA256_ANDROID_BUILDER_CERTIFICATION_DOCKERFILE"',
            "certification recipe",
        ),
        ('--recipe-sha "$SHA256_ANDROID_BUILDER_DOCKERFILE"', "builder recipe"),
        ('--dpkg-sha "$SHA256_ANDROID_BUILDER_DPKG_MANIFEST"', "package manifest"),
        ('--bootstrap-image-id "$ANDROID_BUILDER_BOOTSTRAP_IMAGE_ID"', "bootstrap image"),
        (
            '--bootstrap-manifest-id "$ANDROID_BUILDER_BOOTSTRAP_MANIFEST_ID"',
            "bootstrap manifest",
        ),
        ('--source-date-epoch "$SOURCE_DATE_EPOCH_PIN"', "build epoch"),
        ('--config-id "$ANDROID_BUILDER_CONFIG_ID"', "image configuration"),
        ('--manifest-id "$ANDROID_BUILDER_MANIFEST_ID"', "image manifest"),
    ):
        require(provenance, token, label)

    self_test = section(
        builder,
        "if [ \"$#\" -eq 1 ] && [ \"$1\" = --self-test-vm-authority ]; then",
        "\nfi\n\nOUT_DIR=",
        "VM-authority self-test",
    )
    for token, label in (
        ("verifier_vm_docker version", "real guest Docker request"),
        ("{{.Client.Version}}|{{.Server.Version}}", "client/server version proof"),
        ("ANDROID_BUILDER_VM_AUTHORITY=pass", "authority receipt"),
        ("source=untouched", "source non-access receipt"),
        ("signing=untouched", "signing non-access receipt"),
        ("output=untouched", "output non-access receipt"),
        ("exit 0", "authority-only completion"),
    ):
        require(self_test, token, label)
    for token, label in (
        ("OUT_DIR", "output default access"),
        ("KEYSTORE", "signing default access"),
        ("mktemp", "scratch creation"),
        ("git ", "source access"),
        ("verify-local", "image inspection"),
        (" run ", "container launch"),
    ):
        forbid(self_test, token, label)

    execution = section(
        builder,
        "prepare_execution_contract() {",
        "\n}\n\nprepare_source_snapshot() {",
        "execution contract",
    )
    for token, label in (
        ("rev-parse --verify 'HEAD^{commit}'", "exact commit resolution"),
        ("mktemp -d /tmp/rustdesk-android-build.XXXXXXXXXX", "private workspace"),
        ("$BUILD_UID:$BUILD_GID:700", "workspace ownership"),
        ("RELEASE_SRC_COMMIT", "release snapshot binding"),
        ("RUSTDESK_RELEASE_ONLINE_SNAPSHOT", "release online-snapshot binding"),
        ("RELEASE_DOCKER_IMAGE_ID", "release image binding"),
    ):
        require(execution, token, label)

    source_snapshot = section(
        builder,
        "prepare_source_snapshot() {",
        "\n}\n\nprepare_build_source() {",
        "source snapshot",
    )
    for token, label in (
        ('archive --format=tar "$SOURCE_COMMIT"', "exact-commit archive"),
        ('mode not in (b"100644", b"100755")', "regular-file source policy"),
        ("source-authority", "immutable authority root"),
        ('chmod -R a=rX "$SOURCE_AUTHORITY_ROOT"', "immutable authority modes"),
    ):
        require(source_snapshot, token, label)
    require(builder, "verify-android-build-source.py", "source comparator")

    launch_funnel = section(
        builder,
        "android_docker_run() {",
        "\n}\n\nprepare_pass_output() {",
        "Android launch funnel",
    )
    for token, label in (
        ("verifier_vm_docker run", "guest-only launch"),
        ("--rm --pull=never --network=none --read-only", "immutable offline root"),
        ('--user "$BUILD_UID:$BUILD_GID"', "numeric nonroot identity"),
        ("--cap-drop=ALL --security-opt=no-new-privileges", "privilege confinement"),
    ):
        require(launch_funnel, token, label)
    require_count(builder, "android_docker_run \\\n", 4, "four operation launches")

    require(
        pins,
        'ANDROID_SIGNING_CERT_SHA256="1091322BA0425AFA1EB50DEEAE439A5FFFE2B1DD82C82B04515D9290A0CEEFA9"',
        "stable Android signing-certificate pin",
    )
    signing_files = section(
        builder,
        "assert_private_signing_files() {",
        "\n}\n\npreflight() {",
        "private signing-file admission",
    )
    for token, label in (
        ("must share one protected directory", "shared signing parent"),
        ("stat.S_ISREG(metadata.st_mode)", "regular signing inputs"),
        ("metadata.st_uid != uid", "current-principal signing inputs"),
        ("stat.S_IMODE(metadata.st_mode) != 0o600", "mode-0600 signing inputs"),
        ("stat.S_IMODE(metadata.st_mode) != 0o700", "mode-0700 signing parents"),
    ):
        require(signing_files, token, label)
    key_admission = section(
        builder,
        "assert_keystore_properties() {",
        "\n}\n\nverify_apk_artifact() {",
        "keystore identity admission",
    )
    for token, label in (
        ("SHA256withRSA", "signing algorithm"),
        ("4096-bit RSA key", "signing key size"),
        ('[ "$fingerprint" = "$ANDROID_SIGNING_CERT_SHA256" ]', "certificate identity"),
    ):
        require(key_admission, token, label)
    require(builder, "--verify-apk", "standalone signed-APK verification entry")

    resolve = section(
        builder,
        "resolve_image() {",
        "\n}\n\nactivate_online_snapshot() {",
        "image resolution",
    )
    require(resolve, "require_verifier_vm_android_builder", "guest provenance call")
    require(resolve, '"$RELEASE_DOCKER_IMAGE_ID" != "$IMAGE_ID"', "release image equality")
    require_count(
        builder,
        '/usr/bin/bash "$VERIFIER_VM_ENTRY_PREFLIGHT" >/dev/null',
        7,
        "entry admission and operation pre/post replay",
    )

    operation_specs = (
        (
            "assert_keystore_properties() {",
            "\n}\n\nverify_apk_artifact() {",
            "key inspection",
            ("source=$KEYSTORE,target=/ks/keystore.jks,readonly", "source=$KEYSTORE_PASS_FILE,target=/ks/pass,readonly"),
        ),
        (
            "verify_apk_artifact() {",
            "\n}\n\nbuild_apk() {",
            "artifact verification",
            ("source=$resolved,target=/verify/app.apk,readonly", "source=$ONLINE_DIR,target=/online,readonly"),
        ),
        (
            "build_apk() {",
            "\n}\n\nsign_apk() {",
            "compilation",
            ("source=$BUILD_SOURCE_ROOT,target=/src", "source=$ONLINE_DIR,target=/online,readonly"),
        ),
        (
            "sign_apk() {",
            "\n}\n\nassert_exact_private_result_inventory() {",
            "signing",
            ("source=$unsigned_apk,target=/in/rustdesk-arm64-unsigned.apk,readonly", "source=$KEYSTORE,target=/ks/keystore.jks,readonly", "source=$KEYSTORE_PASS_FILE,target=/ks/pass,readonly"),
        ),
    )
    for start, end, label, mounts in operation_specs:
        operation = section(builder, start, end, label)
        require(operation, "android_docker_run \\\n", f"{label} launch funnel")
        require(operation, "--pids-limit=", f"{label} PID bound")
        require(operation, "--memory=", f"{label} memory bound")
        require(operation, "--memory-swap=", f"{label} swap bound")
        require(operation, "--cpus=", f"{label} CPU bound")
        require(operation, "--tmpfs /tmp:", f"{label} bounded scratch")
        require(operation, '"$IMAGE_ID"', f"{label} immutable image")
        for mount in mounts:
            require(operation, mount, f"{label} least-authority mount")

    for token, label in (
        ('prepare_build_source "$pass"', "fresh per-pass source"),
        ('verify_build_source_unchanged "$BUILD_SOURCE_ROOT" "$pass"', "post-build source proof"),
        ('PASS_A_APK="$apk"', "private pass-A result"),
        ('[ "$PASS_A_SHA256" = "$PASS_B_SHA256" ]', "signed A/B equality"),
        ("assert_exact_private_result_inventory", "closed result inventory"),
        ("verify_apk_artifact", "signed artifact validation"),
        ("verify_all_build_sources_unchanged", "terminal source replay"),
        ("prepare_pending_result", "private publication preparation"),
        ("remove_owned_workspace_exact", "pre-publication workspace retirement"),
        ("publish-artifact-result.py", "descriptor-bound publisher"),
        ("--artifact-kind android-arm64", "closed publication profile"),
    ):
        require(builder, token, label)

    for token, label in (
        ("/var/run/docker.sock", "host Docker socket"),
        ("local_docker", "host-Docker helper"),
        ("initialize_local_docker_authority", "host-Docker initialization"),
        ("remove_local_docker_authority", "host-Docker cleanup"),
        ("require_pinned_builder_image", "ambient provenance helper"),
        ("/usr/bin/docker run", "direct Docker launch"),
        ("docker build", "image-build fallback"),
        ("docker pull", "image-pull fallback"),
        ("--privileged", "privileged container"),
        ("--cap-add", "added capability"),
        ("--network=host", "host network namespace"),
        ("--pid=host", "host PID namespace"),
        ("--ipc=host", "host IPC namespace"),
        ("--uts=host", "host UTS namespace"),
        ("--publish", "published port"),
        ("source=/run/rustdesk-verifier-vm/docker.sock", "guest Docker socket mount"),
        ("source=$REPO_ROOT,target=/src", "live repository mount"),
        ("source=$OUT_DIR,target=/out", "public output mount"),
    ):
        forbid(builder, token, label)

    require(
        verify,
        "python3 scripts/verify-android-builder-authority.py --repo .",
        "main verifier wiring",
    )
    forbid(
        verify,
        "python3 scripts/verify-android-builder-authority.py --repo . --self-test",
        "obsolete mutation-suite invocation",
    )
    for token, label in (
        ('readonly ANDROID_BUILDER_SOURCE="$SCRIPT_DIR/build-android.sh"', "outer source binding"),
        ('readonly ANDROID_BUILDER_CHECKER="$SCRIPT_DIR/verify-android-builder-authority.py"', "outer checker binding"),
        ('repo/scripts/build-android.sh=$ANDROID_BUILDER_SOURCE', "builder payload"),
        ('repo/scripts/verify-android-builder-authority.py=$ANDROID_BUILDER_CHECKER', "checker payload"),
        ("VERIFIER_VM_ANDROID_BUILDER_ENTRY=pass", "outer runtime receipt"),
        ("VERIFIER_VM_ANDROID_BUILDER_SOURCE_GATE=pass", "outer source-gate receipt"),
    ):
        require(outer, token, label)
    for token, label in (
        ('readonly ANDROID_BUILDER_SCRIPT=$VERIFY_REPO/scripts/build-android.sh', "guest entry binding"),
        ("root-android-builder-entry", "root-refusal execution"),
        ("foreign-android-builder-entry", "foreign-refusal execution"),
        ('/bin/bash "$ANDROID_BUILDER_SCRIPT" --self-test-vm-authority', "authorized real entry"),
        ("ANDROID_BUILDER_VM_AUTHORITY=pass", "guest entry receipt"),
        ("VERIFIER_VM_ANDROID_BUILDER_ENTRY=pass", "guest aggregate receipt"),
        ('"$VERIFY_REPO/scripts/verify-android-builder-authority.py"', "guest compact source gate"),
        ("VERIFIER_VM_ANDROID_BUILDER_SOURCE_GATE=pass", "guest source-gate receipt"),
    ):
        require(guest, token, label)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=pathlib.Path, default=pathlib.Path("."))
    args = parser.parse_args()
    try:
        validate(args.repo.resolve())
    except (ContractError, OSError, UnicodeError) as exc:
        print(f"verify-android-builder-authority: FAIL: {exc}")
        return 1
    print("verify-android-builder-authority: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
