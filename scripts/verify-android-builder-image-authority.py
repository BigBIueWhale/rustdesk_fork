#!/usr/bin/env python3
"""Check the Android builder's unique source wiring and retired fallbacks.

Archive, provenance, and canonicalization behavior belongs to
offline-image-provenance.py --self-test. This gate deliberately checks only
the Android-specific shell/Dockerfile topology that those executable fixtures
cannot observe.
"""

from __future__ import annotations

import argparse
import hashlib
import pathlib
import re


class AuthorityError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AuthorityError(message)


def require_all(source: str, tokens: tuple[str, ...], label: str) -> None:
    for token in tokens:
        require(token in source, f"{label}: missing {token!r}")


def require_absent(source: str, tokens: tuple[str, ...], label: str) -> None:
    for token in tokens:
        require(token not in source, f"{label}: forbidden {token!r} remains")


def require_count(source: str, token: str, expected: int, label: str) -> None:
    actual = source.count(token)
    require(
        actual == expected,
        f"{label}: expected {expected} occurrences of {token!r}, found {actual}",
    )


def require_order(source: str, tokens: tuple[str, ...], label: str) -> None:
    position = -1
    for token in tokens:
        position = source.find(token, position + 1)
        require(position >= 0, f"{label}: missing ordered token {token!r}")


def shell_function(source: str, name: str) -> str:
    start_token = f"{name}() {{"
    require_count(source, start_token, 1, f"{name} definition")
    start = source.index(start_token)
    end = source.find("\n}\n", start + len(start_token))
    require(end >= 0, f"{name} has no closing brace")
    return source[start : end + 3]


def pin_value(source: str, name: str) -> str:
    match = re.search(
        rf'^{re.escape(name)}="([^"]+)"(?:\s|$)',
        source,
        re.MULTILINE,
    )
    require(match is not None, f"{name} is not one canonical quoted pin")
    return match.group(1)


EXPECTED_PINS = {
    "SHA256_ANDROID_BUILDER_DOCKERFILE": (
        "a1c2bc0e3475eefc9b16810035013d023b93a2e4db575eaa2cab9f99826bcfed"
    ),
    "SHA256_ANDROID_BUILDER_DPKG_MANIFEST": (
        "89c22fc379536a5279456a7a1e7f841af90034d7ef47a9f8a508516d4d1e1ee4"
    ),
    "ANDROID_BUILDER_BOOTSTRAP_IMAGE_ID": (
        "sha256:c4ba44dab3002ce8331b2a6faf34b2ee6cdbef0914d8c50af9c73f404a14c121"
    ),
    "ANDROID_BUILDER_BOOTSTRAP_CONFIG_ID": (
        "sha256:7e3a21f7335f4ab15eec150c07df242424ef626718a110f5b504174fd3217103"
    ),
    "ANDROID_BUILDER_BOOTSTRAP_MANIFEST_ID": (
        "sha256:8eebca9c54a246acfa16bec3ac9768cf7e1cb0e8687ab17c0438b573bd821259"
    ),
    "SHA256_ANDROID_BUILDER_BOOTSTRAP_IMAGE_ARCHIVE": (
        "8103ee08edb4fd40d5d7d86f825f374692fa3d58f549a47ce05a64beecf2e304"
    ),
    "ANDROID_BUILDER_BOOTSTRAP_IMAGE_ARCHIVE_SIZE": "467527003",
    "SHA256_ANDROID_BUILDER_BOOTSTRAP_OCI_LAYOUT": (
        "5c7d43a27ac02e28ae22d6d37d5a566e09a8a8c22937c33609a2ce1a20cfbf75"
    ),
    "SHA256_ANDROID_BUILDER_CERTIFICATION_DOCKERFILE": (
        "b665c4007b9a24cc7987e42db64e062c824ef737d03462d5df593c5e572c8bcb"
    ),
    "ANDROID_BUILDER_IMAGE_ID": (
        "sha256:fc9adbc23c769c604de4ff046dbb95a6d8bb240377a67f6a070a9db94c7f50f2"
    ),
    "ANDROID_BUILDER_CONFIG_ID": (
        "sha256:cfa64e371976faf5b2183a556f927c3e403b88637175356944db28c0c55db99e"
    ),
    "ANDROID_BUILDER_MANIFEST_ID": (
        "sha256:a20fd135aedd965cadfb2cab3cd13c91b328b17b87b8a298dbf41df987bfe79f"
    ),
    "SHA256_ANDROID_BUILDER_IMAGE_ARCHIVE": (
        "eca8b2c8535c7c050b52fb95d2a92967e936f293e07b04104eb36ae89a0e3b2b"
    ),
    "ANDROID_BUILDER_IMAGE_ARCHIVE_SIZE": "467499398",
    "SOURCE_DATE_EPOCH_PIN": "1700000000",
}


def validate_pins(source: str) -> None:
    for name, expected in EXPECTED_PINS.items():
        require(
            pin_value(source, name) == expected,
            f"{name} differs from the reviewed identity",
        )


def validate_dockerfile(source: str, pins: str) -> None:
    require(
        hashlib.sha256(source.encode("utf-8")).hexdigest()
        == pin_value(pins, "SHA256_ANDROID_BUILDER_CERTIFICATION_DOCKERFILE"),
        "certification Dockerfile bytes differ from their pin",
    )
    require_count(source, "FROM ", 1, "certification base")
    require_count(source, "USER 1000:1000", 1, "certification identity")
    require_count(source, "RUN --network=none ", 1, "certification execution")
    require_all(
        source,
        (
            "FROM android-builder-bootstrap",
            "ARG ANDROID_BUILDER_BOOTSTRAP_IMAGE_ID",
            "ARG ANDROID_BUILDER_BOOTSTRAP_MANIFEST_ID",
            "ARG ANDROID_BUILDER_RECIPE_SHA256",
            "ARG ANDROID_BUILDER_DPKG_MANIFEST_SHA256",
            "ARG SOURCE_DATE_EPOCH",
            '[ "$(/usr/bin/id -u):$(/usr/bin/id -g)" = "1000:1000" ]',
            "/usr/local/share/rustdesk-build-provenance/Dockerfile",
            "/usr/local/share/rustdesk-build-provenance/dpkg-manifest.tsv",
            "/usr/local/share/rustdesk-build-provenance/contract-v1",
            'org.rustdesk.builder-certification.role="android-builder"',
            "org.rustdesk.builder-certification.bootstrap-image-id=",
            "org.rustdesk.builder-certification.bootstrap-manifest-id=",
            "org.rustdesk.builder-certification.recipe-sha256=",
            "org.rustdesk.builder-certification.dpkg-manifest-sha256=",
            "org.rustdesk.builder-certification.source-date-epoch=",
        ),
        "certification Dockerfile",
    )
    require_absent(
        source,
        (
            "\nUSER 0",
            "--network=default",
            "--network=host",
            "\nCOPY ",
            "\nADD ",
            "apt-get ",
            "sudo ",
            "curl ",
            "git clone",
        ),
        "certification Dockerfile",
    )


def validate_online_fetch(source: str) -> None:
    without_vcs = shell_function(source, "online_docker_without_vcs")
    require_all(
        without_vcs,
        (
            "env -i",
            'DOCKER_HOST="$ONLINE_FETCH_DOCKER_HOST"',
            'DOCKER_CONFIG="$ONLINE_FETCH_DOCKER_CONFIG"',
            "BUILDX_GIT_INFO=false",
            '--host "$ONLINE_FETCH_DOCKER_HOST"',
            '--config "$ONLINE_FETCH_DOCKER_CONFIG"',
            "assert_online_fetch_docker_authority",
        ),
        "fixed Docker client without VCS hints",
    )

    certification_args = shell_function(
        source, "android_builder_certification_spec_args"
    )
    require_all(
        certification_args,
        (
            "--role android-builder",
            '--dockerfile-sha "$SHA256_ANDROID_BUILDER_CERTIFICATION_DOCKERFILE"',
            '--recipe-sha "$SHA256_ANDROID_BUILDER_DOCKERFILE"',
            '--dpkg-sha "$SHA256_ANDROID_BUILDER_DPKG_MANIFEST"',
            '--bootstrap-image-id "$ANDROID_BUILDER_BOOTSTRAP_IMAGE_ID"',
            '--bootstrap-manifest-id "$ANDROID_BUILDER_BOOTSTRAP_MANIFEST_ID"',
            '--source-date-epoch "$SOURCE_DATE_EPOCH_PIN"',
            '--config-id "$ANDROID_BUILDER_CONFIG_ID"',
            '--manifest-id "$ANDROID_BUILDER_MANIFEST_ID"',
        ),
        "certified Android builder specification",
    )
    require_absent(
        certification_args,
        ("--expected-id",),
        "candidate-derived Android builder identity",
    )

    loader = shell_function(source, "verify_or_load_android_builder_image")
    require_all(
        loader,
        (
            "require_android_builder_image_pins",
            "android_builder_image_spec_args",
            'verify-load \\\n        --archive "$ONLINE_DIR/build-images/android-builder.docker.tar.gz"',
            '--archive-sha "$SHA256_ANDROID_BUILDER_IMAGE_ARCHIVE"',
            '--archive-size "$ANDROID_BUILDER_IMAGE_ARCHIVE_SIZE"',
            "verify-local",
            '--image-ref "$ANDROID_BUILDER_IMAGE_ID"',
        ),
        "ordinary release loader",
    )
    require_absent(
        loader,
        (
            "BOOTSTRAP_IMAGE_ARCHIVE",
            "android_builder_bootstrap_spec_args",
            "android-builder-bootstrap.docker.tar.gz",
            "docker tag",
        ),
        "ordinary release loader",
    )

    bootstrap = shell_function(source, "build_android_builder_bootstrap_image")
    require_all(
        bootstrap,
        (
            "online_docker build",
            "--role android-builder-bootstrap-candidate",
        ),
        "bootstrap-only acquisition",
    )
    require_absent(
        bootstrap,
        ("--role android-builder ", "ANDROID_BUILDER_IMAGE_ID="),
        "bootstrap-only acquisition",
    )

    certification = shell_function(
        source, "maintenance_build_android_builder_certified_candidate"
    )
    require_all(
        certification,
        (
            "android-builder-bootstrap.docker.tar.gz",
            "android-builder-certified-candidate.docker.tar.gz",
            '"$FLOCK_BIN" --exclusive --nonblock "$lock_fd"',
            "Dockerfile.android-builder-certify",
            "materialize-oci-layout",
            '--archive-sha "$SHA256_ANDROID_BUILDER_BOOTSTRAP_IMAGE_ARCHIVE"',
            '--archive-size "$ANDROID_BUILDER_BOOTSTRAP_IMAGE_ARCHIVE_SIZE"',
            "SHA256_ANDROID_BUILDER_BOOTSTRAP_OCI_LAYOUT",
            "online_docker_without_vcs buildx build",
            "--network=none --pull=false --no-cache",
            "--platform=linux/amd64 --provenance=mode=max",
            "type=oci,name=${export_name},dest=${candidate_oci},tar=true",
            "oci-mediatypes=true,rewrite-timestamp=true",
            "android-builder-bootstrap=oci-layout://${layout}@"
            "${ANDROID_BUILDER_BOOTSTRAP_IMAGE_ID}",
            "maintenance-normalize-certified-oci",
            "verify-load",
        ),
        "networkless certification transaction",
    )
    require_count(
        certification,
        "verify-oci-layout",
        2,
        "pre/post material stability",
    )
    require_order(
        certification,
        (
            "materialize-oci-layout",
            "verify-oci-layout",
            "online_docker_without_vcs buildx build",
            "verify-oci-layout",
            "maintenance-normalize-certified-oci",
            "verify-load",
        ),
        "certification order",
    )
    require_absent(
        certification,
        (
            "docker-image://",
            "--network=default",
            "--network=host",
            "--pull=true",
            "--provenance=mode=min",
            "--cache-from",
            "--cache-to",
            "--allow",
            "--privileged",
            "--cap-add",
            "--secret",
            "--ssh",
            "--push",
            "--publish",
            "docker.sock",
            "--tag ",
            "maintenance-capture",
            "image inspect",
            "docker save",
            "type=docker",
        ),
        "networkless certification transaction",
    )

    promotion = shell_function(
        source, "maintenance_promote_android_builder_certified_candidate"
    )
    require_all(
        promotion,
        (
            "require_android_builder_image_pins",
            "android-builder-certified-candidate.docker.tar.gz",
            'final="$directory/android-builder.docker.tar.gz"',
            "android_builder_image_spec_args",
            "verify-archive",
            "maintenance-rename-noreplace",
            "verify-load",
        ),
        "exact-pin promotion",
    )
    require_order(
        promotion,
        ("verify-archive", "maintenance-rename-noreplace", "verify-load"),
        "exact-pin promotion order",
    )
    require_absent(
        promotion,
        ("maintenance-capture", "docker save", "docker tag", "rm -f", "mv "),
        "exact-pin promotion",
    )
    require_absent(
        source,
        (
            "build_android_builder_image() {",
            "capture_android_builder_image() {",
            "maintenance_capture_android_builder_image() {",
        ),
        "retired self-authorizing or Docker-store path",
    )


def validate_library(source: str) -> None:
    block = shell_function(source, "require_pinned_builder_image")
    require_all(
        block,
        (
            '[ "$#" -eq 3 ]',
            'local role="$1" image_ref="$2" provenance_executor="$3"',
            'declare -F "$provenance_executor"',
            "android-builder) prefix=ANDROID_BUILDER;",
            '"${prefix}_CONFIG_ID"',
            '"${prefix}_MANIFEST_ID"',
            '"${prefix}_BOOTSTRAP_IMAGE_ID"',
            '"${prefix}_BOOTSTRAP_MANIFEST_ID"',
            '"SHA256_${prefix}_CERTIFICATION_DOCKERFILE"',
            "SOURCE_DATE_EPOCH_PIN",
            '--dockerfile-sha "${!certification_dockerfile_var}"',
            '--bootstrap-image-id "${!bootstrap_image_var}"',
            '--bootstrap-manifest-id "${!bootstrap_manifest_var}"',
            '--config-id "${!config_var}"',
            '--manifest-id "${!manifest_var}"',
            '"$provenance_executor" "${args[@]}"',
        ),
        "ordinary runtime verifier",
    )
    require_absent(
        block,
        (
            "LOCAL_DOCKER_AUTHORITY",
            "local_docker",
            'python3 "$LIB_DIR/offline-image-provenance.py"',
            "require_cmd python3 docker",
            '${3:-}',
        ),
        "retired implicit provenance authority",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=pathlib.Path, default=pathlib.Path("."))
    arguments = parser.parse_args()
    repo = arguments.repo.resolve()
    pins = (repo / "scripts/pins.env").read_text(encoding="utf-8")
    validate_pins(pins)
    validate_dockerfile(
        (repo / "scripts/Dockerfile.android-builder-certify").read_text(
            encoding="utf-8"
        ),
        pins,
    )
    validate_online_fetch(
        (repo / "scripts/online-fetch.sh").read_text(encoding="utf-8")
    )
    validate_library((repo / "scripts/lib.sh").read_text(encoding="utf-8"))
    print("verify-android-builder-image-authority: ok")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AuthorityError, OSError) as error:
        print(f"verify-android-builder-image-authority: {error}")
        raise SystemExit(1)
