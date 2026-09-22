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
        "d0935b5fd0849ad630f472c4d163c6eb9fd56d20955a0eeae3ff84c0c74977c1"
    ),
    "SHA256_ANDROID_BUILDER_DPKG_MANIFEST": (
        "747ebf6e4315ae9c71d7d130f68c2980dbf407a7d29403146e43e5161e6512a2"
    ),
    "ANDROID_BUILDER_BOOTSTRAP_IMAGE_ID": (
        "sha256:309400e7e653f180aad33d92ba715e1d67c1320a684896c9d9a6a02936f38c6b"
    ),
    "ANDROID_BUILDER_BOOTSTRAP_CONFIG_ID": (
        "sha256:309400e7e653f180aad33d92ba715e1d67c1320a684896c9d9a6a02936f38c6b"
    ),
    "ANDROID_BUILDER_BOOTSTRAP_MANIFEST_ID": (
        "sha256:0f71087843b2b06b30291ebdb370f29314872817d0bc67d31ae676b28495bfa2"
    ),
    "SHA256_ANDROID_BUILDER_BOOTSTRAP_IMAGE_ARCHIVE": (
        "d67c950403691bb6db099e1fb19e8113a31a24366d8279b5b83a741c90fabdbc"
    ),
    "ANDROID_BUILDER_BOOTSTRAP_IMAGE_ARCHIVE_SIZE": "468001119",
    "SHA256_ANDROID_BUILDER_BOOTSTRAP_OCI_LAYOUT": (
        "9bf7f6754f58c84e792851118fe0f6da57829d043592e59b0301cddcb93ef981"
    ),
    "SHA256_ANDROID_BUILDER_CERTIFICATION_DOCKERFILE": (
        "b665c4007b9a24cc7987e42db64e062c824ef737d03462d5df593c5e572c8bcb"
    ),
    "ANDROID_BUILDER_IMAGE_ID": (
        "sha256:420530ff412c240c70ed510d019c27cfb9cce99c9dc9e669beb9fda818999b43"
    ),
    "ANDROID_BUILDER_CONFIG_ID": (
        "sha256:66059635c06f8e003312d8e897d3ed664fca790ce6cafc5a6b531992b5063119"
    ),
    "ANDROID_BUILDER_MANIFEST_ID": (
        "sha256:38b072fca23d9bebb5f817cf9cc4519544b0435bb3144cd92cfa547f1f0289ac"
    ),
    "SHA256_ANDROID_BUILDER_IMAGE_ARCHIVE": (
        "918c3b696270bbb9a5ff70ea8cabd19f5a5d353503af3268ab2951a0ec66cd06"
    ),
    "ANDROID_BUILDER_IMAGE_ARCHIVE_SIZE": "474623832",
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


def validate_bootstrap_dockerfiles(acquisition: str, seal: str) -> None:
    require_count(acquisition, "\nFROM ", 1, "bootstrap discovery base")
    require_count(acquisition, "\nRUN ", 1, "bootstrap discovery install")
    require_all(
        acquisition,
        (
            "FROM ubuntu:24.04@${BASE_DIGEST}",
            "ARG DOCKERFILE_SHA256",
            "COPY Dockerfile.android-builder ",
            "apt-get update && apt-get install",
            "dpkg-query -W -f='${binary:Package}\\t${Version}\\n'",
            'DPKG_MANIFEST_SHA256="$(sha256sum ',
            "dpkg_manifest_sha256=%s",
            "&& chmod 0444 \\\n"
            "         /usr/local/share/rustdesk-build-provenance/Dockerfile \\\n"
            "         /usr/local/share/rustdesk-build-provenance/dpkg-manifest.tsv \\\n"
            "         /usr/local/share/rustdesk-build-provenance/contract-v1",
            'org.rustdesk.build-input.role="android-builder"',
            'org.rustdesk.build-input.dockerfile-sha256="${DOCKERFILE_SHA256}"',
        ),
        "bootstrap discovery Dockerfile",
    )
    require_absent(
        acquisition,
        (
            "ARG DPKG_MANIFEST_SHA256",
            '"$DPKG_MANIFEST_SHA256" /usr/local/share/rustdesk-build-provenance/dpkg-manifest.tsv | sha256sum -c',
            "org.rustdesk.build-input.dpkg-manifest-sha256=",
        ),
        "bootstrap discovery Dockerfile",
    )
    instructions = tuple(
        line
        for line in seal.splitlines()
        if line and not line.startswith("#")
    )
    require(
        instructions
        == (
            "FROM rustdesk-fork-harness-bootstrap-discovery:local",
            "ARG DPKG_MANIFEST_SHA256",
            'LABEL org.rustdesk.build-input.dpkg-manifest-sha256="${DPKG_MANIFEST_SHA256}"',
        ),
        "bootstrap seal Dockerfile must be one exact metadata-only label build",
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

    candidate_certification_args = shell_function(
        source, "android_builder_certification_candidate_spec_args"
    )
    require_all(
        candidate_certification_args,
        (
            "--role android-builder",
            '--base "ubuntu:24.04@${SHA256_BASEIMAGE_UBUNTU_2404}"',
            '--dockerfile-sha "$SHA256_ANDROID_BUILDER_CERTIFICATION_DOCKERFILE"',
            '--recipe-sha "$SHA256_ANDROID_BUILDER_DOCKERFILE"',
            '--dpkg-sha "$SHA256_ANDROID_BUILDER_DPKG_MANIFEST"',
            '--bootstrap-image-id "$ANDROID_BUILDER_BOOTSTRAP_IMAGE_ID"',
            '--bootstrap-manifest-id "$ANDROID_BUILDER_BOOTSTRAP_MANIFEST_ID"',
            '--source-date-epoch "$SOURCE_DATE_EPOCH_PIN"',
        ),
        "certified Android builder candidate input specification",
    )
    require_absent(
        candidate_certification_args,
        ("--expected-id", "--config-id", "--manifest-id"),
        "candidate-derived Android builder identities",
    )

    certification_args = shell_function(
        source, "android_builder_certification_spec_args"
    )
    require_all(
        certification_args,
        (
            "android_builder_certification_candidate_spec_args",
            '--config-id "$ANDROID_BUILDER_CONFIG_ID"',
            '--manifest-id "$ANDROID_BUILDER_MANIFEST_ID"',
        ),
        "reviewed Android builder specification",
    )
    require_absent(
        certification_args,
        ("--expected-id",),
        "separately pinned Android builder image identity",
    )

    loader = shell_function(source, "verify_or_load_android_builder_image")
    require_all(
        loader,
        (
            "require_android_builder_image_pins",
            "android_builder_image_spec_args",
            "verify-load",
            '--archive "$ONLINE_DIR/build-images/android-builder.docker.tar.gz"',
            '--archive-sha "$SHA256_ANDROID_BUILDER_IMAGE_ARCHIVE"',
            '--archive-size "$ANDROID_BUILDER_IMAGE_ARCHIVE_SIZE"',
            "verify-local",
            '--image-ref "$ANDROID_BUILDER_IMAGE_ID"',
        ),
        "containerd-store release loader",
    )
    require_count(
        loader,
        "--publication-index-runtime",
        2,
        "containerd-store release identity",
    )
    require_absent(
        loader,
        (
            "BOOTSTRAP_IMAGE_ARCHIVE",
            "android_builder_bootstrap_spec_args",
            "android-builder-bootstrap.docker.tar.gz",
            "docker tag",
            '--image-ref "$ANDROID_BUILDER_CONFIG_ID"',
        ),
        "containerd-store release loader",
    )

    bootstrap_helper = shell_function(source, "build_builder_bootstrap_image")
    require_all(
        bootstrap_helper,
        (
            'recipe_sha="$(/usr/bin/sha256sum "$dockerfile"',
            "--network=default --pull=false --no-cache --platform=linux/amd64",
            '--build-arg "DOCKERFILE_SHA256=${recipe_sha}"',
            'maintenance-inspect-bootstrap-discovery',
            '--role "${role}-bootstrap-candidate"',
            'dpkg_sha="$(/usr/bin/sed -n',
            'local discovery_tag="rustdesk-fork-harness-bootstrap-discovery:local"',
            'online_docker image inspect --format \'{{.Id}}\' "$discovery_tag"',
            '[ "$observed_discovery_id" = "$discovery_id" ]',
            "--network=none --pull=false --no-cache --platform=linux/amd64",
            '--build-arg "DPKG_MANIFEST_SHA256=${dpkg_sha}"',
            '-t "$candidate_tag" - <"$seal_dockerfile"',
            "maintenance-verify-bootstrap-seal",
            'BUILT_BOOTSTRAP_IMAGE_ID="$candidate_id"',
            'BUILT_BOOTSTRAP_DPKG_SHA256="$dpkg_sha"',
            'BUILT_BOOTSTRAP_RECIPE_SHA256="$recipe_sha"',
        ),
        "shared bootstrap discovery and metadata seal",
    )
    require_order(
        bootstrap_helper,
        (
            "--network=default",
            "maintenance-inspect-bootstrap-discovery",
            "--network=none",
            "maintenance-verify-bootstrap-seal",
        ),
        "bootstrap discovery/seal order",
    )
    require_absent(
        bootstrap_helper,
        (
            "SHA256_ANDROID_BUILDER_DOCKERFILE",
            "SHA256_ANDROID_BUILDER_DPKG_MANIFEST",
            "SHA256_DEB_BUILDER_DOCKERFILE",
            "SHA256_DEB_BUILDER_DPKG_MANIFEST",
            "SHA256_WIN_HELPER_DOCKERFILE",
            "SHA256_WIN_HELPER_DPKG_MANIFEST",
            "--privileged",
            "--network=host",
            "--pull=true",
            '--build-arg "BOOTSTRAP_IMAGE=${discovery_id}"',
            '--build-arg "BOOTSTRAP_IMAGE_HANDLE=${discovery_tag}"',
            "\nRUN ",
            "\nCOPY ",
            "\nADD ",
        ),
        "bootstrap discovery and metadata seal",
    )
    bootstrap = shell_function(source, "build_android_builder_bootstrap_image")
    require_all(
        bootstrap,
        (
            "build_builder_bootstrap_image",
            '"Android builder" android-builder',
            '"ubuntu:24.04@${SHA256_BASEIMAGE_UBUNTU_2404}"',
            "Dockerfile.android-builder",
        ),
        "Android bootstrap-only acquisition",
    )

    bootstrap_acquisition = shell_function(
        source,
        "maintenance_build_android_builder_bootstrap_candidate",
    )
    require_all(
        bootstrap_acquisition,
        (
            '"$FLOCK_BIN" --exclusive --nonblock "$lock_fd"',
            "android-builder-bootstrap-candidate.docker.tar.gz",
            'online_docker pull "ubuntu:24.04@',
            "build_android_builder_bootstrap_image",
            "capture_builder_bootstrap_candidate",
            '"$BUILT_BOOTSTRAP_RECIPE_SHA256"',
            '"$BUILT_BOOTSTRAP_DPKG_SHA256"',
        ),
        "persistent bootstrap-candidate acquisition",
    )
    require_order(
        bootstrap_acquisition,
        (
            "online_docker pull",
            "build_android_builder_bootstrap_image",
            "capture_builder_bootstrap_candidate",
        ),
        "bootstrap build/capture order",
    )
    require_absent(
        bootstrap_acquisition,
        (
            "android-builder-bootstrap.docker.tar.gz",
            "maintenance-rename-noreplace",
        ),
        "non-authoritative bootstrap acquisition",
    )

    bootstrap_capture = shell_function(
        source,
        "capture_builder_bootstrap_candidate",
    )
    require_all(
        bootstrap_capture,
        (
            "maintenance-capture-bootstrap-candidate",
            "--layout-output",
            "image_id",
            "manifest_id",
            "config_id",
            "layout_sha256",
            '[ "$captured_image" = "$config_id" ]',
            '[ "$captured_image" != "$target_id" ]',
            "BOOTSTRAP_IMAGE_ARCHIVE_SIZE",
            "BOOTSTRAP_OCI_LAYOUT",
            "acquisition_target_id",
            "SHA256_%s_DOCKERFILE",
            "SHA256_%s_DPKG_MANIFEST",
        ),
        "private bootstrap-candidate capture",
    )
    require_absent(
        bootstrap_capture,
        ("maintenance-rename-noreplace",),
        "bootstrap candidate capture",
    )

    bootstrap_promotion = shell_function(
        source,
        "maintenance_promote_android_builder_bootstrap_candidate",
    )
    require_all(
        bootstrap_promotion,
        (
            "require_android_builder_bootstrap_pins",
            "android_builder_bootstrap_spec_args",
            "android-builder-bootstrap-candidate.docker.tar.gz",
            "android-builder-bootstrap.docker.tar.gz",
            "SHA256_ANDROID_BUILDER_BOOTSTRAP_IMAGE_ARCHIVE",
            "ANDROID_BUILDER_BOOTSTRAP_IMAGE_ARCHIVE_SIZE",
            "SHA256_ANDROID_BUILDER_BOOTSTRAP_OCI_LAYOUT",
            "promote_builder_bootstrap_candidate",
        ),
        "pin-reviewed bootstrap promotion",
    )
    promotion_helper = shell_function(
        source,
        "promote_builder_bootstrap_candidate",
    )
    require_order(
        promotion_helper,
        (
            "verify-archive",
            "materialize-oci-layout",
            'observed_layout_sha" = "$expected_layout_sha',
            "maintenance-rename-noreplace",
            "verify-archive",
        ),
        "bootstrap verify/promote order",
    )
    require_absent(
        promotion_helper,
        ("maintenance-capture", "docker save", "docker tag", "verify-load"),
        "bootstrap promotion",
    )

    certification = shell_function(
        source, "maintenance_build_android_builder_certified_candidate"
    )
    require_all(
        certification,
        (
            "require_android_builder_certification_input_pins",
            "android-builder-bootstrap.docker.tar.gz",
            "android-builder-certified-candidate.docker.tar.gz",
            '"$FLOCK_BIN" --exclusive --nonblock "$lock_fd"',
            "Dockerfile.android-builder-certify",
            "materialize-oci-layout",
            '--archive-sha "$SHA256_ANDROID_BUILDER_BOOTSTRAP_IMAGE_ARCHIVE"',
            '--archive-size "$ANDROID_BUILDER_BOOTSTRAP_IMAGE_ARCHIVE_SIZE"',
            "SHA256_ANDROID_BUILDER_BOOTSTRAP_OCI_LAYOUT",
            "online_buildx_build",
            "--network=none --pull=false --no-cache",
            "--platform=linux/amd64 --provenance=mode=max",
            "type=oci,name=${export_name},dest=${candidate_oci},tar=true",
            "oci-mediatypes=true,rewrite-timestamp=true",
            "android-builder-bootstrap=oci-layout://${layout}@"
            "${ANDROID_BUILDER_BOOTSTRAP_MANIFEST_ID}",
            "android_builder_certification_candidate_spec_args",
            "maintenance-normalize-certified-oci",
            '--bootstrap-layout "$layout"',
            'manifest_id="$(/usr/bin/sed -n',
            'config_id="$(/usr/bin/sed -n',
            '--expected-id "$image_id"',
            '--config-id "$config_id"',
            '--manifest-id "$manifest_id"',
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
            "online_buildx_build",
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
            "require_android_builder_image_pins",
            "$ANDROID_BUILDER_IMAGE_ID",
            "$ANDROID_BUILDER_CONFIG_ID",
            "$ANDROID_BUILDER_MANIFEST_ID",
            "$SHA256_ANDROID_BUILDER_IMAGE_ARCHIVE",
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
            "maintenance_capture_android_builder_bootstrap_image() {",
            "--maintenance-build-image-candidates)",
            "--maintenance-capture-android-builder-bootstrap-image)",
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
    validate_bootstrap_dockerfiles(
        (repo / "scripts/Dockerfile.android-builder").read_text(
            encoding="utf-8"
        ),
        (repo / "scripts/Dockerfile.builder-bootstrap-seal").read_text(
            encoding="utf-8"
        ),
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
