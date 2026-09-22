#!/usr/bin/env python3
"""Check the Windows helper's unique source wiring and retired fallbacks.

Archive, provenance, and canonicalization behavior belongs to
offline-image-provenance.py --self-test. This gate deliberately checks only
the Windows-specific shell/Dockerfile/consumer topology that those executable
fixtures cannot observe.
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
    "SHA256_WIN_HELPER_DOCKERFILE": (
        "734784bbf0f0a135b055816ce56edd33aaf12e79c35b4c70b2a1be96a7a90932"
    ),
    "SHA256_WIN_HELPER_DPKG_MANIFEST": (
        "d7978a6763b6e2b0b5dc920a754ab077bc9d6b07b2c6a149f34d62c1cf30c384"
    ),
    "WIN_HELPER_BOOTSTRAP_IMAGE_ID": (
        "sha256:d87ce47b24a9c71a9053d163043c0e64d70a80c342b2c6a7e4c9824f1ce40c13"
    ),
    "WIN_HELPER_BOOTSTRAP_CONFIG_ID": (
        "sha256:d87ce47b24a9c71a9053d163043c0e64d70a80c342b2c6a7e4c9824f1ce40c13"
    ),
    "WIN_HELPER_BOOTSTRAP_MANIFEST_ID": (
        "sha256:40c34d0ec4ce22ead7c57f194fe98b0c4e8b6b397d5c5252ba6a63319a643320"
    ),
    "SHA256_WIN_HELPER_BOOTSTRAP_IMAGE_ARCHIVE": (
        "541abfbed8600324a89d7e77acb7b1782682dab52ca97f039abd4622347a2e69"
    ),
    "WIN_HELPER_BOOTSTRAP_IMAGE_ARCHIVE_SIZE": "995301648",
    "SHA256_WIN_HELPER_BOOTSTRAP_OCI_LAYOUT": (
        "2383c9c3405e937568b62a5eee85237d0874d28c45bf41e671b5dd69bb257644"
    ),
    "SHA256_WIN_HELPER_CERTIFICATION_DOCKERFILE": (
        "f6e9b53451990284a9e81a32c7ae64b17b079182d7aa3f17a6d5d348351b896d"
    ),
    "WIN_HELPER_IMAGE_ID": (
        "sha256:5fe6b794695afc69c32d037f1e6e24224f2925c2e48e98d82c35a23b584ee256"
    ),
    "WIN_HELPER_CONFIG_ID": (
        "sha256:a5a8ff785ebe749eabc4bb4aaf8e438bbf12a6551663148d6ac60f94c02a9ea3"
    ),
    "WIN_HELPER_MANIFEST_ID": (
        "sha256:72e72381f5402ae5ab495b99b9a4ff4ce9c7d08aea2a679ab8760cc2de6bc030"
    ),
    "SHA256_WIN_HELPER_IMAGE_ARCHIVE": (
        "e7dae7a080fda65778ef7ed3c05bcb31b98830f56f514b2f01c084f055b66995"
    ),
    "WIN_HELPER_IMAGE_ARCHIVE_SIZE": "998725383",
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
        == pin_value(pins, "SHA256_WIN_HELPER_CERTIFICATION_DOCKERFILE"),
        "certification Dockerfile bytes differ from their pin",
    )
    require_count(source, "FROM ", 1, "certification base")
    require_count(source, "USER 1000:1000", 1, "certification identity")
    require_count(source, "RUN --network=none ", 1, "certification execution")
    require_all(
        source,
        (
            "FROM win-helper-bootstrap",
            "ARG WIN_HELPER_BOOTSTRAP_IMAGE_ID",
            "ARG WIN_HELPER_BOOTSTRAP_MANIFEST_ID",
            "ARG WIN_HELPER_RECIPE_SHA256",
            "ARG WIN_HELPER_DPKG_MANIFEST_SHA256",
            "ARG SOURCE_DATE_EPOCH",
            '[ "$(/usr/bin/id -u):$(/usr/bin/id -g)" = "1000:1000" ]',
            "/usr/local/share/rustdesk-build-provenance/Dockerfile",
            "/usr/local/share/rustdesk-build-provenance/dpkg-manifest.tsv",
            "/usr/local/share/rustdesk-build-provenance/contract-v1",
            "role=win-helper",
            "base=ubuntu:24.04@sha256:"
            "786a8b558f7be160c6c8c4a54f9a57274f3b4fb1491cf65146521ae77ff1dc54",
            "LC_ALL=C /usr/bin/dpkg-query -W",
            "bash genisoimage grep guestfish head python3 sha256sum sort tail tar",
            "virt-cat virt-ls",
            "/usr/bin/python3 -c 'import olefile'",
            'org.rustdesk.builder-certification.role="win-helper"',
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
            "COPY Dockerfile.win-helper ",
            "apt-get update && apt-get install",
            "dpkg-query -W -f='${binary:Package}\\t${Version}\\n'",
            'DPKG_MANIFEST_SHA256="$(sha256sum ',
            "dpkg_manifest_sha256=%s",
            "&& chmod 0444 \\\n"
            "         /usr/local/share/rustdesk-build-provenance/Dockerfile \\\n"
            "         /usr/local/share/rustdesk-build-provenance/dpkg-manifest.tsv \\\n"
            "         /usr/local/share/rustdesk-build-provenance/contract-v1",
            'org.rustdesk.build-input.role="win-helper"',
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
        source, "win_helper_certification_candidate_spec_args"
    )
    require_all(
        candidate_certification_args,
        (
            "--role win-helper",
            '--base "ubuntu:24.04@${SHA256_BASEIMAGE_UBUNTU_2404}"',
            '--dockerfile-sha "$SHA256_WIN_HELPER_CERTIFICATION_DOCKERFILE"',
            '--recipe-sha "$SHA256_WIN_HELPER_DOCKERFILE"',
            '--dpkg-sha "$SHA256_WIN_HELPER_DPKG_MANIFEST"',
            '--bootstrap-image-id "$WIN_HELPER_BOOTSTRAP_IMAGE_ID"',
            '--bootstrap-manifest-id "$WIN_HELPER_BOOTSTRAP_MANIFEST_ID"',
            '--source-date-epoch "$SOURCE_DATE_EPOCH_PIN"',
        ),
        "certified Windows helper candidate input specification",
    )
    require_absent(
        candidate_certification_args,
        ("--expected-id", "--config-id", "--manifest-id"),
        "candidate-derived Windows helper identities",
    )

    certification_args = shell_function(
        source, "win_helper_certification_spec_args"
    )
    require_all(
        certification_args,
        (
            "win_helper_certification_candidate_spec_args",
            '--config-id "$WIN_HELPER_CONFIG_ID"',
            '--manifest-id "$WIN_HELPER_MANIFEST_ID"',
        ),
        "reviewed Windows helper specification",
    )
    require_absent(
        certification_args,
        ("--expected-id",),
        "separately pinned Windows helper image identity",
    )

    final_args = shell_function(source, "win_helper_image_spec_args")
    require_all(
        final_args,
        (
            '--expected-id "$WIN_HELPER_IMAGE_ID"',
            "win_helper_certification_spec_args",
        ),
        "final Windows helper specification",
    )

    bootstrap_args = shell_function(source, "win_helper_bootstrap_spec_args")
    require_all(
        bootstrap_args,
        (
            "--role win-helper-bootstrap",
            '--expected-id "$WIN_HELPER_BOOTSTRAP_IMAGE_ID"',
            '--base "ubuntu:24.04@${SHA256_BASEIMAGE_UBUNTU_2404}"',
            '--dockerfile-sha "$SHA256_WIN_HELPER_DOCKERFILE"',
            '--dpkg-sha "$SHA256_WIN_HELPER_DPKG_MANIFEST"',
            '--config-id "$WIN_HELPER_BOOTSTRAP_CONFIG_ID"',
            '--manifest-id "$WIN_HELPER_BOOTSTRAP_MANIFEST_ID"',
        ),
        "bootstrap-only Windows helper specification",
    )
    require_absent(
        bootstrap_args,
        (
            "--role win-helper ",
            "WIN_HELPER_CERTIFICATION_DOCKERFILE",
            "WIN_HELPER_IMAGE_ID",
        ),
        "bootstrap-only Windows helper specification",
    )

    loader = shell_function(source, "verify_or_load_win_helper_image")
    require_all(
        loader,
        (
            "require_win_helper_image_pins",
            "win_helper_image_spec_args",
            "online_image_provenance verify-load",
            'win-helper.docker.tar.gz"',
            '--archive-sha "$SHA256_WIN_HELPER_IMAGE_ARCHIVE"',
            '--archive-size "$WIN_HELPER_IMAGE_ARCHIVE_SIZE"',
            "online_image_provenance verify-local",
            '--image-ref "$WIN_HELPER_IMAGE_ID"',
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
            "win_helper_bootstrap_spec_args",
            "win-helper-bootstrap.docker.tar.gz",
            "win-helper-certified-candidate.docker.tar.gz",
            "docker tag",
            "docker save",
            '--image-ref "$WIN_HELPER_CONFIG_ID"',
        ),
        "containerd-store release loader",
    )
    require_all(
        shell_function(source, "load_builder_images"),
        (
            "verify_or_load_deb_builder_image",
            "verify_or_load_android_builder_image",
            "verify_or_load_win_helper_image",
        ),
        "ordinary builder loaders",
    )

    bootstrap_helper = shell_function(source, "build_builder_bootstrap_image")
    require_all(
        bootstrap_helper,
        (
            'recipe_sha="$(/usr/bin/sha256sum "$dockerfile"',
            "--network=default --pull=false --no-cache --platform=linux/amd64",
            '--build-arg "DOCKERFILE_SHA256=${recipe_sha}"',
            "maintenance-inspect-bootstrap-discovery",
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
    bootstrap = shell_function(source, "build_windows_helper_bootstrap_image")
    require_all(
        bootstrap,
        (
            "build_builder_bootstrap_image",
            '"Windows helper" win-helper',
            '"ubuntu:24.04@${SHA256_BASEIMAGE_UBUNTU_2404}"',
            "Dockerfile.win-helper",
        ),
        "Windows-helper bootstrap-only acquisition",
    )

    bootstrap_acquisition = shell_function(
        source,
        "maintenance_build_win_helper_bootstrap_candidate",
    )
    require_all(
        bootstrap_acquisition,
        (
            '"$FLOCK_BIN" --exclusive --nonblock "$lock_fd"',
            "win-helper-bootstrap-candidate.docker.tar.gz",
            'online_docker pull "ubuntu:24.04@',
            "build_windows_helper_bootstrap_image",
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
            "build_windows_helper_bootstrap_image",
            "capture_builder_bootstrap_candidate",
        ),
        "bootstrap build/capture order",
    )
    require_absent(
        bootstrap_acquisition,
        (
            "win-helper-bootstrap.docker.tar.gz",
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

    certification = shell_function(
        source, "maintenance_build_win_helper_certified_candidate"
    )
    require_all(
        certification,
        (
            "require_win_helper_certification_input_pins",
            "win-helper-bootstrap.docker.tar.gz",
            "win-helper-certified-candidate.docker.tar.gz",
            'local export_name="rd-win-helper-certified:authenticated-v1"',
            '"$FLOCK_BIN" --exclusive --nonblock "$lock_fd"',
            "Dockerfile.win-helper-certify",
            "materialize-oci-layout",
            '--archive-sha "$SHA256_WIN_HELPER_BOOTSTRAP_IMAGE_ARCHIVE"',
            '--archive-size "$WIN_HELPER_BOOTSTRAP_IMAGE_ARCHIVE_SIZE"',
            "SHA256_WIN_HELPER_BOOTSTRAP_OCI_LAYOUT",
            "online_buildx_build",
            "--network=none --pull=false --no-cache",
            "--platform=linux/amd64 --provenance=mode=max",
            "type=oci,name=${export_name},dest=${candidate_oci},tar=true",
            "oci-mediatypes=true,rewrite-timestamp=true",
            "win-helper-bootstrap=oci-layout://${layout}@"
            "${WIN_HELPER_BOOTSTRAP_MANIFEST_ID}",
            "WIN_HELPER_BOOTSTRAP_IMAGE_ID="
            "${WIN_HELPER_BOOTSTRAP_IMAGE_ID}",
            "WIN_HELPER_BOOTSTRAP_MANIFEST_ID="
            "${WIN_HELPER_BOOTSTRAP_MANIFEST_ID}",
            "WIN_HELPER_RECIPE_SHA256=${SHA256_WIN_HELPER_DOCKERFILE}",
            "WIN_HELPER_DPKG_MANIFEST_SHA256="
            "${SHA256_WIN_HELPER_DPKG_MANIFEST}",
            "SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH_PIN}",
            "win_helper_certification_candidate_spec_args",
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
        "online_image_provenance verify-oci-layout",
        2,
        "pre/post bootstrap material stability",
    )
    require_order(
        certification,
        (
            "materialize-oci-layout",
            "online_image_provenance verify-oci-layout",
            "online_buildx_build",
            "online_image_provenance verify-oci-layout",
            "maintenance-normalize-certified-oci",
            "online_image_provenance verify-load",
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
            "require_win_helper_image_pins",
            "$WIN_HELPER_IMAGE_ID",
            "$WIN_HELPER_CONFIG_ID",
            "$WIN_HELPER_MANIFEST_ID",
            "$SHA256_WIN_HELPER_IMAGE_ARCHIVE",
        ),
        "networkless certification transaction",
    )

    promotion = shell_function(
        source, "maintenance_promote_win_helper_certified_candidate"
    )
    require_all(
        promotion,
        (
            "require_win_helper_image_pins",
            "win-helper-certified-candidate.docker.tar.gz",
            'final="$directory/win-helper.docker.tar.gz"',
            '[ ! -e "$final" ] && [ ! -L "$final" ]',
            "win_helper_image_spec_args",
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

    bootstrap_promotion = shell_function(
        source,
        "maintenance_promote_win_helper_bootstrap_candidate",
    )
    require_all(
        bootstrap_promotion,
        (
            "require_win_helper_bootstrap_pins",
            "win_helper_bootstrap_spec_args",
            "win-helper-bootstrap-candidate.docker.tar.gz",
            "win-helper-bootstrap.docker.tar.gz",
            "SHA256_WIN_HELPER_BOOTSTRAP_IMAGE_ARCHIVE",
            "WIN_HELPER_BOOTSTRAP_IMAGE_ARCHIVE_SIZE",
            "SHA256_WIN_HELPER_BOOTSTRAP_OCI_LAYOUT",
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
    require_absent(
        source,
        (
            "verify_or_load_builder_image() {",
            "build_windows_helper_image() {",
            "capture_windows_helper_image() {",
            "maintenance_capture_windows_helper_image() {",
            "--maintenance-capture-windows-helper-image)",
            "maintenance_capture_win_helper_bootstrap_image() {",
            "--maintenance-build-image-candidates)",
            "--maintenance-capture-win-helper-bootstrap-image)",
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
            'win-helper) prefix=WIN_HELPER; base="ubuntu:24.04@',
            '|| [ "$role" = win-helper ]; then',
            '"${prefix}_CONFIG_ID"',
            '"${prefix}_MANIFEST_ID"',
            '"${prefix}_BOOTSTRAP_IMAGE_ID"',
            '"${prefix}_BOOTSTRAP_MANIFEST_ID"',
            '"SHA256_${prefix}_CERTIFICATION_DOCKERFILE"',
            "SOURCE_DATE_EPOCH_PIN",
            '--dockerfile-sha "${!certification_dockerfile_var}"',
            '--recipe-sha "$dockerfile_sha"',
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


def validate_runtime(source: str) -> None:
    verifier = shell_function(source, "windows_helper_verify_archive")
    require_all(
        verifier,
        (
            "offline-image-provenance.py",
            "--role win-helper",
            '--expected-id "$WIN_HELPER_IMAGE_ID"',
            '--archive-sha "$SHA256_WIN_HELPER_IMAGE_ARCHIVE"',
            '--archive-size "$WIN_HELPER_IMAGE_ARCHIVE_SIZE"',
            '--dockerfile-sha "$SHA256_WIN_HELPER_CERTIFICATION_DOCKERFILE"',
            '--recipe-sha "$SHA256_WIN_HELPER_DOCKERFILE"',
            '--dpkg-sha "$SHA256_WIN_HELPER_DPKG_MANIFEST"',
            '--bootstrap-image-id "$WIN_HELPER_BOOTSTRAP_IMAGE_ID"',
            '--bootstrap-manifest-id "$WIN_HELPER_BOOTSTRAP_MANIFEST_ID"',
            '--source-date-epoch "$SOURCE_DATE_EPOCH_PIN"',
            '--config-id "$WIN_HELPER_CONFIG_ID"',
            '--manifest-id "$WIN_HELPER_MANIFEST_ID"',
        ),
        "Windows helper archive verifier",
    )
    resolver = shell_function(source, "windows_helper_runtime_resolve")
    require_count(
        resolver,
        'windows_helper_verify_archive "$archive"',
        2,
        "archive pre/post verification",
    )
    require_all(
        resolver,
        (
            'require_pinned_builder_image win-helper "$WIN_HELPER_CONFIG_ID"',
            "confined Windows helper kernel derivation failed",
            "Windows helper image archive changed during kernel derivation",
        ),
        "Windows helper runtime resolver",
    )
    require_order(
        resolver,
        (
            'windows_helper_verify_archive "$archive"',
            "require_pinned_builder_image win-helper",
            "windows-helper-extract-kernel.py",
            'windows_helper_verify_archive "$archive"',
        ),
        "Windows helper runtime resolver",
    )
    require_absent(
        resolver,
        (
            "win-helper-bootstrap",
            "win-helper-certified-candidate",
            "verify_sha256",
        ),
        "Windows helper runtime resolver",
    )


def validate_consumers(sources: tuple[tuple[str, str], ...]) -> None:
    token = (
        'windows_helper_runtime_resolve '
        '"$ONLINE_DIR/build-images/win-helper.docker.tar.gz"'
    )
    for source, label in sources:
        require_count(source, token, 1, f"{label} final helper archive")
        require_absent(
            source,
            (
                "win-helper-bootstrap.docker.tar.gz",
                "win-helper-certified-candidate.docker.tar.gz",
            ),
            f"{label} helper selection",
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=pathlib.Path, default=pathlib.Path("."))
    arguments = parser.parse_args()
    repo = arguments.repo.resolve()
    pins = (repo / "scripts/pins.env").read_text(encoding="utf-8")
    validate_pins(pins)
    validate_dockerfile(
        (repo / "scripts/Dockerfile.win-helper-certify").read_text(
            encoding="utf-8"
        ),
        pins,
    )
    validate_bootstrap_dockerfiles(
        (repo / "scripts/Dockerfile.win-helper").read_text(
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
    validate_runtime(
        (repo / "scripts/windows-helper-runtime.sh").read_text(
            encoding="utf-8"
        )
    )
    validate_consumers(
        tuple(
            (
                (repo / relative).read_text(encoding="utf-8"),
                label,
            )
            for relative, label in (
                ("scripts/build-windows-vm.sh", "Windows build"),
                ("scripts/provision-windows-vm.sh", "Windows provision"),
                ("scripts/verify-windows-golden.sh", "Windows golden verifier"),
            )
        )
    )
    print("verify-win-helper-image-authority: ok")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AuthorityError, OSError) as error:
        print(f"verify-win-helper-image-authority: {error}")
        raise SystemExit(1)
