#!/usr/bin/env python3
"""Bind Debian builder distribution to one authenticated offline image."""

from __future__ import annotations

import argparse
import ast
import hashlib
import pathlib
import re
from dataclasses import dataclass


class AuthorityError(RuntimeError):
    pass


@dataclass(frozen=True)
class Mutation:
    source: str
    old: str
    new: str
    label: str


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AuthorityError(message)


def require_all(source: str, tokens: tuple[str, ...], label: str) -> None:
    for token in tokens:
        require(token in source, f"{label}: missing {token!r}")


def require_absent(source: str, tokens: tuple[str, ...], label: str) -> None:
    for token in tokens:
        require(token not in source, f"{label}: forbidden {token!r} remains")


def require_count(
    source: str,
    token: str,
    expected: int,
    label: str,
) -> None:
    actual = source.count(token)
    require(
        actual == expected,
        f"{label}: expected {expected} occurrences of {token!r}, found {actual}",
    )


def require_order(
    source: str,
    tokens: tuple[str, ...],
    label: str,
) -> None:
    position = -1
    for token in tokens:
        found = source.find(token, position + 1)
        require(found >= 0, f"{label}: missing ordered token {token!r}")
        position = found


def function_block(source: str, name: str) -> str:
    start_token = f"{name}() {{"
    require_count(source, start_token, 1, f"{name} definition")
    start = source.index(start_token)
    end = source.find("\n}\n", start + len(start_token))
    require(end >= 0, f"{name} has no closing brace")
    return source[start : end + 3]


def python_function_block(source: str, name: str) -> str:
    try:
        tree = ast.parse(source)
    except SyntaxError as error:
        raise AuthorityError(
            f"offline image provenance helper does not parse: {error}"
        ) from error
    matches = [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == name
    ]
    require(len(matches) == 1, f"{name} definition is not unique")
    node = matches[0]
    require(node.end_lineno is not None, f"{name} has no source extent")
    lines = source.splitlines(keepends=True)
    return "".join(lines[node.lineno - 1 : node.end_lineno])


def pin_value(source: str, name: str) -> str:
    match = re.search(
        rf'^{re.escape(name)}="([^"]+)"(?:\s|$)',
        source,
        re.MULTILINE,
    )
    require(match is not None, f"{name} is not one canonical quoted pin")
    return match.group(1)


EXPECTED_PINS = {
    "SHA256_DEB_BUILDER_DOCKERFILE": (
        "3f50a91a679138318c5cc0f7151fd4cf1d3ec55e6fa6736b67b88919eab8d9b6"
    ),
    "SHA256_DEB_BUILDER_DPKG_MANIFEST": (
        "e5003404717eea27ffb2cb6cf1aaac72b89b5ea6e70d11c16c605a15129760ae"
    ),
    "DEB_BUILDER_BOOTSTRAP_IMAGE_ID": (
        "sha256:6766564c65b0daead7d7031fcf0ff9ec8becab6ef9e3f9a7efd9f02f1b893776"
    ),
    "DEB_BUILDER_BOOTSTRAP_CONFIG_ID": (
        "sha256:ff9c506bb404f079cf37d36396d25d4a53fb6b57aeff258f7764b1900c62c738"
    ),
    "DEB_BUILDER_BOOTSTRAP_MANIFEST_ID": (
        "sha256:9fa4f01154f278ecf285bad9e59940ebb181d6464489dbd9473f40320e2482f6"
    ),
    "SHA256_DEB_BUILDER_BOOTSTRAP_IMAGE_ARCHIVE": (
        "361e04156023e286e4c0014753e379a2aef1e63c4f3a56ea7dafa316ecb15d6f"
    ),
    "DEB_BUILDER_BOOTSTRAP_IMAGE_ARCHIVE_SIZE": "462069452",
    "SHA256_DEB_BUILDER_BOOTSTRAP_OCI_LAYOUT": (
        "b411562e7deec95cb0f362d09e229df00422dc92b60cd27ce39ce43929f4043c"
    ),
    "SHA256_DEB_BUILDER_CERTIFICATION_DOCKERFILE": (
        "d5f22c0adbec24e9f95a51ad5f40ce32d5fea59c7d840bdbf7f15caca6af0283"
    ),
    "DEB_BUILDER_IMAGE_ID": (
        "sha256:607278bc16cf12eadaa41f8fa63a5a160a34b1a980be8cb2a772c4c3b7d3fdb2"
    ),
    "DEB_BUILDER_CONFIG_ID": (
        "sha256:a9e2b1ca4dde1ad4c4818f27dc312ea2575bd3d235c88f5acf5927193b423179"
    ),
    "DEB_BUILDER_MANIFEST_ID": (
        "sha256:3554ab3356afcac84ef8aeba034bd4fe55f3df95c89fb8abd934d4989808d434"
    ),
    "SHA256_DEB_BUILDER_IMAGE_ARCHIVE": (
        "8138ada8977c431ec3e1c91bc2daa8279687d889d8d0efe65587a5515b36de4b"
    ),
    "DEB_BUILDER_IMAGE_ARCHIVE_SIZE": "462076812",
    "SOURCE_DATE_EPOCH_PIN": "1700000000",
}


def validate_dockerfile(source: str, pins: str) -> None:
    require(
        hashlib.sha256(source.encode("utf-8")).hexdigest()
        == pin_value(pins, "SHA256_DEB_BUILDER_CERTIFICATION_DOCKERFILE"),
        "Debian certification Dockerfile bytes differ from their pin",
    )
    require_count(source, "FROM ", 1, "Debian certification base")
    require_count(source, "RUN --network=none ", 1, "Debian certification run")
    require_count(source, "USER 1000:1000", 1, "Debian certification user")
    require_all(
        source,
        (
            "FROM deb-builder-bootstrap",
            "ARG DEB_BUILDER_BOOTSTRAP_IMAGE_ID",
            "ARG DEB_BUILDER_BOOTSTRAP_MANIFEST_ID",
            "ARG DEB_BUILDER_RECIPE_SHA256",
            "ARG DEB_BUILDER_DPKG_MANIFEST_SHA256",
            "ARG SOURCE_DATE_EPOCH",
            '[ "$(/usr/bin/id -u):$(/usr/bin/id -g)" = "1000:1000" ]',
            "/usr/local/share/rustdesk-build-provenance/Dockerfile",
            "LC_ALL=C /usr/bin/dpkg-query -W",
            "/usr/local/share/rustdesk-build-provenance/dpkg-manifest.tsv",
            "/usr/local/share/rustdesk-build-provenance/contract-v1",
            "role=deb-builder",
            "base=ubuntu:18.04@sha256:"
            "152dc042452c496007f07ca9127571cb9c29697f42acbfad72324b2bb2e43c98",
            "org.rustdesk.builder-certification.contract="
            '"rustdesk-builder-certification-v1"',
            "org.rustdesk.builder-certification.bootstrap-image-id="
            '"${DEB_BUILDER_BOOTSTRAP_IMAGE_ID}"',
            "org.rustdesk.builder-certification.bootstrap-manifest-id="
            '"${DEB_BUILDER_BOOTSTRAP_MANIFEST_ID}"',
            "org.rustdesk.builder-certification.recipe-sha256="
            '"${DEB_BUILDER_RECIPE_SHA256}"',
            "org.rustdesk.builder-certification.dpkg-manifest-sha256="
            '"${DEB_BUILDER_DPKG_MANIFEST_SHA256}"',
            "org.rustdesk.builder-certification.source-date-epoch="
            '"${SOURCE_DATE_EPOCH}"',
            "ar bash cc clang cmake curl dpkg-deb g++ gcc git make nasm ninja",
            "pkg-config python3 tar unzip wget xz yasm zip",
        ),
        "Debian certification Dockerfile",
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
            "apt ",
            "sudo ",
            "git clone",
        ),
        "Debian certification Dockerfile",
    )


def validate_pins(source: str) -> None:
    for name, expected in EXPECTED_PINS.items():
        require(
            pin_value(source, name) == expected,
            f"{name} differs from the reviewed identity",
        )


def validate_online_fetch(source: str) -> None:
    no_vcs = function_block(source, "online_docker_without_vcs")
    require_all(
        no_vcs,
        (
            "env -i",
            "BUILDX_GIT_INFO=false",
            '"$DOCKER_BIN"',
            '--host "$ONLINE_FETCH_DOCKER_HOST"',
            '--config "$ONLINE_FETCH_DOCKER_CONFIG"',
            "assert_online_fetch_docker_authority",
        ),
        "fixed Docker client without VCS hints",
    )

    contract = function_block(source, "deb_builder_certification_spec_args")
    require_all(
        contract,
        (
            "--role deb-builder",
            '--dockerfile-sha "$SHA256_DEB_BUILDER_CERTIFICATION_DOCKERFILE"',
            '--recipe-sha "$SHA256_DEB_BUILDER_DOCKERFILE"',
            '--dpkg-sha "$SHA256_DEB_BUILDER_DPKG_MANIFEST"',
            '--bootstrap-image-id "$DEB_BUILDER_BOOTSTRAP_IMAGE_ID"',
            '--bootstrap-manifest-id "$DEB_BUILDER_BOOTSTRAP_MANIFEST_ID"',
            '--source-date-epoch "$SOURCE_DATE_EPOCH_PIN"',
            '--config-id "$DEB_BUILDER_CONFIG_ID"',
            '--manifest-id "$DEB_BUILDER_MANIFEST_ID"',
        ),
        "certified Debian builder contract",
    )
    require_absent(
        contract,
        ("--expected-id",),
        "candidate-derived Debian image identity",
    )
    require_all(
        function_block(source, "deb_builder_image_spec_args"),
        (
            '--expected-id "$DEB_BUILDER_IMAGE_ID"',
            "deb_builder_certification_spec_args",
        ),
        "final Debian builder contract",
    )
    require_all(
        function_block(source, "deb_builder_bootstrap_spec_args"),
        (
            "--role deb-builder-bootstrap",
            '--expected-id "$DEB_BUILDER_BOOTSTRAP_IMAGE_ID"',
            '--config-id "$DEB_BUILDER_BOOTSTRAP_CONFIG_ID"',
            '--manifest-id "$DEB_BUILDER_BOOTSTRAP_MANIFEST_ID"',
        ),
        "Debian bootstrap contract",
    )

    loader = function_block(source, "verify_or_load_deb_builder_image")
    require_all(
        loader,
        (
            "require_deb_builder_image_pins",
            "deb_builder_image_spec_args",
            '"$ONLINE_DIR/build-images/deb-builder.docker.tar.gz"',
            '--archive-sha "$SHA256_DEB_BUILDER_IMAGE_ARCHIVE"',
            '--archive-size "$DEB_BUILDER_IMAGE_ARCHIVE_SIZE"',
            '--image-ref "$DEB_BUILDER_IMAGE_ID"',
        ),
        "release Debian builder loader",
    )
    require_absent(
        loader,
        (
            "deb-builder-bootstrap.docker.tar.gz",
            "deb-builder-certified-candidate.docker.tar.gz",
            "verify_or_load_builder_image",
        ),
        "release Debian builder loader",
    )

    bootstrap_builder = function_block(
        source,
        "build_deb_builder_bootstrap_image",
    )
    require_all(
        bootstrap_builder,
        (
            "--role deb-builder-bootstrap-candidate",
            'printf \'DEB_BUILDER_BOOTSTRAP_IMAGE_ID="%s"\\n\'',
        ),
        "networked Debian bootstrap builder",
    )
    require_absent(
        bootstrap_builder,
        (
            "--role deb-builder ",
            'printf \'DEB_BUILDER_IMAGE_ID="%s"\\n\'',
        ),
        "networked Debian bootstrap builder",
    )

    candidate = function_block(
        source,
        "maintenance_build_deb_builder_certified_candidate",
    )
    require_all(
        candidate,
        (
            "deb-builder-bootstrap.docker.tar.gz",
            "deb-builder-certified-candidate.docker.tar.gz",
            "Dockerfile.deb-builder-certify",
            "deb_builder_bootstrap_spec_args",
            "materialize-oci-layout",
            '--layout-sha "$SHA256_DEB_BUILDER_BOOTSTRAP_OCI_LAYOUT"',
            "online_docker_without_vcs buildx build",
            "--network=none --pull=false --no-cache",
            "--platform=linux/amd64 --provenance=mode=max",
            "type=oci,name=${export_name},dest=${candidate_oci},tar=true,"
            "compression=gzip,oci-mediatypes=true,rewrite-timestamp=true",
            "deb-builder-bootstrap=oci-layout://${layout}@"
            "${DEB_BUILDER_BOOTSTRAP_IMAGE_ID}",
            "BUILDER_BOOTSTRAP_IMAGE_ID=${DEB_BUILDER_BOOTSTRAP_IMAGE_ID}",
            "BUILDER_BOOTSTRAP_MANIFEST_ID="
            "${DEB_BUILDER_BOOTSTRAP_MANIFEST_ID}",
            "BUILDER_RECIPE_SHA256=${SHA256_DEB_BUILDER_DOCKERFILE}",
            "BUILDER_DPKG_MANIFEST_SHA256="
            "${SHA256_DEB_BUILDER_DPKG_MANIFEST}",
            "maintenance-normalize-certified-oci",
            "deb_builder_certification_spec_args",
            'candidate_args=(--expected-id "$image_id" "${contract_args[@]}")',
            '--archive-size "$archive_size"',
        ),
        "Debian certification transaction",
    )
    require_order(
        candidate,
        (
            "materialize-oci-layout",
            "online_image_provenance verify-oci-layout",
            "online_docker_without_vcs buildx build",
            "Debian builder bootstrap OCI layout changed during the build",
            "maintenance-normalize-certified-oci",
            "online_image_provenance verify-load",
        ),
        "Debian certification transaction",
    )
    require_absent(
        candidate,
        (
            "docker-image://",
            "type=docker",
            "--provenance=mode=min",
            "--network=default",
            "--pull=true",
            "--load",
            "--push",
            "online_docker tag",
            "online_docker save",
            "maintenance-capture",
        ),
        "Debian certification transaction",
    )

    promotion = function_block(
        source,
        "maintenance_promote_deb_builder_certified_candidate",
    )
    require_all(
        promotion,
        (
            "deb-builder-certified-candidate.docker.tar.gz",
            'final="$directory/deb-builder.docker.tar.gz"',
            '[ ! -e "$final" ] && [ ! -L "$final" ]',
            "deb_builder_image_spec_args",
            '--archive-sha "$SHA256_DEB_BUILDER_IMAGE_ARCHIVE"',
            '--archive-size "$DEB_BUILDER_IMAGE_ARCHIVE_SIZE"',
            "maintenance-rename-noreplace",
            "online_image_provenance verify-load",
        ),
        "Debian exact-pin promotion",
    )
    require_order(
        promotion,
        (
            '[ ! -e "$final" ] && [ ! -L "$final" ]',
            "online_image_provenance verify-archive",
            "maintenance-rename-noreplace",
            "online_image_provenance verify-load",
        ),
        "Debian exact-pin promotion",
    )

    bootstrap_capture = function_block(
        source,
        "maintenance_capture_deb_builder_bootstrap_image",
    )
    require_all(
        bootstrap_capture,
        (
            "deb-builder-bootstrap.docker.tar.gz",
            "deb_builder_bootstrap_spec_args",
            "maintenance-capture",
        ),
        "Debian bootstrap capture",
    )
    require_absent(
        bootstrap_capture,
        ("deb-builder.docker.tar.gz", "deb_builder_image_spec_args"),
        "Debian bootstrap capture",
    )
    require_absent(
        function_block(
            source,
            "maintenance_capture_win_helper_bootstrap_image",
        ),
        ("DEB_BUILDER", "deb-builder"),
        "Windows-only bootstrap capture",
    )
    require_absent(
        source,
        (
            "build_deb_builder_image() {",
            "maintenance_capture_builder_images() {",
            "capture_builder_image() {",
            "capture_windows_helper_image() {",
            "maintenance_capture_windows_helper_image() {",
            "--maintenance-capture-builder-images)",
        ),
        "retired final-image Docker-store surfaces",
    )
    require_all(
        source,
        (
            "--maintenance-build-deb-builder-certified-candidate)",
            "maintenance_build_deb_builder_certified_candidate",
            "--maintenance-promote-deb-builder-certified-candidate)",
            "maintenance_promote_deb_builder_certified_candidate",
            "--maintenance-capture-deb-builder-bootstrap-image)",
            "maintenance_capture_deb_builder_bootstrap_image",
        ),
        "Debian maintenance entry points",
    )


def validate_library(source: str) -> None:
    block = function_block(source, "require_pinned_builder_image")
    require_all(
        block,
        (
            'deb-builder) prefix=DEB_BUILDER; base="ubuntu:18.04@',
            '[ "$role" = android-builder ] \\\n'
            '        || [ "$role" = deb-builder ] \\\n'
            '        || [ "$role" = win-helper ]; then',
            '"${prefix}_CONFIG_ID"',
            '"${prefix}_MANIFEST_ID"',
            '"${prefix}_BOOTSTRAP_IMAGE_ID"',
            '"${prefix}_BOOTSTRAP_MANIFEST_ID"',
            '"SHA256_${prefix}_CERTIFICATION_DOCKERFILE"',
            '--dockerfile-sha "${!certification_dockerfile_var}"',
            '--recipe-sha "$dockerfile_sha"',
            '--bootstrap-image-id "${!bootstrap_image_var}"',
            '--bootstrap-manifest-id "${!bootstrap_manifest_var}"',
            '--config-id "${!config_var}"',
            '--manifest-id "${!manifest_var}"',
        ),
        "ordinary certified builder runtime verifier",
    )


def validate_provenance(source: str) -> None:
    attestation = python_function_block(
        source,
        "validate_certified_builder_attestation",
    )
    direct_scanner = python_function_block(
        source,
        "scan_direct_oci_export",
    )
    archive_validator = python_function_block(
        source,
        "validate_modern_archive",
    )
    require_all(
        source,
        (
            "class CertifiedBuilderSpec:",
            'if args.role in {"android-builder", "deb-builder", "win-helper"}:',
            '"deb-builder-bootstrap",',
            'r"(?:android|deb)-builder-bootstrap(?:-candidate)?"',
            "def validate_certified_builder_attestation(",
            "subject_name = spec.export_name.rsplit",
            'context_key = "context:" + spec.bootstrap_context_name',
            "if contains_vcs_authority(statement):",
            "for line in spec.source_location_lines",
            "attested_layers[: spec.bootstrap_layer_count]",
            'f"{prefix}_BOOTSTRAP_IMAGE_ID={spec.bootstrap_image_id}"',
            '"user": "1000:1000"',
            '"network": 2',
            "def prepare_certified_builder_oci_export(",
            "contract.export_oci_name",
            "contract.export_name.rsplit",
            "def canonicalize_certified_builder_oci_export(",
            '        if args.role not in {\n'
            '            "android-builder",\n'
            '            "deb-builder",\n'
            '            "win-helper",\n'
            "        }",
            "canonicalize_certified_builder_oci_export(",
            "if requires_private_archive(spec):",
            "stat.S_IMODE(before.st_mode) != 0o400",
            "expected_archive_size is None or expected_archive_size <= 0",
            "publish_existing_archive_noreplace(",
            "renameat2",
            "RENAME_NOREPLACE",
            "if expanded_bytes > 8 * 1024 * 1024 * 1024:",
            "if position >= 4096:",
        ),
        "certified builder provenance authority",
    )
    require_all(
        attestation,
        (
            "if contains_vcs_authority(statement):",
            '"user": "1000:1000"',
            '"network": 2',
            "for line in spec.source_location_lines",
            "attested_layers[: spec.bootstrap_layer_count]",
        ),
        "certified builder attestation authority",
    )
    require_all(
        direct_scanner,
        (
            "or stat.S_IMODE(before.st_mode) != 0o600:",
            "if expanded_bytes > 8 * 1024 * 1024 * 1024:",
            "if position >= 4096:",
        ),
        "certified builder direct-export scanner",
    )
    require_all(
        archive_validator,
        (
            ") and len(attestations) != 1:",
        ),
        "certified builder sole-attestation authority",
    )
    require_absent(
        source,
        (
            "CertifiedAndroidBuilderSpec",
            "prepare_certified_android_builder_oci_export",
            "canonicalize_certified_android_builder_oci_export",
        ),
        "obsolete Android-only certification abstraction",
    )


def validate_contract(sources: dict[str, str]) -> None:
    validate_pins(sources["pins"])
    validate_dockerfile(sources["dockerfile"], sources["pins"])
    validate_online_fetch(sources["online"])
    validate_library(sources["lib"])
    validate_provenance(sources["provenance"])
    require_all(
        sources["verify"],
        (
            "/usr/bin/python3 -I -S "
            "scripts/verify-deb-builder-image-authority.py "
            "--repo . --self-test",
        ),
        "shared verifier wiring",
    )
    require_all(
        sources["workspace"],
        (
            "validate_android_builder_image_authority_contract(sources)\n"
            "    validate_deb_builder_image_authority_contract(sources)\n"
            "    validate_win_helper_image_authority_contract(sources)\n"
            "    validate_android_keystore_authority_contract(sources)",
            '"deb_builder_image_authority_verifier": (',
            'repo / "scripts/verify-deb-builder-image-authority.py"',
            "Debian builder image authority focused verifier",
        ),
        "independent workspace verifier",
    )
    require_all(
        sources["requirements"],
        (
            '<span class="id">R-S11db</span>',
            "<tr><td>255</td>",
        ),
        "normative Debian builder image authority",
    )
    require_all(
        sources["hardening"],
        (
            "R-S11db/R-S11e-120 — authenticated Debian builder image "
            "distribution authority",
            "CLEAN EXACT-COMMIT R-B2/R-B10 RELEASE",
        ),
        "Debian builder image hardening ledger",
    )


MUTATIONS = (
    Mutation(
        "dockerfile",
        "FROM deb-builder-bootstrap",
        "FROM ubuntu:18.04",
        "exact bootstrap base",
    ),
    Mutation(
        "dockerfile",
        "USER 1000:1000",
        "USER 0:0",
        "numeric nonroot identity",
    ),
    Mutation(
        "dockerfile",
        "RUN --network=none set -eu;",
        "RUN --network=default set -eu;",
        "Dockerfile networklessness",
    ),
    Mutation(
        "dockerfile",
        "org.rustdesk.builder-certification.bootstrap-image-id=",
        "org.rustdesk.builder-certification.unbound-bootstrap-image-id=",
        "bootstrap identity label",
    ),
    Mutation(
        "pins",
        EXPECTED_PINS["DEB_BUILDER_BOOTSTRAP_IMAGE_ID"],
        "sha256:" + "0" * 64,
        "bootstrap image pin",
    ),
    Mutation(
        "pins",
        EXPECTED_PINS["DEB_BUILDER_BOOTSTRAP_MANIFEST_ID"],
        "sha256:" + "1" * 64,
        "bootstrap manifest pin",
    ),
    Mutation(
        "pins",
        EXPECTED_PINS["SHA256_DEB_BUILDER_BOOTSTRAP_IMAGE_ARCHIVE"],
        "2" * 64,
        "bootstrap archive pin",
    ),
    Mutation(
        "pins",
        'DEB_BUILDER_BOOTSTRAP_IMAGE_ARCHIVE_SIZE="462069452"',
        'DEB_BUILDER_BOOTSTRAP_IMAGE_ARCHIVE_SIZE="462069453"',
        "bootstrap archive size",
    ),
    Mutation(
        "pins",
        EXPECTED_PINS["SHA256_DEB_BUILDER_BOOTSTRAP_OCI_LAYOUT"],
        "3" * 64,
        "bootstrap layout pin",
    ),
    Mutation(
        "pins",
        EXPECTED_PINS["DEB_BUILDER_IMAGE_ID"],
        "sha256:" + "4" * 64,
        "certified image pin",
    ),
    Mutation(
        "pins",
        EXPECTED_PINS["DEB_BUILDER_CONFIG_ID"],
        "sha256:" + "5" * 64,
        "certified config pin",
    ),
    Mutation(
        "pins",
        EXPECTED_PINS["DEB_BUILDER_MANIFEST_ID"],
        "sha256:" + "6" * 64,
        "certified manifest pin",
    ),
    Mutation(
        "pins",
        EXPECTED_PINS["SHA256_DEB_BUILDER_IMAGE_ARCHIVE"],
        "7" * 64,
        "certified archive pin",
    ),
    Mutation(
        "pins",
        'DEB_BUILDER_IMAGE_ARCHIVE_SIZE="462076812"',
        'DEB_BUILDER_IMAGE_ARCHIVE_SIZE="462076813"',
        "certified archive size",
    ),
    Mutation(
        "online",
        "BUILDX_GIT_INFO=false",
        "BUILDX_GIT_INFO=true",
        "VCS-hint suppression",
    ),
    Mutation(
        "online",
        "--role deb-builder-bootstrap-candidate",
        "--role deb-builder",
        "bootstrap candidate separation",
    ),
    Mutation(
        "online",
        '"$ONLINE_DIR/build-images/deb-builder.docker.tar.gz"',
        '"$ONLINE_DIR/build-images/deb-builder-bootstrap.docker.tar.gz"',
        "release loader selection",
    ),
    Mutation(
        "online",
        "online_docker_without_vcs buildx build \\\n"
        "            --network=none --pull=false --no-cache \\\n"
        "            --platform=linux/amd64 --provenance=mode=max \\\n"
        "            --output=\"type=oci,name=${export_name},"
        "dest=${candidate_oci},tar=true,compression=gzip,"
        "oci-mediatypes=true,rewrite-timestamp=true\" \\\n"
        "            --build-context \\\n"
        "            \"deb-builder-bootstrap=oci-layout://${layout}@"
        "${DEB_BUILDER_BOOTSTRAP_IMAGE_ID}\"",
        "online_docker_without_vcs buildx build \\\n"
        "            --network=default --pull=true \\\n"
        "            --platform=linux/amd64 --provenance=mode=max \\\n"
        "            --output=\"type=oci,name=${export_name},"
        "dest=${candidate_oci},tar=true,compression=gzip,"
        "oci-mediatypes=true,rewrite-timestamp=true\" \\\n"
        "            --build-context \\\n"
        "            \"deb-builder-bootstrap=oci-layout://${layout}@"
        "${DEB_BUILDER_BOOTSTRAP_IMAGE_ID}\"",
        "certification network/pull boundary",
    ),
    Mutation(
        "online",
        "--platform=linux/amd64 --provenance=mode=max \\\n"
        "            --output=\"type=oci,name=${export_name},"
        "dest=${candidate_oci},tar=true,compression=gzip,"
        "oci-mediatypes=true,rewrite-timestamp=true\" \\\n"
        "            --build-context \\\n"
        "            \"deb-builder-bootstrap=oci-layout://${layout}@"
        "${DEB_BUILDER_BOOTSTRAP_IMAGE_ID}\"",
        "--platform=linux/amd64 --provenance=mode=min \\\n"
        "            --output=\"type=oci,name=${export_name},"
        "dest=${candidate_oci},tar=true,compression=gzip,"
        "oci-mediatypes=true,rewrite-timestamp=true\" \\\n"
        "            --build-context \\\n"
        "            \"deb-builder-bootstrap=oci-layout://${layout}@"
        "${DEB_BUILDER_BOOTSTRAP_IMAGE_ID}\"",
        "mode-max provenance",
    ),
    Mutation(
        "online",
        "deb-builder-bootstrap=oci-layout://${layout}@"
        "${DEB_BUILDER_BOOTSTRAP_IMAGE_ID}",
        "deb-builder-bootstrap=docker-image://"
        "${DEB_BUILDER_BOOTSTRAP_IMAGE_ID}",
        "local OCI-layout context",
    ),
    Mutation(
        "online",
        "mapfile -d '' contract_args < "
        "<(deb_builder_certification_spec_args)\n"
        "    result=\"$(\n"
        "        online_image_provenance "
        "maintenance-normalize-certified-oci \\\n"
        '            --input "$candidate_oci"',
        "mapfile -d '' contract_args < "
        "<(deb_builder_certification_spec_args)\n"
        "    result=\"$(\n"
        "        true # direct OCI normalization removed",
        "direct OCI normalization",
    ),
    Mutation(
        "online",
        "candidate_args=(--expected-id \"$image_id\" "
        "\"${contract_args[@]}\")\n"
        "    online_image_provenance verify-load \\\n"
        '        --archive "$candidate_archive" \\\n'
        '        --archive-sha "$archive_sha" \\\n'
        '        --archive-size "$archive_size" \\\n'
        '        "${candidate_args[@]}" \\\n'
        "        || die \"certified Debian builder candidate load/runtime "
        "verification failed\"",
        "candidate_args=(--expected-id \"$image_id\" "
        "\"${contract_args[@]}\")\n"
        "    true # candidate runtime proof removed\n"
        "        || die \"certified Debian builder candidate load/runtime "
        "verification failed\"",
        "candidate runtime proof",
    ),
    Mutation(
        "online",
        "online_image_provenance maintenance-rename-noreplace \\\n"
        '        --source "$candidate" \\\n'
        '        --destination "$final" \\\n'
        '        || die "certified Debian builder candidate promotion failed"',
        'mv "$candidate" "$final" \\\n'
        '        || die "certified Debian builder candidate promotion failed"',
        "no-clobber promotion",
    ),
    Mutation(
        "online",
        "--maintenance-promote-deb-builder-certified-candidate)",
        "--maintenance-promote-deb-builder-certified-candidate-disabled)",
        "promotion entry point",
    ),
    Mutation(
        "lib",
        '[ "$role" = android-builder ] \\\n'
        '        || [ "$role" = deb-builder ] \\\n'
        '        || [ "$role" = win-helper ]; then',
        '[ "$role" = android-builder ] \\\n'
        '        || [ "$role" = win-helper ]; then',
        "ordinary Debian certification branch",
    ),
    Mutation(
        "provenance",
        'if args.role in {"android-builder", "deb-builder", "win-helper"}:',
        'if args.role in {"android-builder", "win-helper"}:',
        "certified Debian parser role",
    ),
    Mutation(
        "provenance",
        '        if args.role not in {\n'
        '            "android-builder",\n'
        '            "deb-builder",\n'
        '            "win-helper",\n'
        "        }",
        '        if args.role not in {\n'
        '            "android-builder",\n'
        '            "win-helper",\n'
        "        }",
        "Debian direct normalization role",
    ),
    Mutation(
        "provenance",
        "if contains_vcs_authority(statement):\n"
        "        fail(\n"
        "            f\"Docker archive certified {spec.display_name} "
        "provenance contains \"\n"
        "            \"undeclared VCS authority\"\n"
        "        )",
        "if False:\n"
        "        fail(\n"
        "            f\"Docker archive certified {spec.display_name} "
        "provenance contains \"\n"
        "            \"undeclared VCS authority\"\n"
        "        )",
        "VCS authority rejection",
    ),
    Mutation(
        "provenance",
        '"args": ["/bin/sh", "-c", source_runs[0][1]],\n'
        '                        "cwd": "/",\n'
        '                        "env": expected_environment,\n'
        '                        "removeMountStubsRecursive": True,\n'
        '                        "user": "1000:1000",',
        '"args": ["/bin/sh", "-c", source_runs[0][1]],\n'
        '                        "cwd": "/",\n'
        '                        "env": expected_environment,\n'
        '                        "removeMountStubsRecursive": True,\n'
        '                        "user": "0:0",',
        "attested numeric nonroot execution",
    ),
    Mutation(
        "provenance",
        '"network": 2,',
        '"network": 0,',
        "attested networkless execution",
    ),
    Mutation(
        "provenance",
        "and len(attestations) != 1:",
        "and len(attestations) < 1:",
        "sole attestation",
    ),
    Mutation(
        "provenance",
        "or stat.S_IMODE(before.st_mode) != 0o600:",
        "or stat.S_IMODE(before.st_mode) != 0o666:",
        "direct OCI private mode",
    ),
    Mutation(
        "provenance",
        "if expanded_bytes > 8 * 1024 * 1024 * 1024:",
        "if expanded_bytes > 80 * 1024 * 1024 * 1024:",
        "direct OCI byte bound",
    ),
    Mutation(
        "provenance",
        "if position >= 4096:\n"
        "                        fail(\n"
        "                            \"direct certified builder OCI export \"",
        "if position >= 40960:\n"
        "                        fail(\n"
        "                            \"direct certified builder OCI export \"",
        "archive member bound",
    ),
    Mutation(
        "verify",
        "/usr/bin/python3 -I -S "
        "scripts/verify-deb-builder-image-authority.py "
        "--repo . --self-test",
        "true # Debian builder image authority gate removed",
        "shared verifier wiring",
    ),
    Mutation(
        "workspace",
        "validate_android_builder_image_authority_contract(sources)\n"
        "    validate_deb_builder_image_authority_contract(sources)\n"
        "    validate_win_helper_image_authority_contract(sources)\n"
        "    validate_android_keystore_authority_contract(sources)",
        "validate_android_builder_image_authority_contract(sources)\n"
        "    true # Debian builder workspace contract removed\n"
        "    validate_win_helper_image_authority_contract(sources)\n"
        "    validate_android_keystore_authority_contract(sources)",
        "workspace dispatch",
    ),
    Mutation(
        "requirements",
        '<span class="id">R-S11db</span>',
        '<span class="id">R-S11db-disabled</span>',
        "normative requirement",
    ),
    Mutation(
        "requirements",
        "<tr><td>255</td>",
        "<tr><td>255-disabled</td>",
        "Appendix disposition",
    ),
    Mutation(
        "hardening",
        "R-S11db/R-S11e-120 — authenticated Debian builder image "
        "distribution authority",
        "R-S11db/R-S11e-120 — unauthenticated Debian builder tag authority",
        "hardening ledger",
    ),
)


def load_sources(repo: pathlib.Path) -> dict[str, str]:
    paths = {
        "dockerfile": "scripts/Dockerfile.deb-builder-certify",
        "pins": "scripts/pins.env",
        "online": "scripts/online-fetch.sh",
        "lib": "scripts/lib.sh",
        "provenance": "scripts/offline-image-provenance.py",
        "verify": "scripts/verify.sh",
        "workspace": "scripts/verify-verifier-workspace.py",
        "requirements": "requirements.html",
        "hardening": "HARDENING_STATUS.md",
    }
    return {
        name: (repo / relative).read_text(encoding="utf-8")
        for name, relative in paths.items()
    }


def run_mutations(sources: dict[str, str]) -> None:
    for mutation in MUTATIONS:
        original = sources[mutation.source]
        count = original.count(mutation.old)
        require(
            count == 1,
            f"mutation target for {mutation.label} occurs {count} times",
        )
        changed = dict(sources)
        changed[mutation.source] = original.replace(
            mutation.old,
            mutation.new,
            1,
        )
        try:
            validate_contract(changed)
        except AuthorityError:
            continue
        raise AuthorityError(f"mutation was accepted: {mutation.label}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=pathlib.Path, default=pathlib.Path("."))
    parser.add_argument("--self-test", action="store_true")
    arguments = parser.parse_args()
    sources = load_sources(arguments.repo.resolve())
    validate_contract(sources)
    if arguments.self_test:
        run_mutations(sources)
    suffix = f" ({len(MUTATIONS)} mutations)" if arguments.self_test else ""
    print(f"verify-deb-builder-image-authority: OK{suffix}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AuthorityError, OSError) as error:
        print(f"verify-deb-builder-image-authority: {error}")
        raise SystemExit(1)
