#!/usr/bin/env python3
"""Bind Windows-helper distribution to one authenticated offline image."""

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
    "SHA256_WIN_HELPER_DOCKERFILE": (
        "b3b878c453c038a4d566bada84a2820031c57d2c9140ed18371451596b4ef75a"
    ),
    "SHA256_WIN_HELPER_DPKG_MANIFEST": (
        "ac1a8dbaf2702bd3d0dfa312635f46384e6c8d5f6b54cf1f8bc7d624620b8adb"
    ),
    "WIN_HELPER_BOOTSTRAP_IMAGE_ID": (
        "sha256:aa9abae2debc838591649fb0b7b94f9f2f24e7848c699cd70e1103a690db21ce"
    ),
    "WIN_HELPER_BOOTSTRAP_CONFIG_ID": (
        "sha256:9a66ffdc89b43eb424fc8632ad33048ce7a123d0001f2bb5d2d3a283bf4cccd4"
    ),
    "WIN_HELPER_BOOTSTRAP_MANIFEST_ID": (
        "sha256:736a425f6420889bd03a8abb0c2e6faae4765cc34d80af30be9b1480fe9f458e"
    ),
    "SHA256_WIN_HELPER_BOOTSTRAP_IMAGE_ARCHIVE": (
        "d1a13e3eb4de02a325bd9c08636e7a1f0eebc417bc38fade178b5f3627639ab5"
    ),
    "WIN_HELPER_BOOTSTRAP_IMAGE_ARCHIVE_SIZE": "982288329",
    "SHA256_WIN_HELPER_BOOTSTRAP_OCI_LAYOUT": (
        "5ca0ead07997fe6b4981a9d7bf30c37b32a949566d4931ef7847cf97a0dea0a5"
    ),
    "SHA256_WIN_HELPER_CERTIFICATION_DOCKERFILE": (
        "f6e9b53451990284a9e81a32c7ae64b17b079182d7aa3f17a6d5d348351b896d"
    ),
    "WIN_HELPER_IMAGE_ID": (
        "sha256:bfc0d46a9c3806e2ac44ab66337f42ee7c46ff0b5f3fd35c5a6768883d19791e"
    ),
    "WIN_HELPER_CONFIG_ID": (
        "sha256:03fc4ba441cda2ce0feabd51bef78ef081a2a3927252273237f8a93f401215e7"
    ),
    "WIN_HELPER_MANIFEST_ID": (
        "sha256:60d5edd1a08a831815d0727563943219cc3d950b18bd9f1a6a21f569f94c14c6"
    ),
    "SHA256_WIN_HELPER_IMAGE_ARCHIVE": (
        "468f99ec23c4f3bc45599ee98c01163249f4d611f2f5545b45373455c3a5e795"
    ),
    "WIN_HELPER_IMAGE_ARCHIVE_SIZE": "982289690",
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
        "Windows-helper certification Dockerfile bytes differ from their pin",
    )
    require_count(source, "FROM ", 1, "Windows-helper certification base")
    require_count(
        source,
        "RUN --network=none ",
        1,
        "Windows-helper certification run",
    )
    require_count(
        source,
        "USER 1000:1000",
        1,
        "Windows-helper certification user",
    )
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
            "LC_ALL=C /usr/bin/dpkg-query -W",
            "/usr/local/share/rustdesk-build-provenance/dpkg-manifest.tsv",
            "/usr/local/share/rustdesk-build-provenance/contract-v1",
            "role=win-helper",
            "base=ubuntu:24.04@sha256:"
            "786a8b558f7be160c6c8c4a54f9a57274f3b4fb1491cf65146521ae77ff1dc54",
            "bash genisoimage grep guestfish head python3 sha256sum sort tail tar",
            "virt-cat virt-ls",
            "/usr/bin/python3 -c 'import olefile'",
            "org.rustdesk.builder-certification.contract="
            '"rustdesk-builder-certification-v1"',
            "org.rustdesk.builder-certification.role="
            '"win-helper"',
            "org.rustdesk.builder-certification.bootstrap-image-id="
            '"${WIN_HELPER_BOOTSTRAP_IMAGE_ID}"',
            "org.rustdesk.builder-certification.bootstrap-manifest-id="
            '"${WIN_HELPER_BOOTSTRAP_MANIFEST_ID}"',
            "org.rustdesk.builder-certification.recipe-sha256="
            '"${WIN_HELPER_RECIPE_SHA256}"',
            "org.rustdesk.builder-certification.dpkg-manifest-sha256="
            '"${WIN_HELPER_DPKG_MANIFEST_SHA256}"',
            "org.rustdesk.builder-certification.source-date-epoch="
            '"${SOURCE_DATE_EPOCH}"',
        ),
        "Windows-helper certification Dockerfile",
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
        "Windows-helper certification Dockerfile",
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

    contract = function_block(source, "win_helper_certification_spec_args")
    require_count(
        contract,
        "--role win-helper \\",
        1,
        "certified Windows-helper role",
    )
    require_all(
        contract,
        (
            "--role win-helper",
            '--dockerfile-sha "$SHA256_WIN_HELPER_CERTIFICATION_DOCKERFILE"',
            '--recipe-sha "$SHA256_WIN_HELPER_DOCKERFILE"',
            '--dpkg-sha "$SHA256_WIN_HELPER_DPKG_MANIFEST"',
            '--bootstrap-image-id "$WIN_HELPER_BOOTSTRAP_IMAGE_ID"',
            '--bootstrap-manifest-id "$WIN_HELPER_BOOTSTRAP_MANIFEST_ID"',
            '--source-date-epoch "$SOURCE_DATE_EPOCH_PIN"',
            '--config-id "$WIN_HELPER_CONFIG_ID"',
            '--manifest-id "$WIN_HELPER_MANIFEST_ID"',
        ),
        "certified Windows-helper contract",
    )
    require_absent(
        contract,
        ("--expected-id",),
        "candidate-derived Windows-helper image identity",
    )
    require_all(
        function_block(source, "win_helper_image_spec_args"),
        (
            '--expected-id "$WIN_HELPER_IMAGE_ID"',
            "win_helper_certification_spec_args",
        ),
        "final Windows-helper contract",
    )
    require_all(
        function_block(source, "win_helper_bootstrap_spec_args"),
        (
            "--role win-helper-bootstrap",
            '--expected-id "$WIN_HELPER_BOOTSTRAP_IMAGE_ID"',
            '--config-id "$WIN_HELPER_BOOTSTRAP_CONFIG_ID"',
            '--manifest-id "$WIN_HELPER_BOOTSTRAP_MANIFEST_ID"',
        ),
        "Windows-helper bootstrap contract",
    )

    loader = function_block(source, "verify_or_load_win_helper_image")
    require_all(
        loader,
        (
            "require_win_helper_image_pins",
            "win_helper_image_spec_args",
            '"$ONLINE_DIR/build-images/win-helper.docker.tar.gz"',
            '--archive-sha "$SHA256_WIN_HELPER_IMAGE_ARCHIVE"',
            '--archive-size "$WIN_HELPER_IMAGE_ARCHIVE_SIZE"',
            '--image-ref "$WIN_HELPER_IMAGE_ID"',
        ),
        "release Windows-helper loader",
    )
    require_absent(
        loader,
        (
            "win-helper-bootstrap.docker.tar.gz",
            "win-helper-certified-candidate.docker.tar.gz",
            "verify_or_load_builder_image",
        ),
        "release Windows-helper loader",
    )
    require_all(
        function_block(source, "load_builder_images"),
        (
            "verify_or_load_deb_builder_image",
            "verify_or_load_android_builder_image",
            "verify_or_load_win_helper_image",
        ),
        "ordinary builder loaders",
    )

    bootstrap_builder = function_block(
        source,
        "build_windows_helper_bootstrap_image",
    )
    require_all(
        bootstrap_builder,
        (
            "--role win-helper-bootstrap-candidate",
            'printf \'WIN_HELPER_BOOTSTRAP_IMAGE_ID="%s"\\n\'',
        ),
        "networked Windows-helper bootstrap builder",
    )
    require_absent(
        bootstrap_builder,
        (
            "--role win-helper ",
            'printf \'WIN_HELPER_IMAGE_ID="%s"\\n\'',
        ),
        "networked Windows-helper bootstrap builder",
    )

    candidate = function_block(
        source,
        "maintenance_build_win_helper_certified_candidate",
    )
    require_all(
        candidate,
        (
            "win-helper-bootstrap.docker.tar.gz",
            "win-helper-certified-candidate.docker.tar.gz",
            "Dockerfile.win-helper-certify",
            "win_helper_bootstrap_spec_args",
            "materialize-oci-layout",
            '--layout-sha "$SHA256_WIN_HELPER_BOOTSTRAP_OCI_LAYOUT"',
            "online_docker_without_vcs buildx build",
            "--network=none --pull=false --no-cache",
            "--platform=linux/amd64 --provenance=mode=max",
            "type=oci,name=${export_name},dest=${candidate_oci},tar=true,"
            "compression=gzip,oci-mediatypes=true,rewrite-timestamp=true",
            "win-helper-bootstrap=oci-layout://${layout}@"
            "${WIN_HELPER_BOOTSTRAP_IMAGE_ID}",
            "WIN_HELPER_BOOTSTRAP_IMAGE_ID="
            "${WIN_HELPER_BOOTSTRAP_IMAGE_ID}",
            "WIN_HELPER_BOOTSTRAP_MANIFEST_ID="
            "${WIN_HELPER_BOOTSTRAP_MANIFEST_ID}",
            "WIN_HELPER_RECIPE_SHA256=${SHA256_WIN_HELPER_DOCKERFILE}",
            "WIN_HELPER_DPKG_MANIFEST_SHA256="
            "${SHA256_WIN_HELPER_DPKG_MANIFEST}",
            "SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH_PIN}",
            "maintenance-normalize-certified-oci",
            "win_helper_certification_spec_args",
            'candidate_args=(--expected-id "$image_id" "${contract_args[@]}")',
            '--archive-size "$archive_size"',
        ),
        "Windows-helper certification transaction",
    )
    require_order(
        candidate,
        (
            "materialize-oci-layout",
            "online_image_provenance verify-oci-layout",
            "online_docker_without_vcs buildx build",
            "Windows helper bootstrap OCI layout changed during the build",
            "maintenance-normalize-certified-oci",
            "online_image_provenance verify-load",
        ),
        "Windows-helper certification transaction",
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
        "Windows-helper certification transaction",
    )

    promotion = function_block(
        source,
        "maintenance_promote_win_helper_certified_candidate",
    )
    require_all(
        promotion,
        (
            "win-helper-certified-candidate.docker.tar.gz",
            'final="$directory/win-helper.docker.tar.gz"',
            '[ ! -e "$final" ] && [ ! -L "$final" ]',
            "win_helper_image_spec_args",
            '--archive-sha "$SHA256_WIN_HELPER_IMAGE_ARCHIVE"',
            '--archive-size "$WIN_HELPER_IMAGE_ARCHIVE_SIZE"',
            "maintenance-rename-noreplace",
            "online_image_provenance verify-load",
        ),
        "Windows-helper exact-pin promotion",
    )
    require_order(
        promotion,
        (
            '[ ! -e "$final" ] && [ ! -L "$final" ]',
            "online_image_provenance verify-archive",
            "maintenance-rename-noreplace",
            "online_image_provenance verify-load",
        ),
        "Windows-helper exact-pin promotion",
    )

    bootstrap_capture = function_block(
        source,
        "maintenance_capture_win_helper_bootstrap_image",
    )
    require_all(
        bootstrap_capture,
        (
            "win-helper-bootstrap.docker.tar.gz",
            "win_helper_bootstrap_spec_args",
            "maintenance-capture",
        ),
        "Windows-helper bootstrap capture",
    )
    require_absent(
        bootstrap_capture,
        ("win-helper.docker.tar.gz", "win_helper_image_spec_args"),
        "Windows-helper bootstrap capture",
    )
    require_absent(
        source,
        (
            "verify_or_load_builder_image() {",
            "build_windows_helper_image() {",
            "capture_windows_helper_image() {",
            "maintenance_capture_windows_helper_image() {",
            "--maintenance-capture-windows-helper-image)",
        ),
        "retired generic Windows-helper authority surfaces",
    )
    require_all(
        source,
        (
            "--maintenance-build-win-helper-certified-candidate)",
            "maintenance_build_win_helper_certified_candidate",
            "--maintenance-promote-win-helper-certified-candidate)",
            "maintenance_promote_win_helper_certified_candidate",
            "--maintenance-capture-win-helper-bootstrap-image)",
            "maintenance_capture_win_helper_bootstrap_image",
        ),
        "Windows-helper maintenance entry points",
    )


def validate_library(source: str) -> None:
    block = function_block(source, "require_pinned_builder_image")
    require_all(
        block,
        (
            'win-helper) prefix=WIN_HELPER; base="ubuntu:24.04@',
            '|| [ "$role" = win-helper ]; then',
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
        "ordinary certified Windows-helper runtime verifier",
    )


def validate_runtime(source: str) -> None:
    verifier = function_block(source, "windows_helper_verify_archive")
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
        "Windows-helper archive verifier",
    )
    resolver = function_block(source, "windows_helper_runtime_resolve")
    require_count(
        resolver,
        'windows_helper_verify_archive "$archive"',
        2,
        "Windows-helper archive pre/post verification",
    )
    require_all(
        resolver,
        (
            "require_pinned_builder_image win-helper "
            '"$WIN_HELPER_IMAGE_ID"',
            "confined Windows helper kernel derivation failed",
            "Windows helper image archive changed during kernel derivation",
        ),
        "Windows-helper runtime resolver",
    )
    require_order(
        resolver,
        (
            'windows_helper_verify_archive "$archive"',
            "require_pinned_builder_image win-helper",
            "windows-helper-extract-kernel.py",
            'windows_helper_verify_archive "$archive"',
        ),
        "Windows-helper runtime resolver",
    )
    require_absent(
        resolver,
        (
            "win-helper-bootstrap",
            "win-helper-certified-candidate",
            "verify_sha256",
        ),
        "Windows-helper runtime resolver",
    )


def validate_provenance(source: str) -> None:
    attestation = python_function_block(
        source,
        "validate_certified_builder_attestation",
    )
    local = python_function_block(source, "verify_local")
    fixture = python_function_block(
        source,
        "create_certified_builder_fixture_archive",
    )
    require_all(
        source,
        (
            "WIN_HELPER_CERTIFICATION_EXPORT_NAME =",
            '"rd-win-helper-certified:authenticated-v1"',
            "WIN_HELPER_CERTIFICATION_EXPORT_OCI_NAME =",
            "WIN_HELPER_ENV = [",
            'if self.role == "win-helper":',
            'return "Windows helper"',
            'return "win-helper-bootstrap"',
            'return "WIN_HELPER"',
            "return WIN_HELPER_CERTIFICATION_EXPORT_NAME",
            "return WIN_HELPER_CERTIFICATION_EXPORT_OCI_NAME",
            "return WIN_HELPER_ENV",
            'range(20, 45) if self.role == "win-helper"',
            'if self.role in {"android-builder", "win-helper"}:',
            'return ("olefile",) if self.role == "win-helper" else ()',
            'if args.role in {"android-builder", "deb-builder", "win-helper"}:',
            'r"|win-helper-bootstrap(?:-candidate)?"',
            '"win-helper-bootstrap",',
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
            '"win-helper",',
            "canonicalize_certified_builder_oci_export(",
            "create_certified_builder_fixture_archive(",
            "win_spec = create_certified_builder_fixture_archive(\n"
            "            win_archive,\n"
            '            role="win-helper",\n'
            "        )",
            "certified Windows helper image self-test count differs",
            "if requires_private_archive(spec):",
            "stat.S_IMODE(before.st_mode) != 0o400",
            "publish_existing_archive_noreplace(",
            "renameat2",
            "RENAME_NOREPLACE",
        ),
        "certified Windows-helper provenance authority",
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
        local,
        (
            "spec.runtime_python_modules",
            '/usr/bin/python3 -c \\"import $module\\"',
        ),
        "certified Windows-helper runtime module verifier",
    )
    require_all(
        fixture,
        (
            '"win-helper": "Dockerfile.win-helper-certify"',
            "preliminary.source_location_lines",
            "preliminary.runtime_environment",
            "preliminary.argument_prefix",
            "preliminary.bootstrap_context_name",
        ),
        "generalized certified builder fixtures",
    )
    require_absent(
        source,
        (
            "CertifiedWindowsHelperSpec",
            "prepare_certified_windows_helper_oci_export",
            "canonicalize_certified_windows_helper_oci_export",
        ),
        "parallel Windows-only provenance abstraction",
    )


def validate_contract(sources: dict[str, str]) -> None:
    validate_pins(sources["pins"])
    validate_dockerfile(sources["dockerfile"], sources["pins"])
    validate_online_fetch(sources["online"])
    validate_library(sources["lib"])
    validate_runtime(sources["runtime"])
    validate_provenance(sources["provenance"])
    for name, label in (
        ("build", "Windows build"),
        ("provision", "Windows provision"),
        ("golden", "Windows golden verifier"),
    ):
        require_count(
            sources[name],
            'windows_helper_runtime_resolve '
            '"$ONLINE_DIR/build-images/win-helper.docker.tar.gz"',
            1,
            f"{label} final helper archive",
        )
    require_all(
        sources["verify"],
        (
            "/usr/bin/python3 -I -S "
            "scripts/verify-win-helper-image-authority.py "
            "--repo . --self-test",
        ),
        "shared verifier wiring",
    )
    require_all(
        sources["workspace"],
        (
            "validate_deb_builder_image_authority_contract(sources)\n"
            "    validate_win_helper_image_authority_contract(sources)\n"
            "    validate_android_keystore_authority_contract(sources)",
            '"win_helper_image_authority_verifier": (',
            'repo / "scripts/verify-win-helper-image-authority.py"',
            "Windows helper image authority focused verifier",
        ),
        "independent workspace verifier",
    )
    require_all(
        sources["requirements"],
        (
            '<span class="id">R-S11dc</span>',
            "<tr><td>256</td>",
        ),
        "normative Windows-helper image authority",
    )
    require_all(
        sources["hardening"],
        (
            "R-S11dc/R-S11e-121 — authenticated Windows helper image "
            "distribution authority",
            "CLEAN EXACT-COMMIT R-B2/R-B10 RELEASE",
        ),
        "Windows-helper image hardening ledger",
    )


MUTATIONS = (
    Mutation(
        "dockerfile",
        "FROM win-helper-bootstrap",
        "FROM ubuntu:24.04",
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
        "RUN --network=none ",
        "RUN --network=default ",
        "networkless certification",
    ),
    Mutation(
        "dockerfile",
        "/usr/bin/python3 -c 'import olefile'",
        "/usr/bin/true",
        "Python MSI parser",
    ),
    Mutation(
        "dockerfile",
        "virt-cat virt-ls",
        "virt-cat",
        "runtime tool fingerprint",
    ),
    Mutation(
        "pins",
        EXPECTED_PINS["SHA256_WIN_HELPER_DOCKERFILE"],
        "9" * 64,
        "bootstrap recipe pin",
    ),
    Mutation(
        "pins",
        EXPECTED_PINS["SHA256_WIN_HELPER_DPKG_MANIFEST"],
        "a" * 64,
        "package-manifest pin",
    ),
    Mutation(
        "pins",
        EXPECTED_PINS["SHA256_WIN_HELPER_CERTIFICATION_DOCKERFILE"],
        "b" * 64,
        "certification recipe pin",
    ),
    Mutation(
        "pins",
        'SOURCE_DATE_EPOCH_PIN="1700000000"',
        'SOURCE_DATE_EPOCH_PIN="1700000001"',
        "source-date epoch pin",
    ),
    Mutation(
        "pins",
        EXPECTED_PINS["WIN_HELPER_BOOTSTRAP_IMAGE_ID"],
        "sha256:" + "0" * 64,
        "bootstrap image pin",
    ),
    Mutation(
        "pins",
        EXPECTED_PINS["WIN_HELPER_BOOTSTRAP_CONFIG_ID"],
        "sha256:" + "1" * 64,
        "bootstrap config pin",
    ),
    Mutation(
        "pins",
        EXPECTED_PINS["WIN_HELPER_BOOTSTRAP_MANIFEST_ID"],
        "sha256:" + "2" * 64,
        "bootstrap manifest pin",
    ),
    Mutation(
        "pins",
        EXPECTED_PINS["SHA256_WIN_HELPER_BOOTSTRAP_IMAGE_ARCHIVE"],
        "3" * 64,
        "bootstrap archive pin",
    ),
    Mutation(
        "pins",
        'WIN_HELPER_BOOTSTRAP_IMAGE_ARCHIVE_SIZE="982288329"',
        'WIN_HELPER_BOOTSTRAP_IMAGE_ARCHIVE_SIZE="982288330"',
        "bootstrap archive size",
    ),
    Mutation(
        "pins",
        EXPECTED_PINS["SHA256_WIN_HELPER_BOOTSTRAP_OCI_LAYOUT"],
        "4" * 64,
        "bootstrap OCI layout pin",
    ),
    Mutation(
        "pins",
        EXPECTED_PINS["WIN_HELPER_IMAGE_ID"],
        "sha256:" + "5" * 64,
        "final image pin",
    ),
    Mutation(
        "pins",
        EXPECTED_PINS["WIN_HELPER_CONFIG_ID"],
        "sha256:" + "6" * 64,
        "final config pin",
    ),
    Mutation(
        "pins",
        EXPECTED_PINS["WIN_HELPER_MANIFEST_ID"],
        "sha256:" + "7" * 64,
        "final manifest pin",
    ),
    Mutation(
        "pins",
        EXPECTED_PINS["SHA256_WIN_HELPER_IMAGE_ARCHIVE"],
        "8" * 64,
        "final archive pin",
    ),
    Mutation(
        "pins",
        'WIN_HELPER_IMAGE_ARCHIVE_SIZE="982289690"',
        'WIN_HELPER_IMAGE_ARCHIVE_SIZE="982289691"',
        "final archive size",
    ),
    Mutation(
        "online",
        "--role win-helper \\",
        "--role win-helper-bootstrap \\",
        "final certification role",
    ),
    Mutation(
        "online",
        '--dockerfile-sha "$SHA256_WIN_HELPER_CERTIFICATION_DOCKERFILE"',
        '--dockerfile-sha "$SHA256_WIN_HELPER_DOCKERFILE"',
        "certification recipe pin",
    ),
    Mutation(
        "online",
        '--recipe-sha "$SHA256_WIN_HELPER_DOCKERFILE"',
        '--recipe-sha "$SHA256_WIN_HELPER_CERTIFICATION_DOCKERFILE"',
        "bootstrap recipe pin",
    ),
    Mutation(
        "online",
        '--bootstrap-image-id "$WIN_HELPER_BOOTSTRAP_IMAGE_ID"',
        '--bootstrap-image-id "$WIN_HELPER_IMAGE_ID"',
        "bootstrap material identity",
    ),
    Mutation(
        "online",
        "    verify_or_load_win_helper_image\n",
        "    verify_or_load_builder_image\n",
        "final-only loader",
    ),
    Mutation(
        "online",
        "--role win-helper-bootstrap-candidate",
        "--role win-helper",
        "bootstrap-only network build",
    ),
    Mutation(
        "online",
        "--network=none --pull=false --no-cache \\\n"
        "            --platform=linux/amd64 --provenance=mode=max \\\n"
        '            --output="type=oci,name=${export_name},'
        "dest=${candidate_oci},tar=true,compression=gzip,"
        'oci-mediatypes=true,rewrite-timestamp=true" \\\n'
        "            --build-context \\\n"
        '            "win-helper-bootstrap=oci-layout://${layout}@'
        '${WIN_HELPER_BOOTSTRAP_IMAGE_ID}"',
        "--network=default --pull=false --no-cache \\\n"
        "            --platform=linux/amd64 --provenance=mode=max \\\n"
        '            --output="type=oci,name=${export_name},'
        "dest=${candidate_oci},tar=true,compression=gzip,"
        'oci-mediatypes=true,rewrite-timestamp=true" \\\n'
        "            --build-context \\\n"
        '            "win-helper-bootstrap=oci-layout://${layout}@'
        '${WIN_HELPER_BOOTSTRAP_IMAGE_ID}"',
        "certification build network",
    ),
    Mutation(
        "online",
        "--network=none --pull=false --no-cache \\\n"
        "            --platform=linux/amd64 --provenance=mode=max \\\n"
        '            --output="type=oci,name=${export_name},'
        "dest=${candidate_oci},tar=true,compression=gzip,"
        'oci-mediatypes=true,rewrite-timestamp=true" \\\n'
        "            --build-context \\\n"
        '            "win-helper-bootstrap=oci-layout://${layout}@'
        '${WIN_HELPER_BOOTSTRAP_IMAGE_ID}"',
        "--network=none --pull=false --no-cache \\\n"
        "            --platform=linux/amd64 --provenance=mode=min \\\n"
        '            --output="type=oci,name=${export_name},'
        "dest=${candidate_oci},tar=true,compression=gzip,"
        'oci-mediatypes=true,rewrite-timestamp=true" \\\n'
        "            --build-context \\\n"
        '            "win-helper-bootstrap=oci-layout://${layout}@'
        '${WIN_HELPER_BOOTSTRAP_IMAGE_ID}"',
        "complete provenance",
    ),
    Mutation(
        "online",
        "win-helper-bootstrap=oci-layout://${layout}@"
        "${WIN_HELPER_BOOTSTRAP_IMAGE_ID}",
        "win-helper-bootstrap=docker-image://win-helper-bootstrap",
        "local descriptor-verified bootstrap",
    ),
    Mutation(
        "online",
        "online_image_provenance maintenance-normalize-certified-oci \\\n"
        '            --input "$candidate_oci" \\\n'
        '            --output "$candidate_archive" \\\n'
        '            "${contract_args[@]}"\n'
        '    )" || die "certified Windows helper candidate OCI '
        'normalization failed"',
        "online_image_provenance maintenance-capture \\\n"
        '            --input "$candidate_oci" \\\n'
        '            --output "$candidate_archive" \\\n'
        '            "${contract_args[@]}"\n'
        '    )" || die "certified Windows helper candidate OCI '
        'normalization failed"',
        "direct OCI canonicalization",
    ),
    Mutation(
        "online",
        "maintenance_promote_win_helper_certified_candidate() {",
        "maintenance_promote_windows_helper_tag() {",
        "exact promotion",
    ),
    Mutation(
        "online",
        "maintenance_capture_win_helper_bootstrap_image() {",
        "maintenance_capture_windows_helper_image() {",
        "bootstrap-only capture",
    ),
    Mutation(
        "lib",
        '|| [ "$role" = win-helper ]; then',
        "; then",
        "certified ordinary runtime branch",
    ),
    Mutation(
        "runtime",
        'windows_helper_verify_archive "$archive" \\\n'
        '        || die "pinned Windows helper image archive provenance '
        'verification failed"',
        'verify_sha256 "$archive" "$SHA256_WIN_HELPER_IMAGE_ARCHIVE" \\\n'
        '        || die "pinned Windows helper image archive provenance '
        'verification failed"',
        "structural archive precondition",
    ),
    Mutation(
        "runtime",
        '--archive-size "$WIN_HELPER_IMAGE_ARCHIVE_SIZE"',
        '--archive-size "$WIN_HELPER_BOOTSTRAP_IMAGE_ARCHIVE_SIZE"',
        "runtime archive size",
    ),
    Mutation(
        "runtime",
        '--dockerfile-sha "$SHA256_WIN_HELPER_CERTIFICATION_DOCKERFILE"',
        '--dockerfile-sha "$SHA256_WIN_HELPER_DOCKERFILE"',
        "runtime certification graph",
    ),
    Mutation(
        "runtime",
        "require_pinned_builder_image win-helper "
        '"$WIN_HELPER_IMAGE_ID"',
        "true # certified local image check removed",
        "local runtime fingerprint",
    ),
    Mutation(
        "build",
        'windows_helper_runtime_resolve '
        '"$ONLINE_DIR/build-images/win-helper.docker.tar.gz"',
        'windows_helper_runtime_resolve '
        '"$ONLINE_DIR/build-images/win-helper-bootstrap.docker.tar.gz"',
        "Windows build final archive",
    ),
    Mutation(
        "provision",
        'windows_helper_runtime_resolve '
        '"$ONLINE_DIR/build-images/win-helper.docker.tar.gz"',
        'windows_helper_runtime_resolve '
        '"$ONLINE_DIR/build-images/win-helper-bootstrap.docker.tar.gz"',
        "Windows provision final archive",
    ),
    Mutation(
        "golden",
        'windows_helper_runtime_resolve '
        '"$ONLINE_DIR/build-images/win-helper.docker.tar.gz"',
        'windows_helper_runtime_resolve '
        '"$ONLINE_DIR/build-images/win-helper-bootstrap.docker.tar.gz"',
        "Windows golden final archive",
    ),
    Mutation(
        "provenance",
        'return ("olefile",) if self.role == "win-helper" else ()',
        "return ()",
        "Windows Python module fingerprint",
    ),
    Mutation(
        "provenance",
        'range(20, 45) if self.role == "win-helper"',
        "range(20, 44)",
        "Windows source-location graph",
    ),
    Mutation(
        "provenance",
        '"win-helper": "Dockerfile.win-helper-certify"',
        '"win-helper": "Dockerfile.win-helper"',
        "Windows behavioral fixture recipe",
    ),
    Mutation(
        "provenance",
        "win_spec = create_certified_builder_fixture_archive(\n"
        "            win_archive,\n"
        '            role="win-helper",\n'
        "        )",
        "win_spec = create_certified_builder_fixture_archive(\n"
        "            win_archive,\n"
        '            role="android-builder",\n'
        "        )",
        "Windows behavioral fixture dispatch",
    ),
    Mutation(
        "verify",
        "scripts/verify-win-helper-image-authority.py "
        "--repo . --self-test",
        "scripts/verify-win-helper-image-authority.py --repo .",
        "focused mutation gate",
    ),
    Mutation(
        "workspace",
        "validate_deb_builder_image_authority_contract(sources)\n"
        "    validate_win_helper_image_authority_contract(sources)\n"
        "    validate_android_keystore_authority_contract(sources)",
        "validate_deb_builder_image_authority_contract(sources)\n"
        "    true # Windows helper workspace contract removed\n"
        "    validate_android_keystore_authority_contract(sources)",
        "workspace dispatch",
    ),
    Mutation(
        "requirements",
        '<span class="id">R-S11dc</span>',
        '<span class="id">R-S11dc-disabled</span>',
        "normative requirement",
    ),
    Mutation(
        "requirements",
        "<tr><td>256</td>",
        "<tr><td>256-disabled</td>",
        "Appendix disposition",
    ),
    Mutation(
        "hardening",
        "R-S11dc/R-S11e-121 — authenticated Windows helper image "
        "distribution authority",
        "R-S11dc/R-S11e-121 — unauthenticated Windows helper tag authority",
        "hardening ledger",
    ),
)


def load_sources(repo: pathlib.Path) -> dict[str, str]:
    paths = {
        "dockerfile": "scripts/Dockerfile.win-helper-certify",
        "pins": "scripts/pins.env",
        "online": "scripts/online-fetch.sh",
        "lib": "scripts/lib.sh",
        "runtime": "scripts/windows-helper-runtime.sh",
        "build": "scripts/build-windows-vm.sh",
        "provision": "scripts/provision-windows-vm.sh",
        "golden": "scripts/verify-windows-golden.sh",
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
    print(f"verify-win-helper-image-authority: OK{suffix}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AuthorityError, OSError) as error:
        print(f"verify-win-helper-image-authority: {error}")
        raise SystemExit(1)
