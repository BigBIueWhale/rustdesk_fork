#!/usr/bin/env python3
"""Bind Android builder distribution to one authenticated offline image."""

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


def validate_dockerfile(source: str, pins: str) -> None:
    require(
        hashlib.sha256(source.encode("utf-8")).hexdigest()
        == pin_value(pins, "SHA256_ANDROID_BUILDER_CERTIFICATION_DOCKERFILE"),
        "certification Dockerfile bytes differ from their pin",
    )
    require_count(source, "FROM ", 1, "certification base cardinality")
    require_count(source, "RUN --network=none ", 1, "certification execution")
    require_count(source, "USER 1000:1000", 1, "certification identity")
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
            "LC_ALL=C /usr/bin/dpkg-query -W",
            "/usr/local/share/rustdesk-build-provenance/dpkg-manifest.tsv",
            "/usr/local/share/rustdesk-build-provenance/contract-v1",
            "contract=rustdesk-build-image-v1",
            "role=android-builder",
            "base=ubuntu:24.04@sha256:"
            "786a8b558f7be160c6c8c4a54f9a57274f3b4fb1491cf65146521ae77ff1dc54",
            "org.rustdesk.builder-certification.contract="
            '"rustdesk-builder-certification-v1"',
            "org.rustdesk.builder-certification.bootstrap-image-id="
            '"${ANDROID_BUILDER_BOOTSTRAP_IMAGE_ID}"',
            "org.rustdesk.builder-certification.bootstrap-manifest-id="
            '"${ANDROID_BUILDER_BOOTSTRAP_MANIFEST_ID}"',
            "org.rustdesk.builder-certification.recipe-sha256="
            '"${ANDROID_BUILDER_RECIPE_SHA256}"',
            "org.rustdesk.builder-certification.dpkg-manifest-sha256="
            '"${ANDROID_BUILDER_DPKG_MANIFEST_SHA256}"',
            "org.rustdesk.builder-certification.source-date-epoch="
            '"${SOURCE_DATE_EPOCH}"',
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
            "apt ",
            "sudo ",
            "curl ",
            "git clone",
        ),
        "certification Dockerfile",
    )


def validate_pins(source: str) -> None:
    for name, expected in EXPECTED_PINS.items():
        actual = pin_value(source, name)
        require(actual == expected, f"{name} differs from the reviewed identity")


def validate_online_fetch(source: str) -> None:
    no_vcs = function_block(source, "online_docker_without_vcs")
    require_all(
        no_vcs,
        (
            "env -i",
            "DOCKER_HOST=\"$ONLINE_FETCH_DOCKER_HOST\"",
            "DOCKER_CONFIG=\"$ONLINE_FETCH_DOCKER_CONFIG\"",
            "BUILDX_GIT_INFO=false",
            '"$DOCKER_BIN"',
            '--host "$ONLINE_FETCH_DOCKER_HOST"',
            '--config "$ONLINE_FETCH_DOCKER_CONFIG"',
            "assert_online_fetch_docker_authority",
        ),
        "fixed Docker client without VCS hints",
    )

    contract_args = function_block(
        source,
        "android_builder_certification_spec_args",
    )
    require_all(
        contract_args,
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
        "certified Android builder contract",
    )
    final_args = function_block(source, "android_builder_image_spec_args")
    require_all(
        final_args,
        (
            '--expected-id "$ANDROID_BUILDER_IMAGE_ID"',
            "android_builder_certification_spec_args",
        ),
        "pinned certified Android builder specification",
    )
    require_absent(
        contract_args,
        ("--expected-id",),
        "candidate-derived Android builder identity",
    )
    bootstrap_args = function_block(
        source,
        "android_builder_bootstrap_spec_args",
    )
    require_all(
        bootstrap_args,
        (
            "--role android-builder-bootstrap",
            '--expected-id "$ANDROID_BUILDER_BOOTSTRAP_IMAGE_ID"',
            '--dockerfile-sha "$SHA256_ANDROID_BUILDER_DOCKERFILE"',
            '--dpkg-sha "$SHA256_ANDROID_BUILDER_DPKG_MANIFEST"',
            '--config-id "$ANDROID_BUILDER_BOOTSTRAP_CONFIG_ID"',
            '--manifest-id "$ANDROID_BUILDER_BOOTSTRAP_MANIFEST_ID"',
        ),
        "exact Android builder bootstrap specification",
    )

    loader = function_block(source, "verify_or_load_android_builder_image")
    require_all(
        loader,
        (
            "require_android_builder_image_pins",
            "android_builder_image_spec_args",
            "verify-load",
            '"$ONLINE_DIR/build-images/android-builder.docker.tar.gz"',
            '--archive-sha "$SHA256_ANDROID_BUILDER_IMAGE_ARCHIVE"',
            '--archive-size "$ANDROID_BUILDER_IMAGE_ARCHIVE_SIZE"',
            "verify-local",
            '--image-ref "$ANDROID_BUILDER_IMAGE_ID"',
        ),
        "release Android builder loader",
    )
    require_absent(
        loader,
        (
            "BOOTSTRAP_IMAGE_ARCHIVE",
            "android_builder_bootstrap_spec_args",
            "android-builder-bootstrap.docker.tar.gz",
            "docker tag",
        ),
        "release Android builder loader",
    )

    bootstrap_builder = function_block(
        source,
        "build_android_builder_bootstrap_image",
    )
    require_all(
        bootstrap_builder,
        (
            "online_docker build",
            "--role android-builder-bootstrap-candidate",
            "ANDROID_BUILDER_BOOTSTRAP_IMAGE_ID",
        ),
        "networked bootstrap acquisition",
    )
    require_absent(
        bootstrap_builder,
        (
            "--role android-builder ",
            "ANDROID_BUILDER_IMAGE_ID=",
        ),
        "networked bootstrap acquisition",
    )
    require_absent(
        source,
        ("build_android_builder_image() {",),
        "retired self-authorizing Android builder path",
    )

    certification = function_block(
        source,
        "maintenance_build_android_builder_certified_candidate",
    )
    require_all(
        certification,
        (
            "android-builder-bootstrap.docker.tar.gz",
            'local candidate_archive="$directory/'
            'android-builder-certified-candidate.docker.tar.gz"',
            '"$FLOCK_BIN" --exclusive --nonblock "$lock_fd"',
            "Dockerfile.android-builder-certify",
            "materialize-oci-layout",
            '--archive-sha "$SHA256_ANDROID_BUILDER_BOOTSTRAP_IMAGE_ARCHIVE"',
            '--archive-size "$ANDROID_BUILDER_BOOTSTRAP_IMAGE_ARCHIVE_SIZE"',
            '--output "$layout"',
            "SHA256_ANDROID_BUILDER_BOOTSTRAP_OCI_LAYOUT",
            "online_docker_without_vcs buildx build",
            "umask 077",
            "--network=none --pull=false --no-cache",
            "--platform=linux/amd64 --provenance=mode=max",
            '--output="type=oci,name=${export_name},dest=${candidate_oci},'
            "tar=true,compression=gzip,oci-mediatypes=true,"
            'rewrite-timestamp=true"',
            "android-builder-bootstrap=oci-layout://${layout}@"
            "${ANDROID_BUILDER_BOOTSTRAP_IMAGE_ID}",
            "--build-arg \"ANDROID_BUILDER_BOOTSTRAP_IMAGE_ID="
            "${ANDROID_BUILDER_BOOTSTRAP_IMAGE_ID}\"",
            "--build-arg \"ANDROID_BUILDER_BOOTSTRAP_MANIFEST_ID="
            "${ANDROID_BUILDER_BOOTSTRAP_MANIFEST_ID}\"",
            "--build-arg \"ANDROID_BUILDER_RECIPE_SHA256="
            "${SHA256_ANDROID_BUILDER_DOCKERFILE}\"",
            "--build-arg \"ANDROID_BUILDER_DPKG_MANIFEST_SHA256="
            "${SHA256_ANDROID_BUILDER_DPKG_MANIFEST}\"",
            '--build-arg "SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH_PIN}"',
            "android_builder_certification_spec_args",
            "maintenance-normalize-certified-oci",
            '--input "$candidate_oci"',
            "android-builder-certified-candidate.docker.tar.gz",
            "verify-load",
            '--archive-sha "$archive_sha"',
            '--archive-size "$archive_size"',
        ),
        "networkless certification transaction",
    )

    promotion = function_block(
        source,
        "maintenance_promote_android_builder_certified_candidate",
    )
    require_all(
        promotion,
        (
            "require_android_builder_image_pins",
            "android-builder-certified-candidate.docker.tar.gz",
            'final="$directory/android-builder.docker.tar.gz"',
            '"$FLOCK_BIN" --exclusive --nonblock "$lock_fd"',
            "android_builder_image_spec_args",
            "verify-archive",
            '--archive-sha "$SHA256_ANDROID_BUILDER_IMAGE_ARCHIVE"',
            '--archive-size "$ANDROID_BUILDER_IMAGE_ARCHIVE_SIZE"',
            "maintenance-rename-noreplace",
            '--source "$candidate"',
            '--destination "$final"',
            "verify-load",
        ),
        "exact-pin certified Android builder promotion",
    )
    require_order(
        promotion,
        (
            "verify-archive",
            "maintenance-rename-noreplace",
            "verify-load",
        ),
        "certified Android builder promotion order",
    )
    require_absent(
        promotion,
        (
            "maintenance-capture",
            "docker save",
            "docker tag",
            "rm -f",
            "mv ",
        ),
        "exact-pin certified Android builder promotion",
    )

    generic_capture = function_block(
        source,
        "maintenance_capture_windows_helper_image",
    )
    require_absent(
        generic_capture,
        (
            "ANDROID_BUILDER",
            "android-builder",
            "capture_android_builder_image",
        ),
        "non-Android legacy builder capture",
    )
    require_absent(
        source,
        ("capture_android_builder_image() {",),
        "retired Docker-store Android builder capture",
    )
    require_all(
        source,
        (
            "--maintenance-promote-android-builder-certified-candidate)\n",
            "maintenance_promote_android_builder_certified_candidate\n"
            "            return 0",
        ),
        "certified Android builder promotion entry point",
    )
    require_count(
        certification,
        "verify-oci-layout",
        2,
        "pre/post OCI-layout verification",
    )
    require_order(
        certification,
        (
            "materialize-oci-layout",
            "layout_sha=",
            "verify-oci-layout",
            "online_docker_without_vcs buildx build",
            "verify-oci-layout",
            "maintenance-normalize-certified-oci",
            "verify-load",
        ),
        "certification transaction order",
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


def validate_library(source: str) -> None:
    block = function_block(source, "require_pinned_builder_image")
    require_all(
        block,
        (
            "android-builder) prefix=ANDROID_BUILDER;",
            '[ "$role" = android-builder ] || [ "$role" = deb-builder ]',
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
        ),
        "ordinary Android builder runtime verifier",
    )


def validate_provenance(source: str) -> None:
    try:
        ast.parse(source)
    except SyntaxError as error:
        raise AuthorityError(
            f"offline image provenance helper does not parse: {error}"
        ) from error
    require_all(
        source,
        (
            "class CertifiedBuilderSpec:",
            "ANDROID_BUILDER_CERTIFICATION_EXPORT_NAME = (\n"
            '    "rd-android-builder-certified:authenticated-v1"\n'
            ")",
            "def requires_private_archive(spec: ImageSpec) -> bool:",
            'if args.role in {"android-builder", "deb-builder"}:',
            '"android-builder-bootstrap",',
            "f\"certified {spec.display_name} runtime config differs from \"",
            "if contains_vcs_authority(statement):\n"
            "        fail(\n"
            "            f\"Docker archive certified {spec.display_name} "
            "provenance contains \"",
            "provenance contains undeclared VCS authority",
            "resolvedDependencies",
            'context_key = "context:" + spec.bootstrap_context_name',
            "force-network-mode",
            "frontend.caps",
            "source_info.get(\"llbDefinition\") != expected_source_llb",
            "if hashlib.sha256(dockerfile).hexdigest() "
            "!= spec.dockerfile_sha256:\n"
            "        fail(\n"
            "            f\"Docker archive certified {spec.display_name} "
            "Dockerfile differs \"",
            "if len(source_runs) != 1 or source_runs[0][0] != \"none\":",
            '"args": ["/bin/sh", "-c", source_runs[0][1]],\n'
            '                        "cwd": "/",\n'
            '                        "env": expected_environment,\n'
            '                        "removeMountStubsRecursive": True,\n'
            '                        "user": "1000:1000",',
            '"network": 2',
            '"mounts": [{"dest": "/"}]',
            "the exact one-step numeric-nonroot networkless graph",
            ") and len(attestations) != 1:",
            "must contain exactly one provenance attestation",
            "if requires_private_archive(spec):\n"
            "        if before.st_uid != os.getuid() or "
            "before.st_gid != os.getgid():\n"
            "            fail(f\"{spec.role} image archive must be owned by "
            "the invoking identity\")\n"
            "        if stat.S_IMODE(before.st_mode) != 0o400:",
            "must be owned by the invoking identity",
            "must be mode 0400",
            "requires a positive exact size",
            "def verify_oci_layout(",
            "def materialize_oci_layout(",
            "OCI layout output root must be empty",
            "for position, member in enumerate(archive):\n"
            "                    if position >= 4096:\n"
            '                        fail("OCI layout archive exceeds the member bound")',
            "if extracted_bytes > 8 * 1024 * 1024 * 1024:",
            "flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC\n"
            "                    if hasattr(os, \"O_NOFOLLOW\"):\n"
            "                        flags |= os.O_NOFOLLOW\n"
            "                    try:\n"
            "                        output_file_fd = os.open(",
            "and digest.hexdigest() != target_name:",
            "OCI layout blob does not match its name",
            "os.fchmod(output_file_fd, 0o400)",
            "os.fsync(output_file_fd)",
            "os.fchmod(sha_fd, 0o500)",
            "return verify_oci_layout(output)",
            "class DirectOciExport:",
            "def scan_direct_oci_export(",
            '"direct certified builder OCI export verification "\n'
            '            "refuses root execution"',
            "stat.S_IMODE(before.st_mode) != 0o600:",
            '"direct certified builder OCI export must be "\n'
            '                "current-user-owned mode 0600"',
            "if position >= 4096:\n"
            "                        fail(\n"
            "                            \"direct certified builder "
            "OCI export \"",
            "if expanded_bytes > 8 * 1024 * 1024 * 1024:",
            "if sequence != expected_sequence:",
            "blob does not match its name",
            "def prepare_certified_builder_oci_export(",
            "or not isinstance(descriptors, list) \\\n"
            "       or len(descriptors) != 1 \\\n"
            "       or not isinstance(descriptors[0], dict):\n"
            "        fail(\n"
            "            \"direct certified builder OCI export must "
            "name exactly \"",
            '"io.containerd.image.name": (\n'
            "            contract.export_oci_name",
            '"org.opencontainers.image.created": created',
            '"org.opencontainers.image.ref.name": (',
            "does not match the named private exporter contract",
            "canonical_metadata[\"manifest.json\"] = "
            "compatibility_manifest",
            "validate_modern_archive(",
            "def canonicalize_certified_builder_oci_export(",
            "format=tarfile.USTAR_FORMAT",
            '"direct certified builder OCI export changed "\n'
            '                    "between validation and normalization"',
            "verify_archive(temporary, archive_sha, spec, count)",
            "rename_noreplace(temporary, output)",
            "verify_archive(output, archive_sha, spec, count)",
            "def publish_existing_archive_noreplace(",
            "renameat2(RENAME_NOREPLACE)",
            "parent_fd = open_private_directory(\n"
            "        source.parent,\n"
            "        0o700,\n"
            '        "image archive publication directory",\n'
            "    )",
            "certified Android builder archive hash",
            "certified Android builder archive size",
            "certified Android builder VCS attribution",
            "certified Android builder networked execution",
            "certified Android builder root execution",
            "certified Android builder registry context",
            "certified Android builder material identity",
            "certified Android builder layer mapping",
            "certified Android builder missing attestation",
            "certified Android builder extra operation",
            "certified Android builder direct OCI extra root referrer",
            "certified Android builder direct OCI exporter name",
            "certified Android builder normalized archive no-clobber",
            "if android_checks != 39:",
            'subparsers.add_parser("materialize-oci-layout")',
            'subparsers.add_parser("verify-oci-layout")',
            '"maintenance-normalize-certified-oci"',
            'subparsers.add_parser("maintenance-rename-noreplace")',
        ),
        "offline image provenance authority",
    )
    preparation_start = source.index(
        "def prepare_certified_builder_oci_export("
    )
    preparation_end = source.index(
        "\ndef deterministic_tar_info(",
        preparation_start,
    )
    preparation = source[preparation_start:preparation_end]
    require_absent(
        preparation,
        (
            '"annotations": expected_annotations',
            "RepoTags\": [",
        ),
        "normalized certified Android builder archive authority",
    )
    runtime_start = source.index(
        "if isinstance(spec, CertifiedBuilderSpec):",
        source.index("def verify_local("),
    )
    runtime_end = source.index(
        "if isinstance(spec, AppleCheckSpec):",
        runtime_start,
    )
    runtime = source[runtime_start:runtime_end]
    require_all(
        runtime,
        (
            '"--pull=never"',
            '"--network=none"',
            '"--read-only"',
            '"1000:1000"',
            '"--cap-drop=ALL"',
            '"--security-opt=no-new-privileges"',
            '"--pids-limit=32"',
            '"--memory=256m"',
            '"--memory-swap=256m"',
            '"--cpus=1"',
            "/tmp:rw,noexec,nosuid,nodev,mode=1777,size=16m",
        ),
        "certified Android builder runtime fingerprint",
    )
    require_absent(
        runtime,
        (
            '"--network=bridge"',
            '"--privileged"',
            '"--cap-add"',
            "docker.sock",
            '"0:0"',
        ),
        "certified Android builder runtime fingerprint",
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
            "scripts/verify-android-builder-image-authority.py "
            "--repo . --self-test",
        ),
        "shared verifier wiring",
    )
    require_all(
        sources["workspace"],
        (
            "validate_android_builder_authority_contract(sources)\n"
            "    validate_android_builder_image_authority_contract(sources)\n"
            "    validate_deb_builder_image_authority_contract(sources)\n"
            "    validate_android_keystore_authority_contract(sources)",
            '"android_builder_image_authority_verifier": (',
            'repo / "scripts/verify-android-builder-image-authority.py"',
            "Android builder image authority focused verifier",
        ),
        "independent workspace verifier",
    )
    require_all(
        sources["requirements"],
        (
            '<span class="id">R-S11da</span>',
            "<tr><td>254</td>",
        ),
        "normative Android builder image authority",
    )
    require_all(
        sources["hardening"],
        (
            "R-S11da/R-S11e-119 — authenticated Android builder image "
            "distribution authority",
            "CLEAN EXACT-COMMIT R-B2/R-B10 RELEASE",
        ),
        "Android builder image hardening ledger",
    )


MUTATIONS = (
    Mutation(
        "dockerfile",
        "FROM android-builder-bootstrap",
        "FROM ubuntu:24.04",
        "exact bootstrap base",
    ),
    Mutation(
        "dockerfile",
        "USER 1000:1000",
        "USER 0:0",
        "numeric nonroot build/runtime identity",
    ),
    Mutation(
        "dockerfile",
        "RUN --network=none set -eu;",
        "RUN --network=default set -eu;",
        "Dockerfile networklessness",
    ),
    Mutation(
        "dockerfile",
        '$(/usr/bin/id -u):$(/usr/bin/id -g)" = "1000:1000"',
        '$(/usr/bin/id -u):$(/usr/bin/id -g)" = "0:0"',
        "live build identity assertion",
    ),
    Mutation(
        "dockerfile",
        "org.rustdesk.builder-certification.bootstrap-image-id=",
        "org.rustdesk.builder-certification.unbound-bootstrap-image-id=",
        "bootstrap identity label",
    ),
    Mutation(
        "pins",
        EXPECTED_PINS["ANDROID_BUILDER_BOOTSTRAP_IMAGE_ID"],
        "sha256:" + "0" * 64,
        "bootstrap image pin",
    ),
    Mutation(
        "pins",
        EXPECTED_PINS["ANDROID_BUILDER_BOOTSTRAP_MANIFEST_ID"],
        "sha256:" + "1" * 64,
        "bootstrap manifest pin",
    ),
    Mutation(
        "pins",
        EXPECTED_PINS["SHA256_ANDROID_BUILDER_BOOTSTRAP_IMAGE_ARCHIVE"],
        "2" * 64,
        "bootstrap archive pin",
    ),
    Mutation(
        "pins",
        'ANDROID_BUILDER_BOOTSTRAP_IMAGE_ARCHIVE_SIZE="467527003"',
        'ANDROID_BUILDER_BOOTSTRAP_IMAGE_ARCHIVE_SIZE="467527004"',
        "bootstrap archive size",
    ),
    Mutation(
        "pins",
        EXPECTED_PINS["SHA256_ANDROID_BUILDER_BOOTSTRAP_OCI_LAYOUT"],
        "3" * 64,
        "bootstrap layout pin",
    ),
    Mutation(
        "pins",
        EXPECTED_PINS["ANDROID_BUILDER_IMAGE_ID"],
        "sha256:" + "4" * 64,
        "certified image pin",
    ),
    Mutation(
        "pins",
        EXPECTED_PINS["ANDROID_BUILDER_CONFIG_ID"],
        "sha256:" + "5" * 64,
        "certified config pin",
    ),
    Mutation(
        "pins",
        EXPECTED_PINS["ANDROID_BUILDER_MANIFEST_ID"],
        "sha256:" + "6" * 64,
        "certified manifest pin",
    ),
    Mutation(
        "pins",
        EXPECTED_PINS["SHA256_ANDROID_BUILDER_IMAGE_ARCHIVE"],
        "7" * 64,
        "certified archive pin",
    ),
    Mutation(
        "pins",
        'ANDROID_BUILDER_IMAGE_ARCHIVE_SIZE="467499398"',
        'ANDROID_BUILDER_IMAGE_ARCHIVE_SIZE="467499399"',
        "certified archive size",
    ),
    Mutation(
        "online",
        "BUILDX_GIT_INFO=false",
        "BUILDX_GIT_INFO=true",
        "unverified VCS suppression",
    ),
    Mutation(
        "online",
        "--role android-builder-bootstrap-candidate",
        "--role android-builder",
        "bootstrap candidate role separation",
    ),
    Mutation(
        "online",
        '"$ONLINE_DIR/build-images/android-builder.docker.tar.gz"',
        '"$ONLINE_DIR/build-images/android-builder-bootstrap.docker.tar.gz"',
        "release loader archive selection",
    ),
    Mutation(
        "online",
        'online_image_provenance verify-load \\\n'
        '        --archive "$ONLINE_DIR/build-images/'
        'android-builder.docker.tar.gz" \\\n'
        '        --archive-sha "$SHA256_ANDROID_BUILDER_IMAGE_ARCHIVE" \\\n'
        '        --archive-size "$ANDROID_BUILDER_IMAGE_ARCHIVE_SIZE"',
        'online_image_provenance verify-load \\\n'
        '        --archive "$ONLINE_DIR/build-images/'
        'android-builder.docker.tar.gz" \\\n'
        '        --archive-sha "$SHA256_ANDROID_BUILDER_IMAGE_ARCHIVE" \\\n'
        "        true # exact certified archive size removed",
        "release archive size binding",
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
        "            \"android-builder-bootstrap=oci-layout://${layout}@"
        "${ANDROID_BUILDER_BOOTSTRAP_IMAGE_ID}\"",
        "online_docker_without_vcs buildx build \\\n"
        "            --network=default --pull=true \\\n"
        "            --platform=linux/amd64 --provenance=mode=max \\\n"
        "            --output=\"type=oci,name=${export_name},"
        "dest=${candidate_oci},tar=true,compression=gzip,"
        "oci-mediatypes=true,rewrite-timestamp=true\" \\\n"
        "            --build-context \\\n"
        "            \"android-builder-bootstrap=oci-layout://${layout}@"
        "${ANDROID_BUILDER_BOOTSTRAP_IMAGE_ID}\"",
        "certification network/pull/cache boundary",
    ),
    Mutation(
        "online",
        "--platform=linux/amd64 --provenance=mode=max \\\n"
        "            --output=\"type=oci,name=${export_name},"
        "dest=${candidate_oci},tar=true,compression=gzip,"
        "oci-mediatypes=true,rewrite-timestamp=true\" \\\n"
        "            --build-context \\\n"
        "            \"android-builder-bootstrap=oci-layout://${layout}@"
        "${ANDROID_BUILDER_BOOTSTRAP_IMAGE_ID}\"",
        "--platform=linux/amd64 --provenance=mode=min \\\n"
        "            --output=\"type=oci,name=${export_name},"
        "dest=${candidate_oci},tar=true,compression=gzip,"
        "oci-mediatypes=true,rewrite-timestamp=true\" \\\n"
        "            --build-context \\\n"
        "            \"android-builder-bootstrap=oci-layout://${layout}@"
        "${ANDROID_BUILDER_BOOTSTRAP_IMAGE_ID}\"",
        "mode-max provenance",
    ),
    Mutation(
        "online",
        '--output="type=oci,name=${export_name},dest=${candidate_oci},'
        "tar=true,compression=gzip,oci-mediatypes=true,"
        'rewrite-timestamp=true" \\\n'
        "            --build-context \\\n"
        "            \"android-builder-bootstrap=oci-layout://${layout}@"
        "${ANDROID_BUILDER_BOOTSTRAP_IMAGE_ID}\"",
        '--output="type=docker,name=${export_name},dest=${candidate_oci},'
        "tar=true,compression=gzip,oci-mediatypes=true,"
        'rewrite-timestamp=false" \\\n'
        "            --build-context \\\n"
        "            \"android-builder-bootstrap=oci-layout://${layout}@"
        "${ANDROID_BUILDER_BOOTSTRAP_IMAGE_ID}\"",
        "isolated deterministic OCI output policy",
    ),
    Mutation(
        "online",
        "android-builder-bootstrap=oci-layout://${layout}@"
        "${ANDROID_BUILDER_BOOTSTRAP_IMAGE_ID}",
        "android-builder-bootstrap=docker-image://"
        "${ANDROID_BUILDER_BOOTSTRAP_IMAGE_ID}",
        "local OCI-layout material",
    ),
    Mutation(
        "online",
        "online_image_provenance verify-oci-layout \\\n"
        "        --layout \"$layout\" \\\n"
        "        --layout-sha \"$SHA256_ANDROID_BUILDER_BOOTSTRAP_OCI_LAYOUT\" "
        "\\\n        >/dev/null \\\n"
        "        || die \"Android builder bootstrap OCI layout changed during "
        "the build\"",
        "true # post-build OCI-layout proof removed",
        "post-build layout stability",
    ),
    Mutation(
        "online",
        "mapfile -d '' contract_args < "
        "<(android_builder_certification_spec_args)\n"
        "    result=\"$(\n"
        "        online_image_provenance "
        "maintenance-normalize-certified-oci \\\n"
        "            --input \"$candidate_oci\" \\\n"
        "            --output \"$candidate_archive\"",
        "mapfile -d '' contract_args < "
        "<(android_builder_certification_spec_args)\n"
        "    result=\"$(\n"
        "        printf 'image_id=sha256:"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "\\nsha256=unchecked\\nbytes=1\\n'",
        "candidate direct OCI semantic normalization",
    ),
    Mutation(
        "online",
        "candidate_args=(--expected-id \"$image_id\" "
        "\"${contract_args[@]}\")\n"
        "    online_image_provenance verify-load \\\n"
        "        --archive \"$candidate_archive\" \\\n"
        "        --archive-sha \"$archive_sha\" \\\n"
        "        --archive-size \"$archive_size\" \\\n"
        "        \"${candidate_args[@]}\" \\\n"
        "        || die \"certified Android builder candidate load/runtime "
        "verification failed\"",
        "candidate_args=(--expected-id \"$image_id\" "
        "\"${contract_args[@]}\")\n"
        "    true # candidate archive load/runtime proof removed\n"
        "        || die \"certified Android builder candidate load/runtime "
        "verification failed\"",
        "candidate loaded runtime fingerprint",
    ),
    Mutation(
        "online",
        'local candidate_archive="$directory/'
        'android-builder-certified-candidate.docker.tar.gz"',
        'local candidate_archive="$ONLINE_FETCH_TMP/'
        'android-builder-certified-candidate.docker.tar.gz"',
        "persistent no-clobber certified candidate publication",
    ),
    Mutation(
        "online",
        "online_image_provenance verify-archive \\\n"
        "        --archive \"$candidate\" \\\n"
        "        --archive-sha \"$SHA256_ANDROID_BUILDER_IMAGE_ARCHIVE\" \\\n"
        "        --archive-size \"$ANDROID_BUILDER_IMAGE_ARCHIVE_SIZE\"",
        "true # exact candidate pin verification removed",
        "exact-pin candidate promotion",
    ),
    Mutation(
        "online",
        "maintenance_capture_windows_helper_image() {\n"
        "    local names=(",
        "maintenance_capture_windows_helper_image() {\n"
        "    local ANDROID_BUILDER_IMAGE_ID=unreviewed\n"
        "    local names=(",
        "generic Android Docker-store capture absence",
    ),
    Mutation(
        "online",
        "maintenance_promote_android_builder_certified_candidate\n"
        "            return 0",
        "true # certified Android builder promotion entry point removed\n"
        "            return 0",
        "certified candidate promotion wiring",
    ),
    Mutation(
        "lib",
        '--dockerfile-sha "${!certification_dockerfile_var}"',
        '--dockerfile-sha "$dockerfile_sha"',
        "ordinary runtime certification recipe",
    ),
    Mutation(
        "lib",
        '--bootstrap-image-id "${!bootstrap_image_var}"',
        "--bootstrap-image-id sha256:"
        "0000000000000000000000000000000000000000000000000000000000000000",
        "ordinary runtime bootstrap material",
    ),
    Mutation(
        "provenance",
        "if contains_vcs_authority(statement):\n"
        "        fail(\n"
        "            f\"Docker archive certified {spec.display_name} "
        "provenance contains \"",
        "if False:\n"
        "        fail(\n"
        "            f\"Docker archive certified {spec.display_name} "
        "provenance contains \"",
        "VCS-hint rejection",
    ),
    Mutation(
        "provenance",
        "if hashlib.sha256(dockerfile).hexdigest() "
        "!= spec.dockerfile_sha256:\n"
        "        fail(\n"
        "            f\"Docker archive certified {spec.display_name} "
        "Dockerfile differs \"",
        "if False:\n"
        "        fail(\n"
        "            f\"Docker archive certified {spec.display_name} "
        "Dockerfile differs \"",
        "embedded Dockerfile binding",
    ),
    Mutation(
        "provenance",
        'if len(source_runs) != 1 or source_runs[0][0] != "none":',
        "if False:",
        "embedded execution network contract",
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
        "if requires_private_archive(spec):\n"
        "        if before.st_uid != os.getuid() or "
        "before.st_gid != os.getgid():\n"
        "            fail(f\"{spec.role} image archive must be owned by "
        "the invoking identity\")\n"
        "        if stat.S_IMODE(before.st_mode) != 0o400:",
        "if requires_private_archive(spec):\n"
        "        if before.st_uid != os.getuid() or "
        "before.st_gid != os.getgid():\n"
        "            fail(f\"{spec.role} image archive must be owned by "
        "the invoking identity\")\n"
        "        if stat.S_IMODE(before.st_mode) != 0o600:",
        "private archive mode",
    ),
    Mutation(
        "provenance",
        "parent_fd = open_private_directory(\n"
        "        source.parent,\n"
        "        0o700,\n"
        '        "image archive publication directory",\n'
        "    )",
        "parent_fd = os.open(source.parent, os.O_RDONLY)",
        "publication directory descriptor identity",
    ),
    Mutation(
        "provenance",
        "for position, member in enumerate(archive):\n"
        "                    if position >= 4096:\n"
        '                        fail("OCI layout archive exceeds the member bound")',
        "for position, member in enumerate(archive):\n"
        "                    if position >= 40960:\n"
        '                        fail("OCI layout archive exceeds the member bound")',
        "materializer member bound",
    ),
    Mutation(
        "provenance",
        "if extracted_bytes > 8 * 1024 * 1024 * 1024:",
        "if extracted_bytes > 80 * 1024 * 1024 * 1024:",
        "materializer byte bound",
    ),
    Mutation(
        "provenance",
        "flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC\n"
        "                    if hasattr(os, \"O_NOFOLLOW\"):\n"
        "                        flags |= os.O_NOFOLLOW\n"
        "                    try:\n"
        "                        output_file_fd = os.open(",
        "flags = os.O_WRONLY | os.O_CREAT | os.O_CLOEXEC\n"
        "                    if hasattr(os, \"O_NOFOLLOW\"):\n"
        "                        flags |= os.O_NOFOLLOW\n"
        "                    try:\n"
        "                        output_file_fd = os.open(",
        "exclusive materialization",
    ),
    Mutation(
        "provenance",
        "and digest.hexdigest() != target_name:",
        "and False:",
        "materialized blob-name identity",
    ),
    Mutation(
        "provenance",
        "ANDROID_BUILDER_CERTIFICATION_EXPORT_NAME = (\n"
        '    "rd-android-builder-certified:authenticated-v1"\n'
        ")",
        "ANDROID_BUILDER_CERTIFICATION_EXPORT_NAME = (\n"
        '    "unreviewed:latest"\n'
        ")",
        "direct OCI provenance subject name",
    ),
    Mutation(
        "provenance",
        "or stat.S_IMODE(before.st_mode) != 0o600:\n"
        "            fail(\n"
        "                \"direct certified builder OCI export must be \"",
        "or stat.S_IMODE(before.st_mode) != 0o666:\n"
        "            fail(\n"
        "                \"direct certified builder OCI export must be \"",
        "private direct OCI export mode",
    ),
    Mutation(
        "provenance",
        "or not isinstance(descriptors, list) \\\n"
        "       or len(descriptors) != 1 \\\n"
        "       or not isinstance(descriptors[0], dict):\n"
        "        fail(\n"
        "            \"direct certified builder OCI export must name "
        "exactly \"",
        "or not isinstance(descriptors, list) \\\n"
        "       or len(descriptors) < 1 \\\n"
        "       or not isinstance(descriptors[0], dict):\n"
        "        fail(\n"
        "            \"direct certified builder OCI export must name "
        "exactly \"",
        "direct OCI sole-root/referrer rejection",
    ),
    Mutation(
        "provenance",
        '"size": len(image_index_bytes),\n'
        "                }\n"
        "            ],",
        '"size": len(image_index_bytes),\n'
        '                    "annotations": expected_annotations,\n'
        "                }\n"
        "            ],",
        "normalized root annotation removal",
    ),
    Mutation(
        "provenance",
        "if expanded_bytes > 8 * 1024 * 1024 * 1024:\n"
        "                        fail(\n"
        "                            \"direct certified builder OCI "
        "export \"",
        "if expanded_bytes > 80 * 1024 * 1024 * 1024:\n"
        "                        fail(\n"
        "                            \"direct certified builder OCI "
        "export \"",
        "direct OCI expanded-content bound",
    ),
    Mutation(
        "provenance",
        "if android_checks != 39:",
        "if android_checks != 38:",
        "adversarial fixture count",
    ),
    Mutation(
        "verify",
        "/usr/bin/python3 -I -S "
        "scripts/verify-android-builder-image-authority.py "
        "--repo . --self-test",
        "true # Android builder image authority gate removed",
        "shared verifier wiring",
    ),
    Mutation(
        "workspace",
        "validate_android_builder_authority_contract(sources)\n"
        "    validate_android_builder_image_authority_contract(sources)\n"
        "    validate_deb_builder_image_authority_contract(sources)\n"
        "    validate_android_keystore_authority_contract(sources)",
        "validate_android_builder_authority_contract(sources)\n"
        "    true # Android builder image workspace contract removed\n"
        "    validate_deb_builder_image_authority_contract(sources)\n"
        "    validate_android_keystore_authority_contract(sources)",
        "independent workspace dispatch",
    ),
    Mutation(
        "requirements",
        '<span class="id">R-S11da</span>',
        '<span class="id">R-S11da-disabled</span>',
        "normative requirement",
    ),
    Mutation(
        "requirements",
        "<tr><td>254</td>",
        "<tr><td>254-disabled</td>",
        "Appendix disposition",
    ),
    Mutation(
        "hardening",
        "R-S11da/R-S11e-119 — authenticated Android builder image "
        "distribution authority",
        "R-S11da/R-S11e-119 — unauthenticated Android builder tag authority",
        "hardening ledger",
    ),
)


def load_sources(repo: pathlib.Path) -> dict[str, str]:
    paths = {
        "dockerfile": "scripts/Dockerfile.android-builder-certify",
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
    print(f"verify-android-builder-image-authority: OK{suffix}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AuthorityError, OSError) as error:
        print(f"verify-android-builder-image-authority: {error}")
        raise SystemExit(1)
