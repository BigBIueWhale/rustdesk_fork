#!/usr/bin/env python3
"""Verify and capture immutable offline builder images."""

from __future__ import annotations

import argparse
import ctypes
import errno
import gzip
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
from dataclasses import dataclass, replace
from pathlib import Path
from typing import BinaryIO, Callable, Union


CONTRACT = "rustdesk-build-image-v1"
LABEL_PREFIX = "org.rustdesk.build-input."
HEX256 = re.compile(r"[0-9a-f]{64}\Z")
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
PACKAGE = re.compile(rb"[a-z0-9][a-z0-9+.-]*(?::[a-z0-9][a-z0-9-]*)?\Z")
DOCKER = "/usr/bin/docker"
RENAME_NOREPLACE = 1
DEV_CHECK_ENV = [
    "PATH=/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "RUSTUP_HOME=/usr/local/rustup",
    "CARGO_HOME=/usr/local/cargo",
    "RUST_VERSION=1.75.0",
    "SODIUM_USE_PKG_CONFIG=1",
]


class ProvenanceError(RuntimeError):
    pass


@dataclass(frozen=True)
class Spec:
    role: str
    image_id: str
    base: str
    dockerfile_sha256: str
    dpkg_sha256: str

    @property
    def capture_tag(self) -> str:
        return f"rustdesk-offline/{self.role}:provenance-v1"

    @property
    def labels(self) -> dict[str, str]:
        return {
            LABEL_PREFIX + "contract": CONTRACT,
            LABEL_PREFIX + "role": self.role,
            LABEL_PREFIX + "base": self.base,
            LABEL_PREFIX + "dockerfile-sha256": self.dockerfile_sha256,
            LABEL_PREFIX + "dpkg-manifest-sha256": self.dpkg_sha256,
        }

    def contract_bytes(self) -> bytes:
        return (
            f"contract={CONTRACT}\n"
            f"role={self.role}\n"
            f"base={self.base}\n"
            f"dockerfile_sha256={self.dockerfile_sha256}\n"
            f"dpkg_manifest_sha256={self.dpkg_sha256}\n"
        ).encode("ascii")


@dataclass(frozen=True)
class VerifierSpec:
    role: str
    image_id: str
    base: str
    dockerfile_sha256: str
    dpkg_sha256: str
    cargo_sha256: str
    rustc_sha256: str
    source_commit: str
    source_repository: str
    config_id: str
    manifest_id: str

    @property
    def archive_tags(self) -> None:
        return None

    @property
    def root_annotations(self) -> dict[str, str]:
        return {"containerd.io/distribution.source.docker.io": "library/rd-devcheck"}


ImageSpec = Union[Spec, VerifierSpec]


def fail(message: str) -> None:
    raise ProvenanceError(message)


def require_sha(value: str, label: str) -> str:
    if not HEX256.fullmatch(value):
        fail(f"{label} must be exactly 64 lowercase hexadecimal characters")
    return value


def require_image_id(value: str, label: str) -> str:
    if not IMAGE_ID.fullmatch(value):
        fail(f"{label} must be sha256: followed by 64 lowercase hexadecimal characters")
    return value


def spec_from_args(args: argparse.Namespace) -> ImageSpec:
    if args.role == "devcheck":
        if not re.fullmatch(r"rust:1[.]75-slim@sha256:[0-9a-f]{64}", args.base):
            fail("devcheck base image identity is malformed or unsupported")
        if not re.fullmatch(r"[0-9a-f]{40}", args.source_commit or ""):
            fail("devcheck source commit must be exactly 40 lowercase hexadecimal characters")
        if not re.fullmatch(r"https://github[.]com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+[.]git", args.source_repository or ""):
            fail("devcheck source repository is malformed or unsupported")
        return VerifierSpec(
            role=args.role,
            image_id=require_image_id(args.expected_id, "expected image ID"),
            base=args.base,
            dockerfile_sha256=require_sha(args.dockerfile_sha, "Dockerfile SHA-256"),
            dpkg_sha256=require_sha(args.dpkg_sha, "dpkg manifest SHA-256"),
            cargo_sha256=require_sha(args.cargo_sha or "", "Cargo SHA-256"),
            rustc_sha256=require_sha(args.rustc_sha or "", "rustc SHA-256"),
            source_commit=args.source_commit,
            source_repository=args.source_repository,
            config_id=require_image_id(args.config_id or "", "devcheck config ID"),
            manifest_id=require_image_id(args.manifest_id or "", "devcheck manifest ID"),
        )
    if not re.fullmatch(r"(?:deb|android)-builder|win-helper", args.role):
        fail(f"unsupported builder image role: {args.role}")
    if not re.fullmatch(r"ubuntu:(?:18[.]04|24[.]04)@sha256:[0-9a-f]{64}", args.base):
        fail("base image identity is malformed or unsupported")
    return Spec(
        role=args.role,
        image_id=require_image_id(args.expected_id, "expected image ID"),
        base=args.base,
        dockerfile_sha256=require_sha(args.dockerfile_sha, "Dockerfile SHA-256"),
        dpkg_sha256=require_sha(args.dpkg_sha, "dpkg manifest SHA-256"),
    )


def run(command: list[str], *, input_stream: BinaryIO | None = None) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            command,
            stdin=input_stream,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as exc:
        fail(f"cannot execute {command[0]}: {exc}")


def inspect_image(image_ref: str) -> dict[str, object]:
    result = run([DOCKER, "image", "inspect", image_ref])
    if result.returncode != 0:
        fail(f"docker image inspect failed for {image_ref}: {result.stderr.decode(errors='replace').strip()}")
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        fail(f"docker image inspect returned malformed JSON: {exc}")
    if not isinstance(payload, list) or len(payload) != 1 or not isinstance(payload[0], dict):
        fail("docker image inspect must return exactly one image object")
    return payload[0]


def validate_inspect(payload: dict[str, object], image_ref: str, spec: ImageSpec) -> None:
    if payload.get("Id") != spec.image_id:
        fail(f"image reference {image_ref} resolves to {payload.get('Id')!r}, expected {spec.image_id}")
    config = payload.get("Config")
    if not isinstance(config, dict):
        fail("image inspect Config is absent or malformed")
    if isinstance(spec, VerifierSpec):
        if payload.get("Os") != "linux" or payload.get("Architecture") != "amd64":
            fail("devcheck image platform must be exactly linux/amd64")
        if config.get("User") not in (None, ""):
            fail("devcheck image has an unexpected default user")
        if config.get("Env") != DEV_CHECK_ENV:
            fail("devcheck image environment differs from the reviewed contract")
        if config.get("Cmd") != ["bash"]:
            fail("devcheck image command differs from the reviewed contract")
        if config.get("Labels") not in (None, {}):
            fail("devcheck image has unexpected labels")
        return
    labels = config.get("Labels")
    if not isinstance(labels, dict):
        fail("image provenance labels are absent")
    for name, expected in spec.labels.items():
        if labels.get(name) != expected:
            fail(f"image label {name} mismatch: expected {expected!r}, got {labels.get(name)!r}")


def validate_package_manifest(manifest: bytes) -> str:
    if not manifest or not manifest.endswith(b"\n") or b"\r" in manifest or b"\0" in manifest:
        fail("installed-package manifest is empty or not canonical LF-terminated text")
    lines = manifest.splitlines(keepends=True)
    if b"".join(lines) != manifest:
        fail("installed-package manifest has non-canonical line structure")
    previous: bytes | None = None
    packages: set[bytes] = set()
    for raw_line in lines:
        line = raw_line[:-1]
        fields = line.split(b"\t")
        if len(fields) != 2 or not PACKAGE.fullmatch(fields[0]):
            fail(f"malformed installed-package manifest line: {line!r}")
        version = fields[1]
        if not version or any(byte < 0x21 or byte > 0x7E for byte in version):
            fail(f"malformed package version in installed-package manifest: {line!r}")
        if fields[0] in packages:
            fail(f"duplicate installed package: {fields[0].decode('ascii')}")
        if previous is not None and previous >= line:
            fail("installed-package manifest is not sorted bytewise")
        previous = line
        packages.add(fields[0])
    return hashlib.sha256(manifest).hexdigest()


def verify_local(image_ref: str, spec: ImageSpec) -> None:
    if os.getuid() == 0 or os.getgid() == 0:
        fail("local image provenance verification refuses root execution")
    validate_inspect(inspect_image(image_ref), image_ref, spec)
    if isinstance(spec, VerifierSpec):
        command = (
            "set -euo pipefail; "
            "[ \"$(id -u)\" -ne 0 ] && [ \"$(id -g)\" -ne 0 ]; "
            "printf 'rustc=%s\\n' \"$(rustc --version)\"; "
            "printf 'cargo=%s\\n' \"$(cargo --version)\"; "
            "cargo_sha=\"$(sha256sum /usr/local/cargo/bin/cargo)\"; cargo_sha=\"${cargo_sha%% *}\"; "
            "rustc_sha=\"$(sha256sum /usr/local/rustup/toolchains/1.75.0-x86_64-unknown-linux-gnu/bin/rustc)\"; "
            "rustc_sha=\"${rustc_sha%% *}\"; "
            "dpkg_sha=\"$(dpkg-query -W | LC_ALL=C sort | sha256sum)\"; dpkg_sha=\"${dpkg_sha%% *}\"; "
            "printf 'cargo-sha=%s\\n' \"$cargo_sha\"; "
            "printf 'rustc-sha=%s\\n' \"$rustc_sha\"; "
            "printf 'dpkg-sha=%s\\n' \"$dpkg_sha\"; "
            "printf 'sodium=%s\\n' \"${SODIUM_USE_PKG_CONFIG-}\""
        )
        result = run(
            [
                DOCKER,
                "run",
                "--rm",
                "--pull=never",
                "--network=none",
                "--read-only",
                "--user",
                f"{os.getuid()}:{os.getgid()}",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "--pids-limit=32",
                "--memory=256m",
                "--memory-swap=256m",
                "--cpus=1",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,nodev,mode=1777,size=16m",
                "--env",
                "RUSTUP_TOOLCHAIN=1.75.0",
                spec.image_id,
                "/bin/bash",
                "-c",
                command,
            ]
        )
        if result.returncode != 0:
            fail(
                "cannot verify devcheck runtime contents: "
                + result.stderr.decode(errors="replace").strip()
            )
        expected = (
            "rustc=rustc 1.75.0 (82e1608df 2023-12-21)\n"
            "cargo=cargo 1.75.0 (1d8b05cdd 2023-11-20)\n"
            f"cargo-sha={spec.cargo_sha256}\n"
            f"rustc-sha={spec.rustc_sha256}\n"
            f"dpkg-sha={spec.dpkg_sha256}\n"
            "sodium=1\n"
        ).encode("ascii")
        if result.stdout != expected or result.stderr:
            fail("devcheck runtime fingerprint differs from the reviewed pins")
        return
    command = (
        "set -eu; "
        "p=/usr/local/share/rustdesk-build-provenance; "
        "cat \"$p/contract-v1\"; printf '\\0'; "
        "cat \"$p/dpkg-manifest.tsv\"; printf '\\0'; "
        "dpkg-query -W -f='${binary:Package}\\t${Version}\\n' | LC_ALL=C sort; printf '\\0'; "
        "cat \"$p/Dockerfile\""
    )
    result = run(
        [
            DOCKER,
            "run",
            "--rm",
            "--pull=never",
            "--network=none",
            "--read-only",
            "--user",
            f"{os.getuid()}:{os.getgid()}",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--pids-limit=64",
            "--memory=512m",
            "--memory-swap=512m",
            "--cpus=1",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,nodev,mode=1777,size=32m",
            "--entrypoint",
            "/bin/sh",
            spec.image_id,
            "-c",
            command,
        ]
    )
    if result.returncode != 0:
        fail(f"cannot read embedded provenance from {spec.image_id}: {result.stderr.decode(errors='replace').strip()}")
    parts = result.stdout.split(b"\0")
    if len(parts) != 4:
        fail("embedded image provenance output is malformed")
    contract, stored_manifest, live_manifest, dockerfile = parts
    if contract != spec.contract_bytes():
        fail("embedded image provenance contract is absent, malformed, or stale")
    stored_sha = validate_package_manifest(stored_manifest)
    live_sha = validate_package_manifest(live_manifest)
    if stored_manifest != live_manifest or stored_sha != spec.dpkg_sha256 or live_sha != spec.dpkg_sha256:
        fail("embedded and live installed-package manifests do not equal the audited pin")
    if hashlib.sha256(dockerfile).hexdigest() != spec.dockerfile_sha256:
        fail("embedded Dockerfile bytes do not equal the audited pin")


class HashingReader:
    def __init__(self, stream: BinaryIO):
        self.stream = stream
        self.digest = hashlib.sha256()

    def read(self, size: int = -1) -> bytes:
        data = self.stream.read(size)
        self.digest.update(data)
        return data

    def readable(self) -> bool:
        return True


def validate_archive_name(name: str, seen: set[str], folded: set[str]) -> None:
    try:
        encoded = name.encode("ascii")
    except UnicodeEncodeError:
        fail(f"Docker archive has a non-ASCII member: {name!r}")
    if not encoded or encoded.startswith(b"/") or b"\\" in encoded or b":" in encoded:
        fail(f"Docker archive has an unsafe member: {name!r}")
    components = encoded.rstrip(b"/").split(b"/")
    if any(component in (b"", b".", b"..") for component in components):
        fail(f"Docker archive has an ambiguous or traversing member: {name!r}")
    if any(any(byte < 0x20 or byte > 0x7E for byte in component) for component in components):
        fail(f"Docker archive has unsupported path bytes: {name!r}")
    canonical = encoded.rstrip(b"/").decode("ascii")
    if canonical in seen:
        fail(f"Docker archive has a duplicate member: {canonical}")
    case_key = canonical.lower()
    if case_key in folded:
        fail(f"Docker archive has a case-colliding member: {canonical}")
    seen.add(canonical)
    folded.add(case_key)


def parse_json(data: bytes | None, label: str) -> object:
    if data is None:
        fail(f"Docker archive has no {label}")
    try:
        return json.loads(data)
    except json.JSONDecodeError as exc:
        fail(f"Docker archive {label} is malformed: {exc}")


def validate_config(config_json: object, layers: list[str], spec: ImageSpec) -> None:
    if isinstance(spec, VerifierSpec):
        if not isinstance(config_json, dict) \
           or config_json.get("architecture") != "amd64" \
           or config_json.get("os") != "linux":
            fail("Docker archive devcheck config platform is malformed")
        config = config_json.get("config")
        if not isinstance(config, dict) \
           or config.get("Env") != DEV_CHECK_ENV \
           or config.get("Cmd") != ["bash"] \
           or config.get("User") not in (None, "") \
           or config.get("Labels") not in (None, {}):
            fail("Docker archive devcheck runtime config differs from the reviewed contract")
        rootfs = config_json.get("rootfs")
        if not isinstance(rootfs, dict) or rootfs.get("type") != "layers":
            fail("Docker archive devcheck rootfs metadata is malformed")
        diff_ids = rootfs.get("diff_ids")
        if not isinstance(diff_ids, list) or len(diff_ids) != len(layers) or len(diff_ids) != 4 \
           or any(not isinstance(value, str) or not IMAGE_ID.fullmatch(value) for value in diff_ids):
            fail("Docker archive devcheck layer identities differ from the four-layer contract")
        history = config_json.get("history")
        if not isinstance(history, list) or len(history) != 7:
            fail("Docker archive devcheck history differs from the reviewed build topology")
        return
    labels = config_json.get("config", {}).get("Labels") if isinstance(config_json, dict) else None
    if not isinstance(labels, dict):
        fail("Docker archive image config has no provenance labels")
    for name, expected in spec.labels.items():
        if labels.get(name) != expected:
            fail(f"Docker archive image label {name} mismatch")
    rootfs = config_json.get("rootfs") if isinstance(config_json, dict) else None
    if not isinstance(rootfs, dict) or rootfs.get("type") != "layers":
        fail("Docker archive image config has malformed rootfs metadata")
    diff_ids = rootfs.get("diff_ids")
    if not isinstance(diff_ids, list) or len(diff_ids) != len(layers) or any(
        not isinstance(value, str) or not IMAGE_ID.fullmatch(value) for value in diff_ids
    ):
        fail("Docker archive image config layer identities do not match the manifest layer count")


def descriptor_blob(
    descriptor: object,
    metadata: dict[str, bytes],
    member_sizes: dict[str, int],
    member_hashes: dict[str, str],
    label: str,
    require_metadata: bool = True,
) -> tuple[str, bytes]:
    if not isinstance(descriptor, dict):
        fail(f"Docker archive {label} descriptor is malformed")
    digest_value = descriptor.get("digest")
    size = descriptor.get("size")
    if not isinstance(digest_value, str) or not IMAGE_ID.fullmatch(digest_value) or not isinstance(size, int) or size < 0:
        fail(f"Docker archive {label} descriptor identity is malformed")
    name = "blobs/sha256/" + digest_value.removeprefix("sha256:")
    if member_sizes.get(name) != size or member_hashes.get(name) != digest_value.removeprefix("sha256:"):
        fail(f"Docker archive {label} descriptor does not match its blob")
    value = metadata.get(name)
    if value is None and require_metadata:
        fail(f"Docker archive {label} metadata blob is absent or too large")
    return name, value or b""


def validate_verifier_attestation(
    statement: object,
    image_manifest_id: object,
    spec: VerifierSpec,
) -> None:
    expected_digest = str(image_manifest_id).removeprefix("sha256:")
    if not isinstance(statement, dict) or statement.get("subject") != [
        {
            "name": "pkg:docker/rd-devcheck@latest?platform=linux%2Famd64",
            "digest": {"sha256": expected_digest},
        }
    ]:
        fail("Docker archive devcheck provenance subject differs from the image manifest")
    predicate = statement.get("predicate")
    if not isinstance(predicate, dict):
        fail("Docker archive devcheck provenance predicate is absent")
    definition = predicate.get("buildDefinition")
    if not isinstance(definition, dict) \
       or definition.get("buildType") != (
           "https://github.com/moby/buildkit/blob/master/docs/attestations/"
           "slsa-definitions.md"
       ) \
       or definition.get("resolvedDependencies") != [
           {
               "uri": "pkg:docker/rust@1.75-slim?platform=linux%2Famd64",
               "digest": {"sha256": spec.base.rsplit("sha256:", 1)[1]},
           }
       ]:
        fail("Docker archive devcheck provenance does not bind the exact Rust base")
    external = definition.get("externalParameters")
    request = external.get("request") if isinstance(external, dict) else None
    root = request.get("root") if isinstance(request, dict) else None
    root_request = root.get("request") if isinstance(root, dict) else None
    root_args = root_request.get("args") if isinstance(root_request, dict) else None
    if not isinstance(external, dict) \
       or external.get("configSource") != {"path": "Dockerfile.devcheck"} \
       or not isinstance(request, dict) \
       or request.get("frontend") != "dockerfile.v0" \
       or request.get("locals") != [{"name": "context"}, {"name": "dockerfile"}] \
       or not isinstance(root, dict) \
       or root.get("configSource") != {"path": "Dockerfile.devcheck"} \
       or not isinstance(root_args, dict) \
       or root_args.get("vcs:localdir:context") != "scripts" \
       or root_args.get("vcs:localdir:dockerfile") != "scripts" \
       or root_args.get("vcs:revision") != spec.source_commit \
       or root_args.get("vcs:source") != spec.source_repository:
        fail("Docker archive devcheck provenance does not bind the reviewed source revision")
    internal = definition.get("internalParameters")
    if not isinstance(internal, dict) \
       or internal.get("builderPlatform") != "linux/amd64" \
       or internal.get("dockerfileVersion") != "1.25.0":
        fail("Docker archive devcheck provenance builder contract differs")
    run_details = predicate.get("runDetails")
    metadata = run_details.get("metadata") if isinstance(run_details, dict) else None
    buildkit_metadata = metadata.get("buildkit_metadata") if isinstance(metadata, dict) else None
    completeness = metadata.get("buildkit_completeness") if isinstance(metadata, dict) else None
    if not isinstance(buildkit_metadata, dict) \
       or buildkit_metadata.get("vcs") != {
           "localdir:context": "scripts",
           "localdir:dockerfile": "scripts",
           "revision": spec.source_commit,
           "source": spec.source_repository,
       } \
       or completeness != {
           "request": True,
           "resolvedDependencies": False,
       }:
        fail("Docker archive devcheck provenance metadata differs from the reviewed statement")


def validate_modern_archive(
    item: dict[str, object],
    files: set[str],
    directories: set[str],
    metadata: dict[str, bytes],
    member_sizes: dict[str, int],
    member_hashes: dict[str, str],
    spec: ImageSpec,
) -> None:
    if "repositories" in files:
        fail("content-addressed Docker archive must not contain legacy repositories metadata")
    layout = parse_json(metadata.get("oci-layout"), "oci-layout")
    if layout != {"imageLayoutVersion": "1.0.0"}:
        fail("Docker archive OCI layout version is unsupported")
    root_index = parse_json(metadata.get("index.json"), "index.json")
    expected_digest = spec.image_id
    if not isinstance(root_index, dict) or root_index.get("schemaVersion") != 2 \
       or root_index.get("mediaType") != "application/vnd.oci.image.index.v1+json":
        fail("Docker archive root OCI index is malformed")
    root_descriptors = root_index.get("manifests")
    if not isinstance(root_descriptors, list) or len(root_descriptors) != 1:
        fail("Docker archive root OCI index must name exactly one captured image")
    root_descriptor = root_descriptors[0]
    if isinstance(spec, VerifierSpec):
        expected_annotations = spec.root_annotations
    else:
        repository_name = spec.capture_tag.rsplit(":", 1)[0]
        expected_name = (
            f"docker.io/{spec.capture_tag}"
            if "/" in repository_name
            else f"docker.io/library/{spec.capture_tag}"
        )
        expected_annotations = {
            "io.containerd.image.name": expected_name,
            "org.opencontainers.image.ref.name": spec.capture_tag.rsplit(":", 1)[1],
        }
    if not isinstance(root_descriptor, dict) \
       or root_descriptor.get("mediaType") != "application/vnd.oci.image.index.v1+json" \
       or root_descriptor.get("digest") != expected_digest \
       or root_descriptor.get("annotations") != expected_annotations:
        fail("Docker archive root OCI descriptor does not bind the expected image identity")
    expected_index_name, image_index_bytes = descriptor_blob(
        root_descriptor, metadata, member_sizes, member_hashes, "image index"
    )
    image_index = parse_json(image_index_bytes, "image index blob")
    if not isinstance(image_index, dict) or image_index.get("schemaVersion") != 2 \
       or image_index.get("mediaType") != "application/vnd.oci.image.index.v1+json":
        fail("Docker archive image index blob is malformed")
    descriptors = image_index.get("manifests")
    if not isinstance(descriptors, list) or not descriptors:
        fail("Docker archive image index has no manifests")
    image_descriptors = [
        descriptor for descriptor in descriptors
        if isinstance(descriptor, dict) and descriptor.get("platform") == {"architecture": "amd64", "os": "linux"}
    ]
    if len(image_descriptors) != 1:
        fail("Docker archive must contain exactly one linux/amd64 image manifest")
    image_descriptor = image_descriptors[0]
    if image_descriptor.get("mediaType") != "application/vnd.oci.image.manifest.v1+json":
        fail("Docker archive image manifest media type is unsupported")
    if isinstance(spec, VerifierSpec) and image_descriptor.get("digest") != spec.manifest_id:
        fail("Docker archive devcheck image manifest differs from its pin")
    image_manifest_name, image_manifest_bytes = descriptor_blob(
        image_descriptor, metadata, member_sizes, member_hashes, "image manifest"
    )
    image_manifest = parse_json(image_manifest_bytes, "image manifest blob")
    if not isinstance(image_manifest, dict) or image_manifest.get("schemaVersion") != 2 \
       or image_manifest.get("mediaType") != "application/vnd.oci.image.manifest.v1+json":
        fail("Docker archive image manifest blob is malformed")
    config_descriptor = image_manifest.get("config")
    config_name, config_bytes = descriptor_blob(
        config_descriptor, metadata, member_sizes, member_hashes, "image config"
    )
    if not isinstance(config_descriptor, dict) \
       or config_descriptor.get("mediaType") != "application/vnd.oci.image.config.v1+json":
        fail("Docker archive image config media type is unsupported")
    if isinstance(spec, VerifierSpec) and config_descriptor.get("digest") != spec.config_id:
        fail("Docker archive devcheck image config differs from its pin")
    layer_descriptors = image_manifest.get("layers")
    if not isinstance(layer_descriptors, list) or not layer_descriptors:
        fail("Docker archive image manifest has no layers")
    actual_layers: list[str] = []
    expected_blobs = {expected_index_name, image_manifest_name, config_name}
    for position, descriptor in enumerate(layer_descriptors):
        if not isinstance(descriptor, dict) or descriptor.get("mediaType") != "application/vnd.oci.image.layer.v1.tar+gzip":
            fail("Docker archive image layer media type is unsupported")
        name, _ = descriptor_blob(
            descriptor,
            metadata,
            member_sizes,
            member_hashes,
            f"image layer {position}",
            require_metadata=False,
        )
        actual_layers.append(name)
        expected_blobs.add(name)
    if item.get("Config") != config_name or item.get("Layers") != actual_layers:
        fail("Docker archive compatibility manifest disagrees with the OCI image manifest")
    validate_config(parse_json(config_bytes, "image config blob"), actual_layers, spec)

    actual_digest = image_descriptor.get("digest")
    attestations = [descriptor for descriptor in descriptors if descriptor is not image_descriptor]
    if len(attestations) > 1:
        fail("Docker archive has more than one provenance attestation manifest")
    for attestation in attestations:
        if not isinstance(attestation, dict) or attestation.get("mediaType") != "application/vnd.oci.image.manifest.v1+json" \
           or attestation.get("platform") != {"architecture": "unknown", "os": "unknown"} \
           or attestation.get("annotations") != {
               "vnd.docker.reference.digest": actual_digest,
               "vnd.docker.reference.type": "attestation-manifest",
           }:
            fail("Docker archive has an undeclared non-image manifest")
        attestation_name, attestation_bytes = descriptor_blob(
            attestation, metadata, member_sizes, member_hashes, "attestation manifest"
        )
        expected_blobs.add(attestation_name)
        attestation_manifest = parse_json(attestation_bytes, "attestation manifest blob")
        if not isinstance(attestation_manifest, dict) or attestation_manifest.get("schemaVersion") != 2 \
           or attestation_manifest.get("mediaType") != "application/vnd.oci.image.manifest.v1+json":
            fail("Docker archive attestation manifest blob is malformed")
        attestation_config_name, attestation_config = descriptor_blob(
            attestation_manifest.get("config"), metadata, member_sizes, member_hashes, "attestation config"
        )
        attestation_config_descriptor = attestation_manifest.get("config")
        if not isinstance(attestation_config_descriptor, dict) \
           or attestation_config_descriptor.get("mediaType") != "application/vnd.oci.image.config.v1+json":
            fail("Docker archive attestation config media type is unsupported")
        expected_blobs.add(attestation_config_name)
        attestation_config_json = parse_json(attestation_config, "attestation config blob")
        attestation_layers = attestation_manifest.get("layers")
        if not isinstance(attestation_config_json, dict) or attestation_config_json.get("architecture") != "unknown" \
           or attestation_config_json.get("os") != "unknown" \
           or not isinstance(attestation_layers, list) or len(attestation_layers) != 1:
            fail("Docker archive attestation config or layer set is malformed")
        attestation_rootfs = attestation_config_json.get("rootfs")
        if not isinstance(attestation_rootfs, dict) or attestation_rootfs.get("type") != "layers" \
           or not isinstance(attestation_rootfs.get("diff_ids"), list) \
           or len(attestation_rootfs["diff_ids"]) != 1 \
           or not isinstance(attestation_rootfs["diff_ids"][0], str) \
           or not IMAGE_ID.fullmatch(attestation_rootfs["diff_ids"][0]):
            fail("Docker archive attestation rootfs metadata is malformed")
        attestation_layer_name, statement_bytes = descriptor_blob(
            attestation_layers[0], metadata, member_sizes, member_hashes, "attestation statement"
        )
        attestation_layer = attestation_layers[0]
        if not isinstance(attestation_layer, dict) \
           or attestation_layer.get("mediaType") != "application/vnd.in-toto+json" \
           or attestation_layer.get("annotations") != {
               "in-toto.io/predicate-type": "https://slsa.dev/provenance/v1"
           }:
            fail("Docker archive attestation statement media type or predicate annotation is unsupported")
        expected_blobs.add(attestation_layer_name)
        statement = parse_json(statement_bytes, "attestation statement blob")
        subjects = statement.get("subject") if isinstance(statement, dict) else None
        if not isinstance(statement, dict) or statement.get("_type") != "https://in-toto.io/Statement/v1" \
           or statement.get("predicateType") != "https://slsa.dev/provenance/v1" \
           or not isinstance(subjects, list) \
           or not any(isinstance(subject, dict) and subject.get("digest") == {"sha256": str(actual_digest).removeprefix("sha256:")} for subject in subjects):
            fail("Docker archive provenance attestation does not name the image manifest")
        if isinstance(spec, VerifierSpec):
            validate_verifier_attestation(statement, actual_digest, spec)
    if isinstance(spec, VerifierSpec) and len(attestations) != 1:
        fail("Docker archive devcheck image must contain exactly one provenance attestation")
    blob_files = {name for name in files if name.startswith("blobs/sha256/")}
    if blob_files != expected_blobs:
        fail("Docker archive contains an absent, duplicate, or unreferenced OCI blob")
    if files != expected_blobs | {"index.json", "manifest.json", "oci-layout"}:
        fail("Docker archive contains an unreferenced non-blob file")
    if not directories.issubset({"blobs", "blobs/sha256"}):
        fail("Docker archive contains an unreferenced directory")


def validate_legacy_archive(
    item: dict[str, object],
    files: set[str],
    directories: set[str],
    metadata: dict[str, bytes],
    member_hashes: dict[str, str],
    spec: ImageSpec,
) -> None:
    if isinstance(spec, VerifierSpec):
        fail("devcheck recovery requires the content-addressed OCI archive layout")
    expected_config = spec.image_id.removeprefix("sha256:") + ".json"
    layers = item.get("Layers")
    if item.get("Config") != expected_config or expected_config not in files:
        fail(f"Docker archive config does not identify {spec.image_id}")
    if not isinstance(layers, list) or not layers or len(layers) != len(set(layers)) \
       or any(not isinstance(layer, str) or layer not in files for layer in layers):
        fail("Docker archive layer list is absent, duplicated, or references an absent file")
    layer_directories: set[str] = set()
    expected_files = {"manifest.json", "repositories", expected_config}
    for layer in layers:
        match = re.fullmatch(r"([0-9a-f]{64})/layer[.]tar", layer)
        if match is None:
            fail("legacy Docker archive has a non-canonical layer path")
        layer_directory = match.group(1)
        layer_directories.add(layer_directory)
        expected_files.update({layer, f"{layer_directory}/VERSION", f"{layer_directory}/json"})
    if files != expected_files or not directories.issubset(layer_directories):
        fail("legacy Docker archive contains an absent or unreferenced file/directory")
    repository, tag = spec.capture_tag.rsplit(":", 1)
    top_layer = layers[-1].split("/", 1)[0]
    repositories = parse_json(metadata.get("repositories"), "repositories metadata")
    if repositories != {repository: {tag: top_layer}}:
        fail("Docker archive repositories metadata creates an undeclared tag or wrong top layer")
    if member_hashes.get(expected_config) != spec.image_id.removeprefix("sha256:"):
        fail("Docker archive config bytes do not equal the expected immutable image ID")
    validate_config(parse_json(metadata.get(expected_config), "image config"), layers, spec)


def validate_archive_stream(stream: BinaryIO, spec: ImageSpec) -> None:
    seen: set[str] = set()
    folded: set[str] = set()
    files: set[str] = set()
    directories: set[str] = set()
    metadata: dict[str, bytes] = {}
    member_sizes: dict[str, int] = {}
    member_hashes: dict[str, str] = {}
    metadata_bytes = 0
    try:
        archive = tarfile.open(fileobj=stream, mode="r|gz")
        with archive:
            for member in archive:
                validate_archive_name(member.name, seen, folded)
                canonical = member.name.rstrip("/")
                if member.isdir():
                    directories.add(canonical)
                    continue
                if not member.isfile():
                    fail(f"Docker archive member is not a regular file/directory: {member.name}")
                files.add(canonical)
                member_sizes[canonical] = member.size
                extracted = archive.extractfile(member)
                if extracted is None:
                    fail(f"cannot read Docker archive member: {member.name}")
                content_hash = hashlib.sha256()
                keep = member.size <= 16 * 1024 * 1024 and (
                    canonical in {"manifest.json", "repositories", "index.json", "oci-layout"}
                    or canonical.endswith(".json")
                    or canonical.startswith("blobs/sha256/")
                )
                value = bytearray() if keep else None
                while True:
                    block = extracted.read(1024 * 1024)
                    if not block:
                        break
                    content_hash.update(block)
                    if value is not None:
                        value += block
                member_hashes[canonical] = content_hash.hexdigest()
                if value is not None:
                    metadata_bytes += len(value)
                    if metadata_bytes > 64 * 1024 * 1024:
                        fail("Docker archive metadata exceeds the bounded parser budget")
                    metadata[canonical] = bytes(value)
    except (tarfile.TarError, EOFError, OSError) as exc:
        fail(f"malformed Docker image archive: {exc}")
    manifest = parse_json(metadata.get("manifest.json"), "manifest.json")
    if not isinstance(manifest, list) or len(manifest) != 1 or not isinstance(manifest[0], dict):
        fail("Docker archive must contain exactly one compatibility image manifest")
    item = manifest[0]
    expected_tags = spec.archive_tags if isinstance(spec, VerifierSpec) else [spec.capture_tag]
    if item.get("RepoTags") != expected_tags:
        fail(f"Docker archive tags differ from the exact contract: {expected_tags!r}")
    modern_markers = {"index.json", "oci-layout"} & files
    if modern_markers:
        if modern_markers != {"index.json", "oci-layout"}:
            fail("Docker archive has an incomplete content-addressed layout")
        validate_modern_archive(item, files, directories, metadata, member_sizes, member_hashes, spec)
    else:
        validate_legacy_archive(item, files, directories, metadata, member_hashes, spec)


def hash_open_file(stream: BinaryIO) -> str:
    digest = hashlib.sha256()
    while True:
        block = stream.read(1024 * 1024)
        if not block:
            break
        digest.update(block)
    return digest.hexdigest()


def stable_file(before: os.stat_result, after: os.stat_result, path: Path) -> None:
    fields = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(before, field) != getattr(after, field) for field in fields):
        fail(f"image archive mutated while being verified: {path}")


def verify_archive_fd(
    fd: int,
    archive_path: Path,
    expected_archive_sha: str,
    spec: ImageSpec,
    expected_archive_size: int | None = None,
) -> os.stat_result:
    expected_archive_sha = require_sha(expected_archive_sha, "image archive SHA-256")
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        fail("image archive must be one non-hardlinked regular file")
    if isinstance(spec, VerifierSpec):
        if before.st_uid != os.getuid() or before.st_gid != os.getgid():
            fail("devcheck image archive must be owned by the invoking identity")
        if stat.S_IMODE(before.st_mode) != 0o400:
            fail("devcheck image archive must be mode 0400")
        if expected_archive_size is None or expected_archive_size <= 0:
            fail("devcheck image archive requires a positive exact size")
        if before.st_size != expected_archive_size:
            fail(
                "devcheck image archive size mismatch: "
                f"expected {expected_archive_size}, got {before.st_size}"
            )
    os.lseek(fd, 0, os.SEEK_SET)
    with os.fdopen(os.dup(fd), "rb") as stream:
        first_sha = hash_open_file(stream)
    stable_file(before, os.fstat(fd), archive_path)
    if first_sha != expected_archive_sha:
        fail(f"image archive SHA-256 mismatch: expected {expected_archive_sha}, got {first_sha}")
    os.lseek(fd, 0, os.SEEK_SET)
    hashing = HashingReader(os.fdopen(os.dup(fd), "rb"))
    try:
        validate_archive_stream(hashing, spec)
    finally:
        hashing.stream.close()
    if hashing.digest.hexdigest() != expected_archive_sha:
        fail("image archive changed between byte verification and structure verification")
    stable_file(before, os.fstat(fd), archive_path)
    return before


def open_archive(archive_path: Path) -> int:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        return os.open(archive_path, flags)
    except OSError as exc:
        fail(f"cannot open image archive {archive_path}: {exc}")


def verify_archive(
    archive_path: Path,
    expected_archive_sha: str,
    spec: ImageSpec,
    expected_archive_size: int | None = None,
) -> None:
    fd = open_archive(archive_path)
    try:
        verify_archive_fd(fd, archive_path, expected_archive_sha, spec, expected_archive_size)
    finally:
        os.close(fd)


def load_archive(
    archive_path: Path,
    expected_archive_sha: str,
    spec: ImageSpec,
    expected_archive_size: int | None = None,
) -> None:
    fd = open_archive(archive_path)
    try:
        before = verify_archive_fd(
            fd,
            archive_path,
            expected_archive_sha,
            spec,
            expected_archive_size,
        )
        os.lseek(fd, 0, os.SEEK_SET)
        hashing = HashingReader(os.fdopen(os.dup(fd), "rb"))
        try:
            process = subprocess.Popen(
                [DOCKER, "load"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except OSError as exc:
            hashing.stream.close()
            fail(f"cannot execute docker load: {exc}")
        try:
            if process.stdin is None:
                fail("docker load stdin is unavailable")
            with gzip.GzipFile(fileobj=hashing, mode="rb") as decompressed:
                while True:
                    block = decompressed.read(1024 * 1024)
                    if not block:
                        break
                    process.stdin.write(block)
            process.stdin.close()
            process.stdin = None
            _, stderr = process.communicate()
        except BaseException:
            if process.stdin is not None:
                process.stdin.close()
                process.stdin = None
            process.kill()
            process.communicate()
            raise
        finally:
            hashing.stream.close()
        if process.returncode != 0:
            fail(f"docker load failed: {stderr.decode(errors='replace').strip()}")
        if hashing.digest.hexdigest() != expected_archive_sha:
            fail("image archive changed between verification and docker load")
        stable_file(before, os.fstat(fd), archive_path)
    finally:
        os.close(fd)
    verify_local(spec.image_id, spec)


def rename_noreplace(source: Path, destination: Path) -> None:
    if source.parent != destination.parent:
        fail("image archive publication must remain within one private directory")
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        parent_fd = os.open(source.parent, flags)
    except OSError as exc:
        fail(f"cannot open image archive publication directory: {exc}")
    try:
        function = getattr(ctypes.CDLL(None, use_errno=True), "renameat2", None)
        if function is None:
            fail("libc does not expose renameat2(RENAME_NOREPLACE)")
        function.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        function.restype = ctypes.c_int
        if function(
            parent_fd,
            os.fsencode(source.name),
            parent_fd,
            os.fsencode(destination.name),
            RENAME_NOREPLACE,
        ) != 0:
            error = ctypes.get_errno()
            if error == errno.EEXIST:
                fail(f"refusing to replace existing image archive: {destination}")
            fail(f"cannot publish image archive without replacement: {os.strerror(error)}")
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def validate_private_output_parent(parent: Path) -> None:
    try:
        metadata = os.lstat(parent)
    except OSError as exc:
        fail(f"cannot inspect image archive output directory {parent}: {exc}")
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        fail("image archive output parent must be one real directory")
    if metadata.st_uid != os.getuid() or metadata.st_gid != os.getgid() \
       or stat.S_IMODE(metadata.st_mode) != 0o700:
        fail("image archive output parent must be current-user-owned mode 0700")


def capture(output: Path, spec: ImageSpec) -> tuple[str, int]:
    verify_local(spec.image_id, spec)
    if output.exists() or output.is_symlink():
        fail(f"refusing to replace existing image archive: {output}")
    if isinstance(spec, VerifierSpec):
        validate_private_output_parent(output.parent)
        save_ref = spec.image_id
    else:
        output.parent.mkdir(parents=True, exist_ok=True)
        result = run([DOCKER, "tag", spec.image_id, spec.capture_tag])
        if result.returncode != 0:
            fail(f"cannot create fixed capture tag: {result.stderr.decode(errors='replace').strip()}")
        validate_inspect(inspect_image(spec.capture_tag), spec.capture_tag, spec)
        save_ref = spec.capture_tag
    temporary = output.with_name(output.name + ".part")
    if temporary.exists() or temporary.is_symlink():
        fail(f"stale image archive capture temporary exists: {temporary}")
    digest = hashlib.sha256()
    count = 0
    process = subprocess.Popen([DOCKER, "save", save_ref], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        if process.stdout is None:
            fail("docker save stdout is unavailable")
        with temporary.open("xb") as raw:
            class DigestingWriter:
                def write(self, data: bytes) -> int:
                    nonlocal count
                    digest.update(data)
                    count += len(data)
                    return raw.write(data)

                def flush(self) -> None:
                    raw.flush()

            with gzip.GzipFile(filename="", mode="wb", fileobj=DigestingWriter(), mtime=0) as compressed:
                while True:
                    block = process.stdout.read(1024 * 1024)
                    if not block:
                        break
                    compressed.write(block)
            raw.flush()
            os.fsync(raw.fileno())
        stderr = process.stderr.read() if process.stderr is not None else b""
        if process.wait() != 0:
            fail(f"docker save failed: {stderr.decode(errors='replace').strip()}")
        if isinstance(spec, VerifierSpec):
            temporary.chmod(0o400)
            archive_sha = digest.hexdigest()
            verify_archive(temporary, archive_sha, spec, count)
            rename_noreplace(temporary, output)
        else:
            os.replace(temporary, output)
    except BaseException:
        if process.poll() is None:
            process.kill()
            process.wait()
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise
    archive_sha = digest.hexdigest()
    verify_archive(
        output,
        archive_sha,
        spec,
        count if isinstance(spec, VerifierSpec) else None,
    )
    return archive_sha, count


def create_fixture_archive(path: Path, spec: Spec) -> str:
    config = {"config": {"Labels": spec.labels}, "rootfs": {"type": "layers", "diff_ids": ["sha256:" + "a" * 64]}}
    config_bytes = json.dumps(config, sort_keys=True, separators=(",", ":")).encode("ascii")
    fixture_spec = Spec(
        role=spec.role,
        image_id="sha256:" + hashlib.sha256(config_bytes).hexdigest(),
        base=spec.base,
        dockerfile_sha256=spec.dockerfile_sha256,
        dpkg_sha256=spec.dpkg_sha256,
    )
    config_name = fixture_spec.image_id.removeprefix("sha256:") + ".json"
    layer_id = "b" * 64
    layer_name = f"{layer_id}/layer.tar"
    manifest = json.dumps(
        [{"Config": config_name, "RepoTags": [fixture_spec.capture_tag], "Layers": [layer_name]}],
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    repository, tag = fixture_spec.capture_tag.rsplit(":", 1)
    repositories = json.dumps({repository: {tag: layer_id}}, sort_keys=True, separators=(",", ":")).encode("ascii")
    with path.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w|") as archive:
                for name, content in (
                    (config_name, config_bytes),
                    ("manifest.json", manifest),
                    ("repositories", repositories),
                    (f"{layer_id}/VERSION", b"1.0"),
                    (f"{layer_id}/json", b"{}"),
                    (layer_name, b"layer"),
                ):
                    info = tarfile.TarInfo(name)
                    info.size = len(content)
                    info.mtime = 0
                    archive.addfile(info, io.BytesIO(content))
    return fixture_spec.image_id


def create_modern_fixture_archive(path: Path, spec: Spec) -> str:
    def encoded(value: object) -> bytes:
        return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")

    def blob_descriptor(value: bytes, media_type: str, **extra: object) -> dict[str, object]:
        return {
            "mediaType": media_type,
            "digest": "sha256:" + hashlib.sha256(value).hexdigest(),
            "size": len(value),
            **extra,
        }

    layer = gzip.compress(b"fixture layer", mtime=0)
    config = encoded(
        {
            "architecture": "amd64",
            "config": {"Labels": spec.labels},
            "os": "linux",
            "rootfs": {"type": "layers", "diff_ids": ["sha256:" + "a" * 64]},
        }
    )
    config_descriptor = blob_descriptor(config, "application/vnd.oci.image.config.v1+json")
    layer_descriptor = blob_descriptor(layer, "application/vnd.oci.image.layer.v1.tar+gzip")
    image_manifest = encoded(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": config_descriptor,
            "layers": [layer_descriptor],
        }
    )
    image_descriptor = blob_descriptor(
        image_manifest,
        "application/vnd.oci.image.manifest.v1+json",
        platform={"architecture": "amd64", "os": "linux"},
    )
    image_index = encoded(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [image_descriptor],
        }
    )
    fixture_spec = Spec(
        role=spec.role,
        image_id="sha256:" + hashlib.sha256(image_index).hexdigest(),
        base=spec.base,
        dockerfile_sha256=spec.dockerfile_sha256,
        dpkg_sha256=spec.dpkg_sha256,
    )
    index = encoded(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [
                {
                    "mediaType": "application/vnd.oci.image.index.v1+json",
                    "digest": fixture_spec.image_id,
                    "size": len(image_index),
                    "annotations": {
                        "io.containerd.image.name": f"docker.io/{fixture_spec.capture_tag}",
                        "org.opencontainers.image.ref.name": fixture_spec.capture_tag.rsplit(":", 1)[1],
                    },
                }
            ],
        }
    )
    config_name = "blobs/sha256/" + config_descriptor["digest"].removeprefix("sha256:")
    layer_name = "blobs/sha256/" + layer_descriptor["digest"].removeprefix("sha256:")
    manifest = encoded(
        [{"Config": config_name, "RepoTags": [fixture_spec.capture_tag], "Layers": [layer_name]}]
    )
    members = {
        "index.json": index,
        "manifest.json": manifest,
        "oci-layout": encoded({"imageLayoutVersion": "1.0.0"}),
        "blobs/sha256/" + fixture_spec.image_id.removeprefix("sha256:"): image_index,
        "blobs/sha256/" + image_descriptor["digest"].removeprefix("sha256:"): image_manifest,
        config_name: config,
        layer_name: layer,
    }
    with path.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w|") as archive:
                for name, content in sorted(members.items()):
                    info = tarfile.TarInfo(name)
                    info.size = len(content)
                    info.mtime = 0
                    archive.addfile(info, io.BytesIO(content))
    return fixture_spec.image_id


def create_verifier_fixture_archive(
    path: Path, repo_tags: object = None
) -> VerifierSpec:
    def encoded(value: object) -> bytes:
        return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")

    def blob_descriptor(value: bytes, media_type: str, **extra: object) -> dict[str, object]:
        return {
            "mediaType": media_type,
            "digest": "sha256:" + hashlib.sha256(value).hexdigest(),
            "size": len(value),
            **extra,
        }

    layers = [gzip.compress(f"fixture layer {position}".encode("ascii"), mtime=0) for position in range(4)]
    layer_descriptors = [
        blob_descriptor(layer, "application/vnd.oci.image.layer.v1.tar+gzip")
        for layer in layers
    ]
    config = encoded(
        {
            "architecture": "amd64",
            "config": {"Env": DEV_CHECK_ENV, "Cmd": ["bash"]},
            "history": [{"created_by": f"fixture {position}"} for position in range(7)],
            "os": "linux",
            "rootfs": {
                "type": "layers",
                "diff_ids": ["sha256:" + str(position) * 64 for position in range(1, 5)],
            },
        }
    )
    config_descriptor = blob_descriptor(config, "application/vnd.oci.image.config.v1+json")
    image_manifest = encoded(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": config_descriptor,
            "layers": layer_descriptors,
        }
    )
    image_descriptor = blob_descriptor(
        image_manifest,
        "application/vnd.oci.image.manifest.v1+json",
        platform={"architecture": "amd64", "os": "linux"},
    )
    source_commit = "5" * 40
    source_repository = "https://github.com/example/rustdesk_fork.git"
    base_digest = "6" * 64
    statement = encoded(
        {
            "_type": "https://in-toto.io/Statement/v1",
            "predicateType": "https://slsa.dev/provenance/v1",
            "subject": [
                {
                    "name": "pkg:docker/rd-devcheck@latest?platform=linux%2Famd64",
                    "digest": {
                        "sha256": image_descriptor["digest"].removeprefix("sha256:")
                    },
                }
            ],
            "predicate": {
                "buildDefinition": {
                    "buildType": (
                        "https://github.com/moby/buildkit/blob/master/docs/attestations/"
                        "slsa-definitions.md"
                    ),
                    "resolvedDependencies": [
                        {
                            "uri": "pkg:docker/rust@1.75-slim?platform=linux%2Famd64",
                            "digest": {"sha256": base_digest},
                        }
                    ],
                    "externalParameters": {
                        "configSource": {"path": "Dockerfile.devcheck"},
                        "request": {
                            "frontend": "dockerfile.v0",
                            "locals": [{"name": "context"}, {"name": "dockerfile"}],
                            "root": {
                                "configSource": {"path": "Dockerfile.devcheck"},
                                "request": {
                                    "args": {
                                        "vcs:localdir:context": "scripts",
                                        "vcs:localdir:dockerfile": "scripts",
                                        "vcs:revision": source_commit,
                                        "vcs:source": source_repository,
                                    }
                                },
                            },
                        },
                    },
                    "internalParameters": {
                        "builderPlatform": "linux/amd64",
                        "dockerfileVersion": "1.25.0",
                    },
                },
                "runDetails": {
                    "metadata": {
                        "buildkit_metadata": {
                            "vcs": {
                                "localdir:context": "scripts",
                                "localdir:dockerfile": "scripts",
                                "revision": source_commit,
                                "source": source_repository,
                            }
                        },
                        "buildkit_completeness": {
                            "request": True,
                            "resolvedDependencies": False,
                        },
                    }
                },
            },
        }
    )
    statement_descriptor = blob_descriptor(
        statement,
        "application/vnd.in-toto+json",
        annotations={"in-toto.io/predicate-type": "https://slsa.dev/provenance/v1"},
    )
    attestation_config = encoded(
        {
            "architecture": "unknown",
            "config": {},
            "os": "unknown",
            "rootfs": {
                "type": "layers",
                "diff_ids": [
                    "sha256:" + hashlib.sha256(statement).hexdigest(),
                ],
            },
        }
    )
    attestation_config_descriptor = blob_descriptor(
        attestation_config,
        "application/vnd.oci.image.config.v1+json",
    )
    attestation_manifest = encoded(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": attestation_config_descriptor,
            "layers": [statement_descriptor],
        }
    )
    attestation_descriptor = blob_descriptor(
        attestation_manifest,
        "application/vnd.oci.image.manifest.v1+json",
        annotations={
            "vnd.docker.reference.digest": image_descriptor["digest"],
            "vnd.docker.reference.type": "attestation-manifest",
        },
        platform={"architecture": "unknown", "os": "unknown"},
    )
    image_index = encoded(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [image_descriptor, attestation_descriptor],
        }
    )
    image_id = "sha256:" + hashlib.sha256(image_index).hexdigest()
    spec = VerifierSpec(
        role="devcheck",
        image_id=image_id,
        base="rust:1.75-slim@sha256:" + base_digest,
        dockerfile_sha256="7" * 64,
        dpkg_sha256="8" * 64,
        cargo_sha256="9" * 64,
        rustc_sha256="a" * 64,
        source_commit=source_commit,
        source_repository=source_repository,
        config_id=str(config_descriptor["digest"]),
        manifest_id=str(image_descriptor["digest"]),
    )
    root_index = encoded(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [
                {
                    "mediaType": "application/vnd.oci.image.index.v1+json",
                    "digest": image_id,
                    "size": len(image_index),
                    "annotations": spec.root_annotations,
                }
            ],
        }
    )
    config_name = "blobs/sha256/" + spec.config_id.removeprefix("sha256:")
    layer_names = [
        "blobs/sha256/" + str(descriptor["digest"]).removeprefix("sha256:")
        for descriptor in layer_descriptors
    ]
    compatibility_manifest = encoded(
        [{"Config": config_name, "RepoTags": repo_tags, "Layers": layer_names}]
    )
    members = {
        "index.json": root_index,
        "manifest.json": compatibility_manifest,
        "oci-layout": encoded({"imageLayoutVersion": "1.0.0"}),
        "blobs/sha256/" + image_id.removeprefix("sha256:"): image_index,
        "blobs/sha256/" + spec.manifest_id.removeprefix("sha256:"): image_manifest,
        "blobs/sha256/"
        + str(attestation_descriptor["digest"]).removeprefix("sha256:"): attestation_manifest,
        "blobs/sha256/"
        + str(attestation_config_descriptor["digest"]).removeprefix("sha256:"): attestation_config,
        "blobs/sha256/"
        + str(statement_descriptor["digest"]).removeprefix("sha256:"): statement,
        config_name: config,
    }
    members.update(zip(layer_names, layers))
    with path.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w|") as archive:
                for name, content in sorted(members.items()):
                    info = tarfile.TarInfo(name)
                    info.size = len(content)
                    info.mtime = 0
                    archive.addfile(info, io.BytesIO(content))
    path.chmod(0o400)
    return spec


def expect_failure(operation: Callable[[], object], label: str) -> None:
    try:
        operation()
    except ProvenanceError:
        return
    fail(f"self-test mutation was accepted: {label}")


def self_test() -> None:
    manifest = b"alpha\t1.0-1\nbeta:amd64\t2:3.4+5\n"
    dpkg_sha = validate_package_manifest(manifest)
    expect_failure(lambda: validate_package_manifest(b"beta\t1\nalpha\t1\n"), "unsorted package manifest")
    expect_failure(lambda: validate_package_manifest(b"bad line\n"), "malformed package manifest")
    base_spec = Spec(
        role="deb-builder",
        image_id="sha256:" + "0" * 64,
        base="ubuntu:18.04@sha256:" + "1" * 64,
        dockerfile_sha256="2" * 64,
        dpkg_sha256=dpkg_sha,
    )
    payload = {"Id": base_spec.image_id, "Config": {"Labels": base_spec.labels}}
    validate_inspect(payload, base_spec.image_id, base_spec)
    expect_failure(
        lambda: validate_inspect({**payload, "Id": "sha256:" + "f" * 64}, "wrong-tag", base_spec),
        "wrong image tag/ID",
    )
    with tempfile.TemporaryDirectory(prefix="image-provenance-test-") as temporary:
        archive = Path(temporary) / "image.tar.gz"
        fixture_id = create_fixture_archive(archive, base_spec)
        fixture_spec = Spec(
            role=base_spec.role,
            image_id=fixture_id,
            base=base_spec.base,
            dockerfile_sha256=base_spec.dockerfile_sha256,
            dpkg_sha256=base_spec.dpkg_sha256,
        )
        archive_sha = hashlib.sha256(archive.read_bytes()).hexdigest()
        verify_archive(archive, archive_sha, fixture_spec)
        wrong_id = Spec(
            role=fixture_spec.role,
            image_id="sha256:" + "f" * 64,
            base=fixture_spec.base,
            dockerfile_sha256=fixture_spec.dockerfile_sha256,
            dpkg_sha256=fixture_spec.dpkg_sha256,
        )
        expect_failure(lambda: verify_archive(archive, archive_sha, wrong_id), "wrong archive image ID")
        wrong_tag = Spec(
            role="android-builder",
            image_id=fixture_spec.image_id,
            base=fixture_spec.base,
            dockerfile_sha256=fixture_spec.dockerfile_sha256,
            dpkg_sha256=fixture_spec.dpkg_sha256,
        )
        expect_failure(lambda: verify_archive(archive, archive_sha, wrong_tag), "wrong archive image tag")
        expect_failure(lambda: verify_archive(archive, "f" * 64, fixture_spec), "wrong archive pin")
        with archive.open("ab") as stream:
            stream.write(b"mutation")
        expect_failure(lambda: verify_archive(archive, archive_sha, fixture_spec), "mutated archive")

        modern_archive = Path(temporary) / "modern-image.tar.gz"
        modern_id = create_modern_fixture_archive(modern_archive, base_spec)
        modern_spec = Spec(
            role=base_spec.role,
            image_id=modern_id,
            base=base_spec.base,
            dockerfile_sha256=base_spec.dockerfile_sha256,
            dpkg_sha256=base_spec.dpkg_sha256,
        )
        modern_sha = hashlib.sha256(modern_archive.read_bytes()).hexdigest()
        verify_archive(modern_archive, modern_sha, modern_spec)

        verifier_archive = Path(temporary) / "devcheck-image.tar.gz"
        verifier_spec = create_verifier_fixture_archive(verifier_archive)
        verifier_bytes = verifier_archive.read_bytes()
        verifier_sha = hashlib.sha256(verifier_bytes).hexdigest()
        verifier_size = len(verifier_bytes)
        verify_archive(
            verifier_archive,
            verifier_sha,
            verifier_spec,
            verifier_size,
        )
        verifier_payload = {
            "Id": verifier_spec.image_id,
            "Os": "linux",
            "Architecture": "amd64",
            "Config": {
                "User": None,
                "Env": DEV_CHECK_ENV,
                "Cmd": ["bash"],
                "Labels": None,
            },
        }
        validate_inspect(verifier_payload, verifier_spec.image_id, verifier_spec)
        verifier_checks = 2

        def verifier_failure(operation: Callable[[], object], label: str) -> None:
            nonlocal verifier_checks
            expect_failure(operation, label)
            verifier_checks += 1

        verifier_failure(
            lambda: verify_archive(
                verifier_archive,
                "f" * 64,
                verifier_spec,
                verifier_size,
            ),
            "devcheck archive hash",
        )
        verifier_failure(
            lambda: verify_archive(
                verifier_archive,
                verifier_sha,
                verifier_spec,
                verifier_size + 1,
            ),
            "devcheck archive size",
        )
        verifier_failure(
            lambda: verify_archive(
                verifier_archive,
                verifier_sha,
                replace(verifier_spec, image_id="sha256:" + "f" * 64),
                verifier_size,
            ),
            "devcheck image identity",
        )
        verifier_failure(
            lambda: verify_archive(
                verifier_archive,
                verifier_sha,
                replace(verifier_spec, config_id="sha256:" + "f" * 64),
                verifier_size,
            ),
            "devcheck config identity",
        )
        verifier_failure(
            lambda: verify_archive(
                verifier_archive,
                verifier_sha,
                replace(verifier_spec, manifest_id="sha256:" + "f" * 64),
                verifier_size,
            ),
            "devcheck manifest identity",
        )
        verifier_failure(
            lambda: verify_archive(
                verifier_archive,
                verifier_sha,
                replace(
                    verifier_spec,
                    base="rust:1.75-slim@sha256:" + "f" * 64,
                ),
                verifier_size,
            ),
            "devcheck attested base",
        )
        verifier_failure(
            lambda: verify_archive(
                verifier_archive,
                verifier_sha,
                replace(verifier_spec, source_commit="f" * 40),
                verifier_size,
            ),
            "devcheck attested source commit",
        )
        verifier_failure(
            lambda: validate_inspect(
                {
                    **verifier_payload,
                    "Config": {
                        **verifier_payload["Config"],
                        "Env": DEV_CHECK_ENV[:-1],
                    },
                },
                verifier_spec.image_id,
                verifier_spec,
            ),
            "devcheck runtime environment",
        )
        verifier_archive.chmod(0o600)
        verifier_failure(
            lambda: verify_archive(
                verifier_archive,
                verifier_sha,
                verifier_spec,
                verifier_size,
            ),
            "devcheck archive mode",
        )
        verifier_archive.chmod(0o400)
        verifier_link = Path(temporary) / "devcheck-image-hardlink.tar.gz"
        os.link(verifier_archive, verifier_link)
        verifier_failure(
            lambda: verify_archive(
                verifier_archive,
                verifier_sha,
                verifier_spec,
                verifier_size,
            ),
            "devcheck archive hardlink",
        )
        verifier_link.unlink()
        tagged_archive = Path(temporary) / "tagged-devcheck-image.tar.gz"
        tagged_spec = create_verifier_fixture_archive(
            tagged_archive, ["rd-devcheck:latest"]
        )
        tagged_bytes = tagged_archive.read_bytes()
        verifier_failure(
            lambda: verify_archive(
                tagged_archive,
                hashlib.sha256(tagged_bytes).hexdigest(),
                tagged_spec,
                len(tagged_bytes),
            ),
            "devcheck archive tag",
        )
        rename_source = Path(temporary) / "rename-source"
        rename_destination = Path(temporary) / "rename-destination"
        rename_source.write_bytes(b"new")
        rename_noreplace(rename_source, rename_destination)
        if rename_source.exists() or rename_destination.read_bytes() != b"new":
            fail("no-replace publication did not atomically rename the archive")
        verifier_checks += 1
        collision_source = Path(temporary) / "collision-source"
        collision_destination = Path(temporary) / "collision-destination"
        collision_source.write_bytes(b"new")
        collision_destination.write_bytes(b"existing")
        verifier_failure(
            lambda: rename_noreplace(collision_source, collision_destination),
            "devcheck archive no-clobber publication",
        )
        if (
            collision_source.read_bytes() != b"new"
            or collision_destination.read_bytes() != b"existing"
        ):
            fail("no-replace collision changed archive bytes")
        verify_archive(verifier_archive, verifier_sha, verifier_spec, verifier_size)
        verifier_checks += 1
        if verifier_checks != 16:
            fail(f"devcheck image self-test count differs: {verifier_checks}")


def add_spec_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--role", required=True)
    parser.add_argument("--expected-id", required=True)
    parser.add_argument("--base", required=True)
    parser.add_argument("--dockerfile-sha", required=True)
    parser.add_argument("--dpkg-sha", required=True)
    parser.add_argument("--cargo-sha")
    parser.add_argument("--rustc-sha")
    parser.add_argument("--source-commit")
    parser.add_argument("--source-repository")
    parser.add_argument("--config-id")
    parser.add_argument("--manifest-id")


def argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    local = subparsers.add_parser("verify-local")
    add_spec_arguments(local)
    local.add_argument("--image-ref")
    load = subparsers.add_parser("verify-load")
    add_spec_arguments(load)
    load.add_argument("--archive", type=Path, required=True)
    load.add_argument("--archive-sha", required=True)
    load.add_argument("--archive-size", type=int)
    verify = subparsers.add_parser("verify-archive")
    add_spec_arguments(verify)
    verify.add_argument("--archive", type=Path, required=True)
    verify.add_argument("--archive-sha", required=True)
    verify.add_argument("--archive-size", type=int)
    capture_parser = subparsers.add_parser("maintenance-capture")
    add_spec_arguments(capture_parser)
    capture_parser.add_argument("--output", type=Path, required=True)
    estimate = subparsers.add_parser("maintenance-estimate")
    add_spec_arguments(estimate)
    return parser


def main() -> int:
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        print("offline image provenance self-test: PASS")
        return 0
    args = argument_parser().parse_args()
    spec = spec_from_args(args)
    if args.command == "verify-local":
        verify_local(args.image_ref or spec.image_id, spec)
        print(f"verified {spec.role} {spec.image_id}")
    elif args.command == "verify-load":
        load_archive(args.archive, args.archive_sha, spec, args.archive_size)
        print(f"loaded and verified {spec.role} {spec.image_id}")
    elif args.command == "verify-archive":
        verify_archive(args.archive, args.archive_sha, spec, args.archive_size)
        print(f"verified archive for {spec.role} {spec.image_id}")
    elif args.command == "maintenance-capture":
        archive_sha, size = capture(args.output, spec)
        print(f"archive={args.output}")
        print(f"sha256={archive_sha}")
        print(f"bytes={size}")
    elif args.command == "maintenance-estimate":
        payload = inspect_image(spec.image_id)
        validate_inspect(payload, spec.image_id, spec)
        size = payload.get("Size")
        if not isinstance(size, int) or size < 0:
            fail("docker inspect returned an invalid image size")
        print(f"image_id={spec.image_id}")
        print(f"uncompressed_content_bytes={size}")
    else:
        fail(f"unsupported command: {args.command}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ProvenanceError as exc:
        print(f"offline-image-provenance: {exc}", file=sys.stderr)
        raise SystemExit(1)
