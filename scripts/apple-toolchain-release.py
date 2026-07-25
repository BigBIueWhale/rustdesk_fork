#!/usr/bin/env python3
"""Validate the exact signed Rust release inputs used by the Apple-check image."""

from __future__ import annotations

import argparse
import io
import pathlib
import re
import tarfile
import tempfile
import tomllib
from dataclasses import dataclass
from typing import NoReturn


RUST_VERSION = "1.81.0"
RUST_DATE = "2024-09-05"
MINIMAL_PROFILE = ["rustc", "cargo", "rust-std", "rust-mingw"]
PACKAGE_VERSIONS = {
    "rustc": "1.81.0 (eeb90cda1 2024-09-04)",
    "cargo": "0.82.0 (2dbb1af80 2024-08-20)",
    "rust-std": "1.81.0 (eeb90cda1 2024-09-04)",
}
COMPONENT_SHAPES = (
    ("rustc-host", "rustc", "x86_64-unknown-linux-gnu"),
    ("cargo-host", "cargo", "x86_64-unknown-linux-gnu"),
    ("std-host", "rust-std", "x86_64-unknown-linux-gnu"),
    ("std-aarch64-darwin", "rust-std", "aarch64-apple-darwin"),
    ("std-x86_64-darwin", "rust-std", "x86_64-apple-darwin"),
    ("std-aarch64-ios", "rust-std", "aarch64-apple-ios"),
)
LOWER_HEX_256 = re.compile(r"[0-9a-f]{64}")


class VerificationError(RuntimeError):
    """The release input does not meet the exact Apple toolchain contract."""


def fail(message: str) -> NoReturn:
    raise VerificationError(message)


@dataclass(frozen=True)
class Component:
    output: str
    package: str
    target: str
    sha256: str

    @property
    def filename(self) -> str:
        return f"{self.package}-{RUST_VERSION}-{self.target}.tar.xz"

    @property
    def url(self) -> str:
        return f"https://static.rust-lang.org/dist/{RUST_DATE}/{self.filename}"

    def as_tsv(self) -> str:
        return f"{self.output}\t{self.sha256}\t{self.url}"


def components_from_args(args: argparse.Namespace) -> tuple[Component, ...]:
    hashes = (
        args.rustc_host_sha256,
        args.cargo_host_sha256,
        args.rust_std_host_sha256,
        args.rust_std_aarch64_darwin_sha256,
        args.rust_std_x86_64_darwin_sha256,
        args.rust_std_aarch64_ios_sha256,
    )
    for value in hashes:
        if LOWER_HEX_256.fullmatch(value) is None:
            fail("Rust component SHA-256 is malformed")
    return tuple(
        Component(output, package, target, sha256)
        for (output, package, target), sha256 in zip(
            COMPONENT_SHAPES,
            hashes,
            strict=True,
        )
    )


def verify_manifest(path: pathlib.Path, components: tuple[Component, ...]) -> list[str]:
    try:
        manifest = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        fail(f"cannot parse Rust release manifest: {exc}")
    if manifest.get("manifest-version") != "2" or manifest.get("date") != RUST_DATE:
        fail("Rust release manifest identity differs")
    if manifest.get("profiles", {}).get("minimal") != MINIMAL_PROFILE:
        fail("Rust minimal profile differs")
    for package, expected_version in PACKAGE_VERSIONS.items():
        if manifest.get("pkg", {}).get(package, {}).get("version") != expected_version:
            fail(f"Rust release package version differs: {package}")
    lines = []
    for component in components:
        item = (
            manifest.get("pkg", {})
            .get(component.package, {})
            .get("target", {})
            .get(component.target)
        )
        if not isinstance(item, dict) or item.get("available") is not True:
            fail(
                "Rust release component is unavailable: "
                f"{component.package}/{component.target}"
            )
        if item.get("xz_hash") != component.sha256 or item.get("xz_url") != component.url:
            fail(
                "Rust release component identity differs: "
                f"{component.package}/{component.target}"
            )
        lines.append(component.as_tsv())
    return lines


def verify_component_archive(path: pathlib.Path) -> None:
    try:
        package = tarfile.open(path, mode="r:xz")
    except (OSError, tarfile.TarError) as exc:
        fail(f"cannot parse Rust component archive: {exc}")
    roots: set[str] = set()
    count = 0
    try:
        for member in package:
            name = pathlib.PurePosixPath(member.name)
            if (
                name.is_absolute()
                or not name.parts
                or any(part in {"", ".", ".."} for part in name.parts)
            ):
                fail(f"unsafe Rust component member: {member.name!r}")
            if "\\" in member.name or "\0" in member.name:
                fail(f"noncanonical Rust component member: {member.name!r}")
            if not (member.isfile() or member.isdir()):
                fail(f"non-ordinary Rust component member: {member.name!r}")
            roots.add(name.parts[0])
            count += 1
    except (OSError, tarfile.TarError) as exc:
        fail(f"cannot enumerate Rust component archive: {exc}")
    finally:
        package.close()
    if count == 0 or len(roots) != 1:
        fail("Rust component archive does not contain one nonempty root")


def synthetic_manifest(components: tuple[Component, ...]) -> str:
    lines = [
        'manifest-version = "2"',
        f'date = "{RUST_DATE}"',
        "[profiles]",
        'minimal = ["rustc", "cargo", "rust-std", "rust-mingw"]',
    ]
    for package, version in PACKAGE_VERSIONS.items():
        lines.extend((f"[pkg.{package}]", f'version = "{version}"'))
        for component in components:
            if component.package != package:
                continue
            lines.extend(
                (
                    f"[pkg.{package}.target.{component.target}]",
                    "available = true",
                    f'xz_url = "{component.url}"',
                    f'xz_hash = "{component.sha256}"',
                )
            )
    return "\n".join(lines) + "\n"


def self_test() -> None:
    hashes = tuple(f"{index:064x}" for index in range(1, 7))
    components = tuple(
        Component(output, package, target, sha256)
        for (output, package, target), sha256 in zip(
            COMPONENT_SHAPES,
            hashes,
            strict=True,
        )
    )
    with tempfile.TemporaryDirectory(prefix="apple-toolchain-release.") as temporary:
        root = pathlib.Path(temporary)
        manifest = root / "channel.toml"
        manifest.write_text(synthetic_manifest(components), encoding="utf-8")
        if verify_manifest(manifest, components) != [
            component.as_tsv() for component in components
        ]:
            fail("self-test component list differs")
        manifest.write_text(
            synthetic_manifest(components).replace(
                RUST_DATE,
                "2024-09-06",
                1,
            ),
            encoding="utf-8",
        )
        try:
            verify_manifest(manifest, components)
        except VerificationError:
            pass
        else:
            fail("self-test manifest identity mutation was accepted")

        archive = root / "component.tar.xz"
        with tarfile.open(archive, mode="w:xz") as package:
            directory = tarfile.TarInfo("component")
            directory.type = tarfile.DIRTYPE
            directory.mode = 0o755
            package.addfile(directory)
            payload = b"installer"
            installer = tarfile.TarInfo("component/install.sh")
            installer.size = len(payload)
            installer.mode = 0o755
            package.addfile(installer, io.BytesIO(payload))
        verify_component_archive(archive)

        unsafe = root / "unsafe.tar.xz"
        with tarfile.open(unsafe, mode="w:xz") as package:
            payload = b"escape"
            member = tarfile.TarInfo("../escape")
            member.size = len(payload)
            package.addfile(member, io.BytesIO(payload))
        try:
            verify_component_archive(unsafe)
        except VerificationError:
            pass
        else:
            fail("self-test traversal archive was accepted")

        linked = root / "linked.tar.xz"
        with tarfile.open(linked, mode="w:xz") as package:
            member = tarfile.TarInfo("component/link")
            member.type = tarfile.SYMTYPE
            member.linkname = "target"
            package.addfile(member)
        try:
            verify_component_archive(linked)
        except VerificationError:
            pass
        else:
            fail("self-test linked archive was accepted")
    print("apple-toolchain-release: self-test ok")


def add_component_hash_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--rustc-host-sha256", required=True)
    parser.add_argument("--cargo-host-sha256", required=True)
    parser.add_argument("--rust-std-host-sha256", required=True)
    parser.add_argument("--rust-std-aarch64-darwin-sha256", required=True)
    parser.add_argument("--rust-std-x86-64-darwin-sha256", required=True)
    parser.add_argument("--rust-std-aarch64-ios-sha256", required=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    manifest = subparsers.add_parser("manifest")
    manifest.add_argument("--path", type=pathlib.Path, required=True)
    add_component_hash_arguments(manifest)
    archive = subparsers.add_parser("archive")
    archive.add_argument("--path", type=pathlib.Path, required=True)
    subparsers.add_parser("self-test")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.command == "manifest":
            for line in verify_manifest(args.path, components_from_args(args)):
                print(line)
        elif args.command == "archive":
            verify_component_archive(args.path)
            print("apple-toolchain-release: archive ok")
        else:
            self_test()
        return 0
    except VerificationError as exc:
        print(f"apple-toolchain-release: {exc}", file=__import__("sys").stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
