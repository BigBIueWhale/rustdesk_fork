#!/usr/bin/env python3
"""Create the exact regular-file manifest for Windows offline build media."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import stat
import sys
import tempfile
from dataclasses import dataclass
from typing import Callable


FORMAT = "rustdesk-windows-offline-manifest-v2"
DOS_DEVICE = re.compile(
    r"^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$", re.IGNORECASE
)
STABLE_FIELDS = (
    "st_dev",
    "st_ino",
    "st_mode",
    "st_nlink",
    "st_size",
    "st_mtime_ns",
    "st_ctime_ns",
)


class ManifestError(RuntimeError):
    pass


@dataclass(frozen=True)
class Mapping:
    media_path: str
    source_path: pathlib.Path
    authority_root: pathlib.Path


def fail(message: str) -> None:
    raise ManifestError(message)


def require_real_directory(path: pathlib.Path, description: str) -> pathlib.Path:
    absolute = pathlib.Path(os.path.abspath(path))
    try:
        info = os.lstat(absolute)
    except OSError as exc:
        fail(f"cannot inspect {description} {absolute}: {exc}")
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        fail(f"{description} is not a real directory: {absolute}")
    try:
        resolved = absolute.resolve(strict=True)
    except OSError as exc:
        fail(f"cannot resolve {description} {absolute}: {exc}")
    if resolved != absolute:
        fail(f"{description} is not canonical: {absolute}")
    return absolute


def validate_relative(relative: str, kind: str) -> None:
    try:
        encoded = relative.encode("ascii")
    except UnicodeEncodeError:
        fail(f"offline {kind} path is not ASCII: {relative!r}")
    components = relative.split("/")
    if (
        not relative
        or any(component in ("", ".", "..") for component in components)
        or any(byte < 0x20 or byte == 0x7F for byte in encoded)
        or any(character in relative for character in '\\,:<>"|?*')
        or any(component.endswith((" ", ".")) for component in components)
        or any(DOS_DEVICE.fullmatch(component) for component in components)
    ):
        fail(f"offline {kind} path is not Windows/manifest safe: {relative!r}")


def stable(expected: os.stat_result, actual: os.stat_result) -> bool:
    return all(getattr(expected, field) == getattr(actual, field) for field in STABLE_FIELDS)


def hash_regular(path: pathlib.Path, expected: os.stat_result) -> tuple[str, int]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        fail(f"cannot open offline regular file without following links {path}: {exc}")
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or not stable(expected, opened):
            fail(f"offline file changed before hashing: {path}")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(descriptor)
        if not stable(opened, after):
            fail(f"offline file changed while hashing: {path}")
        return digest.hexdigest(), opened.st_size
    finally:
        os.close(descriptor)


def normalized_link_target(
    link: pathlib.Path, relative: str, target: str, authority_root: pathlib.Path
) -> pathlib.Path:
    try:
        encoded = target.encode("ascii")
    except UnicodeEncodeError:
        fail(f"offline symlink target is not ASCII at {relative}")
    if (
        not target
        or target.startswith(("/", "\\"))
        or any(byte < 0x20 or byte == 0x7F for byte in encoded)
        or "\\" in target
        or ":" in target
    ):
        fail(f"offline symlink target is not a safe relative path at {relative}")

    try:
        parent_relative = link.parent.relative_to(authority_root)
    except ValueError:
        fail(f"offline symlink is outside its authenticated root: {relative}")
    components = list(parent_relative.parts)
    for component in target.split("/"):
        if component in ("", "."):
            fail(f"offline symlink target is not canonical at {relative}")
        if component == "..":
            if not components:
                fail(f"offline symlink target escapes its authenticated root at {relative}")
            components.pop()
        else:
            validate_relative(component, "symlink target")
            components.append(component)
    if not components:
        fail(f"offline symlink resolves to its authenticated root directory at {relative}")
    return authority_root.joinpath(*components)


def hash_internal_file_link(
    path: pathlib.Path,
    relative: str,
    link_info: os.stat_result,
    authority_root: pathlib.Path,
) -> tuple[str, int]:
    try:
        target_text = os.readlink(path)
    except OSError as exc:
        fail(f"cannot read offline symlink at {relative}: {exc}")
    target = normalized_link_target(path, relative, target_text, authority_root)

    cursor = authority_root
    target_parts = target.relative_to(authority_root).parts
    for component in target_parts[:-1]:
        cursor = cursor / component
        try:
            info = os.lstat(cursor)
        except OSError as exc:
            fail(f"cannot inspect offline symlink target component at {relative}: {exc}")
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            fail(f"offline symlink target traverses another link or non-directory at {relative}")
    try:
        target_info = os.lstat(target)
    except OSError as exc:
        fail(f"offline symlink is broken at {relative}: {exc}")
    if not stat.S_ISREG(target_info.st_mode):
        fail(f"offline symlink target is not a single-hop regular file at {relative}")
    result = hash_regular(target, target_info)
    try:
        after = os.lstat(path)
    except OSError as exc:
        fail(f"offline symlink disappeared while hashing at {relative}: {exc}")
    if not stable(link_info, after) or os.readlink(path) != target_text:
        fail(f"offline symlink changed while hashing at {relative}")
    return result


def mappings(
    online_root: pathlib.Path,
    wix_root: pathlib.Path,
    olefile_version: str,
    source_ref: str,
    fix_commit: str,
) -> list[Mapping]:
    return [
        Mapping("cargo-vendor", online_root / "cargo-vendor", online_root),
        Mapping(
            "cargo-vendor-config.toml",
            online_root / "cargo-vendor-config.toml",
            online_root,
        ),
        Mapping("pub-cache", online_root / "pub-cache", online_root),
        Mapping(
            f"vcpkg-distfiles/libvpx-{source_ref}.tar.gz",
            online_root / "vcpkg-distfiles" / f"libvpx-{source_ref}.tar.gz",
            online_root,
        ),
        Mapping(
            f"vcpkg-distfiles/libvpx-{fix_commit}.patch",
            online_root / "vcpkg-distfiles" / f"libvpx-{fix_commit}.patch",
            online_root,
        ),
        Mapping(
            "vcpkg-distfiles/libvpx-native-key.txt",
            online_root / "vcpkg-distfiles" / "libvpx-native-key.txt",
            online_root,
        ),
        Mapping(
            "vcpkg-distfiles/windows-tools",
            online_root / "vcpkg-distfiles" / "windows-tools",
            online_root,
        ),
        Mapping(
            f"python-wheels/olefile-{olefile_version}-py2.py3-none-any.whl",
            online_root / f"olefile-{olefile_version}-py2.py3-none-any.whl",
            online_root,
        ),
        Mapping("wix-nuget", wix_root, wix_root),
    ]


def calculate_manifest(
    online_root: pathlib.Path,
    wix_root: pathlib.Path,
    olefile_version: str,
    source_ref: str,
    fix_commit: str,
) -> dict[str, object]:
    online_root = require_real_directory(online_root, "online root")
    wix_root = require_real_directory(wix_root, "extracted WiX root")
    files: list[dict[str, object]] = []
    directories: set[str] = set()
    file_parents: set[str] = set()
    exact_paths: set[str] = set()
    case_paths: dict[str, tuple[str, tuple[object, ...]]] = {}

    def register(relative: str, kind: str, identity: tuple[object, ...]) -> None:
        validate_relative(relative, kind)
        if relative in exact_paths:
            fail(f"offline manifest path is duplicated exactly: {relative!r}")
        exact_paths.add(relative)
        folded = relative.casefold()
        previous = case_paths.get(folded)
        if previous is not None:
            previous_path, previous_identity = previous
            if previous_path == relative or previous_identity != identity:
                fail(f"offline paths collide unsafely on Windows: {previous_path!r} and {relative!r}")
        else:
            case_paths[folded] = (relative, identity)

    def add_file(
        source: pathlib.Path,
        relative: str,
        authority_root: pathlib.Path,
    ) -> None:
        validate_relative(relative, "file")
        try:
            info = os.lstat(source)
        except OSError as exc:
            fail(f"cannot inspect offline input {source}: {exc}")
        if stat.S_ISREG(info.st_mode):
            digest, size = hash_regular(source, info)
        elif stat.S_ISLNK(info.st_mode):
            digest, size = hash_internal_file_link(source, relative, info, authority_root)
        else:
            fail(f"offline input is not a regular file or approved internal file link: {source}")
        register(relative, "file", ("file", digest, size))
        components = relative.split("/")[:-1]
        for index in range(1, len(components) + 1):
            file_parents.add("/".join(components[:index]))
        files.append({"path": relative, "sha256": digest, "size": size})

    for mapping in mappings(online_root, wix_root, olefile_version, source_ref, fix_commit):
        source = mapping.source_path
        try:
            source.relative_to(mapping.authority_root)
        except ValueError:
            fail(f"offline mapping is outside its authenticated root: {source}")
        try:
            source_info = os.lstat(source)
        except OSError as exc:
            fail(f"cannot inspect offline mapping source {source}: {exc}")
        if stat.S_ISDIR(source_info.st_mode) and not stat.S_ISLNK(source_info.st_mode):
            register(mapping.media_path, "directory", ("directory",))
            directories.add(mapping.media_path)
            for directory, names, filenames in os.walk(source, topdown=True, followlinks=False):
                names.sort()
                filenames.sort()
                directory_path = pathlib.Path(directory)
                for name in names:
                    child = directory_path / name
                    child_relative = child.relative_to(source).as_posix()
                    media_relative = f"{mapping.media_path}/{child_relative}"
                    try:
                        info = os.lstat(child)
                    except OSError as exc:
                        fail(f"cannot inspect offline directory input {child}: {exc}")
                    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
                        fail(f"offline input contains a directory symlink or non-directory: {child}")
                    register(media_relative, "directory", ("directory",))
                    directories.add(media_relative)
                for name in filenames:
                    child = directory_path / name
                    child_relative = child.relative_to(source).as_posix()
                    add_file(
                        child,
                        f"{mapping.media_path}/{child_relative}",
                        mapping.authority_root,
                    )
        else:
            add_file(source, mapping.media_path, mapping.authority_root)

    for generated_parent in sorted(file_parents - directories):
        register(generated_parent, "directory", ("directory",))
        directories.add(generated_parent)
    if not files:
        fail("offline media manifest contains no files")
    files.sort(key=lambda item: str(item["path"]))
    return {"directories": sorted(directories), "files": files, "format": FORMAT}


def write_manifest(manifest: dict[str, object], output: pathlib.Path) -> None:
    output = pathlib.Path(os.path.abspath(output))
    temporary = pathlib.Path(f"{output}.tmp")
    if os.path.lexists(output) or os.path.lexists(temporary):
        fail("offline manifest output or temporary path already exists")
    with open(temporary, "x", encoding="ascii", newline="\n") as handle:
        json.dump(manifest, handle, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    try:
        os.link(temporary, output, follow_symlinks=False)
    finally:
        temporary.unlink(missing_ok=True)


def create_fixture(root: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path, str, str, str]:
    online = root / "online"
    wix = root / "wix"
    olefile_version = "0.47"
    source_ref = "source"
    fix_commit = "fix"
    for directory in (
        online / "cargo-vendor",
        online / "pub-cache" / "package" / "module",
        online / "vcpkg-distfiles" / "windows-tools",
        wix / "package",
    ):
        directory.mkdir(parents=True, exist_ok=True)
    (online / "cargo-vendor" / "crate").write_bytes(b"crate\n")
    (online / "cargo-vendor-config.toml").write_bytes(b"config\n")
    license_path = online / "pub-cache" / "package" / "LICENSE"
    license_path.write_bytes(b"license bytes\n")
    os.symlink("../LICENSE", online / "pub-cache" / "package" / "module" / "LICENSE")
    (online / "vcpkg-distfiles" / f"libvpx-{source_ref}.tar.gz").write_bytes(b"source\n")
    (online / "vcpkg-distfiles" / f"libvpx-{fix_commit}.patch").write_bytes(b"patch\n")
    (online / "vcpkg-distfiles" / "libvpx-native-key.txt").write_bytes(b"key\n")
    (online / "vcpkg-distfiles" / "windows-tools" / "tool").write_bytes(b"tool\n")
    (online / f"olefile-{olefile_version}-py2.py3-none-any.whl").write_bytes(b"wheel\n")
    (wix / "package" / "content").write_bytes(b"wix\n")
    return online, wix, olefile_version, source_ref, fix_commit


def expect_failure(label: str, mutation: Callable[[pathlib.Path, pathlib.Path], None]) -> None:
    with tempfile.TemporaryDirectory(prefix="windows-offline-manifest-test-") as temporary:
        root = pathlib.Path(temporary)
        online, wix, olefile_version, source_ref, fix_commit = create_fixture(root)
        mutation(online, wix)
        try:
            calculate_manifest(online, wix, olefile_version, source_ref, fix_commit)
        except ManifestError:
            return
        fail(f"self-test accepted {label}")


def self_test() -> None:
    with tempfile.TemporaryDirectory(prefix="windows-offline-manifest-test-") as temporary:
        root = pathlib.Path(temporary)
        online, wix, olefile_version, source_ref, fix_commit = create_fixture(root)
        manifest = calculate_manifest(online, wix, olefile_version, source_ref, fix_commit)
        entries = {str(entry["path"]): entry for entry in manifest["files"]}
        alias = entries["pub-cache/package/module/LICENSE"]
        expected = hashlib.sha256(b"license bytes\n").hexdigest()
        if alias != {
            "path": "pub-cache/package/module/LICENSE",
            "sha256": expected,
            "size": len(b"license bytes\n"),
        }:
            fail("self-test did not materialize the approved internal file link")
        for expected_path in (
            "python-wheels/olefile-0.47-py2.py3-none-any.whl",
            "wix-nuget/package/content",
        ):
            if expected_path not in entries:
                fail(f"self-test omitted media mapping {expected_path}")
        output = root / "manifest.json"
        write_manifest(manifest, output)
        if json.loads(output.read_text(encoding="ascii")) != manifest:
            fail("self-test manifest publication changed the manifest")
        try:
            write_manifest(manifest, output)
        except ManifestError:
            pass
        else:
            fail("self-test overwrote an occupied manifest output")

    with tempfile.TemporaryDirectory(prefix="windows-offline-manifest-test-") as temporary:
        root = pathlib.Path(temporary)
        online, wix, olefile_version, source_ref, fix_commit = create_fixture(root)
        (online / "cargo-vendor" / "Name").write_bytes(b"same\n")
        (online / "cargo-vendor" / "name").write_bytes(b"same\n")
        manifest = calculate_manifest(online, wix, olefile_version, source_ref, fix_commit)
        paths = {str(entry["path"]) for entry in manifest["files"]}
        if not {"cargo-vendor/Name", "cargo-vendor/name"}.issubset(paths):
            fail("self-test rejected a byte-identical Windows case collision")

    def replace_link(online: pathlib.Path, target: str) -> None:
        link = online / "pub-cache" / "package" / "module" / "LICENSE"
        link.unlink()
        os.symlink(target, link)

    expect_failure("absolute link", lambda online, _wix: replace_link(online, "/etc/passwd"))
    expect_failure("escaping link", lambda online, _wix: replace_link(online, "../../../../outside"))
    expect_failure("directory link", lambda online, _wix: os.symlink("package", online / "pub-cache" / "alias"))
    expect_failure("directory target", lambda online, _wix: replace_link(online, ".."))

    def link_chain(online: pathlib.Path, _wix: pathlib.Path) -> None:
        os.symlink("LICENSE", online / "pub-cache" / "package" / "alias")
        replace_link(online, "../alias")

    expect_failure("link chain", link_chain)
    expect_failure(
        "case collision",
        lambda online, _wix: (
            (online / "cargo-vendor" / "Name").write_bytes(b"same\n"),
            (online / "cargo-vendor" / "name").write_bytes(b"different\n"),
        ),
    )
    expect_failure(
        "special file",
        lambda online, _wix: os.mkfifo(online / "cargo-vendor" / "fifo"),
    )
    print("windows-offline-manifest self-test: ok")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--online-root", type=pathlib.Path)
    parser.add_argument("--wix-root", type=pathlib.Path)
    parser.add_argument("--olefile-version")
    parser.add_argument("--libvpx-source-ref")
    parser.add_argument("--libvpx-fix-commit")
    parser.add_argument("--output", type=pathlib.Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    supplied = (
        args.online_root,
        args.wix_root,
        args.olefile_version,
        args.libvpx_source_ref,
        args.libvpx_fix_commit,
        args.output,
    )
    if args.self_test:
        if any(value is not None for value in supplied):
            parser.error("--self-test does not accept manifest arguments")
    elif any(value is None for value in supplied):
        parser.error("all manifest arguments are required")
    return args


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if args.self_test:
        self_test()
        return 0
    manifest = calculate_manifest(
        args.online_root,
        args.wix_root,
        args.olefile_version,
        args.libvpx_source_ref,
        args.libvpx_fix_commit,
    )
    write_manifest(manifest, args.output)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (ManifestError, OSError) as exc:
        print(f"windows-offline-manifest: FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
