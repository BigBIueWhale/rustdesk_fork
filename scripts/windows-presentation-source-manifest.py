#!/usr/bin/env python3
"""Create or verify the exact source inventory used by the Windows presentation probe."""

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path


FORMAT = "rustdesk-windows-presentation-source-v1"
GENERATED = frozenset({".presentation-source-manifest.json", "run-build.ps1"})
ENTRY_LIMIT = 32768
BYTE_LIMIT = 512 * 1024 * 1024
PATH_BYTE_LIMIT = 4096
FILE_BYTE_LIMIT = 64 * 1024 * 1024
DOS_DEVICE = re.compile(
    r"^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$", re.IGNORECASE
)
HEX_ID = re.compile(r"^[0-9a-f]{40}$|^[0-9a-f]{64}$")


class ManifestError(RuntimeError):
    pass


def validate_relative(relative: str) -> None:
    try:
        encoded = relative.encode("ascii")
    except UnicodeEncodeError as error:
        raise ManifestError(f"source path is not ASCII: {relative!r}") from error
    components = relative.split("/")
    if (
        not relative
        or len(encoded) > PATH_BYTE_LIMIT
        or any(component in ("", ".", "..") for component in components)
        or any(byte < 0x20 or byte == 0x7F for byte in encoded)
        or any(character in relative for character in '\\,:<>"|?*')
        or any(component.endswith((" ", ".")) for component in components)
        or any(DOS_DEVICE.fullmatch(component) for component in components)
    ):
        raise ManifestError(f"source path is not Windows-safe: {relative!r}")


def hash_file(path: Path, expected_size: int) -> str:
    digest = hashlib.sha256()
    observed = 0
    with path.open("rb", buffering=0) as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            observed += len(chunk)
            if observed > expected_size:
                raise ManifestError(f"source file grew while hashing: {path}")
            digest.update(chunk)
    if observed != expected_size:
        raise ManifestError(f"source file changed size while hashing: {path}")
    return digest.hexdigest()


def inventory(root: Path) -> list[dict[str, object]]:
    root_metadata = os.lstat(root)
    if not stat.S_ISDIR(root_metadata.st_mode):
        raise ManifestError("source root is not a real directory")
    files: list[dict[str, object]] = []
    folded: dict[str, str] = {}
    total = 0
    for directory, names, filenames in os.walk(root, topdown=True, followlinks=False):
        names.sort(key=os.fsencode)
        filenames.sort(key=os.fsencode)
        directory_path = Path(directory)
        for name in names:
            child = directory_path / name
            metadata = os.lstat(child)
            if not stat.S_ISDIR(metadata.st_mode):
                raise ManifestError(f"source directory entry is not a real directory: {child}")
            relative = child.relative_to(root).as_posix()
            validate_relative(relative)
            previous = folded.setdefault(relative.casefold(), relative)
            if previous != relative:
                raise ManifestError(
                    f"source paths collide on Windows: {previous!r} and {relative!r}"
                )
        for name in filenames:
            child = directory_path / name
            relative = child.relative_to(root).as_posix()
            if relative in GENERATED:
                continue
            validate_relative(relative)
            previous = folded.setdefault(relative.casefold(), relative)
            if previous != relative:
                raise ManifestError(
                    f"source paths collide on Windows: {previous!r} and {relative!r}"
                )
            metadata = os.lstat(child)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ManifestError(
                    f"source entry is not a single-link regular file: {relative}"
                )
            if metadata.st_size > FILE_BYTE_LIMIT:
                raise ManifestError(f"source file exceeds its byte bound: {relative}")
            total += metadata.st_size
            if total > BYTE_LIMIT:
                raise ManifestError("source inventory exceeds its aggregate byte bound")
            if len(files) >= ENTRY_LIMIT:
                raise ManifestError("source inventory exceeds its entry bound")
            files.append(
                {
                    "path": relative,
                    "sha256": hash_file(child, metadata.st_size),
                    "size": metadata.st_size,
                }
            )
    files.sort(key=lambda entry: os.fsencode(str(entry["path"])))
    if not files:
        raise ManifestError("source inventory is empty")
    return files


def parse_manifest(path: Path) -> dict[str, object]:
    metadata = os.lstat(path)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size <= 0
        or metadata.st_size > 16 * 1024 * 1024
    ):
        raise ManifestError("source manifest is not one bounded regular file")
    try:
        with path.open("r", encoding="ascii", newline="") as stream:
            manifest = json.load(stream)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ManifestError(f"cannot parse source manifest: {error}") from error
    if not isinstance(manifest, dict) or sorted(manifest) != [
        "files",
        "format",
        "source_commit",
        "source_tree",
    ]:
        raise ManifestError("source manifest envelope is not exact")
    if manifest["format"] != FORMAT:
        raise ManifestError("source manifest format is not exact")
    for field in ("source_commit", "source_tree"):
        if not isinstance(manifest[field], str) or not HEX_ID.fullmatch(manifest[field]):
            raise ManifestError(f"source manifest {field} is malformed")
    files = manifest["files"]
    if not isinstance(files, list) or not files:
        raise ManifestError("source manifest file list is invalid")
    for entry in files:
        if not isinstance(entry, dict) or sorted(entry) != ["path", "sha256", "size"]:
            raise ManifestError("source manifest file entry is not exact")
        if (
            not isinstance(entry["path"], str)
            or not isinstance(entry["sha256"], str)
            or re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]) is None
            or not isinstance(entry["size"], int)
            or isinstance(entry["size"], bool)
            or entry["size"] < 0
        ):
            raise ManifestError("source manifest file entry has invalid values")
    return manifest


def write_manifest(root: Path, output: Path, commit: str, tree: str) -> None:
    if not HEX_ID.fullmatch(commit) or not HEX_ID.fullmatch(tree):
        raise ManifestError("source commit or tree is malformed")
    if output.exists() or output.is_symlink():
        raise ManifestError("source manifest output path is occupied")
    manifest = {
        "files": inventory(root),
        "format": FORMAT,
        "source_commit": commit,
        "source_tree": tree,
    }
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    descriptor = os.open(output, flags, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="ascii", newline="\n") as stream:
            json.dump(manifest, stream, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        try:
            os.unlink(output)
        except OSError:
            pass
        raise


def verify_manifest(root: Path, manifest_path: Path) -> dict[str, object]:
    manifest = parse_manifest(manifest_path)
    actual = inventory(root)
    if actual != manifest["files"]:
        raise ManifestError("source tree differs from its exact manifest")
    runner = root / "run-build.ps1"
    canonical_runner = root / "scripts" / "run-flutter-presentation-windows.ps1"
    for path, label in ((runner, "root runner"), (canonical_runner, "canonical runner")):
        metadata = os.lstat(path)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ManifestError(f"{label} is not one regular file")
    if runner.read_bytes() != canonical_runner.read_bytes():
        raise ManifestError("root probe runner differs from its exact source file")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--source-commit")
    parser.add_argument("--source-tree")
    args = parser.parse_args()
    if args.write == args.verify:
        parser.error("exactly one of --write or --verify is required")
    try:
        if args.write:
            if args.source_commit is None or args.source_tree is None:
                parser.error("--write requires --source-commit and --source-tree")
            write_manifest(
                args.root.resolve(),
                args.manifest.resolve(),
                args.source_commit,
                args.source_tree,
            )
            print("windows-presentation-source-manifest: written")
        else:
            if args.source_commit is not None or args.source_tree is not None:
                parser.error("--verify does not accept source identity arguments")
            manifest = verify_manifest(args.root.resolve(), args.manifest.resolve())
            print(
                "windows-presentation-source-manifest: verified "
                f"commit={manifest['source_commit']} tree={manifest['source_tree']} "
                f"files={len(manifest['files'])}"
            )
    except (ManifestError, OSError) as error:
        print(f"windows-presentation-source-manifest: FAIL: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
