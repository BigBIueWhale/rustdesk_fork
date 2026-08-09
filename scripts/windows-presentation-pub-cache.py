#!/usr/bin/env python3
"""Validate the exact hosted-package projection for the Windows presentation probe."""

from __future__ import annotations

import argparse
import importlib.util
import os
import re
import stat
import sys
from pathlib import Path


EXPECTED_FILES = 346
EXPECTED_DIRECTORIES = 82
EXPECTED_SIZE = 5_666_684
EXPECTED_PACKAGES = {
    "characters-1.3.0": "04a925763edad70e8443c99234dc3328f442e811f1d8fd1a72f1c8ad0f69a605",
    "collection-1.18.0": "ee67cb0715911d28db6bf4af1026078bd6f0128b07a5f66fb2ed94ec6783c09a",
    "material_color_utilities-0.11.1": "f7142bb1154231d7ea5f96bc7bde4bda2a0945d2806bb11670e30b850d56bdec",
    "meta-1.15.0": "bdb68674043280c3428e9ec998512fb681678676b3c54e773629ffe74419f8c7",
    "plugin_platform_interface-2.1.8": "4820fbfdb9478b1ebae27888254d445073732dae3d6ea81f0b7e06d5dedc3f02",
    "url_launcher_platform_interface-2.3.2": "552f8a1e663569be95a8190206a38187b531910283c3e982193e4f2733f01029",
    "url_launcher_windows-3.1.4": "3284b6d2ac454cf34f114e1d3319866fdd1e19cdc329999057e44ffe936cfa77",
    "vector_math-2.1.4": "80b3257d1492ce4d091729e3a67a60407d227c27241d6927be0130c98e741803",
}


class ProjectionError(RuntimeError):
    pass


def load_cache_validator():
    path = Path(__file__).with_name("online-pub-cache-output.py")
    specification = importlib.util.spec_from_file_location(
        "online_pub_cache_output", path
    )
    if specification is None or specification.loader is None:
        raise ProjectionError("cannot load the Pub-cache tree validator")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


def exact_names(root: Path, expected: set[str], label: str, directory: bool) -> None:
    try:
        entries = list(os.scandir(root))
    except OSError as error:
        raise ProjectionError(f"cannot inspect {label}: {error}") from error
    names = {entry.name for entry in entries}
    if names != expected or len(entries) != len(expected):
        raise ProjectionError(f"{label} inventory differs")
    for entry in entries:
        metadata = entry.stat(follow_symlinks=False)
        expected_type = stat.S_ISDIR if directory else stat.S_ISREG
        if entry.is_symlink() or not expected_type(metadata.st_mode):
            raise ProjectionError(f"{label} entry has the wrong type: {entry.name}")


def validate(root: Path, expected_digest: str, uid: int, gid: int) -> object:
    if (
        not root.is_absolute()
        or Path(os.path.normpath(os.fspath(root))) != root
        or re.fullmatch(r"[0-9a-f]{64}", expected_digest) is None
        or uid < 1
        or gid < 1
    ):
        raise ProjectionError("projection arguments are malformed")
    validator = load_cache_validator()
    try:
        summary = validator.inspect_tree(
            root, owners={(uid, gid)}, published=False
        )
    except (OSError, validator.PubCacheError) as error:
        raise ProjectionError(str(error)) from error
    if (
        summary.digest != expected_digest
        or summary.files != EXPECTED_FILES
        or summary.directories != EXPECTED_DIRECTORIES
        or summary.symlinks != 0
        or summary.size != EXPECTED_SIZE
    ):
        raise ProjectionError("projection tree identity differs")

    exact_names(root, {"hosted", "hosted-hashes"}, "projection root", True)
    exact_names(root / "hosted", {"pub.dev"}, "hosted root", True)
    exact_names(root / "hosted-hashes", {"pub.dev"}, "hosted-hashes root", True)
    exact_names(
        root / "hosted" / "pub.dev",
        set(EXPECTED_PACKAGES),
        "hosted package",
        True,
    )
    expected_hash_files = {f"{package}.sha256" for package in EXPECTED_PACKAGES}
    hash_root = root / "hosted-hashes" / "pub.dev"
    exact_names(hash_root, expected_hash_files, "hosted hash", False)
    for package, expected_hash in EXPECTED_PACKAGES.items():
        try:
            observed = (hash_root / f"{package}.sha256").read_text(
                encoding="ascii"
            ).strip()
        except (OSError, UnicodeError) as error:
            raise ProjectionError(f"cannot read hosted hash for {package}: {error}") from error
        if observed != expected_hash:
            raise ProjectionError(f"hosted hash differs for {package}")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--expected-digest", required=True)
    parser.add_argument("--uid", required=True, type=int)
    parser.add_argument("--gid", required=True, type=int)
    arguments = parser.parse_args()
    try:
        summary = validate(
            arguments.root, arguments.expected_digest, arguments.uid, arguments.gid
        )
    except ProjectionError as error:
        print(f"windows-presentation-pub-cache: FAIL: {error}", file=sys.stderr)
        return 1
    print(
        "windows-presentation-pub-cache: verified "
        f"sha256={summary.digest} files={summary.files} "
        f"directories={summary.directories} symlinks={summary.symlinks} "
        f"size={summary.size} packages={len(EXPECTED_PACKAGES)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
