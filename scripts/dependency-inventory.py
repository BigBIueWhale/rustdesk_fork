#!/usr/bin/env python3
"""Verify RustDesk dependency and build-surface inventory facts.

The Rust unsafe-block metric is lexical: it counts an ``unsafe`` token whose
next non-comment token is ``{``.  It is deliberately not an AST or safety
proof.  The Git index defines the candidate source set; non-ignored untracked
Rust sources and build scripts make the inventory fail closed.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tempfile
import tomllib
from typing import Any
from urllib.parse import urlsplit


EXPECTED = {
    "build_rs": {
        "paths": [
            "build.rs",
            "libs/clipboard/build.rs",
            "libs/enigo/build.rs",
            "libs/hbb_common/build.rs",
            "libs/portable/build.rs",
            "libs/scrap/build.rs",
        ],
        "regular_files": 6,
    },
    "cargo_lock": {
        "git_record_identities_sha256": "5f04a0476697c3433ef5a9f5e087ff29b5dc9f9689c41d524dfd9829a82fd7e1",
        "git_source_identities_sha256": "c4502af3f4c24f3d2c536bb4d39b2e85831450a838fa890140e1238ab3a91e24",
        "git_sourced_records": 36,
        "package_records": 905,
        "package_records_sha256": "6c2f1b15047dc82fe54074aebb19584150171d3bacae21bfa98c4158dc1645e7",
        "rustdesk_org_git_records": 26,
        "unique_git_source_urls": 26,
    },
    "flutter_pubspec": {
        "dependencies": [
            "auto_size_text",
            "auto_size_text_field",
            "back_button_interceptor",
            "bot_toast",
            "contextmenu",
            "dash_chat_2",
            "debounce_throttle",
            "desktop_drop",
            "desktop_multi_window",
            "device_info_plus",
            "draggable_float_widget",
            "dropdown_button2",
            "dynamic_layouts",
            "extended_text",
            "external_path",
            "ffi",
            "file_picker",
            "flex_color_picker",
            "flutter",
            "flutter_breadcrumb",
            "flutter_custom_cursor",
            "flutter_gpu_texture_renderer",
            "flutter_keyboard_visibility",
            "flutter_launcher_icons",
            "flutter_localizations",
            "flutter_rust_bridge",
            "flutter_svg",
            "freezed_annotation",
            "get",
            "google_fonts",
            "http",
            "image",
            "package_info_plus",
            "password_strength",
            "path",
            "path_provider",
            "percent_indicator",
            "provider",
            "pull_down_button",
            "qr_flutter",
            "scroll_pos",
            "settings_ui",
            "sqflite",
            "texture_rgba_renderer",
            "toggle_switch",
            "tuple",
            "uni_links",
            "uni_links_desktop",
            "url_launcher",
            "url_launcher_ios",
            "uuid",
            "vector_math",
            "visibility_detector",
            "wakelock_plus",
            "win32",
            "window_manager",
            "window_size",
            "xterm",
        ],
        "dependencies_entries": 58,
        "dev_dependencies": [
            "build_runner",
            "ffigen",
            "flutter_lints",
            "flutter_test",
            "freezed",
            "icons_launcher",
        ],
        "dev_dependencies_entries": 6,
        "direct_dependency_identities_sha256": "c4d142298306a81d3cd2e91040b52a0e55a5d896c2470298c6ee0e75c0006216",
        "direct_dependency_records_sha256": "28aa004608f2c323a5db5986f4693caa296a606c3d93a5854f43c03c6de652e1",
        "sdk_entries_excluded": 0,
        "union_entries": 64,
    },
    "flutter_pubspec_lock": {
        "git_hosted_records": 8,
        "git_record_identities_sha256": "56790997dedb97adf3c387a00b01175f1094ab03e2561b3a01ae1625ba59b9c4",
        "git_source_identities": {
            "dash_chat_2": "https://github.com/rustdesk-org/dash-chat-2",
            "desktop_multi_window": "https://github.com/rustdesk-org/rustdesk_desktop_multi_window",
            "dynamic_layouts": "https://github.com/rustdesk-org/dynamic_layouts",
            "flutter_gpu_texture_renderer": "https://github.com/rustdesk-org/flutter_gpu_texture_renderer",
            "texture_rgba_renderer": "https://github.com/rustdesk-org/flutter_texture_rgba_renderer",
            "uni_links": "https://github.com/rustdesk-org/uni_links",
            "window_manager": "https://github.com/rustdesk-org/window_manager",
            "window_size": "https://github.com/google/flutter-desktop-embedding",
        },
        "package_records": 199,
        "package_records_sha256": "ef70b0ff377a13464e5df50aa873c856b45446ba38370623fb3c40822527e157",
        "rustdesk_org_git_records": 7,
    },
    "github_workflows": {
        "disabled_workflow_definition_files": [
            "bridge.yml.disabled",
            "ci.yml.disabled",
            "flutter-build.yml.disabled",
            "flutter-ci.yml.disabled",
            "flutter-tag.yml.disabled",
            "third-party-RustDeskTempTopMostWindow.yml.disabled",
            "wf-cliprdr-ci.yml.disabled",
        ],
        "disabled_workflow_definitions": 7,
        "documentation_files": ["DISABLED.md"],
        "documentation_regular_files": 1,
        "enabled_workflow_definition_files": [],
        "enabled_workflow_definitions": 0,
        "regular_files": 8,
    },
    "rust_sources": {
        "files_with_unsafe_blocks": 74,
        "lexical_counts_by_file_sha256": "4d89e200c4b55df2e74f6c38cd8e336630ff41ecd70369a95a02a2f84ec42044",
        "lexical_unsafe_open_brace_blocks": 855,
        "tracked_rs_files": 247,
    },
}

YAML_KEY = re.compile(r"[A-Za-z0-9_.+-]+\Z")
URL_SCHEMES = frozenset({"git", "http", "https", "ssh"})


class InventoryError(RuntimeError):
    """An input is malformed, ambiguous, or unsafe to inventory."""


def _require_regular_file(path: Path) -> None:
    try:
        mode = path.lstat().st_mode
    except OSError as exc:
        raise InventoryError(f"cannot stat required file {path}: {exc}") from exc
    if stat.S_ISLNK(mode):
        raise InventoryError(f"required file is a symlink: {path}")
    if not stat.S_ISREG(mode):
        raise InventoryError(f"required path is not a regular file: {path}")


def _read_utf8(path: Path) -> str:
    _require_regular_file(path)
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise InventoryError(f"cannot read UTF-8 file {path}: {exc}") from exc


@dataclass(frozen=True)
class CanonicalGitUrl:
    identity: str
    github_owner: str | None


def _canonical_host(host: str, source: str) -> str:
    if not host or any(char.isspace() or ord(char) < 0x20 for char in host):
        raise InventoryError(f"{source}: malformed Git URL host")
    try:
        ipaddress.ip_address(host)
        return host.lower()
    except ValueError:
        pass
    try:
        ascii_host = host.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise InventoryError(f"{source}: malformed internationalized Git host") from exc
    if len(ascii_host) > 253 or any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        or re.fullmatch(r"[a-z0-9-]+", label) is None
        for label in ascii_host.rstrip(".").split(".")
    ):
        raise InventoryError(f"{source}: malformed Git URL host {host!r}")
    if ascii_host.endswith("."):
        ascii_host = ascii_host[:-1]
    return ascii_host


def _canonical_git_path(path: str, source: str, hierarchical: bool) -> list[str]:
    if "\\" in path or any(ord(char) < 0x20 for char in path):
        raise InventoryError(f"{source}: ambiguous Git URL path")
    if hierarchical:
        if not path.startswith("/") or path.startswith("//"):
            raise InventoryError(f"{source}: hierarchical Git URL needs one leading slash")
        path = path[1:]
    elif path.startswith("/"):
        raise InventoryError(f"{source}: SCP-style Git path must be relative")
    if path.endswith("/"):
        path = path[:-1]
    if not path:
        raise InventoryError(f"{source}: Git URL has no repository path")
    if re.search(r"%(?:2e|2f|5c)", path, flags=re.IGNORECASE):
        raise InventoryError(f"{source}: encoded dot or separator in Git URL path")
    if re.search(r"%(?![0-9A-Fa-f]{2})", path):
        raise InventoryError(f"{source}: malformed percent escape in Git URL path")
    segments = path.split("/")
    if any(not segment or segment in {".", ".."} for segment in segments):
        raise InventoryError(f"{source}: empty or dot Git URL path segment")
    return segments


def canonicalize_git_url(value: str, source: str = "Git URL") -> CanonicalGitUrl:
    if not isinstance(value, str) or not value:
        raise InventoryError(f"{source}: Git URL must be a non-empty string")
    if value.startswith("git+"):
        value = value[4:]
        if value.startswith("git+"):
            raise InventoryError(f"{source}: repeated Cargo git+ URL wrapper")
    if any(char.isspace() or ord(char) < 0x20 for char in value):
        raise InventoryError(f"{source}: whitespace or control character in Git URL")

    hierarchical = "://" in value
    username: str | None
    port: int | None
    if hierarchical:
        try:
            parsed = urlsplit(value)
            parsed_hostname = parsed.hostname
            parsed_username = parsed.username
            parsed_password = parsed.password
        except ValueError as exc:
            raise InventoryError(f"{source}: malformed hierarchical Git authority") from exc
        scheme = parsed.scheme.lower()
        if scheme not in URL_SCHEMES or not parsed.netloc or parsed_hostname is None:
            raise InventoryError(f"{source}: unsupported or malformed hierarchical Git URL")
        if parsed_password is not None:
            raise InventoryError(f"{source}: passwords in Git URLs are not accepted")
        username = parsed_username
        if username is not None and re.fullmatch(r"[A-Za-z0-9._-]+", username) is None:
            raise InventoryError(f"{source}: ambiguous Git URL username")
        try:
            port = parsed.port
        except ValueError as exc:
            raise InventoryError(f"{source}: malformed Git URL port") from exc
        host = _canonical_host(parsed_hostname, source)
        segments = _canonical_git_path(parsed.path, source, True)
        query = parsed.query
        fragment = parsed.fragment
    else:
        base, separator, fragment = value.partition("#")
        if separator and "#" in fragment:
            raise InventoryError(f"{source}: multiple Git URL fragments")
        base, separator, query = base.partition("?")
        if separator and "?" in query:
            raise InventoryError(f"{source}: multiple Git URL query delimiters")
        match = re.fullmatch(
            r"(?:(?P<user>[A-Za-z0-9._-]+)@)?(?P<host>[^/:@]+):(?P<path>.+)",
            base,
        )
        if match is None:
            raise InventoryError(f"{source}: malformed SCP-style Git URL")
        scheme = "ssh"
        username = match.group("user")
        port = None
        host = _canonical_host(match.group("host"), source)
        segments = _canonical_git_path(match.group("path"), source, False)

    if any(char.isspace() or ord(char) < 0x20 for char in query + fragment):
        raise InventoryError(f"{source}: ambiguous Git URL query or fragment")
    github_owner: str | None = None
    if host == "github.com":
        if username not in {None, "git"} or port is not None or len(segments) != 2:
            raise InventoryError(f"{source}: ambiguous GitHub repository authority or path")
        owner, repository = segments
        if re.fullmatch(r"[A-Za-z0-9_.-]+", owner) is None or re.fullmatch(
            r"[A-Za-z0-9_.-]+(?:\.git)?", repository, flags=re.IGNORECASE
        ) is None:
            raise InventoryError(f"{source}: malformed GitHub owner or repository")
        if repository.lower().endswith(".git"):
            repository = repository[:-4]
        if owner in {".", ".."} or repository in {"", ".", ".."}:
            raise InventoryError(f"{source}: ambiguous GitHub owner or repository")
        owner = owner.lower()
        repository = repository.lower()
        github_owner = owner
        canonical_path = f"{owner}/{repository}"
        authority = "github.com"
    else:
        canonical_path = "/".join(segments)
        userinfo = f"{username}@" if username is not None else ""
        port_text = f":{port}" if port is not None else ""
        authority_host = f"[{host}]" if ":" in host else host
        authority = f"{userinfo}{authority_host}{port_text}"
    suffix = (f"?{query}" if query else "") + (f"#{fragment}" if fragment else "")
    return CanonicalGitUrl(
        identity=f"{scheme}://{authority}/{canonical_path}{suffix}",
        github_owner=github_owner,
    )


def _stable_digest(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def inventory_cargo_lock(path: Path) -> dict[str, Any]:
    _require_regular_file(path)
    try:
        with path.open("rb") as stream:
            document = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise InventoryError(f"cannot parse {path} as TOML: {exc}") from exc

    packages = document.get("package")
    if not isinstance(packages, list):
        raise InventoryError(f"{path}: top-level 'package' must be an array of tables")

    git_sources: list[str] = []
    git_records: list[str] = []
    rustdesk_records = 0
    for index, package in enumerate(packages):
        if not isinstance(package, dict):
            raise InventoryError(f"{path}: package record {index} is not a table")
        source = package.get("source")
        if source is not None and not isinstance(source, str):
            raise InventoryError(f"{path}: package record {index} has a non-string source")
        if isinstance(source, str) and source.startswith("git+"):
            canonical = canonicalize_git_url(source, f"{path}: package record {index} source")
            git_sources.append(source)
            name = package.get("name")
            version = package.get("version")
            if not isinstance(name, str) or not isinstance(version, str):
                raise InventoryError(
                    f"{path}: git package record {index} needs string name and version"
                )
            git_records.append(f"{name}@{version}|{source}")
            if canonical.github_owner == "rustdesk-org":
                rustdesk_records += 1

    git_source_identities = sorted(set(git_sources))
    return {
        "git_sourced_records": len(git_sources),
        "git_record_identities_sha256": _stable_digest(sorted(git_records)),
        "git_source_identities_sha256": _stable_digest(git_source_identities),
        "package_records_sha256": _stable_digest(packages),
        "package_records": len(packages),
        "rustdesk_org_git_records": rustdesk_records,
        "unique_git_source_urls": len(git_source_identities),
    }


def _yaml_mapping_line(
    line: str, source: str, line_number: int
) -> tuple[int, str, str] | None:
    if "\t" in line:
        raise InventoryError(f"{source}:{line_number}: tabs are not allowed")
    if not line.strip() or line.lstrip().startswith("#"):
        return None

    indent = len(line) - len(line.lstrip(" "))
    if indent % 2:
        raise InventoryError(
            f"{source}:{line_number}: indentation must use two-space levels"
        )
    content = line[indent:]
    quote: str | None = None
    escaped = False
    delimiter = -1
    comment = len(content)
    index = 0
    while index < len(content):
        char = content[index]
        if quote == '"':
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quote = None
        elif quote == "'":
            if char == "'":
                if index + 1 < len(content) and content[index + 1] == "'":
                    index += 1
                else:
                    quote = None
        elif char in "'\"":
            quote = char
        elif char == ":" and delimiter < 0:
            if index + 1 < len(content) and not content[index + 1].isspace():
                raise InventoryError(
                    f"{source}:{line_number}: mapping ':' must be followed by whitespace"
                )
            delimiter = index
        elif char == "#" and (index == 0 or content[index - 1].isspace()):
            comment = index
            break
        index += 1

    if quote is not None or escaped:
        raise InventoryError(f"{source}:{line_number}: unterminated quoted scalar")
    if delimiter < 0 or delimiter >= comment:
        raise InventoryError(f"{source}:{line_number}: expected a mapping entry")

    raw_key = content[:delimiter]
    key = raw_key.strip()
    if raw_key != key:
        raise InventoryError(
            f"{source}:{line_number}: whitespace around mapping keys is ambiguous"
        )
    if not YAML_KEY.fullmatch(key):
        raise InventoryError(
            f"{source}:{line_number}: unsupported or ambiguous mapping key {key!r}"
        )
    value = content[delimiter + 1 : comment].strip()
    if value.startswith(("[", "{", "|", ">", "&", "*", "!")):
        raise InventoryError(
            f"{source}:{line_number}: unsupported YAML scalar form {value!r}"
        )
    return indent, key, value


def _yaml_scalar(value: str, source: str, line_number: int) -> str:
    if not value:
        raise InventoryError(f"{source}:{line_number}: expected a scalar value")
    if value.startswith('"'):
        if not value.endswith('"'):
            raise InventoryError(f"{source}:{line_number}: malformed quoted scalar")
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError as exc:
            raise InventoryError(
                f"{source}:{line_number}: unsupported double-quoted scalar: {exc.msg}"
            ) from exc
        if not isinstance(decoded, str):
            raise InventoryError(f"{source}:{line_number}: scalar is not a string")
        return decoded
    if value.startswith("'"):
        if len(value) < 2 or not value.endswith("'"):
            raise InventoryError(f"{source}:{line_number}: malformed quoted scalar")
        return value[1:-1].replace("''", "'")
    if '"' in value or "'" in value:
        raise InventoryError(
            f"{source}:{line_number}: quotes inside a plain scalar are ambiguous"
        )
    return value


def parse_strict_yaml_mapping(text: str, source: str) -> dict[str, Any]:
    """Parse the mapping-only subset used by pub lockfile dependency records."""

    tokens: list[tuple[int, int, str, str]] = []
    for line_number, line in enumerate(text.splitlines(), 1):
        parsed = _yaml_mapping_line(line, source, line_number)
        if parsed is not None:
            indent, key, value = parsed
            tokens.append((line_number, indent, key, value))
    if not tokens:
        raise InventoryError(f"{source}: document contains no mapping entries")

    def parse_level(index: int, expected_indent: int) -> tuple[dict[str, Any], int]:
        result: dict[str, Any] = {}
        while index < len(tokens):
            line_number, indent, key, value = tokens[index]
            if indent < expected_indent:
                break
            if indent > expected_indent:
                raise InventoryError(
                    f"{source}:{line_number}: unexpected indentation level {indent}"
                )
            if key in result:
                raise InventoryError(f"{source}:{line_number}: duplicate key {key!r}")
            index += 1
            if value:
                result[key] = _yaml_scalar(value, source, line_number)
                if index < len(tokens) and tokens[index][1] > indent:
                    raise InventoryError(
                        f"{source}:{tokens[index][0]}: scalar {key!r} cannot have children"
                    )
            else:
                if index >= len(tokens) or tokens[index][1] <= indent:
                    raise InventoryError(
                        f"{source}:{line_number}: empty mapping {key!r} is ambiguous"
                    )
                if tokens[index][1] != indent + 2:
                    raise InventoryError(
                        f"{source}:{tokens[index][0]}: mapping children must indent by two spaces"
                    )
                result[key], index = parse_level(index, indent + 2)
        return result, index

    if tokens[0][1] != 0:
        raise InventoryError(f"{source}:{tokens[0][0]}: first mapping entry must be top-level")
    document, final_index = parse_level(0, 0)
    if final_index != len(tokens):
        raise InventoryError(f"{source}:{tokens[final_index][0]}: unparsed YAML content")
    return document


def inventory_flutter_lock(path: Path) -> dict[str, Any]:
    document = parse_strict_yaml_mapping(_read_utf8(path), str(path))
    packages = document.get("packages")
    if not isinstance(packages, dict):
        raise InventoryError(f"{path}: top-level 'packages' must be a mapping")

    git_records = 0
    rustdesk_records = 0
    git_identities: dict[str, Any] = {}
    for name, package in packages.items():
        if not isinstance(package, dict):
            raise InventoryError(f"{path}: package {name!r} must be a mapping")
        source = package.get("source")
        if not isinstance(source, str):
            raise InventoryError(f"{path}: package {name!r} must have a scalar source")
        if source == "git":
            description = package.get("description")
            if not isinstance(description, dict):
                raise InventoryError(
                    f"{path}: git package {name!r} must have a mapping description"
                )
            url = description.get("url")
            if not isinstance(url, str):
                raise InventoryError(
                    f"{path}: git package {name!r} must have a scalar URL"
                )
            canonical = canonicalize_git_url(url, f"{path}: git package {name!r} URL")
            git_records += 1
            git_identities[name] = description
            if canonical.github_owner == "rustdesk-org":
                rustdesk_records += 1

    return {
        "git_hosted_records": git_records,
        "git_record_identities_sha256": _stable_digest(git_identities),
        "git_source_identities": {
            name: canonicalize_git_url(description["url"], f"{path}: {name}").identity
            for name, description in sorted(git_identities.items())
        },
        "package_records_sha256": _stable_digest(packages),
        "package_records": len(packages),
        "rustdesk_org_git_records": rustdesk_records,
    }


def _pubspec_sections(text: str, source: str) -> dict[str, dict[str, Any]]:
    wanted = {"dependencies", "dev_dependencies"}
    lines = text.splitlines()
    headings: list[tuple[int, str, str]] = []
    found: dict[str, int] = {}

    for index, line in enumerate(lines):
        if "\t" in line:
            raise InventoryError(f"{source}:{index + 1}: tabs are not allowed")
        if not line.strip() or line.lstrip().startswith("#") or line.startswith(" "):
            continue
        parsed = _yaml_mapping_line(line, source, index + 1)
        if parsed is None or parsed[0] != 0:
            raise InventoryError(f"{source}:{index + 1}: malformed top-level entry")
        _, key, value = parsed
        headings.append((index, key, value))
        if key in wanted:
            if key in found:
                raise InventoryError(f"{source}:{index + 1}: duplicate section {key!r}")
            found[key] = len(headings) - 1

    missing = wanted - found.keys()
    if missing:
        raise InventoryError(f"{source}: missing sections: {', '.join(sorted(missing))}")

    sections: dict[str, dict[str, Any]] = {}
    for key in sorted(wanted):
        heading_position = found[key]
        start, _, value = headings[heading_position]
        if value:
            raise InventoryError(f"{source}:{start + 1}: section {key!r} must be a mapping")
        end = (
            headings[heading_position + 1][0]
            if heading_position + 1 < len(headings)
            else len(lines)
        )
        fragment = "\n".join(lines[start:end])
        parsed_fragment = parse_strict_yaml_mapping(fragment, f"{source}:{start + 1}")
        section = parsed_fragment.get(key)
        if not isinstance(section, dict):
            raise InventoryError(f"{source}:{start + 1}: section {key!r} is not a mapping")
        sections[key] = section
    return sections


def inventory_flutter_pubspec(path: Path) -> dict[str, Any]:
    sections = _pubspec_sections(_read_utf8(path), str(path))
    dependencies = set(sections["dependencies"])
    dev_dependencies = set(sections["dev_dependencies"])
    sdk_entries = int("sdk" in dependencies) + int("sdk" in dev_dependencies)
    dependencies.discard("sdk")
    dev_dependencies.discard("sdk")
    dependency_identities = {
        "dependencies": sorted(dependencies),
        "dev_dependencies": sorted(dev_dependencies),
    }
    return {
        "dependencies": dependency_identities["dependencies"],
        "dependencies_entries": len(dependencies),
        "dev_dependencies": dependency_identities["dev_dependencies"],
        "dev_dependencies_entries": len(dev_dependencies),
        "direct_dependency_identities_sha256": _stable_digest(dependency_identities),
        "direct_dependency_records_sha256": _stable_digest(sections),
        "sdk_entries_excluded": sdk_entries,
        "union_entries": len(dependencies | dev_dependencies),
    }


def inventory_workflows(path: Path) -> dict[str, Any]:
    try:
        mode = path.lstat().st_mode
    except OSError as exc:
        raise InventoryError(f"cannot stat workflows directory {path}: {exc}") from exc
    if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
        raise InventoryError(f"workflows path is not a real directory: {path}")

    enabled_definitions: list[str] = []
    disabled_definitions: list[str] = []
    documentation_files: list[str] = []
    try:
        entries = sorted(os.scandir(path), key=lambda entry: entry.name)
    except OSError as exc:
        raise InventoryError(f"cannot scan workflows directory {path}: {exc}") from exc
    for entry in entries:
        if entry.is_symlink():
            raise InventoryError(f"workflow entry is a symlink: {entry.path}")
        try:
            is_file = entry.is_file(follow_symlinks=False)
        except OSError as exc:
            raise InventoryError(f"cannot classify workflow entry {entry.path}: {exc}") from exc
        if not is_file:
            raise InventoryError(f"workflow entry is not a regular file: {entry.path}")
        if entry.name.endswith((".yml", ".yaml")):
            enabled_definitions.append(entry.name)
        elif entry.name.endswith((".yml.disabled", ".yaml.disabled")):
            disabled_definitions.append(entry.name)
        elif entry.name.endswith(".md"):
            documentation_files.append(entry.name)
        else:
            raise InventoryError(
                f"unknown regular entry in workflows directory: {entry.path}"
            )
    return {
        "disabled_workflow_definition_files": disabled_definitions,
        "disabled_workflow_definitions": len(disabled_definitions),
        "documentation_files": documentation_files,
        "documentation_regular_files": len(documentation_files),
        "enabled_workflow_definition_files": enabled_definitions,
        "enabled_workflow_definitions": len(enabled_definitions),
        "regular_files": len(enabled_definitions + disabled_definitions + documentation_files),
    }


def _git_environment() -> dict[str, str]:
    environment = os.environ.copy()
    for variable in list(environment):
        if variable in {
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "GIT_CEILING_DIRECTORIES",
            "GIT_COMMON_DIR",
            "GIT_CONFIG_PARAMETERS",
            "GIT_DIR",
            "GIT_GLOB_PATHSPECS",
            "GIT_ICASE_PATHSPECS",
            "GIT_INDEX_FILE",
            "GIT_LITERAL_PATHSPECS",
            "GIT_NOGLOB_PATHSPECS",
            "GIT_OBJECT_DIRECTORY",
            "GIT_PREFIX",
            "GIT_WORK_TREE",
        } or re.fullmatch(r"GIT_CONFIG_(?:COUNT|KEY_\d+|VALUE_\d+)", variable):
            environment.pop(variable, None)
    environment["GIT_CONFIG_NOSYSTEM"] = "1"
    environment["GIT_CONFIG_GLOBAL"] = os.devnull
    return environment


def _validate_git_relative_path(path: str, description: str) -> None:
    parts = path.split("/")
    if (
        not path
        or path.startswith("/")
        or re.match(r"^[A-Za-z]:", path) is not None
        or "\\" in path
        or any(ord(char) < 0x20 or ord(char) == 0x7F for char in path)
        or any(part in {"", ".", ".."} for part in parts)
        or PurePosixPath(path).is_absolute()
    ):
        raise InventoryError(f"git returned an unsafe {description} path: {path!r}")


def _parse_tagged_git_paths(
    output: bytes, description: str
) -> tuple[list[str], list[str]]:
    if not output:
        return [], []
    if not output.endswith(b"\0"):
        raise InventoryError(
            f"git returned unterminated NUL-delimited {description} output"
        )
    records = output[:-1].split(b"\0")
    if any(not record for record in records):
        raise InventoryError(f"git returned an empty {description} path record")

    indexed: list[str] = []
    untracked: list[str] = []
    seen: set[str] = set()
    for record in records:
        if len(record) < 3 or record[1:2] != b" ":
            raise InventoryError(f"git returned a malformed tagged {description} record")
        tag = record[:1]
        try:
            path = record[2:].decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise InventoryError(
                f"{description} path is not valid UTF-8: {exc}"
            ) from exc
        _validate_git_relative_path(path, description)
        if path in seen:
            raise InventoryError(f"git returned duplicate {description} path {path!r}")
        seen.add(path)
        if tag in {b"H", b"S"}:
            indexed.append(path)
        elif tag == b"?":
            untracked.append(path)
        else:
            raise InventoryError(
                f"git returned unsupported {description} status tag {tag!r}"
            )
    return sorted(indexed), sorted(untracked)


def _indexed_paths_from_git(
    root: Path, pathspecs: list[str], description: str
) -> list[str]:
    environment = _git_environment()
    try:
        resolved_root = root.resolve(strict=True)
        if not resolved_root.is_dir():
            raise InventoryError(f"{description} root is not a directory: {resolved_root}")
        repository_probe = subprocess.run(
            [
                "git",
                "-c",
                f"core.excludesFile={os.devnull}",
                "-C",
                str(resolved_root),
                "rev-parse",
                "--is-inside-work-tree",
                "--is-bare-repository",
                "--show-prefix",
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            env=environment,
        )
        if repository_probe.returncode != 0:
            message = repository_probe.stderr.decode("utf-8", errors="replace").strip()
            raise InventoryError(f"cannot identify top repository for {description}: {message}")
        if repository_probe.stdout != b"true\nfalse\n\n":
            raise InventoryError(
                f"{description} root {resolved_root} is not an unambiguous top worktree"
            )
        completed = subprocess.run(
            [
                "git",
                "-c",
                f"core.excludesFile={os.devnull}",
                "-C",
                str(resolved_root),
                "ls-files",
                "--cached",
                "--others",
                "--exclude-standard",
                "--full-name",
                "-t",
                "-z",
                "--",
                *pathspecs,
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise InventoryError(f"cannot list tracked {description}: {exc}") from exc
    if completed.returncode != 0:
        message = completed.stderr.decode("utf-8", errors="replace").strip()
        raise InventoryError(f"git ls-files for {description} failed: {message}")
    indexed, untracked = _parse_tagged_git_paths(completed.stdout, description)
    if untracked:
        joined = ", ".join(repr(path) for path in untracked)
        raise InventoryError(
            f"untracked non-ignored {description} must be staged or removed: {joined}"
        )
    return indexed


def inventory_build_rs(root: Path) -> dict[str, Any]:
    paths = _indexed_paths_from_git(root, [":(glob)**/build.rs"], "build.rs")
    for relative in paths:
        if Path(relative).name != "build.rs":
            raise InventoryError(f"Git pathspec returned a non-build.rs path: {relative!r}")
        _require_regular_file(root / relative)
    return {"paths": paths, "regular_files": len(paths)}


def _skip_block_comment(text: str, index: int, source: str) -> int:
    depth = 1
    index += 2
    while index < len(text):
        if text.startswith("/*", index):
            depth += 1
            index += 2
        elif text.startswith("*/", index):
            depth -= 1
            index += 2
            if depth == 0:
                return index
        else:
            index += 1
    raise InventoryError(f"{source}: unterminated Rust block comment")


def _skip_space_and_comments(text: str, index: int, source: str) -> int:
    while index < len(text):
        if text[index].isspace():
            index += 1
        elif text.startswith("//", index):
            newline = text.find("\n", index + 2)
            index = len(text) if newline < 0 else newline + 1
        elif text.startswith("/*", index):
            index = _skip_block_comment(text, index, source)
        else:
            break
    return index


def _skip_raw_string(text: str, index: int, source: str) -> int | None:
    cursor = index
    if text.startswith(("br", "cr"), cursor):
        cursor += 2
    elif text.startswith("r", cursor):
        cursor += 1
    else:
        return None
    hash_start = cursor
    while cursor < len(text) and text[cursor] == "#":
        cursor += 1
    if cursor - hash_start > 255:
        raise InventoryError(f"{source}: Rust raw string has more than 255 hashes")
    if cursor >= len(text) or text[cursor] != '"':
        return None
    hashes = text[hash_start:cursor]
    closing = '"' + hashes
    end = text.find(closing, cursor + 1)
    if end < 0:
        raise InventoryError(f"{source}: unterminated Rust raw string")
    return end + len(closing)


def _skip_quoted_string(text: str, index: int, source: str) -> int:
    index += 1
    while index < len(text):
        if text[index] == "\\":
            if index + 1 >= len(text):
                break
            index += 2
        elif text[index] == '"':
            return index + 1
        else:
            index += 1
    raise InventoryError(f"{source}: unterminated Rust string")


def _rust_identifier_start(char: str) -> bool:
    return char == "_" or char.isidentifier()


def _rust_identifier_continue(char: str) -> bool:
    return char == "_" or ("a" + char).isidentifier()


def _rust_identifier_end(text: str, index: int) -> int:
    index += 1
    while index < len(text) and _rust_identifier_continue(text[index]):
        index += 1
    return index


def _skip_char_literal(text: str, index: int, source: str) -> int | None:
    cursor = index + 1
    if cursor >= len(text) or text[cursor] in "\r\n'":
        return None
    if text[cursor] == "\\":
        cursor += 1
        if cursor >= len(text):
            raise InventoryError(f"{source}: unterminated Rust character escape")
        escape = text[cursor]
        if escape == "x":
            if cursor + 2 >= len(text) or any(
                char not in "0123456789abcdefABCDEF" for char in text[cursor + 1 : cursor + 3]
            ):
                raise InventoryError(f"{source}: malformed Rust hexadecimal character escape")
            cursor += 3
        elif escape == "u" and cursor + 1 < len(text) and text[cursor + 1] == "{":
            close = text.find("}", cursor + 2)
            if close < 0:
                raise InventoryError(f"{source}: unterminated Rust Unicode character escape")
            digits = text[cursor + 2 : close].replace("_", "")
            if not 1 <= len(digits) <= 6 or any(
                char not in "0123456789abcdefABCDEF" for char in digits
            ):
                raise InventoryError(f"{source}: malformed Rust Unicode character escape")
            cursor = close + 1
        elif escape in "nrt0\\'\"":
            cursor += 1
        else:
            raise InventoryError(f"{source}: unsupported Rust character escape \\{escape}")
    else:
        if text[cursor] in "\\\r\n":
            return None
        cursor += 1
    if cursor < len(text) and text[cursor] == "'":
        return cursor + 1
    return None


def count_lexical_unsafe_blocks(data: bytes, source: str) -> int:
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise InventoryError(f"{source}: Rust source is not valid UTF-8: {exc}") from exc
    count = 0
    index = 0
    while index < len(text):
        skipped = _skip_space_and_comments(text, index, source)
        if skipped != index:
            index = skipped
            continue

        raw_end = _skip_raw_string(text, index, source)
        if raw_end is not None:
            index = raw_end
            continue
        if text.startswith(("b\"", "c\""), index):
            index = _skip_quoted_string(text, index + 1, source)
            continue
        if text.startswith("b'", index):
            char_end = _skip_char_literal(text, index + 1, source)
            if char_end is None:
                raise InventoryError(f"{source}: malformed Rust byte character literal")
            index = char_end
            continue
        char = text[index]
        if char == '"':
            index = _skip_quoted_string(text, index, source)
            continue
        if char == "'":
            char_end = _skip_char_literal(text, index, source)
            if char_end is not None:
                index = char_end
                continue
            if index + 1 < len(text) and _rust_identifier_start(text[index + 1]):
                index = _rust_identifier_end(text, index + 1)
                continue
            raise InventoryError(f"{source}: malformed Rust apostrophe token")
        if char.isdecimal():
            index += 1
            while index < len(text) and (
                _rust_identifier_continue(text[index])
                or text[index] in "."
            ):
                index += 1
            continue
        if _rust_identifier_start(char):
            if text.startswith("r#", index) and index + 2 < len(text):
                cursor = index + 2
                if _rust_identifier_start(text[cursor]):
                    cursor = _rust_identifier_end(text, cursor)
                    index = cursor
                    continue
            cursor = _rust_identifier_end(text, index)
            if text[index:cursor] == "unsafe":
                next_token = _skip_space_and_comments(text, cursor, source)
                if next_token < len(text) and text[next_token] == "{":
                    count += 1
            index = cursor
            continue
        if _rust_identifier_continue(char):
            raise InventoryError(
                f"{source}: isolated Unicode identifier continuation at character {index}"
            )
        if ord(char) > 0x7F:
            raise InventoryError(f"{source}: unsupported non-ASCII Rust token {char!r}")
        index += 1
    return count


def _tracked_rust_paths(root: Path) -> list[str]:
    return _indexed_paths_from_git(root, ["*.rs"], "Rust source")


def inventory_rust_sources(root: Path) -> dict[str, Any]:
    paths = _tracked_rust_paths(root)
    counts_by_file: dict[str, int] = {}
    for relative in paths:
        path = root / relative
        _require_regular_file(path)
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise InventoryError(f"cannot read tracked Rust source {path}: {exc}") from exc
        counts_by_file[relative] = count_lexical_unsafe_blocks(data, relative)
    return {
        "files_with_unsafe_blocks": sum(value > 0 for value in counts_by_file.values()),
        "lexical_counts_by_file_sha256": _stable_digest(counts_by_file),
        "lexical_unsafe_open_brace_blocks": sum(counts_by_file.values()),
        "tracked_rs_files": len(paths),
    }


def collect_inventory(root: Path) -> dict[str, dict[str, Any]]:
    return {
        "build_rs": inventory_build_rs(root),
        "cargo_lock": inventory_cargo_lock(root / "Cargo.lock"),
        "flutter_pubspec": inventory_flutter_pubspec(root / "flutter/pubspec.yaml"),
        "flutter_pubspec_lock": inventory_flutter_lock(root / "flutter/pubspec.lock"),
        "github_workflows": inventory_workflows(root / ".github/workflows"),
        "rust_sources": inventory_rust_sources(root),
    }


def _drift_lines(actual: Any, expected: Any, prefix: str = "") -> list[str]:
    if isinstance(actual, dict) and isinstance(expected, dict):
        lines: list[str] = []
        for key in sorted(set(actual) | set(expected)):
            child = f"{prefix}.{key}" if prefix else key
            if key not in actual:
                lines.append(f"{child}: missing (expected {expected[key]!r})")
            elif key not in expected:
                lines.append(f"{child}: unexpected value {actual[key]!r}")
            else:
                lines.extend(_drift_lines(actual[key], expected[key], child))
        return lines
    if actual != expected:
        return [f"{prefix}: expected {expected!r}, got {actual!r}"]
    return []


def _write_fixture(root: Path) -> None:
    (root / "flutter").mkdir()
    (root / ".github/workflows").mkdir(parents=True)
    (root / "src").mkdir()
    (root / "pkg").mkdir()
    (root / "Cargo.lock").write_text(
        """version = 3

[[package]]
name = "local"
version = "1.0.0"

[[package]]
name = "org"
version = "1.0.0"
source = "git+https://github.com/rustdesk-org/example#abc"

[[package]]
name = "other"
version = "1.0.0"
source = "git+https://example.test/other#def"
""",
        encoding="utf-8",
    )
    (root / "flutter/pubspec.lock").write_text(
        """packages:
  hosted:
    description:
      name: hosted
      url: "https://pub.dev"
    source: hosted
    version: "1.0.0"
  org:
    dependency: "direct main"
    description:
      path: .
      ref: abc
      resolved-ref: abc
      url: "https://github.com/rustdesk-org/example"
    source: git
    version: "1.0.0"
  other:
    description:
      url: "https://example.test/other"
    source: git
    version: "1.0.0"
sdks:
  dart: ">=3.0.0 <4.0.0"
""",
        encoding="utf-8",
    )
    (root / "flutter/pubspec.yaml").write_text(
        """name: fixture
dependencies:
  flutter:
    sdk: flutter
  alpha: ^1.0.0
dev_dependencies:
  flutter_test:
    sdk: flutter
  beta: ^1.0.0
flutter:
  uses-material-design: true
""",
        encoding="utf-8",
    )
    (root / ".github/workflows/ci.yml").write_text("name: ci\n", encoding="utf-8")
    (root / ".github/workflows/old.yml.disabled").write_text(
        "name: old\n", encoding="utf-8"
    )
    (root / ".github/workflows/README.md").write_text(
        "# Fixture workflows\n", encoding="utf-8"
    )
    (root / "build.rs").write_text("fn main() {}\n", encoding="utf-8")
    (root / "pkg/build.rs").write_text("fn main() {}\n", encoding="utf-8")
    (root / "src/tracked.rs").write_text(
        "fn f() { unsafe { call(); } }\n",
        encoding="utf-8",
    )


def run_self_test() -> list[str]:
    checks: list[str] = []

    def expect_error(
        label: str, action: Any, expected_fragment: str | None = None
    ) -> None:
        try:
            action()
        except InventoryError as exc:
            if expected_fragment is not None and expected_fragment not in str(exc):
                raise InventoryError(
                    f"self-test {label!r}: expected error containing "
                    f"{expected_fragment!r}, got {str(exc)!r}"
                ) from exc
            checks.append(label)
            return
        raise InventoryError(f"self-test {label!r} did not fail closed")

    def assert_equal(label: str, actual: Any, expected: Any) -> None:
        if actual != expected:
            raise InventoryError(
                f"self-test {label!r}: expected {expected!r}, got {actual!r}"
            )
        checks.append(label)

    def git(root: Path, *arguments: str) -> None:
        try:
            completed = subprocess.run(
                ["git", *arguments],
                cwd=root,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise InventoryError(f"self-test Git command failed: {exc}") from exc
        if completed.returncode != 0:
            message = completed.stderr.decode("utf-8", errors="replace").strip()
            raise InventoryError(f"self-test Git command failed: {message}")

    assert_equal(
        "tagged-git-paths",
        _parse_tagged_git_paths(
            b"? src/new.rs\0H build.rs\0S src/skip.rs\0", "fixture source"
        ),
        (["build.rs", "src/skip.rs"], ["src/new.rs"]),
    )
    for label, output in {
        "git-output-unterminated": b"H src/lib.rs",
        "git-output-empty-record": b"H src/lib.rs\0\0",
        "git-output-missing-tag-separator": b"Hsrc/lib.rs\0",
        "git-output-unknown-tag": b"M src/lib.rs\0",
        "git-output-invalid-utf8": b"H src/\xff.rs\0",
        "git-output-duplicate": b"H src/lib.rs\0? src/lib.rs\0",
        "git-path-empty": b"H \0",
        "git-path-absolute": b"H /src/lib.rs\0",
        "git-path-drive-absolute": b"H C:/src/lib.rs\0",
        "git-path-parent": b"H src/../lib.rs\0",
        "git-path-current": b"H src/./lib.rs\0",
        "git-path-empty-component": b"H src//lib.rs\0",
        "git-path-backslash": b"H src\\lib.rs\0",
        "git-path-control": b"H src/bad\nname.rs\0",
    }.items():
        expect_error(
            label,
            lambda output=output: _parse_tagged_git_paths(output, "fixture source"),
        )

    with tempfile.TemporaryDirectory(prefix="dependency-inventory-") as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        git(root, "init", "-q")
        _write_fixture(root)
        git(root, "add", "--", "build.rs", "pkg/build.rs", "src/tracked.rs")

        cargo_org_source = "git+https://github.com/rustdesk-org/example#abc"
        cargo_other_source = "git+https://example.test/other#def"
        fixture_expected = {
            "build_rs": {"paths": ["build.rs", "pkg/build.rs"], "regular_files": 2},
            "cargo_lock": {
                "git_record_identities_sha256": _stable_digest(
                    sorted(
                        [
                            f"org@1.0.0|{cargo_org_source}",
                            f"other@1.0.0|{cargo_other_source}",
                        ]
                    )
                ),
                "git_source_identities_sha256": _stable_digest(
                    sorted([cargo_org_source, cargo_other_source])
                ),
                "package_records_sha256": _stable_digest(
                    tomllib.loads((root / "Cargo.lock").read_text(encoding="utf-8"))["package"]
                ),
                "git_sourced_records": 2,
                "package_records": 3,
                "rustdesk_org_git_records": 1,
                "unique_git_source_urls": 2,
            },
            "flutter_pubspec": {
                "dependencies": ["alpha", "flutter"],
                "dependencies_entries": 2,
                "dev_dependencies": ["beta", "flutter_test"],
                "dev_dependencies_entries": 2,
                "direct_dependency_identities_sha256": _stable_digest(
                    {
                        "dependencies": ["alpha", "flutter"],
                        "dev_dependencies": ["beta", "flutter_test"],
                    }
                ),
                "direct_dependency_records_sha256": _stable_digest(
                    _pubspec_sections(
                        (root / "flutter/pubspec.yaml").read_text(encoding="utf-8"),
                        "fixture pubspec",
                    )
                ),
                "sdk_entries_excluded": 0,
                "union_entries": 4,
            },
            "flutter_pubspec_lock": {
                "git_hosted_records": 2,
                "git_record_identities_sha256": _stable_digest(
                    {
                        "org": {
                            "path": ".",
                            "ref": "abc",
                            "resolved-ref": "abc",
                            "url": "https://github.com/rustdesk-org/example",
                        },
                        "other": {"url": "https://example.test/other"},
                    }
                ),
                "git_source_identities": {
                    "org": "https://github.com/rustdesk-org/example",
                    "other": "https://example.test/other",
                },
                "package_records_sha256": _stable_digest(
                    parse_strict_yaml_mapping(
                        (root / "flutter/pubspec.lock").read_text(encoding="utf-8"),
                        "fixture lock",
                    )["packages"]
                ),
                "package_records": 3,
                "rustdesk_org_git_records": 1,
            },
            "github_workflows": {
                "disabled_workflow_definition_files": ["old.yml.disabled"],
                "disabled_workflow_definitions": 1,
                "documentation_files": ["README.md"],
                "documentation_regular_files": 1,
                "enabled_workflow_definition_files": ["ci.yml"],
                "enabled_workflow_definitions": 1,
                "regular_files": 3,
            },
            "rust_sources": {
                "files_with_unsafe_blocks": 1,
                "lexical_counts_by_file_sha256": _stable_digest(
                    {"build.rs": 0, "pkg/build.rs": 0, "src/tracked.rs": 1}
                ),
                "lexical_unsafe_open_brace_blocks": 1,
                "tracked_rs_files": 3,
            },
        }
        assert_equal("baseline-end-to-end", collect_inventory(root), fixture_expected)

        cargo_path = root / "Cargo.lock"
        cargo_baseline = cargo_path.read_text(encoding="utf-8")
        cargo_path.write_text(cargo_baseline + "[[package]\n", encoding="utf-8")
        expect_error("malformed-cargo-toml", lambda: inventory_cargo_lock(cargo_path))
        cargo_path.write_text(
            cargo_baseline
            + """
[[package]]
name = "added"
version = "2.0.0"
source = "git+ssh://git@github.com/rustdesk-org/added.git#123"
""",
            encoding="utf-8",
        )
        cargo_added = inventory_cargo_lock(cargo_path)
        assert_equal("cargo-package-addition", cargo_added["package_records"], 4)
        assert_equal("cargo-git-addition", cargo_added["git_sourced_records"], 3)
        assert_equal("cargo-owner-addition", cargo_added["rustdesk_org_git_records"], 2)
        if cargo_added["git_record_identities_sha256"] == fixture_expected["cargo_lock"]["git_record_identities_sha256"]:
            raise InventoryError("self-test Cargo source addition did not change its digest")
        checks.append("cargo-source-digest-addition")
        drift = _drift_lines(collect_inventory(root), fixture_expected)
        if not any(line.startswith("cargo_lock.") for line in drift):
            raise InventoryError("self-test explicit EXPECTED comparison missed Cargo drift")
        checks.append("explicit-expected-collection-drift")
        cargo_path.write_text(
            cargo_baseline.replace("github.com/rustdesk-org/example", "example.test/substitute"),
            encoding="utf-8",
        )
        assert_equal(
            "cargo-source-substitution",
            inventory_cargo_lock(cargo_path)["rustdesk_org_git_records"],
            0,
        )
        cargo_path.write_text(
            cargo_baseline.replace("https://example.test/other", "https://mirror.test/other"),
            encoding="utf-8",
        )
        cargo_source_swap = inventory_cargo_lock(cargo_path)
        assert_equal("cargo-source-swap-keeps-count", cargo_source_swap["git_sourced_records"], 2)
        if cargo_source_swap["git_source_identities_sha256"] == fixture_expected["cargo_lock"]["git_source_identities_sha256"]:
            raise InventoryError("self-test Cargo source digest ignored a same-count URL swap")
        checks.append("cargo-source-swap-digest")
        cargo_path.write_text(
            cargo_baseline.replace('name = "local"\nversion = "1.0.0"', 'name = "local"\nversion = "1.1.0"'),
            encoding="utf-8",
        )
        cargo_non_git_change = inventory_cargo_lock(cargo_path)
        assert_equal(
            "cargo-non-git-keeps-git-digest",
            cargo_non_git_change["git_record_identities_sha256"],
            fixture_expected["cargo_lock"]["git_record_identities_sha256"],
        )
        if cargo_non_git_change["package_records_sha256"] == fixture_expected["cargo_lock"]["package_records_sha256"]:
            raise InventoryError("self-test Cargo package digest ignored a non-Git version change")
        checks.append("cargo-all-package-record-digest")
        cargo_path.write_text(cargo_baseline, encoding="utf-8")

        flutter_lock_path = root / "flutter/pubspec.lock"
        flutter_lock_baseline = flutter_lock_path.read_text(encoding="utf-8")
        flutter_lock_path.write_text("packages:\n   bad:\n    source: hosted\n", encoding="utf-8")
        expect_error("malformed-flutter-lock-yaml", lambda: inventory_flutter_lock(flutter_lock_path))
        flutter_lock_path.write_text(
            flutter_lock_baseline.replace(
                "sdks:\n",
                """  added:
    description:
      url: git@github.com:rustdesk-org/added.git
    source: git
    version: "2.0.0"
sdks:
""",
            ),
            encoding="utf-8",
        )
        flutter_added = inventory_flutter_lock(flutter_lock_path)
        assert_equal("flutter-lock-package-addition", flutter_added["package_records"], 4)
        assert_equal("flutter-lock-git-addition", flutter_added["git_hosted_records"], 3)
        assert_equal("flutter-lock-owner-addition", flutter_added["rustdesk_org_git_records"], 2)
        if flutter_added["git_record_identities_sha256"] == fixture_expected["flutter_pubspec_lock"]["git_record_identities_sha256"]:
            raise InventoryError("self-test Flutter source addition did not change its digest")
        checks.append("flutter-lock-source-digest-addition")
        flutter_lock_path.write_text(
            flutter_lock_baseline.replace("github.com/rustdesk-org/example", "example.test/substitute"),
            encoding="utf-8",
        )
        assert_equal(
            "flutter-lock-url-substitution",
            inventory_flutter_lock(flutter_lock_path)["rustdesk_org_git_records"],
            0,
        )
        flutter_lock_path.write_text(
            flutter_lock_baseline.replace(
                '    source: hosted\n    version: "1.0.0"',
                '    source: hosted\n    version: "1.1.0"',
                1,
            ),
            encoding="utf-8",
        )
        flutter_non_git_change = inventory_flutter_lock(flutter_lock_path)
        assert_equal(
            "flutter-non-git-keeps-git-digest",
            flutter_non_git_change["git_record_identities_sha256"],
            fixture_expected["flutter_pubspec_lock"]["git_record_identities_sha256"],
        )
        if flutter_non_git_change["package_records_sha256"] == fixture_expected["flutter_pubspec_lock"]["package_records_sha256"]:
            raise InventoryError("self-test Flutter package digest ignored a hosted version change")
        checks.append("flutter-all-package-record-digest")
        flutter_lock_path.write_text(flutter_lock_baseline, encoding="utf-8")

        pubspec_path = root / "flutter/pubspec.yaml"
        pubspec_baseline = pubspec_path.read_text(encoding="utf-8")
        pubspec_path.write_text(
            "dependencies:\n  a: 1\n  a: 2\ndev_dependencies:\n  b: 1\n",
            encoding="utf-8",
        )
        expect_error("malformed-pubspec-yaml", lambda: inventory_flutter_pubspec(pubspec_path))
        pubspec_path.write_text(
            pubspec_baseline.replace("  alpha: ^1.0.0\n", "  alpha: ^1.0.0\n  gamma: ^1.0.0\n"),
            encoding="utf-8",
        )
        assert_equal(
            "pubspec-dependency-addition",
            inventory_flutter_pubspec(pubspec_path)["dependencies"],
            ["alpha", "flutter", "gamma"],
        )
        pubspec_path.write_text(
            pubspec_baseline.replace("  alpha: ^1.0.0\n", ""), encoding="utf-8"
        )
        assert_equal(
            "pubspec-dependency-removal",
            inventory_flutter_pubspec(pubspec_path)["dependencies"],
            ["flutter"],
        )
        pubspec_path.write_text(
            pubspec_baseline.replace("  alpha: ^1.0.0", "  gamma: ^1.0.0"),
            encoding="utf-8",
        )
        pubspec_swap = inventory_flutter_pubspec(pubspec_path)
        assert_equal("pubspec-swap-keeps-count", pubspec_swap["dependencies_entries"], 2)
        assert_equal("pubspec-swap-identity", pubspec_swap["dependencies"], ["flutter", "gamma"])
        pubspec_path.write_text(
            pubspec_baseline.replace("  alpha: ^1.0.0\n", "  alpha: ^1.0.0\n  beta: ^1.0.0\n"),
            encoding="utf-8",
        )
        assert_equal(
            "pubspec-dependency-overlap",
            inventory_flutter_pubspec(pubspec_path)["union_entries"],
            4,
        )
        pubspec_path.write_text(pubspec_baseline, encoding="utf-8")
        pubspec_path.write_text(
            pubspec_baseline.replace("alpha: ^1.0.0", "alpha: ^2.0.0"), encoding="utf-8"
        )
        version_substitution = inventory_flutter_pubspec(pubspec_path)
        assert_equal(
            "pubspec-version-keeps-identities",
            version_substitution["dependencies"],
            ["alpha", "flutter"],
        )
        if version_substitution["direct_dependency_records_sha256"] == fixture_expected["flutter_pubspec"]["direct_dependency_records_sha256"]:
            raise InventoryError("self-test pubspec record digest ignored a version substitution")
        checks.append("pubspec-version-record-digest")
        pubspec_path.write_text(pubspec_baseline, encoding="utf-8")

        workflows = root / ".github/workflows"
        for filename, field, expected_names in [
            ("added.yaml", "enabled_workflow_definition_files", ["added.yaml", "ci.yml"]),
            (
                "added.yaml.disabled",
                "disabled_workflow_definition_files",
                ["added.yaml.disabled", "old.yml.disabled"],
            ),
            ("NOTES.md", "documentation_files", ["NOTES.md", "README.md"]),
        ]:
            added = workflows / filename
            added.write_text("fixture\n", encoding="utf-8")
            assert_equal(
                f"workflow-add-{filename}", inventory_workflows(workflows)[field], expected_names
            )
            added.unlink()
        baseline_workflow = workflows / "ci.yml"
        swapped_workflow = workflows / "replacement.yml"
        baseline_workflow.rename(swapped_workflow)
        workflow_swap = inventory_workflows(workflows)
        assert_equal("workflow-swap-keeps-count", workflow_swap["enabled_workflow_definitions"], 1)
        assert_equal(
            "workflow-swap-identity",
            workflow_swap["enabled_workflow_definition_files"],
            ["replacement.yml"],
        )
        swapped_workflow.rename(baseline_workflow)
        unknown = workflows / "notes.txt"
        unknown.write_text("unknown\n", encoding="utf-8")
        expect_error("unknown-workflow-entry", lambda: inventory_workflows(workflows))
        unknown.unlink()
        workflow_link = workflows / "link.yml"
        workflow_link.symlink_to("ci.yml")
        expect_error("workflow-symlink", lambda: inventory_workflows(workflows))
        workflow_link.unlink()

        nested = root / "pkg/nested"
        nested.mkdir()
        nested_build = nested / "build.rs"
        nested_build.write_text("fn main() {}\n", encoding="utf-8")
        expect_error(
            "untracked-build-rs-rejected",
            lambda: inventory_build_rs(root),
            "untracked non-ignored build.rs must be staged or removed: 'pkg/nested/build.rs'",
        )
        git(root, "add", "--", "pkg/nested/build.rs")
        assert_equal(
            "tracked-build-rs-addition",
            inventory_build_rs(root),
            {
                "paths": ["build.rs", "pkg/build.rs", "pkg/nested/build.rs"],
                "regular_files": 3,
            },
        )
        tracked_build_drift = _drift_lines(collect_inventory(root), fixture_expected)
        if not any(line.startswith("build_rs.") for line in tracked_build_drift):
            raise InventoryError("self-test explicit EXPECTED comparison missed tracked build.rs")
        checks.append("tracked-build-rs-expected-drift")
        git(root, "rm", "--cached", "-q", "--", "pkg/nested/build.rs")
        nested_build.unlink()

        replacement_build = nested / "build.rs"
        replacement_build.write_text("fn main() {}\n", encoding="utf-8")
        original_build = root / "pkg/build.rs"
        git(root, "rm", "--cached", "-q", "--", "pkg/build.rs")
        original_build.unlink()
        git(root, "add", "--", "pkg/nested/build.rs")
        build_swap = inventory_build_rs(root)
        assert_equal("build-rs-swap-keeps-count", build_swap["regular_files"], 2)
        assert_equal(
            "build-rs-swap-identity",
            build_swap["paths"],
            ["build.rs", "pkg/nested/build.rs"],
        )
        if not _drift_lines(build_swap, fixture_expected["build_rs"], "build_rs"):
            raise InventoryError("self-test same-count tracked build.rs substitution was missed")
        checks.append("build-rs-swap-expected-drift")
        git(root, "rm", "--cached", "-q", "--", "pkg/nested/build.rs")
        replacement_build.unlink()
        original_build.write_text("fn main() {}\n", encoding="utf-8")
        git(root, "add", "--", "pkg/build.rs")

        ignore_file = root / ".gitignore"
        ignore_file.write_text(
            "/src/ignored.rs\n/pkg/ignored/build.rs\n", encoding="utf-8"
        )
        ignored_source = root / "src/ignored.rs"
        ignored_source.write_text("unsafe { ignored(); }\n", encoding="utf-8")
        ignored_build = root / "pkg/ignored/build.rs"
        ignored_build.parent.mkdir()
        ignored_build.write_text("fn main() {}\n", encoding="utf-8")
        assert_equal(
            "ignored-rust-excluded",
            inventory_rust_sources(root),
            fixture_expected["rust_sources"],
        )
        assert_equal(
            "ignored-build-rs-excluded",
            inventory_build_rs(root),
            fixture_expected["build_rs"],
        )
        ignored_source.unlink()
        ignored_build.unlink()
        ignored_build.parent.rmdir()
        ignore_file.unlink()

        ambient = root / ".claude/worktrees/ambient"
        ambient.mkdir(parents=True)
        git(ambient, "init", "-q")
        (ambient / "build.rs").write_text("fn main() {}\n", encoding="utf-8")
        (ambient / "ambient.rs").write_text(
            "unsafe { ambient(); }\n", encoding="utf-8"
        )
        embedded = root / "vendor/embedded"
        embedded.mkdir(parents=True)
        git(embedded, "init", "-q")
        (embedded / "build.rs").write_text("fn main() {}\n", encoding="utf-8")
        (embedded / "embedded.rs").write_text(
            "unsafe { embedded(); }\n", encoding="utf-8"
        )
        assert_equal(
            "nested-repositories-build-rs-excluded",
            inventory_build_rs(root),
            fixture_expected["build_rs"],
        )
        assert_equal(
            "nested-repositories-rust-excluded",
            inventory_rust_sources(root),
            fixture_expected["rust_sources"],
        )

        tracked_link = root / "linked/build.rs"
        tracked_link.parent.mkdir()
        tracked_link.symlink_to("../build.rs")
        git(root, "add", "--", "linked/build.rs")
        expect_error("tracked-build-rs-symlink", lambda: inventory_build_rs(root))
        git(root, "rm", "--cached", "-q", "--", "linked/build.rs")
        tracked_link.unlink()
        tracked_build = root / "pkg/build.rs"
        tracked_build.unlink()
        expect_error("tracked-build-rs-missing", lambda: inventory_build_rs(root))
        tracked_build.write_text("fn main() {}\n", encoding="utf-8")

        untracked_source = root / "src/untracked.rs"
        untracked_source.write_text(
            "fn g() { unsafe { call(); } }\n", encoding="utf-8"
        )
        expect_error(
            "untracked-rust-rejected",
            lambda: inventory_rust_sources(root),
            "untracked non-ignored Rust source must be staged or removed: 'src/untracked.rs'",
        )
        git(root, "add", "--", "src/untracked.rs")
        tracked_added = inventory_rust_sources(root)
        assert_equal("tracked-rust-addition-files", tracked_added["tracked_rs_files"], 4)
        assert_equal(
            "tracked-rust-addition-blocks",
            tracked_added["lexical_unsafe_open_brace_blocks"],
            2,
        )
        baseline_tracked_source = (root / "src/tracked.rs").read_text(encoding="utf-8")
        baseline_untracked_source = (root / "src/untracked.rs").read_text(encoding="utf-8")
        (root / "src/tracked.rs").write_text("fn no_unsafe() {}\n", encoding="utf-8")
        (root / "src/untracked.rs").write_text(
            "fn two() { unsafe { one(); } unsafe { two(); } }\n", encoding="utf-8"
        )
        rust_cancellation = inventory_rust_sources(root)
        assert_equal(
            "rust-aggregate-cancellation-total",
            rust_cancellation["lexical_unsafe_open_brace_blocks"],
            tracked_added["lexical_unsafe_open_brace_blocks"],
        )
        if rust_cancellation["lexical_counts_by_file_sha256"] == tracked_added["lexical_counts_by_file_sha256"]:
            raise InventoryError("self-test per-file Rust digest missed aggregate cancellation")
        checks.append("rust-aggregate-cancellation-digest")
        (root / "src/tracked.rs").write_text(baseline_tracked_source, encoding="utf-8")
        (root / "src/untracked.rs").write_text(baseline_untracked_source, encoding="utf-8")
        git(root, "rm", "--cached", "-q", "--", "src/untracked.rs")
        expect_error(
            "unstaged-rust-removal-rejected",
            lambda: inventory_rust_sources(root),
            "untracked non-ignored Rust source must be staged or removed: 'src/untracked.rs'",
        )
        untracked_source.unlink()
        assert_equal(
            "untracked-rust-removal-restores-candidate",
            inventory_rust_sources(root)["tracked_rs_files"],
            3,
        )

        lexical_fixture = (
            "fn lexical() {\n"
            " unsafe { one(); }\n"
            " unsafe /* outer /* nested */ comment */ { two(); }\n"
            " \u00e9unsafe { } unsafe\u00e9 { } e\u0301unsafe { } unsafe\u0301 { }\n"
            " 'unsafe: loop { break 'unsafe; } r#unsafe { }\n"
            " unsafe fn f() {} unsafe impl X {} unsafe trait T {}\n"
            " unsafe extern \"C\" fn g() {}\n"
            " // unsafe { }\n"
            " /* unsafe { } /* unsafe { } */ */\n"
            " let _ = \"unsafe { }\"; let _ = b\"unsafe { }\";\n"
            " let _ = c\"unsafe { }\"; let _ = r#\"unsafe { }\"#;\n"
            " let _ = br##\"unsafe { }\"##; let _ = cr\"unsafe { }\";\n"
            " let _ = 'x'; let _ = b'x';\n"
            "}\n"
        )
        (root / "src/tracked.rs").write_text(lexical_fixture, encoding="utf-8")
        lexical_inventory = inventory_rust_sources(root)
        assert_equal(
            "lexical-rust-end-to-end",
            lexical_inventory["lexical_unsafe_open_brace_blocks"],
            2,
        )
        if lexical_inventory["lexical_counts_by_file_sha256"] == fixture_expected["rust_sources"]["lexical_counts_by_file_sha256"]:
            raise InventoryError("self-test lexical digest ignored a per-file count mutation")
        checks.append("lexical-per-file-digest")
        for label, malformed in {
            "unterminated-block-comment": b"/*",
            "unterminated-string": b'\"unsafe {',
            "unterminated-byte-string": b'b\"unsafe {',
            "unterminated-c-string": b'c\"unsafe {',
            "unterminated-raw-string": b'r#\"unsafe {',
            "unterminated-byte-raw-string": b'br#\"unsafe {',
            "unterminated-c-raw-string": b'cr#\"unsafe {',
            "malformed-byte-char": b"b'x",
            "isolated-combining-mark": "\u0301unsafe {".encode("utf-8"),
            "invalid-rust-utf8": b"\xffunsafe {",
        }.items():
            expect_error(label, lambda malformed=malformed: count_lexical_unsafe_blocks(malformed, label))

        accepted_urls = {
            "https": ("https://github.com/RustDesk-Org/Repo.git", "rustdesk-org"),
            "ssh": ("ssh://git@github.com/rustdesk-org/repo.git", "rustdesk-org"),
            "scp": ("git@github.com:rustdesk-org/repo.git", "rustdesk-org"),
            "cargo": ("git+https://github.com/rustdesk-org/repo#abc", "rustdesk-org"),
            "non-github-hierarchical": ("ssh://git@example.test/team/repo.git", None),
            "non-github-scp": ("git@example.test:team/repo.git", None),
        }
        for label, (url, owner) in accepted_urls.items():
            assert_equal(f"git-url-{label}", canonicalize_git_url(url, label).github_owner, owner)
        assert_equal(
            "git-url-github-case-and-dotgit-normalization",
            canonicalize_git_url(accepted_urls["https"][0]).identity,
            "https://github.com/rustdesk-org/repo",
        )
        assert_equal(
            "git-url-scp-normalization",
            canonicalize_git_url(accepted_urls["scp"][0]).identity,
            canonicalize_git_url(accepted_urls["ssh"][0]).identity,
        )
        assert_equal(
            "git-url-cargo-wrapper-normalization",
            canonicalize_git_url(accepted_urls["cargo"][0]).identity,
            "https://github.com/rustdesk-org/repo#abc",
        )
        rejected_urls = {
            "dot-segment": "https://github.com/rustdesk-org/../evil",
            "encoded-dot": "https://github.com/rustdesk-org/%2e%2e",
            "encoded-slash": "https://github.com/rustdesk-org%2fevil/repo",
            "double-encoded-slash": "https://github.com/rustdesk-org%252fevil/repo",
            "backslash": "https://github.com/rustdesk-org\\evil/repo",
            "credential": "https://evil@github.com/rustdesk-org/repo",
            "port": "https://github.com:443/rustdesk-org/repo",
            "extra-path": "https://github.com/rustdesk-org/repo/extra",
            "encoded-host": "https://github.com%2fevil/rustdesk-org/repo",
            "missing-authority": "https:///github.com/rustdesk-org/repo",
            "malformed-bracket-authority": "ssh://[github.com/rustdesk-org/repo",
            "repeated-wrapper": "git+git+https://github.com/rustdesk-org/repo",
            "absolute-scp-path": "git@github.com:/rustdesk-org/repo",
        }
        for label, url in rejected_urls.items():
            expect_error(
                f"git-url-reject-{label}",
                lambda url=url, label=label: canonicalize_git_url(url, label),
            )

    return checks


def _text_inventory(inventory: dict[str, dict[str, Any]], status: str) -> str:
    cargo = inventory["cargo_lock"]
    flutter_lock = inventory["flutter_pubspec_lock"]
    flutter = inventory["flutter_pubspec"]
    workflows = inventory["github_workflows"]
    rust = inventory["rust_sources"]
    return "\n".join(
        [
            f"dependency inventory: {status}",
            (
                "Cargo.lock: "
                f"{cargo['package_records']} packages, {cargo['git_sourced_records']} git, "
                f"{cargo['unique_git_source_urls']} unique git URLs, "
                f"{cargo['rustdesk_org_git_records']} rustdesk-org"
            ),
            (
                "flutter/pubspec.lock: "
                f"{flutter_lock['package_records']} packages, "
                f"{flutter_lock['git_hosted_records']} git, "
                f"{flutter_lock['rustdesk_org_git_records']} rustdesk-org"
            ),
            (
                "flutter/pubspec.yaml: "
                f"{flutter['dependencies_entries']} dependencies, "
                f"{flutter['dev_dependencies_entries']} dev dependencies, "
                f"{flutter['union_entries']} union, "
                f"{flutter['sdk_entries_excluded']} direct sdk keys excluded"
            ),
            (
                ".github/workflows: "
                f"enabled definitions {workflows['enabled_workflow_definitions']}, "
                f"disabled definitions {workflows['disabled_workflow_definitions']}, "
                f"documentation regular files {workflows['documentation_regular_files']}, "
                f"total regular files {workflows['regular_files']}"
            ),
            f"build.rs: {inventory['build_rs']['regular_files']} regular files",
            (
                "Rust lexical unsafe { blocks: "
                f"{rust['lexical_unsafe_open_brace_blocks']} across "
                f"{rust['tracked_rs_files']} Git-tracked *.rs files (not an AST proof)"
            ),
        ]
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="run mutation tests in a private temporary fixture repository",
    )
    parser.add_argument(
        "--text",
        action="store_true",
        help="emit concise human-readable text instead of stable JSON",
    )
    args = parser.parse_args(argv)

    try:
        if args.self_test:
            checks = run_self_test()
            if args.text:
                print(f"dependency inventory self-test: ok ({len(checks)} checks)")
            else:
                print(json.dumps({"checks": checks, "status": "ok"}, indent=2, sort_keys=True))
            return 0

        root = Path(__file__).resolve().parent.parent
        inventory = collect_inventory(root)
        drift = _drift_lines(inventory, EXPECTED)
        if args.text:
            print(_text_inventory(inventory, "drift" if drift else "ok"))
            for line in drift:
                print(f"drift: {line}", file=sys.stderr)
        else:
            output: dict[str, Any] = {
                "inventory": inventory,
                "status": "drift" if drift else "ok",
            }
            if drift:
                output["drift"] = drift
            print(json.dumps(output, indent=2, sort_keys=True))
        return 1 if drift else 0
    except InventoryError as exc:
        if args.text:
            print(f"dependency inventory: error: {exc}", file=sys.stderr)
        else:
            print(json.dumps({"error": str(exc), "status": "error"}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
