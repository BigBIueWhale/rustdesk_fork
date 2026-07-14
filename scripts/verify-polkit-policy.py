#!/usr/bin/env python3
import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path


ACTION_ID = "com.carriez.RustDesk.set-unattended-password"
SOURCE_POLICY = Path("res/com.carriez.RustDesk.policy")
DEB_POLICY = Path("usr/share/polkit-1/actions/com.carriez.RustDesk.policy")
LEGACY_POLKIT_STUB = Path("usr/share/rustdesk/files/polkit")
EXPECTED_DEFAULTS = {
    "allow_any": "auth_admin",
    "allow_inactive": "auth_admin",
    "allow_active": "auth_admin",
}
PERMISSIVE_VALUES = {"yes", "auth_self", "auth_self_keep", "auth_admin_keep"}
SKIP_DIRS = {
    ".git",
    ".harness-state",
    ".dart_tool",
    ".pub-cache",
    "build",
    "dist",
    "online",
    "target",
    "tmpdeb",
}


def fail(message):
    print(f"FAIL polkit policy assurance: {message}", file=sys.stderr)
    sys.exit(1)


def tag_name(tag):
    return tag.rsplit("}", 1)[-1]


def parse_policy(path, label):
    try:
        root = ET.parse(path).getroot()
    except Exception as err:
        fail(f"{label}: XML parse failed: {err}")

    if tag_name(root.tag) != "policyconfig":
        fail(f"{label}: root element is not policyconfig")

    actions = [child for child in root if tag_name(child.tag) == "action"]
    if len(actions) != 1:
        fail(f"{label}: expected exactly one action, found {len(actions)}")

    action = actions[0]
    if action.get("id") != ACTION_ID:
        fail(f"{label}: unexpected action id {action.get('id')!r}")

    defaults = [child for child in action if tag_name(child.tag) == "defaults"]
    if len(defaults) != 1:
        fail(f"{label}: expected exactly one defaults block, found {len(defaults)}")

    values = {}
    for child in defaults[0]:
        key = tag_name(child.tag)
        value = (child.text or "").strip()
        values[key] = value
        if value in PERMISSIVE_VALUES:
            fail(f"{label}: {key} uses permissive value {value!r}")

    if values != EXPECTED_DEFAULTS:
        fail(f"{label}: defaults are {values!r}, expected {EXPECTED_DEFAULTS!r}")

    for elem in root.iter():
        text = (elem.text or "").strip()
        if text in PERMISSIVE_VALUES:
            fail(f"{label}: permissive polkit value {text!r} appears in <{tag_name(elem.tag)}>")


def validate_repo_rules(repo):
    for root, dirs, files in os.walk(repo):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in files:
            if not name.endswith(".rules"):
                continue
            path = Path(root) / name
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError as err:
                fail(f"failed to read polkit rules file {path}: {err}")
            if ACTION_ID in text:
                fail(f"repo ships a polkit .rules override for {ACTION_ID}: {path}")


def validate_build_py(repo):
    path = repo / "build.py"
    text = path.read_text(encoding="utf-8")
    copy_re = re.compile(
        r"""['"]cp\s+(?:\.\./)?res/com\.carriez\.RustDesk\.policy\s+tmpdeb/usr/share/polkit-1/actions/?['"]"""
    )
    mkdir_re = re.compile(r"""['"]mkdir\s+-p\s+tmpdeb/usr/share/polkit-1/actions['"]""")

    copies = copy_re.findall(text)
    mkdirs = mkdir_re.findall(text)
    if len(copies) != 1:
        fail(f"build.py must stage the polkit policy in the sole Debian path; found {len(copies)} copies")
    if len(mkdirs) != 1:
        fail(f"build.py must create the polkit action directory in the sole Debian path; found {len(mkdirs)} mkdirs")

    for line_no, line in enumerate(text.splitlines(), 1):
        if "com.carriez.RustDesk.policy" in line and "cp " in line and not copy_re.search(line):
            fail(f"build.py:{line_no}: policy copy does not target tmpdeb/usr/share/polkit-1/actions")
        if "tmpdeb/usr/share/rustdesk/files/polkit" in line:
            fail(f"build.py:{line_no}: legacy executable polkit stub must not be packaged")


def deb_contents(deb):
    if shutil.which("dpkg-deb") is None:
        fail("dpkg-deb is required to validate a built .deb policy payload")
    try:
        return subprocess.check_output(
            ["dpkg-deb", "--contents", str(deb)],
            universal_newlines=True,
        )
    except subprocess.CalledProcessError as err:
        fail(f"{deb}: dpkg-deb --contents failed with status {err.returncode}")


def parse_deb_contents_line(line):
    parts = line.split()
    if len(parts) < 6:
        return None
    path = parts[-1]
    if path.startswith("./"):
        path = path[2:]
    return parts[0], parts[1], path


def validate_deb(repo, deb):
    contents = deb_contents(deb)
    entries = []
    for line in contents.splitlines():
        parsed = parse_deb_contents_line(line)
        if parsed is not None:
            entries.append(parsed)

    policy_entries = [entry for entry in entries if entry[2].startswith("usr/share/polkit-1/actions/") and entry[2].endswith(".policy")]
    expected_entries = [entry for entry in policy_entries if entry[2] == str(DEB_POLICY)]
    legacy_stub_entries = [entry for entry in entries if entry[2] == str(LEGACY_POLKIT_STUB)]

    if len(policy_entries) != 1:
        fail(f"{deb}: expected exactly one packaged polkit policy, found {len(policy_entries)}")
    if len(expected_entries) != 1:
        fail(f"{deb}: missing packaged policy at {DEB_POLICY}")

    mode, owner, _ = expected_entries[0]
    if not mode.startswith("-"):
        fail(f"{deb}: packaged policy is not a regular file ({mode})")
    if len(mode) < 9 or mode[5] == "w" or mode[8] == "w":
        fail(f"{deb}: packaged policy is group/world writable ({mode})")
    if owner != "root/root":
        fail(f"{deb}: packaged policy owner is {owner}, expected root/root")
    if legacy_stub_entries:
        fail(f"{deb}: legacy executable polkit stub is packaged at {LEGACY_POLKIT_STUB}")

    with tempfile.TemporaryDirectory(prefix="rustdesk-polkit-deb.") as tmp:
        try:
            subprocess.check_call(["dpkg-deb", "-x", str(deb), tmp], stdout=subprocess.DEVNULL)
        except subprocess.CalledProcessError as err:
            fail(f"{deb}: dpkg-deb -x failed with status {err.returncode}")
        extracted = Path(tmp) / DEB_POLICY
        if not extracted.is_file():
            fail(f"{deb}: extracted policy missing at {DEB_POLICY}")
        parse_policy(extracted, f"{deb}:{DEB_POLICY}")

        source = repo / SOURCE_POLICY
        if extracted.read_bytes() != source.read_bytes():
            fail(f"{deb}: packaged policy bytes differ from {SOURCE_POLICY}")


def main():
    parser = argparse.ArgumentParser(description="Verify RustDesk's Linux polkit policy and optional .deb payloads.")
    parser.add_argument("--repo", default=".", help="repository root")
    parser.add_argument("--deb", action="append", default=[], help="built .deb to validate; may be repeated")
    args = parser.parse_args()

    repo = Path(args.repo).resolve()
    source = repo / SOURCE_POLICY
    if not source.is_file():
        fail(f"missing source policy {SOURCE_POLICY}")

    parse_policy(source, str(SOURCE_POLICY))
    validate_repo_rules(repo)
    validate_build_py(repo)
    for deb in args.deb:
        validate_deb(repo, Path(deb).resolve())

    print("ok  Linux polkit policy uses one admin-auth action and packaged payloads preserve it")


if __name__ == "__main__":
    main()
