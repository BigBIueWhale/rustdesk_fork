#!/usr/bin/env python3
import argparse
import dataclasses
import pathlib
import re
import subprocess
import sys


PACKAGE = "com.carriez.flutter_hbb"
MAIN_ACTIVITY = f"{PACKAGE}.MainActivity"

EXPECTED_COMPONENTS = {
    (f"{PACKAGE}.BootReceiver", "receiver"): False,
    (f"{PACKAGE}.InputService", "service"): False,
    (MAIN_ACTIVITY, "activity"): True,
    (f"{PACKAGE}.PermissionRequestTransparentActivity", "activity"): False,
    (f"{PACKAGE}.MainService", "service"): False,
}

ALLOWED_COMPONENTS = EXPECTED_COMPONENTS.keys() | {
    ("io.flutter.plugins.urllauncher.WebViewActivity", "activity"),
    ("androidx.startup.InitializationProvider", "provider"),
}

ALLOWED_USES_PERMISSIONS = {
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.POST_NOTIFICATIONS",
    "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
    "android.permission.INTERNET",
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.FOREGROUND_SERVICE",
    "android.permission.RECORD_AUDIO",
    "android.permission.WAKE_LOCK",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    f"{PACKAGE}.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION",
}

FORBIDDEN_USES_PERMISSIONS = {
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.SYSTEM_ALERT_WINDOW",
}

FORBIDDEN_COMPONENTS = {
    "androidx.profileinstaller.ProfileInstallReceiver",
}

BOOT_ACTIONS = {
    "android.intent.action.BOOT_COMPLETED",
    "android.intent.action.QUICKBOOT_POWERON",
}


@dataclasses.dataclass
class Node:
    tag: str
    attrs: dict
    children: list
    line: int | None = None


def run_aapt2(aapt2, apk):
    cmd = [str(aapt2), "dump", "xmltree", str(apk), "--file", "AndroidManifest.xml"]
    return subprocess.run(cmd, check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def parse_attr(line):
    match = re.match(r"\s*A:\s+([^=(]+)(?:\([^)]*\))?=(.*)$", line)
    if not match:
        return None
    name, value = match.groups()
    name = name.strip().rsplit(":", 1)[-1]
    return name, parse_value(value.strip())


def parse_value(value):
    if value == "true":
        return True
    if value == "false":
        return False
    if value.startswith('"'):
        match = re.match(r'"((?:[^"\\]|\\.)*)"', value)
        if match:
            return match.group(1)
    hex_match = re.search(r"0x[0-9a-fA-F]+$", value)
    if hex_match:
        number = int(hex_match.group(0), 16)
        if "(type 0x12)" in value:
            return number != 0
        return number
    if re.fullmatch(r"-?\d+", value):
        return int(value, 10)
    return value


def parse_xmltree(text):
    root = Node("root", {}, [])
    stack = [(-1, root)]
    for raw_line in text.splitlines():
        stripped = raw_line.lstrip()
        indent = len(raw_line) - len(stripped)
        if stripped.startswith("E: "):
            match = re.match(r"E:\s+([^\s(]+)(?:\s+\(line=(\d+)\))?", stripped)
            if not match:
                continue
            tag, line = match.groups()
            node = Node(tag, {}, [], int(line) if line else None)
            while stack and indent <= stack[-1][0]:
                stack.pop()
            stack[-1][1].children.append(node)
            stack.append((indent, node))
        elif stripped.startswith("A: "):
            parsed = parse_attr(raw_line)
            if parsed:
                stack[-1][1].attrs[parsed[0]] = parsed[1]
    return root


def walk(node):
    yield node
    for child in node.children:
        yield from walk(child)


def first_child(node, tag):
    for child in node.children:
        if child.tag == tag:
            return child
    return None


def children(node, tag):
    return [child for child in node.children if child.tag == tag]


def normalize_component_name(name):
    if not isinstance(name, str) or not name:
        return name
    if name.startswith("."):
        return f"{PACKAGE}{name}"
    if "." not in name:
        return f"{PACKAGE}.{name}"
    return name


def attr_bool(errors, where, attrs, name):
    value = attrs.get(name)
    if isinstance(value, bool):
        return value
    errors.append(f"{where}: missing or non-boolean android:{name}")
    return None


def action_names(component):
    names = set()
    for intent in children(component, "intent-filter"):
        for action in children(intent, "action"):
            name = action.attrs.get("name")
            if isinstance(name, str):
                names.add(name)
    return names


def category_names(component):
    names = set()
    for intent in children(component, "intent-filter"):
        for category in children(intent, "category"):
            name = category.attrs.get("name")
            if isinstance(name, str):
                names.add(name)
    return names


def data_schemes(component):
    schemes = set()
    for intent in children(component, "intent-filter"):
        for data in children(intent, "data"):
            scheme = data.attrs.get("scheme")
            if isinstance(scheme, str):
                schemes.add(scheme)
    return schemes


def validate_permissions(errors, manifest):
    declared = {child.attrs.get("name") for child in children(manifest, "uses-permission")}
    declared = {name for name in declared if isinstance(name, str)}

    forbidden = sorted(declared & FORBIDDEN_USES_PERMISSIONS)
    if forbidden:
        errors.append("forbidden uses-permission present in final APK: " + ", ".join(forbidden))

    unknown = sorted(declared - ALLOWED_USES_PERMISSIONS - FORBIDDEN_USES_PERMISSIONS)
    if unknown:
        errors.append("unexpected uses-permission present in final APK: " + ", ".join(unknown))

    dynamic = f"{PACKAGE}.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION"
    custom = [
        node for node in children(manifest, "permission")
        if node.attrs.get("name") == dynamic
    ]
    if custom:
        protection = custom[0].attrs.get("protectionLevel")
        if protection != 2:
            errors.append(f"{dynamic}: protectionLevel must be signature")


def validate_components(errors, app):
    seen = set()
    app_children = [child for child in app.children if child.tag in {"activity", "service", "receiver", "provider"}]
    for component in app_children:
        raw_name = component.attrs.get("name")
        name = normalize_component_name(raw_name)
        where = f"{component.tag}:{name or '<missing-name>'}"
        if not isinstance(name, str) or not name:
            errors.append(f"{where}: missing android:name")
            continue
        seen.add((name, component.tag))

        if (name, component.tag) not in ALLOWED_COMPONENTS:
            errors.append(f"{where}: unexpected component present in final APK")

        if name in FORBIDDEN_COMPONENTS:
            errors.append(f"{where}: forbidden component present in final APK")

        exported = attr_bool(errors, where, component.attrs, "exported")
        if exported is True and name != MAIN_ACTIVITY:
            errors.append(f"{where}: only {MAIN_ACTIVITY} may be exported")
        if component.tag in {"service", "receiver", "provider"} and exported is True:
            errors.append(f"{where}: services, receivers, and providers must not be exported")

    for key, expected_exported in EXPECTED_COMPONENTS.items():
        if key not in seen:
            errors.append(f"{key[1]}:{key[0]}: expected component missing from final APK")
            continue
        for component in app_children:
            name = normalize_component_name(component.attrs.get("name"))
            if (name, component.tag) == key and component.attrs.get("exported") != expected_exported:
                errors.append(f"{component.tag}:{name}: exported must be {str(expected_exported).lower()}")

    check_component_shape(errors, app_children)


def check_component_shape(errors, components):
    by_name = {
        (normalize_component_name(component.attrs.get("name")), component.tag): component
        for component in components
    }

    boot = by_name.get((f"{PACKAGE}.BootReceiver", "receiver"))
    if boot:
        actions = action_names(boot)
        if actions != BOOT_ACTIONS:
            errors.append("receiver:BootReceiver: boot actions must be exactly " + ", ".join(sorted(BOOT_ACTIONS)))

    input_service = by_name.get((f"{PACKAGE}.InputService", "service"))
    if input_service:
        if input_service.attrs.get("permission") != "android.permission.BIND_ACCESSIBILITY_SERVICE":
            errors.append("service:InputService: must require BIND_ACCESSIBILITY_SERVICE")

    main_activity = by_name.get((MAIN_ACTIVITY, "activity"))
    if main_activity:
        actions = action_names(main_activity)
        categories = category_names(main_activity)
        schemes = data_schemes(main_activity)
        if "android.intent.action.MAIN" not in actions:
            errors.append("activity:MainActivity: missing MAIN action")
        if "android.intent.category.LAUNCHER" not in categories:
            errors.append("activity:MainActivity: missing LAUNCHER category")
        if "android.intent.action.VIEW" not in actions or "rustdesk" not in schemes:
            errors.append("activity:MainActivity: missing rustdesk VIEW deep-link")

    permission_activity = by_name.get((f"{PACKAGE}.PermissionRequestTransparentActivity", "activity"))
    if permission_activity and children(permission_activity, "intent-filter"):
        errors.append("activity:PermissionRequestTransparentActivity: must not have intent filters")

    main_service = by_name.get((f"{PACKAGE}.MainService", "service"))
    if main_service and children(main_service, "intent-filter"):
        errors.append("service:MainService: must not have intent filters")


def validate_manifest(tree):
    errors = []
    manifests = [node for node in walk(tree) if node.tag == "manifest"]
    if len(manifests) != 1:
        errors.append(f"expected one manifest node, found {len(manifests)}")
        return errors
    manifest = manifests[0]
    package = manifest.attrs.get("package")
    if package != PACKAGE:
        errors.append(f"manifest package must be {PACKAGE}, got {package!r}")

    uses_sdk = first_child(manifest, "uses-sdk")
    if uses_sdk is None:
        errors.append("manifest missing uses-sdk")
    else:
        if uses_sdk.attrs.get("minSdkVersion") != 22:
            errors.append("uses-sdk: minSdkVersion must be 22")
        if uses_sdk.attrs.get("targetSdkVersion") != 33:
            errors.append("uses-sdk: targetSdkVersion must be 33")

    validate_permissions(errors, manifest)

    app = first_child(manifest, "application")
    if app is None:
        errors.append("manifest missing application")
        return errors
    if attr_bool(errors, "application", app.attrs, "allowBackup") is not False:
        errors.append("application: allowBackup must be false")

    validate_components(errors, app)
    return errors


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--apk", required=True, type=pathlib.Path)
    parser.add_argument("--aapt2", required=True, type=pathlib.Path)
    args = parser.parse_args()

    if not args.apk.is_file():
        print(f"APK not found: {args.apk}", file=sys.stderr)
        return 1
    if not args.aapt2.is_file():
        print(f"aapt2 not found: {args.aapt2}", file=sys.stderr)
        return 1

    proc = run_aapt2(args.aapt2, args.apk)
    if proc.returncode != 0:
        if proc.stderr:
            print(proc.stderr, file=sys.stderr, end="")
        return proc.returncode

    errors = validate_manifest(parse_xmltree(proc.stdout))
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1

    print(f"ok Android APK manifest authority: {args.apk}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
