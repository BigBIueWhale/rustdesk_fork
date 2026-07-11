#!/usr/bin/env python3
import argparse
import pathlib
import re
import sys


EXPECTED = ("preinst", "postinst", "prerm", "postrm")
RELOAD = "/bin/systemctl --system daemon-reload >/dev/null"


def stripped_lines(path):
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines()]


def require(errors, script, condition, message):
    if not condition:
        errors.append(f"{script}: {message}")


def require_contains(errors, script, lines, needle):
    require(errors, script, needle in lines, f"missing `{needle}`")


def count_contains(lines, needle):
    return sum(1 for line in lines if line == needle)


def index_of(errors, script, lines, needle):
    try:
        return lines.index(needle)
    except ValueError:
        errors.append(f"{script}: missing `{needle}`")
        return -1


def require_order(errors, script, lines, *needles):
    indexes = [index_of(errors, script, lines, needle) for needle in needles]
    if any(index < 0 for index in indexes):
        return
    if indexes != sorted(indexes):
        rendered = " -> ".join(needles)
        errors.append(f"{script}: out-of-order lifecycle sequence `{rendered}`")


def check_common(errors, script, path, lines):
    require(errors, script, path.exists(), "missing maintainer script")
    if not path.exists():
        return
    require(errors, script, lines[:1] == ["#!/bin/sh"], "must use #!/bin/sh")
    require_contains(errors, script, lines, "set -e")

    text = path.read_text(encoding="utf-8")
    if re.search(r"\|\|\s*true", text):
        errors.append(f"{script}: masks maintainer-script failure with `|| true`")
    if "deb-systemd-invoke daemon-reload" in text:
        errors.append(f"{script}: daemon-reload must not use deb-systemd-invoke")

    for number, line in enumerate(lines, start=1):
        if "systemctl" in line and line != RELOAD:
            errors.append(f"{script}:{number}: only `{RELOAD}` may call systemctl")
        if line.startswith("deb-systemd-invoke "):
            if not re.fullmatch(r'deb-systemd-invoke (start|stop|restart) "\$unit" >/dev/null', line):
                errors.append(f"{script}:{number}: invalid deb-systemd-invoke action")
        if line.startswith("deb-systemd-helper "):
            if not re.fullmatch(r'deb-systemd-helper (enable|disable|purge) "\$unit" >/dev/null', line):
                errors.append(f"{script}:{number}: invalid deb-systemd-helper action")


def check_preinst(errors, lines):
    script = "preinst"
    require_contains(errors, script, lines, "unit=rustdesk.service")
    require_contains(errors, script, lines, "upgrade)")
    require_contains(
        errors,
        script,
        lines,
        'if [ -e "/etc/systemd/system/$unit" ] || [ -e "/usr/lib/systemd/system/$unit" ] || [ -e "/lib/systemd/system/$unit" ]; then',
    )
    require(errors, script, count_contains(lines, 'deb-systemd-invoke stop "$unit" >/dev/null') == 1, "must stop old unit exactly once")
    require_order(
        errors,
        script,
        lines,
        'if [ -e "/etc/systemd/system/$unit" ] || [ -e "/usr/lib/systemd/system/$unit" ] || [ -e "/lib/systemd/system/$unit" ]; then',
        'deb-systemd-invoke stop "$unit" >/dev/null',
        "sleep 1",
        "rm -f /usr/bin/libsciter-gtk.so",
    )


def check_postinst(errors, lines):
    script = "postinst"
    require_contains(errors, script, lines, "unit=rustdesk.service")
    require_contains(errors, script, lines, "unit_path=/usr/lib/systemd/system/rustdesk.service")
    require_contains(errors, script, lines, 'if [ "$1" = configure ]; then')
    require_order(
        errors,
        script,
        lines,
        'cp /usr/share/rustdesk/files/systemd/rustdesk.service "$unit_path"',
        'deb-systemd-helper enable "$unit" >/dev/null',
        RELOAD,
        'deb-systemd-invoke start "$unit" >/dev/null',
    )


def check_prerm(errors, lines):
    script = "prerm"
    require_contains(errors, script, lines, "unit=rustdesk.service")
    require_contains(errors, script, lines, "remove|upgrade|deconfigure)")
    require_order(
        errors,
        script,
        lines,
        'deb-systemd-invoke stop "$unit" >/dev/null',
        'if [ "$1" = remove ] || [ "$1" = deconfigure ]; then',
        'deb-systemd-helper disable "$unit" >/dev/null',
        "rm -f /usr/bin/rustdesk",
        "rm -f /usr/lib/systemd/system/rustdesk.service",
        RELOAD,
    )


def check_postrm(errors, lines):
    script = "postrm"
    require_contains(errors, script, lines, "unit=rustdesk.service")
    require_contains(errors, script, lines, "purge)")
    require_order(
        errors,
        script,
        lines,
        'deb-systemd-helper purge "$unit" >/dev/null',
        "rm -rf -- /root/.config/RustDesk /root/.config/rustdesk",
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--scripts-dir", required=True)
    args = parser.parse_args()

    scripts_dir = pathlib.Path(args.scripts_dir)
    errors = []
    loaded = {}

    for script in EXPECTED:
        path = scripts_dir / script
        lines = stripped_lines(path) if path.exists() else []
        loaded[script] = lines
        check_common(errors, script, path, lines)

    if not errors:
        check_preinst(errors, loaded["preinst"])
        check_postinst(errors, loaded["postinst"])
        check_prerm(errors, loaded["prerm"])
        check_postrm(errors, loaded["postrm"])

    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
