#!/usr/bin/env python3
import argparse
import pathlib
import re
import sys


EXPECTED = ("preinst", "postinst", "prerm", "postrm")
SYSTEMD_ACTIVE = "if [ -d /run/systemd/system ]; then"
RELOAD = "/bin/systemctl --system daemon-reload >/dev/null"
OLD_UNIT_PREDICATE = (
    'if [ -e "/etc/systemd/system/$unit" ] || '
    '[ -e "/usr/lib/systemd/system/$unit" ] || '
    '[ -e "/lib/systemd/system/$unit" ]; then'
)
SYSTEMD_UNIT_PATH_FRAGMENTS = (
    "/etc/systemd/system",
    "/usr/lib/systemd/system",
    "/usr/lib/systemd/user",
    "/lib/systemd/system",
    "/usr/share/rustdesk/files/systemd",
)


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
    if re.search(r"(?m)^\s*/etc/init\.d/", text):
        errors.append(f"{script}: must use invoke-rc.d instead of executing an init script directly")
    if re.search(r"\b(start-stop-daemon|pidof|pgrep|pkill|killall|ps)\b", text):
        errors.append(f"{script}: must delegate exact process ownership to the selected init backend")

    for number, line in enumerate(lines, start=1):
        if "systemctl" in line and line != RELOAD:
            errors.append(f"{script}:{number}: only `{RELOAD}` may call systemctl")
        if line.startswith("deb-systemd-invoke "):
            if not re.fullmatch(r'deb-systemd-invoke (start|stop) "\$unit" >/dev/null', line):
                errors.append(f"{script}:{number}: invalid deb-systemd-invoke action")
        if line.startswith("deb-systemd-helper "):
            if not re.fullmatch(r'deb-systemd-helper (enable|disable|purge) "\$unit" >/dev/null', line):
                errors.append(f"{script}:{number}: invalid deb-systemd-helper action")
        if line.startswith("invoke-rc.d "):
            if not re.fullmatch(r'invoke-rc\.d "\$service" (start|stop) >/dev/null', line):
                errors.append(f"{script}:{number}: invalid invoke-rc.d action")
        if line.startswith("update-rc.d "):
            if not re.fullmatch(r'update-rc\.d "\$service" (defaults|remove) >/dev/null', line):
                errors.append(f"{script}:{number}: invalid update-rc.d action")

    unit_path_lines = [
        line for line in lines
        if any(fragment in line for fragment in SYSTEMD_UNIT_PATH_FRAGMENTS)
    ]
    expected_unit_path_lines = [OLD_UNIT_PREDICATE] if script == "preinst" else []
    if unit_path_lines != expected_unit_path_lines:
        errors.append(
            f"{script}: systemd unit paths must be package-owned; only the exact preinst read predicate is allowed"
        )


def check_preinst(errors, lines):
    script = "preinst"
    require_contains(errors, script, lines, "unit=rustdesk.service")
    require_contains(errors, script, lines, "service=rustdesk")
    require_contains(errors, script, lines, "upgrade)")
    require(errors, script, count_contains(lines, SYSTEMD_ACTIVE) == 1, "must select systemd exactly once")
    require(errors, script, count_contains(lines, 'deb-systemd-invoke stop "$unit" >/dev/null') == 1, "must stop the old systemd unit exactly once")
    require(errors, script, count_contains(lines, 'invoke-rc.d "$service" stop >/dev/null') == 1, "must stop the old SysV service exactly once")
    require_order(
        errors,
        script,
        lines,
        "upgrade)",
        SYSTEMD_ACTIVE,
        OLD_UNIT_PREDICATE,
        'deb-systemd-invoke stop "$unit" >/dev/null',
        "elif [ -x /etc/init.d/rustdesk ]; then",
        'invoke-rc.d "$service" stop >/dev/null',
        "sleep 1",
        "rm -f /usr/bin/libsciter-gtk.so",
    )


def check_postinst(errors, lines):
    script = "postinst"
    require_contains(errors, script, lines, "unit=rustdesk.service")
    require_contains(errors, script, lines, "service=rustdesk")
    require_contains(errors, script, lines, 'if [ "$1" = configure ]; then')
    require(errors, script, count_contains(lines, SYSTEMD_ACTIVE) == 1, "must select systemd exactly once")
    require(errors, script, count_contains(lines, 'invoke-rc.d "$service" start >/dev/null') == 1, "must start the SysV service exactly once")
    require_order(
        errors,
        script,
        lines,
        'ln -f -s /usr/share/rustdesk/rustdesk /usr/bin/rustdesk',
        'update-rc.d "$service" defaults >/dev/null',
        SYSTEMD_ACTIVE,
        'deb-systemd-helper enable "$unit" >/dev/null',
        RELOAD,
        'deb-systemd-invoke start "$unit" >/dev/null',
        "else",
        'invoke-rc.d "$service" start >/dev/null',
    )


def check_prerm(errors, lines):
    script = "prerm"
    require_contains(errors, script, lines, "unit=rustdesk.service")
    require_contains(errors, script, lines, "service=rustdesk")
    require_contains(errors, script, lines, "remove|upgrade|deconfigure)")
    require(errors, script, count_contains(lines, SYSTEMD_ACTIVE) == 2, "must gate stop and disable on the active systemd backend")
    require(errors, script, count_contains(lines, 'invoke-rc.d "$service" stop >/dev/null') == 1, "must stop the SysV service exactly once")
    require_order(
        errors,
        script,
        lines,
        "remove|upgrade|deconfigure)",
        SYSTEMD_ACTIVE,
        'deb-systemd-invoke stop "$unit" >/dev/null',
        "elif [ -x /etc/init.d/rustdesk ]; then",
        'invoke-rc.d "$service" stop >/dev/null',
        'if [ "$1" = remove ] || [ "$1" = deconfigure ]; then',
        'deb-systemd-helper disable "$unit" >/dev/null',
        'update-rc.d "$service" remove >/dev/null',
        "rm -f /usr/bin/rustdesk",
    )


def check_postrm(errors, lines):
    script = "postrm"
    require_contains(errors, script, lines, "unit=rustdesk.service")
    require_contains(errors, script, lines, "service=rustdesk")
    require_contains(errors, script, lines, "purge)")
    require_contains(errors, script, lines, "remove|purge)")
    require(errors, script, count_contains(lines, SYSTEMD_ACTIVE) == 1, "must reload the active systemd backend exactly once after package-file removal")
    require(errors, script, count_contains(lines, RELOAD) == 1, "must reload systemd exactly once after package-file removal")
    require_order(
        errors,
        script,
        lines,
        'deb-systemd-helper purge "$unit" >/dev/null',
        'update-rc.d "$service" remove >/dev/null',
        "rm -rf -- /root/.config/RustDesk /root/.config/rustdesk",
        "remove|purge)",
        SYSTEMD_ACTIVE,
        RELOAD,
    )


def check_init_script(errors, path):
    script = "rustdesk.init"
    require(errors, script, path.exists(), "missing SysV init script")
    if not path.exists():
        return
    lines = stripped_lines(path)
    text = path.read_text(encoding="utf-8")
    require(errors, script, lines[:1] == ["#!/bin/sh"], "must use #!/bin/sh")
    for needle in (
        "### BEGIN INIT INFO",
        "# Provides:          rustdesk",
        "# Default-Start:     2 3 4 5",
        "# Default-Stop:      0 1 6",
        "set -e",
        ". /lib/lsb/init-functions",
        "DAEMON=/usr/bin/rustdesk",
        "DAEMON_ARGS=--service",
        "NAME=rustdesk",
        "PIDFILE=/run/rustdesk.pid",
        "start-stop-daemon --status --quiet \\",
        "if start-stop-daemon --start --quiet --oknodo \\",
        "--background --make-pidfile \\",
        "--startas \"$DAEMON\" \\",
        "--chuid root:root \\",
        "--chdir / \\",
        "--umask 027 \\",
        "if start-stop-daemon --stop --quiet --oknodo \\",
        "--retry=TERM/30/KILL/5 \\",
        "--remove-pidfile \\",
        "restart|force-reload)",
        "try-restart)",
        "status)",
    ):
        require_contains(errors, script, lines, needle)

    require(errors, script, count_contains(lines, '--pidfile "$PIDFILE" \\') == 3, "status, start, and stop must each bind the same PID file")
    require(errors, script, count_contains(lines, '--exec "$DAEMON" \\') == 3, "status, start, and stop must each bind the exact executable")
    require(errors, script, count_contains(lines, '--name "$NAME" \\') == 3, "status, start, and stop must each bind the exact process name")
    require(errors, script, text.count("--user root") == 3, "status, start, and stop must each bind the exact root UID")
    require(errors, script, count_contains(lines, "--user root \\") == 1, "start must match the exact root-owned process")
    require(errors, script, text.count("start-stop-daemon --stop") == 1, "must have one stop authority with no second executable-only sweep")

    forbidden = re.search(
        r"\b(pidof|pgrep|pkill|killall|kill|ps)\b|/proc/|rm\s+-f\s+\"?\$PIDFILE|/lib/init/init-d-script",
        text,
    )
    if forbidden:
        errors.append(f"{script}: contains forbidden process rediscovery or PID-file deletion: {forbidden.group(0)!r}")
    if "--pidfile \"$PIDFILE\"" not in text or "--exec \"$DAEMON\"" not in text:
        errors.append(f"{script}: lifecycle authority is not bound to PID file plus executable")


def check_openrc_script(errors, path):
    script = "rustdesk.openrc"
    require(errors, script, path.is_file() and not path.is_symlink(), "missing regular OpenRC service script")
    if not path.is_file() or path.is_symlink():
        return
    lines = stripped_lines(path)
    text = path.read_text(encoding="utf-8")
    require(errors, script, lines[:1] == ["#!/sbin/openrc-run"], "must use #!/sbin/openrc-run")
    for needle in (
        'description="RustDesk service supervisor"',
        'command="/usr/bin/rustdesk"',
        'command_args="--service"',
        "command_background=true",
        'command_user="root:root"',
        'directory="/"',
        'pidfile="/run/rustdesk.pid"',
        'retry="TERM/30/KILL/5"',
        "umask=027",
        "depend() {",
        "use net",
        "after bootmisc",
    ):
        require_contains(errors, script, lines, needle)
    for prefix in (
        "command=", "command_args=", "command_background=", "command_user=",
        "directory=", "pidfile=", "retry=", "umask=",
    ):
        require(
            errors,
            script,
            sum(1 for line in lines if line.startswith(prefix)) == 1,
            f"must define `{prefix}` exactly once",
        )
    forbidden = re.search(
        r"\b(procname|pidof|pgrep|pkill|killall|kill|ps|sudo|su)\b|/proc/|--server|service-owned-server|(^|\n)\s*(start|stop)\s*\(\)",
        text,
    )
    if forbidden:
        errors.append(f"{script}: contains process rediscovery, child authority, or a custom lifecycle function: {forbidden.group(0)!r}")


def check_foreground_template(errors, script, path):
    require(errors, script, path.is_file() and not path.is_symlink(), "missing regular foreground service script")
    if not path.is_file() or path.is_symlink():
        return
    lines = path.read_text(encoding="utf-8").splitlines()
    expected = [
        "#!/bin/sh",
        "set -eu",
        "umask 027",
        "cd /",
        "exec /usr/bin/rustdesk --service",
    ]
    require(
        errors,
        script,
        lines == expected,
        "must be the exact foreground exec wrapper for /usr/bin/rustdesk --service",
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--scripts-dir", required=True)
    parser.add_argument("--init-script", required=True)
    parser.add_argument("--openrc-script", required=True)
    parser.add_argument("--runit-run", required=True)
    parser.add_argument("--manual-run", required=True)
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
    check_init_script(errors, pathlib.Path(args.init_script))
    check_openrc_script(errors, pathlib.Path(args.openrc_script))
    check_foreground_template(errors, "rustdesk.runit.run", pathlib.Path(args.runit_run))
    check_foreground_template(errors, "rustdesk.manual", pathlib.Path(args.manual_run))

    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
