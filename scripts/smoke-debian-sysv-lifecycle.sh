#!/usr/bin/env bash
set -euo pipefail
umask 077

readonly ROOT=/work
readonly BINARY=$ROOT/target/debug/rustdesk
readonly INIT_SOURCE=$ROOT/res/rustdesk.init
readonly UNIT_SOURCE=$ROOT/res/rustdesk.service
readonly CONTROL_SOURCE=$ROOT/res/DEBIAN
readonly READY=$ROOT/scripts/smoke-ready.sh
readonly PROCESS_GUARD=$ROOT/scripts/smoke-process-guard.py
readonly LAUNCHER_SOURCE=$ROOT/target/smoke-server-launcher
readonly FIXTURE=/tmp/rustdesk-debian-sysv
readonly PACKAGE=rustdesk-sysv-smoke
readonly PORTABLE_UID=4000

SERVICE_PID=
SERVICE_START=
PORTABLE_PID=
PORTABLE_START=
PORTABLE_GID=
PORTABLE_EXE_ID=
WRONG_PID=
WRONG_START=

fail() {
    printf 'Debian SysV lifecycle smoke: %s\n' "$*" >&2
    exit 1
}

cleanup() {
    status=$?
    trap - EXIT HUP INT TERM
    if [ -n "$PORTABLE_PID" ] && [ -n "$PORTABLE_START" ] \
        && "$READY" --is-running "$PORTABLE_PID" "$PORTABLE_START" 2>/dev/null; then
        "$READY" --stop "$PORTABLE_PID" "$PORTABLE_START" >/dev/null 2>&1 || status=1
    fi
    if [ -n "$WRONG_PID" ] && [ -n "$WRONG_START" ] \
        && "$READY" --is-running "$WRONG_PID" "$WRONG_START" 2>/dev/null; then
        "$READY" --stop "$WRONG_PID" "$WRONG_START" >/dev/null 2>&1 || status=1
    fi
    if [ -x /etc/init.d/rustdesk ]; then
        /etc/init.d/rustdesk stop >/dev/null 2>&1 || status=1
    fi
    dpkg --purge "$PACKAGE" >/dev/null 2>&1 || true
    rm -rf -- "$FIXTURE"
    exit "$status"
}

trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

[ "$(id -u)" = 0 ] || fail 'must run as root inside the disposable container'
[ -r /etc/os-release ] || fail '/etc/os-release is absent'
. /etc/os-release
[ "${ID:-}" = debian ] || fail "container is not Debian: ${ID:-unknown}"
[ "${VERSION_CODENAME:-}" = bookworm ] || fail "container is not the audited Debian bookworm fixture: ${VERSION_CODENAME:-unknown}"
[ ! -e /run/systemd/system ] || fail 'systemd is active; the SysV backend was not selected'
for command in dpkg dpkg-deb dpkg-query invoke-rc.d start-stop-daemon update-rc.d useradd; do
    command -v "$command" >/dev/null || fail "required Debian command is absent: $command"
done
for path in "$BINARY" "$INIT_SOURCE" "$UNIT_SOURCE" "$READY" "$PROCESS_GUARD" "$LAUNCHER_SOURCE"; do
    [ -f "$path" ] && [ ! -L "$path" ] || fail "required source fixture is not a regular file: $path"
done
[ -x "$BINARY" ] && [ -x "$INIT_SOURCE" ] && [ -x "$READY" ] && [ -x "$PROCESS_GUARD" ] \
    && [ -x "$LAUNCHER_SOURCE" ] || fail 'one or more lifecycle fixtures are not executable'
[ "$(stat -c '%u:%g:%a' -- "$BINARY")" = 0:0:755 ] \
    || fail 'the actual RustDesk binary is not root-owned mode 0755'

source_identity=$(stat -c '%d:%i:%u:%g:%a' -- "$ROOT")
source_hash=$(sha256sum \
    "$BINARY" "$INIT_SOURCE" "$UNIT_SOURCE" \
    "$CONTROL_SOURCE/preinst" "$CONTROL_SOURCE/postinst" \
    "$CONTROL_SOURCE/prerm" "$CONTROL_SOURCE/postrm" \
    "$READY" "$PROCESS_GUARD" "$LAUNCHER_SOURCE")

[ ! -e /usr/bin/rustdesk ] && [ ! -L /usr/bin/rustdesk ] \
    || fail 'container unexpectedly has an installed /usr/bin/rustdesk'
[ ! -e /etc/init.d/rustdesk ] && [ ! -L /etc/init.d/rustdesk ] \
    || fail 'container unexpectedly has an installed RustDesk init script'

mkdir -p "$FIXTURE"
chmod 0711 "$FIXTURE"
printf '#!/bin/sh\nexit 0\n' >/usr/sbin/policy-rc.d
chmod 0755 /usr/sbin/policy-rc.d

build_package() {
    version=$1
    staging=$FIXTURE/package-$version
    output=$FIXTURE/rustdesk-sysv-smoke-$version.deb
    mkdir -p \
        "$staging/DEBIAN" \
        "$staging/etc/init.d" \
        "$staging/usr/bin" \
        "$staging/usr/lib/systemd/system" \
        "$staging/usr/share/rustdesk"
    chmod 0755 \
        "$staging" \
        "$staging/DEBIAN" \
        "$staging/etc" \
        "$staging/etc/init.d" \
        "$staging/usr" \
        "$staging/usr/bin" \
        "$staging/usr/lib" \
        "$staging/usr/lib/systemd" \
        "$staging/usr/lib/systemd/system" \
        "$staging/usr/share" \
        "$staging/usr/share/rustdesk"
    install -o root -g root -m 0755 "$BINARY" "$staging/usr/share/rustdesk/rustdesk"
    ln -s ../share/rustdesk/rustdesk "$staging/usr/bin/rustdesk"
    install -o root -g root -m 0755 "$INIT_SOURCE" "$staging/etc/init.d/rustdesk"
    install -o root -g root -m 0644 "$UNIT_SOURCE" "$staging/usr/lib/systemd/system/rustdesk.service"
    for script in preinst postinst prerm postrm; do
        install -o root -g root -m 0755 "$CONTROL_SOURCE/$script" "$staging/DEBIAN/$script"
    done
    printf '%s\n' \
        "Package: $PACKAGE" \
        "Version: $version" \
        'Section: net' \
        'Priority: optional' \
        'Architecture: amd64' \
        'Maintainer: RustDesk lifecycle smoke' \
        'Description: isolated RustDesk Debian SysV lifecycle fixture' \
        >"$staging/DEBIAN/control"
    printf '/etc/init.d/rustdesk\n' >"$staging/DEBIAN/conffiles"
    chmod 0644 "$staging/DEBIAN/control" "$staging/DEBIAN/conffiles"
    dpkg-deb --root-owner-group --build "$staging" "$output" >/dev/null
}

capture_service() {
    [ -f /run/rustdesk.pid ] && [ ! -L /run/rustdesk.pid ] \
        || fail 'service PID file is absent or is a symlink'
    [ "$(stat -c '%u:%g:%a:%h' -- /run/rustdesk.pid)" = 0:0:644:1 ] \
        || fail 'service PID file is not root-owned mode 0644 with one link'
    IFS= read -r SERVICE_PID </run/rustdesk.pid
    [[ "$SERVICE_PID" =~ ^[1-9][0-9]*$ ]] || fail 'service PID file is not canonical'
    SERVICE_START=$($READY --identity "$SERVICE_PID")
    service_uid=$(awk '/^Uid:/{print $2 ":" $3 ":" $4 ":" $5}' "/proc/$SERVICE_PID/status")
    [ "$service_uid" = 0:0:0:0 ] || fail 'service supervisor does not have four root UIDs'
    [ "$(readlink -f "/proc/$SERVICE_PID/exe")" = /usr/share/rustdesk/rustdesk ] \
        || fail 'service supervisor does not execute the installed RustDesk object'
    grep -zFxq -- --service "/proc/$SERVICE_PID/cmdline" \
        || fail 'service supervisor lacks its exact --service role'
    /etc/init.d/rustdesk status >/dev/null \
        || fail 'init script status does not recognize the exact supervisor'
}

assert_prior_service_gone() {
    prior_pid=$1
    prior_start=$2
    if "$READY" --is-running "$prior_pid" "$prior_start" 2>/dev/null; then
        fail "prior service supervisor remains live: $prior_pid/$prior_start"
    fi
}

wait_for_process_identity() {
    pid=$1
    label=$2
    attempts=0
    while [ "$attempts" -lt 100 ]; do
        if identity=$($READY --identity "$pid" 2>/dev/null); then
            printf '%s\n' "$identity"
            return 0
        fi
        attempts=$((attempts + 1))
        sleep 0.1
    done
    [ ! -f "$FIXTURE/portable/portable.log" ] || sed -n '1,160p' "$FIXTURE/portable/portable.log" >&2
    fail "$label did not retain a live PID identity: $pid"
}

start_portable() {
    if ! id -u rdportable >/dev/null 2>&1; then
        useradd -M -u "$PORTABLE_UID" -U -s /usr/sbin/nologin rdportable
    fi
    [ "$(id -u rdportable)" = "$PORTABLE_UID" ] || fail 'portable user UID differs'
    PORTABLE_GID=$(id -g rdportable)
    portable_root=$FIXTURE/portable
    install -d -o root -g root -m 0755 "$portable_root" "$portable_root/bin"
    install -d -o "$PORTABLE_UID" -g "$PORTABLE_GID" -m 0700 "$portable_root/home"
    install -o root -g root -m 0555 "$LAUNCHER_SOURCE" "$portable_root/bin/smoke-server-launcher"
    (
        export HOME=$portable_root/home
        export XDG_CONFIG_HOME=$portable_root/home/config
        start-stop-daemon --start --quiet --background --make-pidfile \
            --pidfile "$portable_root/portable.pid" \
            --output "$portable_root/portable.log" \
            --startas "$portable_root/bin/smoke-server-launcher" \
            --chuid "$PORTABLE_UID:$PORTABLE_GID" \
            --chdir "$portable_root/home" \
            -- "$BINARY"
    )
    IFS= read -r PORTABLE_PID <"$portable_root/portable.pid"
    [[ "$PORTABLE_PID" =~ ^[1-9][0-9]*$ ]] || fail 'portable PID file is not canonical'
    PORTABLE_START=$(wait_for_process_identity "$PORTABLE_PID" 'portable RustDesk process')
    "$PROCESS_GUARD" wait-server "$PORTABLE_PID" "$PORTABLE_START" "$BINARY"
    PORTABLE_EXE_ID=$(stat -Lc '%d:%i' "/proc/$PORTABLE_PID/exe")
    assert_portable_alive
}

assert_portable_alive() {
    "$READY" --is-running "$PORTABLE_PID" "$PORTABLE_START" \
        || fail 'unrelated portable RustDesk process stopped or changed identity'
    [ "$(stat -Lc '%d:%i' "/proc/$PORTABLE_PID/exe")" = "$PORTABLE_EXE_ID" ] \
        || fail 'unrelated portable RustDesk executable identity changed'
    portable_uid=$(awk '/^Uid:/{print $2 ":" $3 ":" $4 ":" $5}' "/proc/$PORTABLE_PID/status")
    [ "$portable_uid" = "$PORTABLE_UID:$PORTABLE_UID:$PORTABLE_UID:$PORTABLE_UID" ] \
        || fail 'unrelated portable RustDesk process changed UID'
    grep -zFxq -- --server "/proc/$PORTABLE_PID/cmdline" \
        || fail 'unrelated portable RustDesk process lost its exact --server role'
    if grep -zFxq -- --service-owned-server "/proc/$PORTABLE_PID/cmdline"; then
        fail 'portable RustDesk process acquired the service-owned role'
    fi
}

assert_wrong_executable_alive() {
    "$READY" --is-running "$WRONG_PID" "$WRONG_START" \
        || fail 'stale PID fixture with the wrong executable was signaled'
    [ "$(readlink -f "/proc/$WRONG_PID/exe")" = /usr/bin/sleep ] \
        || fail 'stale PID fixture changed executable identity'
}

assert_package_command_link() {
    [ -L /usr/bin/rustdesk ] \
        && [ "$(readlink /usr/bin/rustdesk)" = ../share/rustdesk/rustdesk ] \
        || fail 'installed RustDesk command is not the exact package-owned relative link'
    dpkg-query -S /usr/bin/rustdesk 2>/dev/null \
        | grep -qFx "$PACKAGE: /usr/bin/rustdesk" \
        || fail 'installed RustDesk command link is not owned by the package database'
}

build_package 1.0
build_package 2.0

dpkg -i "$FIXTURE/rustdesk-sysv-smoke-1.0.deb" >"$FIXTURE/install.log" 2>&1 \
    || { sed -n '1,200p' "$FIXTURE/install.log" >&2; fail 'initial package install failed'; }
assert_package_command_link
capture_service
installed_pid=$SERVICE_PID
installed_start=$SERVICE_START
start_portable

/etc/init.d/rustdesk restart >"$FIXTURE/restart.log" 2>&1 \
    || { sed -n '1,200p' "$FIXTURE/restart.log" >&2; fail 'SysV restart failed'; }
capture_service
assert_prior_service_gone "$installed_pid" "$installed_start"
[ "$SERVICE_PID:$SERVICE_START" != "$installed_pid:$installed_start" ] \
    || fail 'SysV restart retained the prior supervisor identity'
assert_portable_alive
restart_pid=$SERVICE_PID
restart_start=$SERVICE_START

dpkg -i "$FIXTURE/rustdesk-sysv-smoke-2.0.deb" >"$FIXTURE/upgrade.log" 2>&1 \
    || { sed -n '1,240p' "$FIXTURE/upgrade.log" >&2; fail 'package upgrade failed'; }
assert_package_command_link
capture_service
assert_prior_service_gone "$restart_pid" "$restart_start"
[ "$SERVICE_PID:$SERVICE_START" != "$restart_pid:$restart_start" ] \
    || fail 'package upgrade retained the prior supervisor identity'
assert_portable_alive
upgrade_pid=$SERVICE_PID
upgrade_start=$SERVICE_START

/etc/init.d/rustdesk stop >"$FIXTURE/stop.log" 2>&1 \
    || { sed -n '1,200p' "$FIXTURE/stop.log" >&2; fail 'installed SysV stop failed'; }
assert_prior_service_gone "$upgrade_pid" "$upgrade_start"
assert_portable_alive

sleep 120 &
WRONG_PID=$!
WRONG_START=$($READY --identity "$WRONG_PID")
printf '%s\n' "$WRONG_PID" >/run/rustdesk.pid
/etc/init.d/rustdesk stop >"$FIXTURE/stale-stop.log" 2>&1 \
    || { sed -n '1,200p' "$FIXTURE/stale-stop.log" >&2; fail 'stale wrong-executable stop did not fail closed'; }
assert_wrong_executable_alive
assert_portable_alive

/etc/init.d/rustdesk start >"$FIXTURE/start-after-stale.log" 2>&1 \
    || { sed -n '1,200p' "$FIXTURE/start-after-stale.log" >&2; fail 'SysV start over a stale wrong-executable PID failed'; }
capture_service
assert_wrong_executable_alive
assert_portable_alive
removal_pid=$SERVICE_PID
removal_start=$SERVICE_START

dpkg -r "$PACKAGE" >"$FIXTURE/remove.log" 2>&1 \
    || { sed -n '1,240p' "$FIXTURE/remove.log" >&2; fail 'package removal failed'; }
assert_prior_service_gone "$removal_pid" "$removal_start"
[ ! -e /run/rustdesk.pid ] && [ ! -L /run/rustdesk.pid ] \
    || fail 'service PID file survived package stop/removal'
[ ! -e /usr/bin/rustdesk ] && [ ! -L /usr/bin/rustdesk ] \
    || fail 'package-owned executable link survived removal'
[ ! -e /usr/lib/systemd/system/rustdesk.service ] \
    || fail 'staged systemd unit survived removal'
assert_portable_alive
assert_wrong_executable_alive

dpkg --purge "$PACKAGE" >"$FIXTURE/purge.log" 2>&1 \
    || { sed -n '1,160p' "$FIXTURE/purge.log" >&2; fail 'package purge failed'; }
[ ! -e /etc/init.d/rustdesk ] && [ ! -L /etc/init.d/rustdesk ] \
    || fail 'SysV conffile survived purge'

assert_portable_alive
"$READY" --stop "$PORTABLE_PID" "$PORTABLE_START"
PORTABLE_PID=
PORTABLE_START=
"$READY" --stop "$WRONG_PID" "$WRONG_START"
WRONG_PID=
WRONG_START=

[ "$source_identity" = "$(stat -c '%d:%i:%u:%g:%a' -- "$ROOT")" ] \
    || fail 'read-only source mount identity changed'
[ "$source_hash" = "$(sha256sum \
    "$BINARY" "$INIT_SOURCE" "$UNIT_SOURCE" \
    "$CONTROL_SOURCE/preinst" "$CONTROL_SOURCE/postinst" \
    "$CONTROL_SOURCE/prerm" "$CONTROL_SOURCE/postrm" \
    "$READY" "$PROCESS_GUARD" "$LAUNCHER_SOURCE")" ] \
    || fail 'read-only source fixtures changed'

printf 'DEBIAN_SYSV_INSTALLED_LIFECYCLE=pass os=debian-%s portable_uid=%s stale_wrong_exec=survived\n' \
    "$VERSION_ID" "$PORTABLE_UID"

trap - EXIT HUP INT TERM
rm -rf -- "$FIXTURE"
