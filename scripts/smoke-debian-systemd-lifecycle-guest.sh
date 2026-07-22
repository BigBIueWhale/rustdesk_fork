#!/usr/bin/env bash
set -euo pipefail
umask 077

MODE=source
ROOT=
RUNTIME_LIBS=
ARTIFACT=
EXPECTED_ARTIFACT_SHA256=
EXPECTED_COMMIT=
case "$#" in
    2)
        ROOT=$1
        RUNTIME_LIBS=$2
        ;;
    6)
        [ "$1" = --release-deb ] \
            || { printf 'usage: %s ROOT RUNTIME_LIBS | --release-deb ROOT RUNTIME_LIBS DEB SHA256 COMMIT\n' "${0##*/}" >&2; exit 2; }
        MODE=release-deb
        ROOT=$2
        RUNTIME_LIBS=$3
        ARTIFACT=$4
        EXPECTED_ARTIFACT_SHA256=$5
        EXPECTED_COMMIT=$6
        ;;
    *)
        printf 'usage: %s ROOT RUNTIME_LIBS | --release-deb ROOT RUNTIME_LIBS DEB SHA256 COMMIT\n' "${0##*/}" >&2
        exit 2
        ;;
esac
readonly MODE ROOT RUNTIME_LIBS ARTIFACT EXPECTED_ARTIFACT_SHA256 EXPECTED_COMMIT
if [ "$MODE" = source ]; then
    BINARY=$ROOT/target/debug/rustdesk
    PACKAGE=rustdesk-systemd-smoke
else
    BINARY=/usr/share/rustdesk/rustdesk
    PACKAGE=rustdesk
fi
readonly BINARY PACKAGE
readonly INIT_SOURCE=$ROOT/res/rustdesk.init
readonly UNIT_SOURCE=$ROOT/res/rustdesk.service
readonly CONTROL_SOURCE=$ROOT/res/DEBIAN
readonly LOGINCTL_SOURCE=$ROOT/scripts/smoke-debian-systemd-loginctl.sh
readonly FIXTURE=/var/tmp/rustdesk-debian-systemd
readonly UNIT=rustdesk.service
readonly PORTABLE_UNIT=rustdesk-portable-smoke.service
readonly SEAT_UID=4001
readonly SEAT_GID=4001
readonly PORTABLE_UID=4000

PORTABLE_PID=
PORTABLE_START=
LAST_MAIN_PID=
LAST_MAIN_START=
LAST_CHILD_PID=
LAST_CHILD_START=
LAST_GENERATION=

fail() {
    printf 'Debian systemd lifecycle smoke: %s\n' "$*" >&2
    exit 1
}

process_start_time() {
    python3 - "$1" <<'PY'
import sys

pid = int(sys.argv[1])
raw = open(f"/proc/{pid}/stat", "rb").read()
fields = raw.rsplit(b") ", 1)[1].split()
if len(fields) < 20 or fields[0] in {b"Z", b"X"}:
    raise SystemExit(1)
print(int(fields[19]))
PY
}

process_is_exact() {
    local pid=$1 start=$2 current
    current=$(process_start_time "$pid" 2>/dev/null) || return 1
    [ "$current" = "$start" ]
}

assert_process_gone() {
    local pid=$1 start=$2 label=$3
    if process_is_exact "$pid" "$start"; then
        fail "$label remains live at exact identity $pid/$start"
    fi
}

cleanup() {
    local status=$? cleanup_status=0
    trap - EXIT HUP INT TERM
    systemctl stop "$UNIT" >/dev/null 2>&1 || true
    systemctl stop "$PORTABLE_UNIT" >/dev/null 2>&1 || true
    dpkg --purge "$PACKAGE" >/dev/null 2>&1 || true
    if [ "$status" -ne 0 ]; then
        systemctl status "$UNIT" --no-pager -l >&2 || true
        journalctl -b -u "$UNIT" --no-pager -n 160 >&2 || true
        journalctl -b -u cloud-final.service --no-pager -n 80 >&2 || true
    fi
    rm -rf -- "$FIXTURE" || cleanup_status=1
    if [ "$cleanup_status" -ne 0 ]; then
        status=1
    fi
    exit "$status"
}

trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

[ "$(id -u)" = 0 ] || fail 'must run as root inside the disposable VM'
[ "$(cat /proc/1/comm)" = systemd ] || fail 'guest PID 1 is not systemd'
[ -d /run/systemd/system ] || fail 'the systemd running-system marker is absent'
[ -r /etc/os-release ] || fail '/etc/os-release is absent'
. /etc/os-release
[ "${ID:-}" = debian ] || fail "guest is not Debian: ${ID:-unknown}"
[ "${VERSION_CODENAME:-}" = bookworm ] \
    || fail "guest is not the audited Debian bookworm fixture: ${VERSION_CODENAME:-unknown}"
for command in \
    deb-systemd-helper deb-systemd-invoke dpkg dpkg-deb dpkg-query findmnt ldconfig \
    python3 sha256sum systemctl systemd-analyze systemd-run update-rc.d useradd xargs; do
    command -v "$command" >/dev/null || fail "required guest command is absent: $command"
done
mountpoints=("$ROOT" "$RUNTIME_LIBS")
[ "$MODE" != release-deb ] || mountpoints+=("$ARTIFACT")
for mountpoint in "${mountpoints[@]}"; do
    mount_options=$(findmnt -n -o OPTIONS --target "$mountpoint") \
        || fail "fixture mount is absent: $mountpoint"
    case ",$mount_options," in
        *,ro,*) ;;
        *) fail "fixture mount is not read-only: $mountpoint ($mount_options)" ;;
    esac
done
source_files=("$UNIT_SOURCE" "$LOGINCTL_SOURCE")
if [ "$MODE" = source ]; then
    source_files+=(
        "$BINARY" "$INIT_SOURCE"
        "$CONTROL_SOURCE/preinst" "$CONTROL_SOURCE/postinst"
        "$CONTROL_SOURCE/prerm" "$CONTROL_SOURCE/postrm"
    )
else
    [[ "$EXPECTED_ARTIFACT_SHA256" =~ ^[0-9a-f]{64}$ ]] \
        || fail 'release artifact SHA-256 is not lowercase 64-hex'
    [[ "$EXPECTED_COMMIT" =~ ^[0-9a-f]{40}$ ]] \
        || fail 'release source commit is not lowercase 40-hex'
    [ -f "$ARTIFACT" ] && [ ! -L "$ARTIFACT" ] && [ -s "$ARTIFACT" ] \
        || fail 'release artifact is not a regular non-empty ISO member'
    [ "$(sha256sum "$ARTIFACT" | awk '{print $1}')" = "$EXPECTED_ARTIFACT_SHA256" ] \
        || fail 'release artifact SHA-256 differs inside the guest'
    [ "$(dpkg-deb -f "$ARTIFACT" Package 2>/dev/null)" = rustdesk ] \
        || fail 'release artifact package identity differs inside the guest'
    [ "$(dpkg-deb -f "$ARTIFACT" Architecture 2>/dev/null)" = amd64 ] \
        || fail 'release artifact architecture differs inside the guest'
    source_files+=("$ARTIFACT")
fi
for path in "${source_files[@]}"; do
    [ -f "$path" ] && [ ! -L "$path" ] \
        || fail "required source fixture is not a regular file: $path"
done
[ -x "$LOGINCTL_SOURCE" ] || fail 'loginctl fixture lacks execute permission'
[ "$MODE" != source ] || {
    [ -x "$BINARY" ] && [ -x "$INIT_SOURCE" ] \
        || fail 'one or more source lifecycle fixtures lack execute permission'
}

source_identity=$(stat -c '%d:%i:%u:%g:%a' -- "$ROOT")
source_hash=$(sha256sum "${source_files[@]}")

[ ! -e /usr/bin/rustdesk ] && [ ! -L /usr/bin/rustdesk ] \
    || fail 'base guest unexpectedly has an installed /usr/bin/rustdesk'
[ ! -e /usr/lib/systemd/system/rustdesk.service ] \
    || fail 'base guest unexpectedly has an installed RustDesk unit'
[ ! -e /usr/sbin/policy-rc.d ] && [ ! -L /usr/sbin/policy-rc.d ] \
    || fail 'base guest has a policy-rc.d override that could suppress the lifecycle'

mkdir -p "$FIXTURE"
chmod 0700 "$FIXTURE"

groupadd -g "$SEAT_GID" rdseat
groupadd -g 4101 rdseat-extra
useradd -m -u "$SEAT_UID" -g "$SEAT_GID" -G rdseat-extra -s /bin/sh rdseat
useradd -m -u "$PORTABLE_UID" -U -s /bin/sh rdportable
[ "$(id -G rdseat | tr ' ' ',')" = 4001,4101 ] \
    || fail 'active-seat supplementary-group fixture differs'
install -d -o rdseat -g rdseat -m 0700 /run/user/4001
install -o root -g root -m 0755 "$LOGINCTL_SOURCE" /usr/bin/loginctl

# The real debug executable is dynamically linked against the already-pinned
# Debian devcheck image. Install that read-only bundle into an isolated loader
# directory inside the disposable guest, then rebuild only the guest's loader
# cache. This keeps the production unit byte-exact and also serves the non-root
# child after production code rebuilds its environment without LD_LIBRARY_PATH.
install -d -o root -g root -m 0755 /usr/local/lib/rustdesk-systemd-smoke
find "$RUNTIME_LIBS" -mindepth 1 -maxdepth 1 -type f -print0 \
    | xargs -0 -r install -o root -g root -m 0644 \
        -t /usr/local/lib/rustdesk-systemd-smoke
printf '%s\n' '/usr/local/lib/rustdesk-systemd-smoke' \
    >/etc/ld.so.conf.d/rustdesk-systemd-smoke.conf
chmod 0644 /etc/ld.so.conf.d/rustdesk-systemd-smoke.conf
ldconfig

build_package() {
    local staging=$FIXTURE/package output=$FIXTURE/rustdesk-systemd-smoke.deb script
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
    install -o root -g root -m 0644 \
        "$UNIT_SOURCE" "$staging/usr/lib/systemd/system/rustdesk.service"
    for script in preinst postinst prerm postrm; do
        install -o root -g root -m 0755 "$CONTROL_SOURCE/$script" "$staging/DEBIAN/$script"
    done
    printf '%s\n' \
        "Package: $PACKAGE" \
        'Version: 1.0' \
        'Section: net' \
        'Priority: optional' \
        'Architecture: amd64' \
        'Maintainer: RustDesk lifecycle smoke' \
        'Description: isolated RustDesk Debian systemd lifecycle fixture' \
        >"$staging/DEBIAN/control"
    printf '/etc/init.d/rustdesk\n' >"$staging/DEBIAN/conffiles"
    chmod 0644 "$staging/DEBIAN/control" "$staging/DEBIAN/conffiles"
    dpkg-deb --root-owner-group --build "$staging" "$output" >/dev/null
}

wait_for_active_unit() {
    local expected_not_pid=${1:-} attempt main
    for attempt in $(seq 1 300); do
        if systemctl is-active --quiet "$UNIT"; then
            main=$(systemctl show "$UNIT" -p MainPID --value)
            if [[ "$main" =~ ^[1-9][0-9]*$ ]] \
                && { [ -z "$expected_not_pid" ] || [ "$main" != "$expected_not_pid" ]; } \
                && process_start_time "$main" >/dev/null 2>&1; then
                return 0
            fi
        fi
        sleep 0.1
    done
    fail 'RustDesk systemd unit did not reach a live active MainPID'
}

validate_service_child() {
    local main_pid=$1
    python3 - "$main_pid" "$SEAT_UID" "$SEAT_GID" <<'PY'
import hashlib
import os
import re
import stat
import sys
import uuid

main_pid = int(sys.argv[1])
seat_uid = int(sys.argv[2])
seat_gid = int(sys.argv[3])
record_path = "/run/rustdesk/service-child.record"
metadata = os.lstat(record_path)
if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
    raise SystemExit("service child record is not one regular file")
if (metadata.st_uid, metadata.st_gid, stat.S_IMODE(metadata.st_mode)) != (0, 0, 0o600):
    raise SystemExit("service child record authority metadata differs")
raw = open(record_path, "rb").read(1025)
if not 0 < len(raw) <= 1024:
    raise SystemExit("service child record size differs")
pattern = re.compile(
    rb"version=1\n"
    rb"pid=([1-9][0-9]*)\n"
    rb"start_time=([1-9][0-9]*)\n"
    rb"boot_id=([0-9a-f-]{36})\n"
    rb"exe_dev=([0-9]+)\n"
    rb"exe_ino=([1-9][0-9]*)\n"
    rb"uid=([0-9]+)\n"
    rb"generation=([0-9a-f-]{36})\n"
    rb"role=--server\+--service-owned-server\n"
)
matched = pattern.fullmatch(raw)
if matched is None:
    raise SystemExit("service child record grammar differs")
pid, start, boot_id, exe_dev, exe_ino, uid, generation = [
    value.decode("ascii") for value in matched.groups()
]
if int(uid) != seat_uid:
    raise SystemExit("service child record UID differs")
if str(uuid.UUID(boot_id)) != boot_id or str(uuid.UUID(generation)) != generation:
    raise SystemExit("service child record UUID is noncanonical")
if open("/proc/sys/kernel/random/boot_id", encoding="ascii").read().strip() != boot_id:
    raise SystemExit("service child boot identity differs")
pid_number = int(pid)
raw_stat = open(f"/proc/{pid_number}/stat", "rb").read()
fields = raw_stat.rsplit(b") ", 1)[1].split()
if len(fields) < 20 or fields[0] in {b"Z", b"X"} or int(fields[19]) != int(start):
    raise SystemExit("service child process start identity differs")
status_lines = open(f"/proc/{pid_number}/status", encoding="ascii").read().splitlines()
status = {
    line.split(":", 1)[0]: line.split(":", 1)[1].strip()
    for line in status_lines if ":" in line
}
if status.get("PPid") != str(main_pid):
    raise SystemExit("service child is not directly owned by the unit MainPID")
if status.get("Uid", "").split() != [str(seat_uid)] * 4:
    raise SystemExit("service child real/effective/saved/filesystem UID differs")
if status.get("Gid", "").split() != [str(seat_gid)] * 4:
    raise SystemExit("service child real/effective/saved/filesystem GID differs")
if sorted(map(int, status.get("Groups", "").split())) != [4001, 4101]:
    raise SystemExit("service child supplementary groups differ")
for capability_set in ("CapInh", "CapPrm", "CapEff", "CapAmb"):
    if int(status.get(capability_set, "1"), 16) != 0:
        raise SystemExit(f"service child retained {capability_set}")
if status.get("NoNewPrivs") != "1":
    raise SystemExit("service child did not arm no-new-privileges")
executable = os.stat(f"/proc/{pid_number}/exe")
installed = os.stat("/usr/share/rustdesk/rustdesk")
if (executable.st_dev, executable.st_ino) != (int(exe_dev), int(exe_ino)):
    raise SystemExit("service child executable differs from its durable record")
if (executable.st_dev, executable.st_ino) != (installed.st_dev, installed.st_ino):
    raise SystemExit("service child does not execute the installed RustDesk object")
argv = open(f"/proc/{pid_number}/cmdline", "rb").read().split(b"\0")
if re.fullmatch(rb"/proc/self/fd/[0-9]+", argv[0]) is None:
    raise SystemExit("non-root service child was not descriptor-executed")
if argv[1:] != [b"--server", b"--service-owned-server", b""]:
    raise SystemExit("service child exact role differs")
environment = {}
for entry in open(f"/proc/{pid_number}/environ", "rb").read().split(b"\0"):
    if not entry:
        continue
    key, value = entry.split(b"=", 1)
    if key in environment:
        raise SystemExit("service child environment has duplicate keys")
    environment[key] = value
expected = {
    b"PATH": b"/usr/bin:/bin",
    b"HOME": b"/home/rdseat",
    b"USER": b"rdseat",
    b"LOGNAME": b"rdseat",
    b"XDG_RUNTIME_DIR": b"/run/user/4001",
    b"DISPLAY": b":0",
    b"XAUTHORITY": b"/home/rdseat/.Xauthority",
    b"RUSTDESK_SERVICE_OWNED_SERVER_LAUNCH_PARENT": str(main_pid).encode("ascii"),
    b"RUSTDESK_SERVICE_OWNED_SERVER_GENERATION": generation.encode("ascii"),
    b"RUSTDESK_SERVICE_OWNED_SERVER_EXECUTABLE_FD": argv[0].rsplit(b"/", 1)[1],
}
if set(environment) != set(expected) | {b"TERM"}:
    raise SystemExit("service child environment escaped its bounded allowlist")
if any(environment[key] != value for key, value in expected.items()):
    raise SystemExit("service child environment binding differs")
if environment[b"TERM"] not in {b"xterm", b"xterm-256color"}:
    raise SystemExit("service child TERM differs")
main_cgroup = open(f"/proc/{main_pid}/cgroup", encoding="ascii").read().strip()
child_cgroup = open(f"/proc/{pid_number}/cgroup", encoding="ascii").read().strip()
if main_cgroup != child_cgroup or not main_cgroup.endswith("/system.slice/rustdesk.service"):
    raise SystemExit("service child escaped the RustDesk unit cgroup")
print(pid, start, generation, hashlib.sha256(raw).hexdigest())
PY
}

capture_unit() {
    local attempt fragment main_uid main_exe main_cgroup child_fields
    wait_for_active_unit
    fragment=$(systemctl show "$UNIT" -p FragmentPath --value)
    [ "$(readlink -f "$fragment")" = /usr/lib/systemd/system/rustdesk.service ] \
        || fail "unit fragment is not the package-installed production file: $fragment"
    [ -z "$(systemctl show "$UNIT" -p DropInPaths --value)" ] \
        || fail 'installed production unit unexpectedly has a drop-in'
    LAST_MAIN_PID=$(systemctl show "$UNIT" -p MainPID --value)
    [[ "$LAST_MAIN_PID" =~ ^[1-9][0-9]*$ ]] || fail 'unit MainPID is not canonical'
    LAST_MAIN_START=$(process_start_time "$LAST_MAIN_PID") \
        || fail 'unit MainPID has no stable start identity'
    main_uid=$(awk '/^Uid:/{print $2 ":" $3 ":" $4 ":" $5}' \
        "/proc/$LAST_MAIN_PID/status")
    [ "$main_uid" = 0:0:0:0 ] || fail 'unit MainPID does not retain four root UIDs'
    main_exe=$(stat -Lc '%d:%i' "/proc/$LAST_MAIN_PID/exe")
    [ "$main_exe" = "$(stat -Lc '%d:%i' /usr/share/rustdesk/rustdesk)" ] \
        || fail 'unit MainPID does not execute the installed RustDesk object'
    [ "$(tr '\0' ' ' <"/proc/$LAST_MAIN_PID/cmdline")" = '/usr/bin/rustdesk --service ' ] \
        || fail 'unit MainPID exact argv differs'
    main_cgroup=$(cat "/proc/$LAST_MAIN_PID/cgroup")
    case "$main_cgroup" in
        *'/system.slice/rustdesk.service') ;;
        *) fail "unit MainPID is outside its exact cgroup: $main_cgroup" ;;
    esac
    [ "$(stat -c '%u:%g:%a' /run/rustdesk)" = 0:0:700 ] \
        || fail 'RuntimeDirectory is not root-owned mode 0700'
    for attempt in $(seq 1 300); do
        if [ -f /run/rustdesk/service-child.record ] && [ ! -L /run/rustdesk/service-child.record ]; then
            if child_fields=$(validate_service_child "$LAST_MAIN_PID" 2>"$FIXTURE/child-validate.log"); then
                read -r LAST_CHILD_PID LAST_CHILD_START LAST_GENERATION _ <<<"$child_fields"
                return 0
            fi
        fi
        process_is_exact "$LAST_MAIN_PID" "$LAST_MAIN_START" \
            || { cat "$FIXTURE/child-validate.log" >&2 || true; fail 'unit MainPID exited before its non-root child was proven'; }
        sleep 0.1
    done
    cat "$FIXTURE/child-validate.log" >&2 || true
    fail 'non-root service child did not reach the exact installed authority state'
}

start_portable() {
    install -d -o root -g root -m 0755 /opt/rustdesk-portable-smoke
    install -o root -g root -m 0755 "$BINARY" /opt/rustdesk-portable-smoke/rustdesk
    systemd-run --unit="$PORTABLE_UNIT" \
        --property=Type=simple \
        --property=User=rdportable \
        --property=NoNewPrivileges=yes \
        --property=CapabilityBoundingSet= \
        --property=Environment=HOME=/home/rdportable \
        --property=Environment=USER=rdportable \
        --property=Environment=LOGNAME=rdportable \
        --property=Environment=RUST_LOG=info \
        /opt/rustdesk-portable-smoke/rustdesk --server >/dev/null
    for _ in $(seq 1 200); do
        if systemctl is-active --quiet "$PORTABLE_UNIT"; then
            PORTABLE_PID=$(systemctl show "$PORTABLE_UNIT" -p MainPID --value)
            if [[ "$PORTABLE_PID" =~ ^[1-9][0-9]*$ ]] \
                && PORTABLE_START=$(process_start_time "$PORTABLE_PID" 2>/dev/null); then
                break
            fi
        fi
        sleep 0.1
    done
    [[ "$PORTABLE_PID" =~ ^[1-9][0-9]*$ ]] \
        || fail 'portable RustDesk unit did not acquire a MainPID'
    assert_portable_alive
}

assert_portable_alive() {
    local uid_line cgroup
    process_is_exact "$PORTABLE_PID" "$PORTABLE_START" \
        || fail 'unrelated portable RustDesk process stopped or changed identity'
    uid_line=$(awk '/^Uid:/{print $2 ":" $3 ":" $4 ":" $5}' "/proc/$PORTABLE_PID/status")
    [ "$uid_line" = 4000:4000:4000:4000 ] || fail 'portable RustDesk UID differs'
    [ "$(tr '\0' ' ' <"/proc/$PORTABLE_PID/cmdline")" \
        = '/opt/rustdesk-portable-smoke/rustdesk --server ' ] \
        || fail 'portable RustDesk exact argv differs'
    cgroup=$(cat "/proc/$PORTABLE_PID/cgroup")
    case "$cgroup" in
        *'/system.slice/rustdesk-portable-smoke.service') ;;
        *) fail "portable RustDesk has an unexpected cgroup: $cgroup" ;;
    esac
    [ "$cgroup" != "$(cat "/proc/$LAST_MAIN_PID/cgroup" 2>/dev/null || true)" ] \
        || fail 'portable RustDesk was placed in the installed service cgroup'
}

if [ "$MODE" = source ]; then
    build_package
    install_deb=$FIXTURE/rustdesk-systemd-smoke.deb
    install_argv=(--install "$install_deb")
else
    install_deb=$ARTIFACT
    # The pinned cloud image is intentionally minimal and offline. Runtime
    # libraries were derived from this exact artifact and staged above; force
    # only dependency admission so dpkg still unpacks, configures, and executes
    # the artifact's real maintainer scripts in the disposable guest.
    install_argv=(--force-depends --install "$install_deb")
fi
mkdir -p /etc/systemd/system
ln -s /usr/lib/systemd/system/rustdesk.service /etc/systemd/system/rustdesk.service
dpkg "${install_argv[@]}" >"$FIXTURE/install.log" 2>&1 \
    || { sed -n '1,240p' "$FIXTURE/install.log" >&2; fail 'initial package install failed'; }
[ "$(dpkg-query -W -f='${db:Status-Abbrev}' "$PACKAGE" 2>/dev/null)" = 'ii ' ] \
    || fail 'installed package did not reach configured state'
[ -f "$BINARY" ] && [ ! -L "$BINARY" ] && [ -x "$BINARY" ] \
    || fail 'installed RustDesk executable is absent or non-executable'
[ -L /usr/bin/rustdesk ] \
    && [ "$(readlink /usr/bin/rustdesk)" = ../share/rustdesk/rustdesk ] \
    || fail 'installed RustDesk command is not the exact package-owned relative link'
dpkg-query -S /usr/bin/rustdesk 2>/dev/null \
    | grep -qFx "$PACKAGE: /usr/bin/rustdesk" \
    || fail 'installed RustDesk command link is not owned by the package database'
ldd "$BINARY" >"$FIXTURE/ldd.log"
if grep -q 'not found' "$FIXTURE/ldd.log"; then
    cat "$FIXTURE/ldd.log" >&2
    fail 'read-only runtime-library bundle is incomplete'
fi
[ "$MODE" != release-deb ] || {
    [ -z "$(dpkg --verify "$PACKAGE" 2>"$FIXTURE/dpkg-verify.err")" ] \
        || fail 'installed release artifact payload failed dpkg verification'
    [ ! -s "$FIXTURE/dpkg-verify.err" ] \
        || { cat "$FIXTURE/dpkg-verify.err" >&2; fail 'dpkg could not verify the installed release artifact'; }
}
cmp -s "$UNIT_SOURCE" /usr/lib/systemd/system/rustdesk.service \
    || fail 'installed RustDesk unit differs from the production source fixture'
[ -L /etc/systemd/system/rustdesk.service ] \
    && [ "$(readlink /etc/systemd/system/rustdesk.service)" = /usr/lib/systemd/system/rustdesk.service ] \
    || fail 'package install replaced the administrator-owned systemd unit link'
systemd-analyze verify /usr/lib/systemd/system/rustdesk.service >/dev/null \
    || fail 'installed production RustDesk unit failed systemd-analyze verify'
capture_unit
install_main=$LAST_MAIN_PID
install_main_start=$LAST_MAIN_START
install_child=$LAST_CHILD_PID
install_child_start=$LAST_CHILD_START
install_generation=$LAST_GENERATION

start_portable

systemctl restart "$UNIT"
capture_unit
assert_process_gone "$install_main" "$install_main_start" 'pre-restart supervisor'
assert_process_gone "$install_child" "$install_child_start" 'pre-restart service child'
[ "$LAST_GENERATION" != "$install_generation" ] \
    || fail 'normal systemd restart retained the prior service generation'
assert_portable_alive
restart_main=$LAST_MAIN_PID
restart_main_start=$LAST_MAIN_START
restart_child=$LAST_CHILD_PID
restart_child_start=$LAST_CHILD_START
restart_generation=$LAST_GENERATION
printf 'SYSTEMD_NORMAL_RESTART=pass prior_generation=%s generation=%s\n' \
    "$install_generation" "$restart_generation"

systemctl stop "$UNIT"
assert_process_gone "$restart_main" "$restart_main_start" 'stopped supervisor'
assert_process_gone "$restart_child" "$restart_child_start" 'stopped service child'
systemctl is-active --quiet "$UNIT" && fail 'deliberately stopped unit restarted unexpectedly'
[ ! -e /run/rustdesk ] && [ ! -L /run/rustdesk ] \
    || fail 'RuntimeDirectory survived a deliberate clean stop'
assert_portable_alive

systemctl start "$UNIT"
capture_unit
[ "$LAST_GENERATION" != "$restart_generation" ] \
    || fail 'clean stop/start retained the prior service generation'
assert_portable_alive
precrash_main=$LAST_MAIN_PID
precrash_main_start=$LAST_MAIN_START
precrash_child=$LAST_CHILD_PID
precrash_child_start=$LAST_CHILD_START
precrash_generation=$LAST_GENERATION
printf 'SYSTEMD_STOP_START=pass generation=%s\n' "$precrash_generation"

systemctl kill --kill-whom=main --signal=KILL "$UNIT"
assert_process_gone "$precrash_main" "$precrash_main_start" 'crashed supervisor'
wait_for_active_unit "$precrash_main"
capture_unit
assert_process_gone "$precrash_child" "$precrash_child_start" 'crashed supervisor child'
[ "$LAST_MAIN_PID" != "$precrash_main" ] \
    || fail 'systemd crash recovery retained the prior supervisor PID'
[ "$LAST_GENERATION" != "$precrash_generation" ] \
    || fail 'systemd crash recovery retained the prior generation'
nrestarts=$(systemctl show "$UNIT" -p NRestarts --value)
[[ "$nrestarts" =~ ^[1-9][0-9]*$ ]] \
    || fail "systemd did not account for the automatic restart: $nrestarts"
journalctl -b -u "$UNIT" --no-pager >"$FIXTURE/recovery-journal.log" \
    || fail 'could not read the installed unit recovery journal'
grep -Eq 'Discarding (exited|stale) Linux service child record' "$FIXTURE/recovery-journal.log" \
    || fail 'fresh supervisor did not report exact stale crash-record recovery'
assert_portable_alive
crash_generation=$LAST_GENERATION
printf 'SYSTEMD_CRASH_RESTART=pass prior_generation=%s generation=%s nrestarts=%s\n' \
    "$precrash_generation" "$crash_generation" "$nrestarts"

removal_main=$LAST_MAIN_PID
removal_main_start=$LAST_MAIN_START
removal_child=$LAST_CHILD_PID
removal_child_start=$LAST_CHILD_START
dpkg -r "$PACKAGE" >"$FIXTURE/remove.log" 2>&1 \
    || { sed -n '1,240p' "$FIXTURE/remove.log" >&2; fail 'package removal failed'; }
assert_process_gone "$removal_main" "$removal_main_start" 'package-removed supervisor'
assert_process_gone "$removal_child" "$removal_child_start" 'package-removed service child'
[ ! -e /usr/bin/rustdesk ] && [ ! -L /usr/bin/rustdesk ] \
    || fail 'package-owned executable link survived removal'
[ ! -e /usr/lib/systemd/system/rustdesk.service ] \
    || fail 'package-owned systemd unit survived removal'
[ -L /etc/systemd/system/rustdesk.service ] \
    && [ "$(readlink /etc/systemd/system/rustdesk.service)" = /usr/lib/systemd/system/rustdesk.service ] \
    || fail 'package removal deleted the administrator-owned systemd unit link'
[ ! -e /run/rustdesk ] && [ ! -L /run/rustdesk ] \
    || fail 'RuntimeDirectory survived package removal'
assert_portable_alive

dpkg --purge "$PACKAGE" >"$FIXTURE/purge.log" 2>&1 \
    || { sed -n '1,160p' "$FIXTURE/purge.log" >&2; fail 'package purge failed'; }
[ ! -e /etc/init.d/rustdesk ] && [ ! -L /etc/init.d/rustdesk ] \
    || fail 'SysV conffile survived package purge'
[ -L /etc/systemd/system/rustdesk.service ] \
    && [ "$(readlink /etc/systemd/system/rustdesk.service)" = /usr/lib/systemd/system/rustdesk.service ] \
    || fail 'package purge deleted the administrator-owned systemd unit link'
rm -f /etc/systemd/system/rustdesk.service
assert_portable_alive

systemctl stop "$PORTABLE_UNIT"
assert_process_gone "$PORTABLE_PID" "$PORTABLE_START" 'explicitly stopped portable RustDesk'
PORTABLE_PID=
PORTABLE_START=

[ "$source_identity" = "$(stat -c '%d:%i:%u:%g:%a' -- "$ROOT")" ] \
    || fail 'read-only source mount identity changed'
[ "$source_hash" = "$(sha256sum "${source_files[@]}")" ] \
    || fail 'read-only source fixtures changed'

systemd_version=$(systemd --version | sed -n '1s/^systemd \([0-9][0-9]*\).*/\1/p')
printf 'DEBIAN_SYSTEMD_INSTALLED_LIFECYCLE=pass os=debian-%s systemd=%s seat_uid=%s portable_uid=%s crash_generation=%s\n' \
    "$VERSION_ID" "$systemd_version" "$SEAT_UID" "$PORTABLE_UID" "$crash_generation"
[ "$MODE" != release-deb ] || printf \
    'DEBIAN_RELEASE_ARTIFACT_LIFECYCLE=pass sha256=%s commit=%s\n' \
    "$EXPECTED_ARTIFACT_SHA256" "$EXPECTED_COMMIT"

trap - EXIT HUP INT TERM
rm -rf -- "$FIXTURE"
