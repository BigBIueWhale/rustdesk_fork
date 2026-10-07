#!/usr/bin/env bash
set -Eeuo pipefail
trap 'status=$?; printf "VERIFIER_VM_RUN_ADMISSION_FAILURE line=%s status=%s command=%q\n" "$LINENO" "$status" "$BASH_COMMAND" >&2' ERR

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
uid=$(/usr/bin/id -u)
gid=$(/usr/bin/id -g)
[ "$uid" -ne 0 ] && [ "$gid" -ne 0 ] || exit 1
umask 077
/bin/bash "$SCRIPT_DIR/verify-vm-entry-preflight.sh" >/dev/null
workspace=$(/usr/bin/mktemp -d /tmp/verifier-run-admission.XXXXXXXXXX)
workspace_id=$(/usr/bin/stat -c '%d:%i' -- "$workspace")
success=0
cleanup() {
    local status=$?
    trap - EXIT HUP INT TERM
    /usr/bin/python3 -I -S "$SCRIPT_DIR/verify-private-tree-closure.py" \
        --remove-private-root "$workspace" --expected-identity "$workspace_id" \
        || status=1
    if [ "$status" -eq 0 ] && [ "$success" -eq 1 ]; then
        printf 'VERIFIER_VM_RUN_ADMISSION=pass retained=refused file=refused symlink=refused lock=refused unsafe=refused concurrent=16 winners=1 cross_root_marker=refused active_lock=retained app_capsule=refused cleanup=joined\n'
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

for entry in smoke-verifier-vm-authority online-fetch-vm; do
    /usr/bin/awk '
        /^reserve_verifier_run\(\) \{$/ { found++; copy = 1 }
        copy { print; if ($0 == "}") copy = 0 }
        END { if (found != 1 || copy) exit 1 }
    ' "$SCRIPT_DIR/$entry.sh" >"$workspace/$entry.function.sh"
done
/usr/bin/awk '
    /^capture_listeners\(\) \{$/ { found++; copy = 1 }
    copy { print; if ($0 == "}") copy = 0 }
    END { if (found != 1 || copy) exit 1 }
' "$SCRIPT_DIR/smoke-verifier-vm-authority.sh" >"$workspace/smoke-verifier-vm-authority.listeners.sh"
/usr/bin/awk '
    /^capture_listeners\(\) \{$/ { found++; copy = 1 }
    copy { print; if ($0 == "}") copy = 0 }
    END { if (found != 1 || copy) exit 1 }
' "$SCRIPT_DIR/online-fetch-vm.sh" >"$workspace/online-fetch-vm.listeners.sh"
/usr/bin/python3 -I -S - "$workspace" <<'PY'
from contextlib import ExitStack
from pathlib import Path
import socket
import subprocess
import sys

environment = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'HOME': '/nonexistent'}
families = ((socket.AF_INET, '127.0.0.1'), (socket.AF_INET6, '::1'))
types = ((socket.SOCK_STREAM, 'tcp'), (socket.SOCK_DGRAM, 'udp'))

def endpoint(sock, protocol):
    address, port = sock.getsockname()[:2]
    if sock.family == socket.AF_INET6:
        address = '[' + address + ']'
    return protocol + ' ' + address + ':' + str(port)

def bind(stack, family, kind, address, port=0):
    sock = stack.enter_context(socket.socket(family, kind))
    sock.settimeout(2)
    if family == socket.AF_INET6:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    sock.bind((address, port))
    if kind == socket.SOCK_STREAM:
        sock.listen(2)
    return sock

def queues(owned):
    result = subprocess.run(['/usr/bin/ss', '-H', '-lntu'], env=environment,
                            check=True, capture_output=True, text=True, timeout=5)
    values = {}
    for line in result.stdout.splitlines():
        fields = line.split()
        assert len(fields) == 6, fields
        key = fields[0] + ' ' + fields[4]
        if key in owned:
            assert key not in values, key
            values[key] = int(fields[2])
    assert values.keys() == owned, (values, owned)
    return values

for entry in ('smoke-verifier-vm-authority', 'online-fetch-vm'):
    source = str(Path(sys.argv[1]) / (entry + '.listeners.sh'))

    def snapshot():
        result = subprocess.run([
            '/bin/bash', '--noprofile', '--norc', '-c',
            'set -euo pipefail; source "$1"; capture_listeners', 'listener-test', source,
        ], env=environment, check=True, capture_output=True, text=True, timeout=5)
        assert not result.stderr, result.stderr
        lines = result.stdout.splitlines()
        assert lines == sorted(set(lines)), lines
        assert all(len(line.split()) == 2 and line.split()[0] in ('tcp', 'udp')
                   for line in lines), lines
        return set(lines)

    original = snapshot()
    with ExitStack() as stack:
        incumbents = []
        for family, address in families:
            tcp = bind(stack, family, socket.SOCK_STREAM, address)
            udp = bind(stack, family, socket.SOCK_DGRAM, address, tcp.getsockname()[1])
            incumbents.extend(((tcp, 'tcp'), (udp, 'udp')))
        owned = {endpoint(sock, protocol) for sock, protocol in incumbents}
        assert len(owned) == 4 and not owned.intersection(original), owned
        baseline = snapshot()
        assert baseline == original | owned, (baseline, original, owned)
        assert all(value == 0 for value in queues(owned).values())

        for server, protocol in incumbents:
            client = stack.enter_context(socket.socket(server.family, server.type))
            client.settimeout(2)
            client.connect(server.getsockname())
            if protocol == 'udp':
                assert client.send(b'queue-observation') == 17
        assert all(value > 0 for value in queues(owned).values())
        assert snapshot() == baseline, 'traffic-dependent queue state leaked into inventory'

        for family, address in families:
            for kind, protocol in types:
                with ExitStack() as added:
                    server = bind(added, family, kind, address)
                    key = endpoint(server, protocol)
                    assert key not in baseline, key
                    current = snapshot()
                    assert current - baseline == {key}, (entry, current, baseline, key)
                    assert baseline <= current, 'an incumbent endpoint disappeared'
                assert snapshot() == baseline, 'retired test endpoint remains'
    assert snapshot() == original, 'owned listener/client socket cleanup did not converge'
    print(f'VERIFIER_VM_LISTENER_INVENTORY_NATIVE=pass entry={entry} '
          'families=ipv4,ipv6 protocols=tcp,udp paired_ports=2 additions=4 '
          'queue_changes=4 inventory=stable uid=nonroot cleanup=joined',
          file=sys.stderr, flush=True)
PY
/usr/bin/awk '
    /^retire_disposable_vm_file\(\) \{$/ { found++; copy = 1 }
    copy { print; if ($0 == "}") copy = 0 }
    END { if (found != 1 || copy) exit 1 }
' "$SCRIPT_DIR/smoke-verifier-vm-authority.sh" >"$workspace/retire-disposable-vm-file.sh"

/usr/bin/awk '
    /^process_start_time\(\) \{$/ { found++; copy = 1 }
    copy { print; if ($0 == "}") copy = 0 }
    END { if (found != 1 || copy) exit 1 }
' "$SCRIPT_DIR/verify-vm-entry-preflight.sh" >"$workspace/process-start.sh"
for entry in smoke-verifier-vm-authority online-fetch-vm; do
    /usr/bin/awk '
        /^(process_stat_fields|process_start_time|is_live_process_generation|is_exact_virtiofsd_process|is_owned_virtiofsd_generation|is_exact_process|is_virtiofsd_generation)\(\) \{$/ { found++; copy = 1 }
        copy { print; if ($0 == "}") copy = 0 }
        END { if (found != 5 || copy) exit 1 }
    ' "$SCRIPT_DIR/$entry.sh" >"$workspace/$entry.process.sh"
done
/usr/bin/python3 -I -S - "$workspace" <<'PY'
import ctypes
import os
from pathlib import Path
import subprocess
import sys

libc = ctypes.CDLL(None, use_errno=True)
libc.prctl.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_ulong,
                      ctypes.c_ulong, ctypes.c_ulong]
libc.prctl.restype = ctypes.c_int
original_name = Path('/proc/self/comm').read_bytes()[:-1]
pid = str(os.getpid())
executable = str(Path('/proc/self/exe').resolve(strict=True))
environment = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'HOME': '/nonexistent'}
names = [('normal', b'rd-kernel-proof'), ('space', b'rd a b'),
         ('parenthesis', b'rd ) ( a b'), ('newline', b'rd)\n x y'),
         ('tab-carriage', b'rd\t x\r y')]

def rename(name):
    if libc.prctl(15, ctypes.cast(ctypes.c_char_p(name), ctypes.c_void_p), 0, 0, 0):
        raise OSError(ctypes.get_errno(), 'PR_SET_NAME failed')

def inspect(action, value, start='', role=executable):
    return subprocess.run([
        '/bin/bash', '--noprofile', '--norc', '-c', '''
set -euo pipefail
source "$1"
VIRTIOFSD_BINARY=$5
case "$2" in
    start) process_start_time "$3" ;;
    live) is_live_process_generation "$3" "$4" ;;
    role)
        if declare -F is_exact_virtiofsd_process >/dev/null; then
            is_exact_virtiofsd_process "$3" "$4"
        else
            is_exact_process "$3" "$4" "$5"
        fi ;;
    owned)
        if declare -F is_owned_virtiofsd_generation >/dev/null; then
            is_owned_virtiofsd_generation "$3" "$4"
        else
            is_virtiofsd_generation "$3" "$4"
        fi ;;
    *) exit 1 ;;
esac
''', 'process-stat', source, action, value, start, role,
    ], env=environment, capture_output=True, timeout=5)

def legacy(field, value):
    return subprocess.run(['/usr/bin/awk', '{ print $' + field + ' }',
                           f'/proc/{value}/stat'], env=environment, check=True,
                          capture_output=True, timeout=5).stdout

try:
    for entry in ('verify-vm-entry-preflight', 'smoke-verifier-vm-authority', 'online-fetch-vm'):
        has_generation_checks = entry != 'verify-vm-entry-preflight'
        source = str(Path(sys.argv[1]) / (entry + '.process.sh' if has_generation_checks else 'process-start.sh'))
        generation_actions = ('live', 'role', 'owned') if has_generation_checks else ()
        rename(b'rd-kernel-proof')
        baseline = legacy('22', pid)
        assert baseline.strip().isdigit() and int(baseline) > 0
        for label, name in names:
            rename(name)
            current = inspect('start', pid)
            old = legacy('22', pid)
            assert current.returncode == 0 and current.stdout == baseline, (entry, label, current)
            assert (old == baseline) == (label == 'normal'), (entry, label, old)
            for action in generation_actions:
                accepted = inspect(action, pid, baseline.decode().strip())
                assert accepted.returncode == 0 and not accepted.stdout, (entry, label, action, accepted)
                stale = inspect(action, pid, str(int(baseline) + 1))
                assert stale.returncode != 0 and not stale.stdout, (entry, label, action, stale)
            if has_generation_checks:
                wrong_role = inspect('role', pid, baseline.decode().strip(), '/nonexistent')
                assert wrong_role.returncode != 0 and not wrong_role.stdout, wrong_role

            child = os.fork()
            if child == 0:
                try:
                    rename(name)
                    os._exit(0)
                except BaseException:
                    os._exit(1)
            try:
                exited = os.waitid(os.P_PID, child, os.WEXITED | os.WNOWAIT)
                assert exited.si_code == os.CLD_EXITED and exited.si_status == 0, exited
                fields = Path(f'/proc/{child}/stat').read_bytes().rpartition(b') ')[2].split()
                assert fields[0] == b'Z' and fields[19].isdigit(), fields
                zombie_start = fields[19].decode()
                parsed = inspect('start', str(child))
                assert parsed.returncode == 0 and parsed.stdout == fields[19] + b'\n', parsed
                for action in generation_actions:
                    refused = inspect(action, str(child), zombie_start)
                    assert refused.returncode != 0 and not refused.stdout, (entry, label, action, refused)
                old_state = legacy('3', str(child))
                assert (old_state == b'Z\n') == (label == 'normal'), (entry, label, old_state)
            finally:
                joined_pid, joined_status = os.waitpid(child, 0)
                assert joined_pid == child and joined_status == 0, (joined_pid, joined_status)
            print(f'VERIFIER_VM_PROCESS_STAT_NATIVE entry={entry} case={label} '
                  f'start=same zombie_start=same generation_checks={has_generation_checks} child=joined',
                  file=sys.stderr, flush=True)
        missing_pid = str(int(Path('/proc/sys/kernel/pid_max').read_text()) + 1)
        for invalid in ('0', 'self', '../self', '-1', pid + 'x', missing_pid):
            for action in ('start',) + generation_actions:
                refused = inspect(action, invalid, baseline.decode().strip())
                assert refused.returncode != 0 and not refused.stdout, (entry, invalid, action, refused)
        print(f'VERIFIER_VM_PROCESS_STAT_NATIVE=pass entry={entry} '
              'comm_cases=5 zombie_cases=5 legacy_start_mismatches=4 legacy_zombie_mismatches=4 '
              f'generation_checks={has_generation_checks} pid=refused missing=refused uid=nonroot cleanup=joined',
              file=sys.stderr, flush=True)
finally:
    rename(original_name)
PY

invoke() {
    /bin/bash --noprofile --norc -c '
        set -euo pipefail
        fail() { printf "%s\n" "$*" >&2; exit 1; }
        source "$1"
        RUN_ROOT=$2
        INPUT_ROOT=${6:-$RUN_ROOT}
        case "$1" in
            *online-fetch-vm.function.sh) INPUT_ROOT=${6:-${RUN_ROOT%/*}} ;;
        esac
        HOST_UID=$(/usr/bin/id -u)
        HOST_GID=$(/usr/bin/id -g)
        MODE=${3:-authority-smoke}
        RUN_MARKER=
        RUN_MARKER_ID=
        RUN_ADMISSION_FD=
        ANDROID_ARTIFACT_STATE_ROOT=${4:-}
        FLUTTER_APP_STATE_ROOT=${4:-}
        FLUTTER_ENGINE_STATE_ROOT=${4:-}
        FLUTTER_APP_BUILD_ONLY=${5:-0}
        reserve_verifier_run
        [ -n "$RUN_ADMISSION_FD" ] \
            && [ "/proc/$$/fd/$RUN_ADMISSION_FD" -ef "$INPUT_ROOT" ] \
            || fail "shared run-admission descriptor was not retained"
        exec {probe_descriptor}<"$INPUT_ROOT"
        if /usr/bin/flock --exclusive --nonblock "$probe_descriptor"; then
            fail "shared run-admission lock was released before the run"
        fi
        exec {RUN_ADMISSION_FD}<&-
        exec {probe_descriptor}<&-
        for descriptor in /proc/$$/fd/*; do
            if [ "$descriptor" -ef "$RUN_ROOT" ] \
               || [ "$descriptor" -ef "$INPUT_ROOT" ]; then
                fail "run-admission descriptor remains open"
            fi
        done
        printf "%s %s\n" "$RUN" "$RUN_ID"
    ' run-admission "$function_file" "$1" "${2:-authority-smoke}" "${3:-}" "${4:-0}" "${5:-}"
}

require_refusal() {
    local root=$1 expected=$2
    if invoke "$root" "${3:-authority-smoke}" "${4:-}" "${5:-0}" "${6:-}" >"$workspace/refusal.out" 2>"$workspace/refusal.err"; then
        printf 'Unexpected run admission: %s\n' "$root" >&2
        exit 1
    fi
    [ ! -s "$workspace/refusal.out" ]
    /usr/bin/grep -Fq -- "$expected" "$workspace/refusal.err"
}

run_admission_cases() {
    local entry=$1 scope=$workspace/$1
    local function_file=$workspace/$1.function.sh
    local root result run run_id kind capsule lock_fd index pid winners
    local -a pids
    /usr/bin/mkdir -m 0700 -- "$scope"
    root=$scope/retained
    /usr/bin/mkdir -m 0700 -- "$root"
    result=$(invoke "$root")
    run=${result% *}
    run_id=${result##* }
    [[ "$run" == "$root"/run.* ]]
    [ "$run_id" = "$(/usr/bin/stat -c '%d:%i' -- "$run")" ]
    [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$run")" = "$uid:$gid:700" ]
    require_refusal "$root" 'earlier verifier run remains'
    [ "$(/usr/bin/find "$root" -mindepth 1 -maxdepth 1 -name 'run.*' | /usr/bin/wc -l)" -eq 1 ]
    /usr/bin/python3 -I -S "$SCRIPT_DIR/verify-private-tree-closure.py" \
        --remove-private-root "$run" --expected-identity "$run_id"
    result=$(invoke "$root")
    run=${result% *}
    run_id=${result##* }
    /usr/bin/flock --exclusive --nonblock "$root" /usr/bin/true
    if [ "$entry" = online-fetch-vm ]; then
        /usr/bin/flock --exclusive --nonblock "$scope" /usr/bin/true
    fi
    /usr/bin/python3 -I -S "$SCRIPT_DIR/verify-private-tree-closure.py" \
        --remove-private-root "$run" --expected-identity "$run_id"

    for kind in file symlink; do
        root=$scope/$kind
        /usr/bin/mkdir -m 0700 -- "$root"
        if [ "$kind" = file ]; then
            : >"$root/run.retained"
        else
            /usr/bin/ln -s -- missing "$root/run.retained"
        fi
        require_refusal "$root" 'earlier verifier run remains'
        [ "$(/usr/bin/find "$root" -mindepth 1 -maxdepth 1 | /usr/bin/wc -l)" -eq 1 ]
    done

    if [ "$entry" = smoke-verifier-vm-authority ]; then
        for kind in directory file symlink; do
            root=$scope/peer-run-$kind
            capsule=$scope/peer-capsule-$kind
            /usr/bin/mkdir -m 0700 -- "$root" "$capsule"
            case "$kind" in
                directory) /usr/bin/mkdir -m 0700 -- "$capsule/retained" ;;
                file) : >"$capsule/retained" ;;
                symlink) /usr/bin/ln -s -- missing "$capsule/retained" ;;
            esac
            require_refusal "$root" 'an earlier Android peer artifact remains' android-peer-build "$capsule"
            [ -z "$(/usr/bin/find "$root" -mindepth 1 -maxdepth 1 -print -quit)" ]
            [ "$(/usr/bin/find "$capsule" -mindepth 1 -maxdepth 1 | /usr/bin/wc -l)" -eq 1 ]
            require_refusal "$root" 'an earlier Linux Flutter app artifact remains' flutter-peer-presentation "$capsule" 1
            [ -z "$(/usr/bin/find "$root" -mindepth 1 -maxdepth 1 -print -quit)" ]
            [ "$(/usr/bin/find "$capsule" -mindepth 1 -maxdepth 1 | /usr/bin/wc -l)" -eq 1 ]
            require_refusal "$root" 'an earlier Flutter engine artifact remains' linux-flutter-engine-build "$capsule"
            [ -z "$(/usr/bin/find "$root" -mindepth 1 -maxdepth 1 -print -quit)" ]
            [ "$(/usr/bin/find "$capsule" -mindepth 1 -maxdepth 1 | /usr/bin/wc -l)" -eq 1 ]
        done
    fi

    root=$scope/locked
    /usr/bin/mkdir -m 0700 -- "$root"
    exec {lock_fd}<"$root"
    /usr/bin/flock --exclusive --nonblock "$lock_fd"
    require_refusal "$root" 'another verifier run is active or reserving'
    [ -z "$(/usr/bin/find "$root" -mindepth 1 -maxdepth 1 -print -quit)" ]
    exec {lock_fd}<&-

    root=$scope/unsafe
    /usr/bin/mkdir -m 0755 -- "$root"
    require_refusal "$root" 'run-root authority differs'
    [ -z "$(/usr/bin/find "$root" -mindepth 1 -maxdepth 1 -print -quit)" ]

    root=$scope/concurrent
    /usr/bin/mkdir -m 0700 -- "$root"
    pids=()
    for index in $(/usr/bin/seq 1 16); do
        invoke "$root" >"$scope/concurrent.$index.out" \
            2>"$scope/concurrent.$index.err" &
        pids+=("$!")
    done
    winners=0
    for pid in "${pids[@]}"; do
        if wait "$pid"; then winners=$((winners + 1)); fi
    done
    [ "$winners" -eq 1 ] || {
        printf 'VERIFIER_VM_RUN_ADMISSION_FAILURE entry=%s winners=%s expected=1\n' "$entry" "$winners" >&2
        /usr/bin/head -c 512 -- "$scope"/concurrent.*.err >&2
        exit 1
    }
    # Each caller proves its descriptors closed. Global availability is only
    # observable after every contender has joined, not immediately after release.
    /usr/bin/flock --exclusive --nonblock "$root" /usr/bin/true
    if [ "$entry" = online-fetch-vm ]; then
        /usr/bin/flock --exclusive --nonblock "$scope" /usr/bin/true
    fi
    [ "$(/usr/bin/find "$root" -mindepth 1 -maxdepth 1 -name 'run.*' | /usr/bin/wc -l)" -eq 1 ]
    for index in $(/usr/bin/seq 1 16); do
        if [ -s "$scope/concurrent.$index.out" ]; then
            [ ! -s "$scope/concurrent.$index.err" ]
        else
            /usr/bin/grep -Eq \
                'earlier verifier run remains|another verifier run is active or reserving' \
                "$scope/concurrent.$index.err"
        fi
    done
    printf 'VERIFIER_VM_RUN_ADMISSION_NATIVE entry=%s retained=refused file=refused symlink=refused lock=refused unsafe=refused readmission=pass concurrent=16 winners=1 descriptor=closed\n' "$entry" >&2
}
run_admission_cases smoke-verifier-vm-authority
run_admission_cases online-fetch-vm

shared=$workspace/shared-run-root
/usr/bin/mkdir -m 0700 -- "$shared" "$shared/online-fetch-runs"
function_file=$workspace/smoke-verifier-vm-authority.function.sh
result=$(invoke "$shared")
run=${result% *}
run_id=${result##* }
function_file=$workspace/online-fetch-vm.function.sh
require_refusal "$shared/online-fetch-runs" 'earlier verifier run remains' authority-smoke '' 0 "$shared"
/usr/bin/python3 -I -S "$SCRIPT_DIR/verify-private-tree-closure.py" \
    --remove-private-root "$run" --expected-identity "$run_id"
result=$(invoke "$shared/online-fetch-runs" authority-smoke '' 0 "$shared")
run=${result% *}
run_id=${result##* }
function_file=$workspace/smoke-verifier-vm-authority.function.sh
require_refusal "$shared" 'earlier verifier run remains'
/usr/bin/python3 -I -S "$SCRIPT_DIR/verify-private-tree-closure.py" \
    --remove-private-root "$run" --expected-identity "$run_id"
pids=()
for index in $(/usr/bin/seq 1 16); do
    if [ $((index % 2)) -eq 1 ]; then
        function_file=$workspace/smoke-verifier-vm-authority.function.sh
        root=$shared
    else
        function_file=$workspace/online-fetch-vm.function.sh
        root=$shared/online-fetch-runs
    fi
    invoke "$root" authority-smoke '' 0 "$shared" >"$shared/concurrent.$index.out" \
        2>"$shared/concurrent.$index.err" &
    pids+=("$!")
done
winners=0
for pid in "${pids[@]}"; do
    if wait "$pid"; then winners=$((winners + 1)); fi
done
[ "$winners" -eq 1 ] || {
    printf 'VERIFIER_VM_CROSS_ROOT_ADMISSION_FAILURE winners=%s expected=1\n' "$winners" >&2
    /usr/bin/head -c 512 -- "$shared"/concurrent.*.err >&2
    exit 1
}
/usr/bin/flock --exclusive --nonblock "$shared" /usr/bin/true
/usr/bin/flock --exclusive --nonblock "$shared/online-fetch-runs" /usr/bin/true
for index in $(/usr/bin/seq 1 16); do
    if [ -s "$shared/concurrent.$index.out" ]; then
        [ ! -s "$shared/concurrent.$index.err" ]
        result=$(/usr/bin/head -n 1 "$shared/concurrent.$index.out")
        run=${result% *}
        run_id=${result##* }
        /usr/bin/python3 -I -S "$SCRIPT_DIR/verify-private-tree-closure.py" \
            --remove-private-root "$run" --expected-identity "$run_id"
    else
        /usr/bin/grep -Eq \
            'earlier verifier run remains|another verifier run is active or reserving' \
            "$shared/concurrent.$index.err"
    fi
done
printf 'VERIFIER_VM_CROSS_ROOT_ADMISSION_NATIVE direct_blocks_acquisition=pass acquisition_blocks_direct=pass concurrent=16 winners=1\n' >&2

scope=$workspace/lifecycle-distinct
shared=$scope/shared
root=$scope/private
/usr/bin/mkdir -m 0700 -- "$scope" "$shared" "$shared/online-fetch-runs" "$root"
function_file=$workspace/smoke-verifier-vm-authority.function.sh
result=$(invoke "$root" authority-smoke '' 0 "$shared")
run=${result% *}
run_id=${result##* }
marker=$(/usr/bin/find "$shared" -mindepth 1 -maxdepth 1 -type d -name 'run.*' -print)
[[ "$marker" == "$shared"/run.* ]]
[ "$marker" != "$run" ] && [ "$run_id" = "$(/usr/bin/stat -c '%d:%i' -- "$run")" ]
[ "${marker##*/}" = "${run##*/}" ]
[ "$(/usr/bin/find "$shared" -mindepth 1 -maxdepth 1 -type d -name 'run.*' | /usr/bin/wc -l)" -eq 1 ]
marker_id=$(/usr/bin/stat -c '%d:%i' -- "$marker")
require_refusal "$shared" 'earlier verifier run remains'
require_refusal "$root" 'earlier verifier run remains' authority-smoke '' 0 "$shared"
function_file=$workspace/online-fetch-vm.function.sh
require_refusal "$shared/online-fetch-runs" 'earlier verifier run remains' authority-smoke '' 0 "$shared"
/usr/bin/python3 -I -S "$SCRIPT_DIR/verify-private-tree-closure.py" \
    --remove-private-root "$run" --expected-identity "$run_id"
function_file=$workspace/smoke-verifier-vm-authority.function.sh
require_refusal "$shared" 'earlier verifier run remains'
/usr/bin/python3 -I -S "$SCRIPT_DIR/verify-private-tree-closure.py" \
    --remove-empty-private-root "$marker" --expected-identity "$marker_id"
result=$(invoke "$shared")
run=${result% *}
run_id=${result##* }
/usr/bin/python3 -I -S "$SCRIPT_DIR/verify-private-tree-closure.py" \
    --remove-private-root "$run" --expected-identity "$run_id"
printf 'VERIFIER_VM_DISTINCT_ROOT_ADMISSION_NATIVE marker=blocks-direct-and-acquisition active_lock=retained readmission=pass\n' >&2

HOST_UID=$uid HOST_GID=$gid
source "$workspace/retire-disposable-vm-file.sh"
storage=$workspace/disposable-vm-storage
/usr/bin/mkdir -m 0700 -- "$storage"
/usr/bin/printf 'diagnostic\n' >"$storage/serial.log"
/usr/bin/printf 'disposable\n' >"$storage/overlay.qcow2"
retire_disposable_vm_file "$storage/overlay.qcow2"
[ ! -e "$storage/overlay.qcow2" ] && [ -f "$storage/serial.log" ]
/usr/bin/ln -s -- serial.log "$storage/payload.iso"
if retire_disposable_vm_file "$storage/payload.iso"; then exit 1; fi
[ -L "$storage/payload.iso" ] && [ -f "$storage/serial.log" ]
/usr/bin/ln -- "$storage/serial.log" "$storage/seed.iso"
if retire_disposable_vm_file "$storage/seed.iso"; then exit 1; fi
[ -f "$storage/seed.iso" ] && [ -f "$storage/serial.log" ]
/usr/bin/rm -- "$storage/payload.iso" "$storage/seed.iso"
/usr/bin/printf 'VERIFIER_VM_FAILURE_STORAGE_NATIVE regular=retired diagnostic=retained symlink=refused hardlink=refused\n' >&2

root=$workspace/acquisition-old-primitive
/usr/bin/mkdir -m 0700 -- "$root"
/usr/bin/mktemp -d "$root/run.XXXXXXXXXX" >/dev/null
/usr/bin/mktemp -d "$root/run.XXXXXXXXXX" >/dev/null
[ "$(/usr/bin/find "$root" -mindepth 1 -maxdepth 1 -name 'run.*' | /usr/bin/wc -l)" -eq 2 ]
printf 'ONLINE_FETCH_VM_RUN_ADMISSION_NATIVE_AB old_unguarded_mktemp=2 corrected_retained=refused corrected_concurrent=16 winners=1\n' >&2
success=1
