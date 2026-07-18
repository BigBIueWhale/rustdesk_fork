#!/usr/bin/env bash
set -euo pipefail
umask 077

[ "$#" -eq 1 ] || { echo "usage: smoke-server-stage.sh STAGE" >&2; exit 2; }
cd /work

readonly READY=/work/scripts/smoke-ready.sh
readonly PROCESS_GUARD=/work/scripts/smoke-process-guard.py
readonly SERVER_LAUNCHER=/work/target/smoke-server-launcher
readonly BIND_SHIM=/work/target/smoke-bind-loopback.so

SRV=
SRV_START=

start_server() {
  local executable=$1 log=$2
  [ "${executable#/}" != "$executable" ] || { echo "server executable must be absolute" >&2; return 1; }
  LD_PRELOAD="$BIND_SHIM" "$SERVER_LAUNCHER" "$executable" >"$log" 2>&1 &
  SRV=$!
  SRV_START=$($READY --identity "$SRV") || return 1
  "$PROCESS_GUARD" wait-server "$SRV" "$SRV_START" "$executable"
}

case "$1" in
  build)
    cargo build --features linux-pkg-config --bin rustdesk --example seed_password --example probe_client --example smoke_readiness --example pf_echo --example flood_probe --example mdwe_codec_probe --color never
    chmod 0755 target/debug/rustdesk
    cc -shared -fPIC -O2 -Wall -Wextra -Werror -o target/smoke-bind-loopback.so scripts/smoke-bind-loopback.c -ldl
    cc -O2 -Wall -Wextra -Werror -o target/smoke-server-launcher scripts/smoke-server-launcher.c
    ;;
  mdwe)
    ./target/debug/examples/mdwe_codec_probe
    echo "EXIT=0"
    ;;
  service-lifecycle-manual)
    [ ! -e /usr/bin/rustdesk ] && [ ! -L /usr/bin/rustdesk ] || {
      echo "manual lifecycle installed path already exists" >&2
      exit 1
    }
    install -o root -g root -m 0755 /work/target/debug/rustdesk /usr/bin/rustdesk
    bash --noprofile --norc /work/scripts/smoke-service-lifecycle.sh
    ;;
  service-pid-reuse)
    bash --noprofile --norc /work/scripts/smoke-service-pid-reuse.sh
    ;;
  debian-sysv-installed-lifecycle)
    bash --noprofile --norc /work/scripts/smoke-debian-sysv-lifecycle.sh
    ;;
  debian-openrc-native-lifecycle)
    bash --noprofile --norc /work/scripts/smoke-openrc-lifecycle.sh
    ;;
  sibling-docker-server)
    control=/sibling
    installed_server=/usr/bin/rustdesk
    [ -d "$control" ] && [ ! -L "$control" ] || {
      echo "sibling docker control directory is absent" >&2
      exit 1
    }
    export HOME=/tmp/rd-sibling
    mkdir -p "$HOME"
    [ ! -e "$installed_server" ] && [ ! -L "$installed_server" ] || {
      echo "sibling docker installed path already exists" >&2
      exit 1
    }
    install -o root -g root -m 0755 /work/target/debug/rustdesk "$installed_server"
    source_identity=$(stat -Lc '%d:%i' /work/target/debug/rustdesk)
    installed_identity=$(stat -Lc '%d:%i' "$installed_server")
    [ "$installed_identity" != "$source_identity" ] || {
      echo "sibling docker installed executable did not acquire a distinct file identity" >&2
      exit 1
    }
    source_sha256=$(sha256sum /work/target/debug/rustdesk | awk '{print $1}')
    [ "$(sha256sum "$installed_server" | awk '{print $1}')" = "$source_sha256" ]
    mount_namespace=$(stat -Lc %i /proc/self/ns/mnt)
    pid_namespace=$(stat -Lc %i /proc/self/ns/pid)
    service_generation=$(tr -d '\n' </proc/sys/kernel/random/uuid)
    sibling_cleanup() {
      status=$?
      trap - EXIT HUP INT TERM
      if [ -n "$SRV" ] && [ -n "$SRV_START" ] && "$READY" --is-running "$SRV" "$SRV_START" 2>/dev/null; then
        "$READY" --stop "$SRV" "$SRV_START" >/dev/null 2>&1 || true
        wait "$SRV" 2>/dev/null || true
      fi
      exit "$status"
    }
    trap sibling_cleanup EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM
    env -i HOME="$HOME" PATH=/usr/bin:/bin RUST_LOG=info \
      RUSTDESK_SERVICE_OWNED_SERVER_LAUNCH_PARENT="$$" \
      RUSTDESK_SERVICE_OWNED_SERVER_GENERATION="$service_generation" \
      setpriv --no-new-privs --inh-caps=-all --ambient-caps=-all --bounding-set=-all \
      "$SERVER_LAUNCHER" "$installed_server" --service-owned-server \
      >/tmp/sibling-docker.log 2>&1 &
    SRV=$!
    SRV_START=$($READY --identity "$SRV")
    "$PROCESS_GUARD" wait-service-server "$SRV" "$SRV_START" "$installed_server" \
      "$$" "$service_generation"
    "$READY" --wait-parked "$SRV" "$SRV_START" /tmp/sibling-docker.log /work/target/debug/examples/smoke_readiness 0
    printf 'SIBLING_DOCKER_READY pid=%s start=%s\n' "$SRV" "$SRV_START"
    printf 'SIBLING_CONTAINER_IDENTITY_READY pid=%s start=%s path=/usr/bin/rustdesk exe=%s source=%s sha256=%s mnt=%s pidns=%s generation=%s\n' \
      "$SRV" "$SRV_START" "$installed_identity" "$source_identity" "$source_sha256" \
      "$mount_namespace" "$pid_namespace" "$service_generation"
    (umask 022 && printf 'ready\n' >"$control/ready")
    while [ ! -e "$control/stop" ] && [ ! -L "$control/stop" ]; do
      "$READY" --hold-running "$SRV" "$SRV_START" /tmp/sibling-docker.log 1 "sibling docker stop poll"
    done
    [ -f "$control/stop" ] && [ ! -L "$control/stop" ]
    grep -Fxq stop "$control/stop"
    "$READY" --stop "$SRV" "$SRV_START"
    wait "$SRV"
    printf 'SIBLING_DOCKER_SURVIVED=pass pid=%s start=%s\n' "$SRV" "$SRV_START"
    printf 'SIBLING_CONTAINER_IDENTITY_SURVIVED=pass pid=%s start=%s path=/usr/bin/rustdesk exe=%s generation=%s\n' \
      "$SRV" "$SRV_START" "$installed_identity" "$service_generation"
    SRV=
    SRV_START=
    trap - EXIT HUP INT TERM
    ;;
  parked)
    export HOME=/tmp/rd1
    mkdir -p "$HOME"
    start_server /work/target/debug/rustdesk /tmp/srv1.log
    $READY --wait-parked "$SRV" "$SRV_START" /tmp/srv1.log /work/target/debug/examples/smoke_readiness 0
    echo "ALIVE=$($READY --is-running "$SRV" "$SRV_START" && echo yes || echo no)"
    echo "TCP_LISTEN=[$(awk '$4=="0A"{print $2}' /proc/net/tcp /proc/net/tcp6 2>/dev/null | tr '\n' ' ')]"
    grep -m1 "the direct listener is PARKED" /tmp/srv1.log || true
    grep -m1 "Direct server listening" /tmp/srv1.log || true
    $READY --stop "$SRV" "$SRV_START"
    wait "$SRV" 2>/dev/null || true
    ;;
  listen)
    export HOME=/tmp/rd2
    mkdir -p "$HOME"
    ./target/debug/examples/seed_password "Str0ng-Test-Pw-123" >/dev/null 2>&1 || { echo SEED_FAIL; exit 1; }
    start_server /work/target/debug/rustdesk /tmp/srv.log
    $READY --wait-server "$SRV" "$SRV_START" /tmp/srv.log /work/target/debug/examples/smoke_readiness 0
    echo "TCP_LISTEN=[$(awk '$4=="0A"{print $2}' /proc/net/tcp /proc/net/tcp6 2>/dev/null | tr '\n' ' ')]"
    echo "UDP_COUNT=$(( $(tail -n +2 /proc/net/udp 2>/dev/null | wc -l) + $(tail -n +2 /proc/net/udp6 2>/dev/null | wc -l) ))"
    grep -m1 "Direct server listening" /tmp/srv.log || true
    grep -m1 "socket surface verified" /tmp/srv.log || true
    $READY --terminate-server "$SRV" "$SRV_START" /tmp/srv.log
    wait "$SRV"
    grep "R-T9: graceful shutdown complete" /tmp/srv.log || true
    ;;
  password-root)
    export HOME=/tmp/rd2b
    mkdir -p "$HOME"
    ./target/debug/examples/seed_password "Initial-Seed-Pw-000" >/dev/null 2>&1 || { echo SEED_FAIL; exit 1; }
    start_server /work/target/debug/rustdesk /tmp/srv.log
    $READY --wait-user-server "$SRV" "$SRV_START" /tmp/srv.log /work/target/debug/examples/smoke_readiness 0
    RECOVERY_SECONDS=$(./target/debug/examples/smoke_readiness password-recovery-seconds)
    [ "$RECOVERY_SECONDS" = 600 ]
    if PW_OUT=$(timeout --signal=TERM --kill-after=5s "$((RECOVERY_SECONDS + 60))" ./target/debug/rustdesk --password-stdin <<<"Changed-Via-Ipc-Pw-9" 2>&1); then
      PW_EXIT=0
    else
      PW_EXIT=$?
    fi
    echo "PW_EXIT=$PW_EXIT"
    echo "PW_OUT=[$PW_OUT]"
    [ "$PW_EXIT" = 0 ] || exit "$PW_EXIT"
    KEYED_NEW_OUT=$(./target/debug/examples/probe_client "127.0.0.1:21118" "Changed-Via-Ipc-Pw-9" ok 2>&1)
    printf '%s\n' "$KEYED_NEW_OUT"
    echo "KEYED_NEW: $(grep -oE 'keying ok=(true|false)' <<<"$KEYED_NEW_OUT")"
    KEYED_OLD_OUT=$(./target/debug/examples/probe_client "127.0.0.1:21118" "Initial-Seed-Pw-000" fail 2>&1)
    printf '%s\n' "$KEYED_OLD_OUT"
    echo "KEYED_OLD: $(grep -oE 'keying ok=(true|false)' <<<"$KEYED_OLD_OUT")"
    $READY --terminate-server "$SRV" "$SRV_START" /tmp/srv.log
    wait "$SRV"
    ;;
  password-nonroot)
    id -u rduser >/dev/null 2>&1 || useradd -m -u 4000 rduser
    [ "$(id -u rduser)" = 4000 ]
    gid=$(id -g rduser)
    fixture=/tmp/rd-smoke-nonroot
    source_meta=$(stat -c '%d:%i:%u:%g:%a' /work)
    source_hash=$(sha256sum /work/target/debug/rustdesk /work/target/debug/examples/seed_password /work/target/debug/examples/probe_client /work/target/debug/examples/smoke_readiness /work/target/smoke-bind-loopback.so /work/target/smoke-server-launcher /work/scripts/smoke-ready.sh /work/scripts/smoke-process-guard.py /work/scripts/smoke-server-stage.sh)
    install -d -o root -g "$gid" -m 0750 "$fixture" "$fixture/bin"
    install -d -o rduser -g "$gid" -m 0700 "$fixture/home"
    install -o root -g "$gid" -m 0550 target/debug/rustdesk "$fixture/bin/rustdesk"
    install -o root -g "$gid" -m 0550 target/debug/examples/seed_password "$fixture/bin/seed_password"
    install -o root -g "$gid" -m 0550 target/debug/examples/probe_client "$fixture/bin/probe_client"
    install -o root -g "$gid" -m 0550 target/debug/examples/smoke_readiness "$fixture/bin/smoke_readiness"
    install -o root -g "$gid" -m 0440 target/smoke-bind-loopback.so "$fixture/bin/smoke-bind-loopback.so"
    install -o root -g "$gid" -m 0550 target/smoke-server-launcher "$fixture/bin/smoke-server-launcher"
    install -o root -g "$gid" -m 0550 scripts/smoke-ready.sh "$fixture/bin/smoke-ready.sh"
    install -o root -g "$gid" -m 0550 scripts/smoke-process-guard.py "$fixture/bin/smoke-process-guard.py"
    cat > "$fixture/run.sh" <<'EOS'
#!/bin/bash
set -euo pipefail
export HOME=/tmp/rd-smoke-nonroot/home
cd "$HOME"
bin=/tmp/rd-smoke-nonroot/bin
echo "UID=$(id -u)"
"$bin/seed_password" Initial-Seed-Pw-000 >/dev/null 2>&1 || { echo SEED_FAIL; exit 1; }
SRV=
SRV_START=
cleanup_server() {
  status=$?
  trap - EXIT
  cleanup_status=0
  if [ -n "$SRV" ] && [ -n "$SRV_START" ] && "$bin/smoke-ready.sh" --is-running "$SRV" "$SRV_START"; then
    "$bin/smoke-ready.sh" --stop "$SRV" "$SRV_START" || cleanup_status=$?
    wait "$SRV" 2>/dev/null || true
  fi
  if [ "$cleanup_status" -ne 0 ]; then
    echo "NONROOT_SERVER_CLEANUP_EXIT=$cleanup_status" >&2
  fi
  exit "$status"
}
trap cleanup_server EXIT
LD_PRELOAD="$bin/smoke-bind-loopback.so" "$bin/smoke-server-launcher" "$bin/rustdesk" >srv2c.log 2>&1 &
SRV=$!
SRV_START=$("$bin/smoke-ready.sh" --identity "$SRV") || exit 1
"$bin/smoke-process-guard.py" wait-server "$SRV" "$SRV_START" "$bin/rustdesk"
"$bin/smoke-ready.sh" --wait-user-server "$SRV" "$SRV_START" "$HOME/srv2c.log" "$bin/smoke_readiness" 4000
server_exe=$(readlink -f "/proc/$SRV/exe")
echo "SERVER_UID=$(awk '/^Uid:/{print $2}' "/proc/$SRV/status")"
echo "PORTABLE_EXE=$server_exe"
[ "$server_exe" = "$bin/rustdesk" ]
if grep -zFxq -- --service-owned-server "/proc/$SRV/cmdline"; then exit 1; fi
echo "SERVICE_ROLE_MARKER=absent"
RECOVERY_SECONDS=$("$bin/smoke_readiness" password-recovery-seconds)
[ "$RECOVERY_SECONDS" = 600 ]
if PW_OUT=$(timeout --signal=TERM --kill-after=5s "$((RECOVERY_SECONDS + 60))" "$bin/rustdesk" --password-stdin <<<"Changed-Same-Uid-Pw-9" 2>&1); then
  PW_EXIT=0
else
  PW_EXIT=$?
fi
echo "PW_EXIT=$PW_EXIT"
echo "PW_OUT=[$PW_OUT]"
[ "$PW_EXIT" = 0 ] || exit "$PW_EXIT"
KEYED_NEW_OUT=$("$bin/probe_client" 127.0.0.1:21118 Changed-Same-Uid-Pw-9 ok 2>&1)
printf '%s\n' "$KEYED_NEW_OUT"
echo "KEYED_NEW: $(grep -oE 'keying ok=(true|false)' <<<"$KEYED_NEW_OUT")"
KEYED_OLD_OUT=$("$bin/probe_client" 127.0.0.1:21118 Initial-Seed-Pw-000 fail 2>&1)
printf '%s\n' "$KEYED_OLD_OUT"
echo "KEYED_OLD: $(grep -oE 'keying ok=(true|false)' <<<"$KEYED_OLD_OUT")"
"$bin/smoke-ready.sh" --terminate-server "$SRV" "$SRV_START" "$HOME/srv2c.log"
wait "$SRV"
echo "SERVER_EXIT=$?"
SRV=
SRV_START=
EOS
    chown root:"$gid" "$fixture/run.sh"
    chmod 0550 "$fixture/run.sh"
    cd /tmp
    su -s /bin/bash -c /tmp/rd-smoke-nonroot/run.sh rduser
    [ "$source_meta" = "$(stat -c '%d:%i:%u:%g:%a' /work)" ]
    [ "$source_hash" = "$(sha256sum /work/target/debug/rustdesk /work/target/debug/examples/seed_password /work/target/debug/examples/probe_client /work/target/debug/examples/smoke_readiness /work/target/smoke-bind-loopback.so /work/target/smoke-server-launcher /work/scripts/smoke-ready.sh /work/scripts/smoke-process-guard.py /work/scripts/smoke-server-stage.sh)" ]
    echo SOURCE_BIND_UNCHANGED=yes
    ;;
  password-installed)
    export HOME=/tmp/rd2d
    mkdir -p "$HOME"
    install -D ./target/debug/rustdesk /usr/share/rustdesk/rustdesk
    ./target/debug/examples/seed_password "Installed-Initial-Pw-0" >/dev/null 2>&1 || { echo SEED_FAIL; exit 1; }
    start_server /usr/share/rustdesk/rustdesk /tmp/srv2d.log
    $READY --wait-server "$SRV" "$SRV_START" /tmp/srv2d.log /work/target/debug/examples/smoke_readiness 0
    RECOVERY_SECONDS=$(./target/debug/examples/smoke_readiness password-recovery-seconds)
    [ "$RECOVERY_SECONDS" = 600 ]
    if timeout --signal=TERM --kill-after=5s "$((RECOVERY_SECONDS + 60))" /usr/share/rustdesk/rustdesk --password-stdin <<<"Installed-Fallback-Must-Fail-9" >/tmp/pw2d.out 2>&1; then
      PW_EXIT=0
    else
      PW_EXIT=$?
    fi
    echo "PW_EXIT=$PW_EXIT"
    echo "PW_OUT=[$(tr -d '\n' </tmp/pw2d.out)]"
    [ "$PW_EXIT" = 1 ]
    KEYED_NEW_OUT=$(./target/debug/examples/probe_client 127.0.0.1:21118 Installed-Fallback-Must-Fail-9 fail 2>&1)
    printf '%s\n' "$KEYED_NEW_OUT"
    echo "KEYED_NEW: $(grep -oE 'keying ok=(true|false)' <<<"$KEYED_NEW_OUT")"
    KEYED_OLD_OUT=$(./target/debug/examples/probe_client 127.0.0.1:21118 Installed-Initial-Pw-0 ok 2>&1)
    printf '%s\n' "$KEYED_OLD_OUT"
    echo "KEYED_OLD: $(grep -oE 'keying ok=(true|false)' <<<"$KEYED_OLD_OUT")"
    $READY --terminate-server "$SRV" "$SRV_START" /tmp/srv2d.log
    wait "$SRV"
    ;;
  keying)
    export HOME=/tmp/rd3
    mkdir -p "$HOME"
    ./target/debug/examples/seed_password "Str0ng-Test-Pw-123" >/dev/null 2>&1 || { echo SEED_FAIL; exit 1; }
    start_server /work/target/debug/rustdesk /tmp/srv.log
    $READY --wait-server "$SRV" "$SRV_START" /tmp/srv.log /work/target/debug/examples/smoke_readiness 0
    echo "CORRECT: $(./target/debug/examples/probe_client '127.0.0.1:21118' 'Str0ng-Test-Pw-123' ok)"
    echo "WRONG:   $(./target/debug/examples/probe_client '127.0.0.1:21118' 'WRONG-Password-xyz' fail)"
    $READY --wait-key-failure "$SRV" "$SRV_START" /tmp/srv.log
    grep -m1 "security summary" /tmp/srv.log || true
    $READY --terminate-server "$SRV" "$SRV_START" /tmp/srv.log
    wait "$SRV"
    ;;
  flood)
    export HOME=/tmp/rd4
    mkdir -p "$HOME"
    ./target/debug/examples/seed_password "Str0ng-Test-Pw-123" >/dev/null 2>&1 || { echo SEED_FAIL; exit 1; }
    start_server /work/target/debug/rustdesk /tmp/srv.log
    $READY --wait-server "$SRV" "$SRV_START" /tmp/srv.log /work/target/debug/examples/smoke_readiness 0
    ./target/debug/examples/flood_probe "127.0.0.1:21118" 300 >/dev/null 2>&1 & FLOOD=$!
    FLOOD_START=$($READY --identity "$FLOOD")
    $READY --wait-capacity-shed "$SRV" "$SRV_START" /tmp/srv.log
    grep -m1 "security summary.*shed=" /tmp/srv.log || echo "(no shed summary)"
    if $READY --is-running "$FLOOD" "$FLOOD_START"; then
      $READY --stop "$FLOOD" "$FLOOD_START"
    fi
    wait "$FLOOD" 2>/dev/null || true
    $READY --terminate-server "$SRV" "$SRV_START" /tmp/srv.log
    wait "$SRV"
    ;;
  full-session)
    export HOME=/tmp/rd6
    mkdir -p "$HOME"
    ./target/debug/examples/seed_password "Str0ng-Test-Pw-123" >/dev/null 2>&1 || { echo SEED_FAIL; exit 1; }
    start_server /work/target/debug/rustdesk /tmp/srv.log
    $READY --wait-server "$SRV" "$SRV_START" /tmp/srv.log /work/target/debug/examples/smoke_readiness 0
    ./target/debug/examples/probe_client "127.0.0.1:21118" "Str0ng-Test-Pw-123" ok login 2>&1
    $READY --terminate-server "$SRV" "$SRV_START" /tmp/srv.log
    wait "$SRV"
    ;;
  port-forward)
    export HOME=/tmp/rd6b
    mkdir -p "$HOME"
    ./target/debug/examples/seed_password "Str0ng-Test-Pw-123" >/dev/null 2>&1 || { echo SEED_FAIL; exit 1; }
    start_server /work/target/debug/rustdesk /tmp/srv.log
    $READY --wait-server "$SRV" "$SRV_START" /tmp/srv.log /work/target/debug/examples/smoke_readiness 0
    ./target/debug/examples/pf_echo 5555 >/tmp/pf_echo.log 2>&1 & ECHO=$!
    ECHO_START=$($READY --identity "$ECHO")
    $READY --wait-tcp-listener "$ECHO" "$ECHO_START" /tmp/pf_echo.log 0100007F:15B3 "port-forward echo listener"
    PF_TARGET=127.0.0.1:5555 ./target/debug/examples/probe_client "127.0.0.1:21118" "Str0ng-Test-Pw-123" ok portforward 2>&1
    $READY --stop "$ECHO" "$ECHO_START"
    wait "$ECHO" 2>/dev/null || true
    $READY --terminate-server "$SRV" "$SRV_START" /tmp/srv.log
    wait "$SRV"
    ;;
  file-transfer)
    export HOME=/tmp/rd6c
    mkdir -p "$HOME"
    ./target/debug/examples/seed_password "Str0ng-Test-Pw-123" >/dev/null 2>&1 || { echo SEED_FAIL; exit 1; }
    start_server /work/target/debug/rustdesk /tmp/srv.log
    $READY --wait-server "$SRV" "$SRV_START" /tmp/srv.log /work/target/debug/examples/smoke_readiness 0
    ./target/debug/examples/probe_client "127.0.0.1:21118" "Str0ng-Test-Pw-123" ok filetransfer 2>&1
    $READY --terminate-server "$SRV" "$SRV_START" /tmp/srv.log
    wait "$SRV"
    ;;
  inject)
    export HOME=/tmp/rd7
    mkdir -p "$HOME"
    ./target/debug/examples/seed_password "Str0ng-Test-Pw-123" >/dev/null 2>&1 || { echo SEED_FAIL; exit 1; }
    start_server /work/target/debug/rustdesk /tmp/srv.log
    $READY --wait-server "$SRV" "$SRV_START" /tmp/srv.log /work/target/debug/examples/smoke_readiness 0
    INJECT_OUT=$(./target/debug/examples/probe_client "127.0.0.1:21118" "Str0ng-Test-Pw-123" ok inject 2>&1)
    printf '%s\n' "$INJECT_OUT"
    $READY --wait-log "$SRV" "$SRV_START" /tmp/srv.log "Connection closed: decryption error" "forged-frame rejection"
    grep -m1 "Connection closed: decryption error" /tmp/srv.log || echo "(no decryption-error close)"
    $READY --terminate-server "$SRV" "$SRV_START" /tmp/srv.log
    wait "$SRV"
    ;;
  limiter)
    export HOME=/tmp/rd8
    mkdir -p "$HOME"
    ./target/debug/examples/seed_password "Str0ng-Test-Pw-123" >/dev/null 2>&1 || { echo SEED_FAIL; exit 1; }
    start_server /work/target/debug/rustdesk /tmp/srv.log
    $READY --wait-server "$SRV" "$SRV_START" /tmp/srv.log /work/target/debug/examples/smoke_readiness 0
    for i in $(seq 11); do ./target/debug/examples/probe_client "127.0.0.1:21118" "WRONG-PW-$i-zz" fail >/dev/null 2>&1; done
    OWNER_OUT=$(./target/debug/examples/probe_client "127.0.0.1:21118" "Str0ng-Test-Pw-123" ok "" "127.0.0.2:0" 2>&1)
    printf '%s\n' "$OWNER_OUT"
    echo "OWNER_DIFF_SRC: $(grep -oE 'keying ok=(true|false)' <<<"$OWNER_OUT")"
    FLOODER_OUT=$(./target/debug/examples/probe_client "127.0.0.1:21118" "Str0ng-Test-Pw-123" fail 2>&1)
    printf '%s\n' "$FLOODER_OUT"
    echo "FLOODER_SAME_SRC: $(grep -oE 'keying ok=(true|false)' <<<"$FLOODER_OUT")"
    $READY --terminate-server "$SRV" "$SRV_START" /tmp/srv.log
    wait "$SRV"
    ;;
  capture)
    if ! command -v tcpdump >/dev/null; then
      apt-get update -q >/dev/null 2>&1
      apt-get install -y -q tcpdump >/dev/null 2>&1
    fi
    command -v tcpdump >/dev/null
    export HOME=/tmp/rd9
    mkdir -p "$HOME"
    ./target/debug/examples/seed_password "Str0ng-Test-Pw-123" >/dev/null 2>&1 || { echo SEED_FAIL; exit 1; }
    start_server /work/target/debug/rustdesk /tmp/srv.log
    $READY --wait-server "$SRV" "$SRV_START" /tmp/srv.log /work/target/debug/examples/smoke_readiness 0
    tcpdump -U -i lo -w /tmp/cap.pcap "tcp port 21118" >/tmp/tcpdump.log 2>&1 & TCPD=$!
    TCPD_START=$($READY --identity "$TCPD")
    $READY --wait-log "$TCPD" "$TCPD_START" /tmp/tcpdump.log "listening on lo" "tcpdump capture readiness"
    LOGIN_OUT=$(./target/debug/examples/probe_client "127.0.0.1:21118" "Str0ng-Test-Pw-123" ok login 2>&1)
    printf '%s\n' "$LOGIN_OUT"
    $READY --interrupt "$TCPD" "$TCPD_START"
    wait "$TCPD"
    echo "PCAP_SIZE: $(wc -c < /tmp/cap.pcap 2>/dev/null || echo 0)"
    echo "CANARY_IN_BINARY: $(grep -a -c PLAINTEXT-CANARY-DEADBEEF ./target/debug/examples/probe_client)"
    grep -a -q "PLAINTEXT-CANARY-DEADBEEF" /tmp/cap.pcap 2>/dev/null && echo "CANARY_ON_WIRE: YES" || echo "CANARY_ON_WIRE: NO"
    $READY --terminate-server "$SRV" "$SRV_START" /tmp/srv.log
    wait "$SRV"
    ;;
  decay)
    export HOME=/tmp/rd10
    mkdir -p "$HOME"
    ./target/debug/examples/seed_password "Str0ng-Test-Pw-123" >/dev/null 2>&1 || { echo SEED_FAIL; exit 1; }
    start_server /work/target/debug/rustdesk /tmp/srv.log
    $READY --wait-server "$SRV" "$SRV_START" /tmp/srv.log /work/target/debug/examples/smoke_readiness 0
    for i in $(seq 11); do ./target/debug/examples/probe_client "127.0.0.1:21118" "WRONG-PW-$i-zz" fail >/dev/null 2>&1; done
    BLOCKED_OUT=$(./target/debug/examples/probe_client "127.0.0.1:21118" "Str0ng-Test-Pw-123" fail 2>&1)
    printf '%s\n' "$BLOCKED_OUT"
    echo "BLOCKED_NOW: $(grep -oE 'keying ok=(true|false)' <<<"$BLOCKED_OUT")"
    echo "(holding the exact server identity for 64s so the 60s GUESS_WINDOW lapses...)"
    $READY --hold-running "$SRV" "$SRV_START" /tmp/srv.log 64 "limiter-decay interval"
    DECAYED_OUT=$(./target/debug/examples/probe_client "127.0.0.1:21118" "Str0ng-Test-Pw-123" ok 2>&1)
    printf '%s\n' "$DECAYED_OUT"
    echo "DECAYED_AFTER_WINDOW: $(grep -oE 'keying ok=(true|false)' <<<"$DECAYED_OUT")"
    $READY --terminate-server "$SRV" "$SRV_START" /tmp/srv.log
    wait "$SRV"
    ;;
  *)
    echo "unknown smoke stage: $1" >&2
    exit 2
    ;;
esac
