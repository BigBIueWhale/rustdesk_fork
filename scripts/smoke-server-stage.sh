#!/usr/bin/env bash
set -euo pipefail
umask 077

[ "$#" -eq 1 ] || { echo "usage: smoke-server-stage.sh STAGE" >&2; exit 2; }
cd /work

readonly READY=/work/scripts/smoke-ready.sh
readonly PROCESS_GUARD=/work/scripts/smoke-process-guard.py
readonly SERVER_LAUNCHER=/smoke-target/smoke-server-launcher
readonly BIND_SHIM=/smoke-target/smoke-bind-loopback.so
readonly CARGO_VENDOR_DIR=/online/cargo-vendor
readonly CARGO_VENDOR_CONFIG=/online/cargo-vendor-config.toml
readonly CARGO_VENDOR_PROVENANCE=/work/scripts/online-input-provenance.py

SRV=
SRV_START=

smoke_build_input_die() {
  echo "smoke build: $*" >&2
  return 1
}

verify_smoke_build_inputs() {
  local actual_config_sha
  [[ "${SMOKE_EXPECTED_VENDOR_CLOSURE_SHA256:-}" =~ ^[0-9a-f]{64}$ ]] \
    || smoke_build_input_die "missing or malformed Cargo vendor closure pin" || return 1
  [[ "${SMOKE_EXPECTED_VENDOR_CONFIG_SHA256:-}" =~ ^[0-9a-f]{64}$ ]] \
    || smoke_build_input_die "missing or malformed Cargo vendor config pin" || return 1
  [ -d "$CARGO_VENDOR_DIR" ] && [ ! -L "$CARGO_VENDOR_DIR" ] \
    || smoke_build_input_die "sealed Cargo vendor directory is unavailable" || return 1
  [ -f "$CARGO_VENDOR_CONFIG" ] && [ ! -L "$CARGO_VENDOR_CONFIG" ] \
    || smoke_build_input_die "canonical Cargo vendor config is unavailable" || return 1
  [ -f "$CARGO_VENDOR_PROVENANCE" ] && [ ! -L "$CARGO_VENDOR_PROVENANCE" ] \
    || smoke_build_input_die "Cargo vendor provenance verifier is unavailable" || return 1
  actual_config_sha=$(/usr/bin/sha256sum -- "$CARGO_VENDOR_CONFIG" | /usr/bin/awk '{print $1}')
  [ "$actual_config_sha" = "$SMOKE_EXPECTED_VENDOR_CONFIG_SHA256" ] \
    || smoke_build_input_die "canonical Cargo vendor config differs from its pin" || return 1
  /usr/bin/python3 -I -S "$CARGO_VENDOR_PROVENANCE" verify-subtree \
    --tree "$CARGO_VENDOR_DIR" --expected "$SMOKE_EXPECTED_VENDOR_CLOSURE_SHA256" \
    || smoke_build_input_die "sealed Cargo vendor tree differs from its pin"
}

prepare_smoke_cargo_home() {
  [ "${CARGO_HOME:-}" = /tmp/smoke-cargo-home ] \
    || smoke_build_input_die "CARGO_HOME is not the private smoke path" || return 1
  [ "${CARGO_TARGET_DIR:-}" = /smoke-target ] \
    || smoke_build_input_die "CARGO_TARGET_DIR is not the private mounted target" || return 1
  [ "${CARGO_NET_OFFLINE:-}" = true ] && [ "${CARGO_NET_RETRY:-}" = 0 ] \
    || smoke_build_input_die "Cargo network refusal is incomplete" || return 1
  [ "${CARGO_INCREMENTAL:-}" = 0 ] \
    || smoke_build_input_die "incremental compilation must be disabled" || return 1
  [ "${RUSTUP_TOOLCHAIN:-}" = "${SMOKE_EXPECTED_RUSTUP_TOOLCHAIN:-}" ] \
    && [[ "$RUSTUP_TOOLCHAIN" =~ ^[0-9]+\.[0-9]+\.0-x86_64-unknown-linux-gnu$ ]] \
    || smoke_build_input_die "Rustup toolchain is not the exact smoke pin" || return 1
  [ ! -e "$CARGO_HOME" ] && [ ! -L "$CARGO_HOME" ] \
    || smoke_build_input_die "private Cargo home already exists" || return 1
  /usr/bin/install -d -m 0700 -- "$CARGO_HOME"
  {
    printf '[net]\noffline = true\n'
    /usr/bin/sed 's#^directory = .*$#directory = "/online/cargo-vendor"#' "$CARGO_VENDOR_CONFIG"
  } > "$CARGO_HOME/config.toml"
  /usr/bin/chmod 0400 -- "$CARGO_HOME/config.toml"
  [ "$(/usr/bin/grep -c '^directory = "/online/cargo-vendor"$' "$CARGO_HOME/config.toml")" -eq 1 ] \
    || smoke_build_input_die "private Cargo source map has invalid vendor-directory cardinality" || return 1
  [ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$CARGO_HOME/config.toml")" = "$(/usr/bin/id -u):$(/usr/bin/id -g):400:1" ] \
    || smoke_build_input_die "private Cargo source map metadata is invalid" || return 1
  SMOKE_CARGO_CONFIG_SHA256=$(/usr/bin/sha256sum -- "$CARGO_HOME/config.toml" | /usr/bin/awk '{print $1}')
  readonly SMOKE_CARGO_CONFIG_SHA256
}

verify_smoke_build_postconditions() {
  verify_smoke_build_inputs || return 1
  [ "$(/usr/bin/sha256sum -- "$CARGO_HOME/config.toml" | /usr/bin/awk '{print $1}')" = "$SMOKE_CARGO_CONFIG_SHA256" ] \
    || smoke_build_input_die "private Cargo source map changed during compilation" || return 1
  [ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$CARGO_HOME/config.toml")" = "$(/usr/bin/id -u):$(/usr/bin/id -g):400:1" ] \
    || smoke_build_input_die "private Cargo source map metadata changed during compilation"
}

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
    verify_smoke_build_inputs
    prepare_smoke_cargo_home
    cargo build --locked --offline --features linux-pkg-config --bin rustdesk --example seed_password --example probe_client --example smoke_readiness --example pf_echo --example flood_probe --example mdwe_codec_probe --example video_pipeline_probe --color never
    cargo test --locked --offline --features linux-pkg-config --example video_pipeline_probe --color never
    cargo test --locked --offline --features linux-pkg-config --lib --no-run --color never
    mapfile -t viewer_pipeline_test_artifacts < <(
      find /smoke-target/debug/deps -maxdepth 1 -type f -name 'librustdesk-*' -perm -u+x -print
    )
    [ "${#viewer_pipeline_test_artifacts[@]}" -eq 1 ] || {
      echo "smoke build: expected one exact librustdesk test executable, found ${#viewer_pipeline_test_artifacts[@]}" >&2
      exit 1
    }
    [ ! -e /smoke-target/production-viewer-pipeline-tests ] \
      && [ ! -L /smoke-target/production-viewer-pipeline-tests ] || {
      echo "smoke build: fixed production viewer test artifact already exists" >&2
      exit 1
    }
    /usr/bin/install -m 0555 -- "${viewer_pipeline_test_artifacts[0]}" \
      /smoke-target/production-viewer-pipeline-tests
    [ "$(stat -c '%u:%g:%a:%h' -- /smoke-target/production-viewer-pipeline-tests)" \
      = "$(id -u):$(id -g):555:1" ]
    printf 'PRODUCTION_VIEWER_TEST_ARTIFACT sha256=%s\n' \
      "$(sha256sum /smoke-target/production-viewer-pipeline-tests | awk '{print $1}')"
    verify_smoke_build_postconditions
    chmod 0755 /smoke-target/debug/rustdesk
    cc -shared -fPIC -O2 -Wall -Wextra -Werror -o /smoke-target/smoke-bind-loopback.so scripts/smoke-bind-loopback.c -ldl
    cc -O2 -Wall -Wextra -Werror -o /smoke-target/smoke-server-launcher scripts/smoke-server-launcher.c
    cc -O2 -Wall -Wextra -Werror -o /smoke-target/smoke-x11-motion scripts/smoke-x11-motion.c -lX11
    ;;
  mdwe)
    /smoke-target/debug/examples/mdwe_codec_probe
    echo "EXIT=0"
    ;;
  service-lifecycle-manual)
    [ ! -e /usr/bin/rustdesk ] && [ ! -L /usr/bin/rustdesk ] || {
      echo "manual lifecycle installed path already exists" >&2
      exit 1
    }
    install -o root -g root -m 0711 /smoke-target/debug/rustdesk /usr/bin/rustdesk
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
  debian-runit-native-lifecycle)
    bash --noprofile --norc /work/scripts/smoke-runit-lifecycle.sh
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
    install -o root -g root -m 0711 /smoke-target/debug/rustdesk "$installed_server"
    source_identity=$(stat -Lc '%d:%i' /smoke-target/debug/rustdesk)
    installed_identity=$(stat -Lc '%d:%i' "$installed_server")
    [ "$installed_identity" != "$source_identity" ] || {
      echo "sibling docker installed executable did not acquire a distinct file identity" >&2
      exit 1
    }
    source_sha256=$(sha256sum /smoke-target/debug/rustdesk | awk '{print $1}')
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
      RD_SERVICE_SMOKE_UNSUPERVISED_RECOVERY_FIXTURE=1 \
      setpriv --no-new-privs --inh-caps=-all --ambient-caps=-all --bounding-set=-all \
      "$SERVER_LAUNCHER" "$installed_server" --service-owned-server \
      >/tmp/sibling-docker.log 2>&1 &
    SRV=$!
    SRV_START=$($READY --identity "$SRV")
    "$PROCESS_GUARD" wait-service-server "$SRV" "$SRV_START" "$installed_server" \
      "$$" "$service_generation"
    "$READY" --wait-parked "$SRV" "$SRV_START" /tmp/sibling-docker.log /smoke-target/debug/examples/smoke_readiness "$(id -u)"
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
    start_server /smoke-target/debug/rustdesk /tmp/srv1.log
    $READY --wait-parked "$SRV" "$SRV_START" /tmp/srv1.log /smoke-target/debug/examples/smoke_readiness "$(id -u)"
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
    /smoke-target/debug/examples/seed_password "Str0ng-Test-Pw-123" >/dev/null 2>&1 || { echo SEED_FAIL; exit 1; }
    start_server /smoke-target/debug/rustdesk /tmp/srv.log
    $READY --wait-server "$SRV" "$SRV_START" /tmp/srv.log /smoke-target/debug/examples/smoke_readiness "$(id -u)"
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
    /smoke-target/debug/examples/seed_password "Initial-Seed-Pw-000" >/dev/null 2>&1 || { echo SEED_FAIL; exit 1; }
    start_server /smoke-target/debug/rustdesk /tmp/srv.log
    $READY --wait-user-server "$SRV" "$SRV_START" /tmp/srv.log /smoke-target/debug/examples/smoke_readiness "$(id -u)"
    RECOVERY_SECONDS=$(/smoke-target/debug/examples/smoke_readiness password-recovery-seconds)
    [ "$RECOVERY_SECONDS" = 600 ]
    if PW_OUT=$(timeout --signal=TERM --kill-after=5s "$((RECOVERY_SECONDS + 60))" /smoke-target/debug/rustdesk --password-stdin <<<"Changed-Via-Ipc-Pw-9" 2>&1); then
      PW_EXIT=0
    else
      PW_EXIT=$?
    fi
    echo "PW_EXIT=$PW_EXIT"
    echo "PW_OUT=[$PW_OUT]"
    [ "$PW_EXIT" = 0 ] || exit "$PW_EXIT"
    KEYED_NEW_OUT=$(/smoke-target/debug/examples/probe_client "127.0.0.1:21118" "Changed-Via-Ipc-Pw-9" ok 2>&1)
    printf '%s\n' "$KEYED_NEW_OUT"
    echo "KEYED_NEW: $(grep -oE 'keying ok=(true|false)' <<<"$KEYED_NEW_OUT")"
    KEYED_OLD_OUT=$(/smoke-target/debug/examples/probe_client "127.0.0.1:21118" "Initial-Seed-Pw-000" fail 2>&1)
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
    source_hash=$(sha256sum /smoke-target/debug/rustdesk /smoke-target/debug/examples/seed_password /smoke-target/debug/examples/probe_client /smoke-target/debug/examples/smoke_readiness /smoke-target/smoke-bind-loopback.so /smoke-target/smoke-server-launcher /work/scripts/smoke-ready.sh /work/scripts/smoke-process-guard.py /work/scripts/smoke-server-stage.sh)
    install -d -o root -g "$gid" -m 0750 "$fixture" "$fixture/bin"
    install -d -o rduser -g "$gid" -m 0700 "$fixture/home"
    install -o root -g "$gid" -m 0550 /smoke-target/debug/rustdesk "$fixture/bin/rustdesk"
    install -o root -g "$gid" -m 0550 /smoke-target/debug/examples/seed_password "$fixture/bin/seed_password"
    install -o root -g "$gid" -m 0550 /smoke-target/debug/examples/probe_client "$fixture/bin/probe_client"
    install -o root -g "$gid" -m 0550 /smoke-target/debug/examples/smoke_readiness "$fixture/bin/smoke_readiness"
    install -o root -g "$gid" -m 0440 /smoke-target/smoke-bind-loopback.so "$fixture/bin/smoke-bind-loopback.so"
    install -o root -g "$gid" -m 0550 /smoke-target/smoke-server-launcher "$fixture/bin/smoke-server-launcher"
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
    [ "$source_hash" = "$(sha256sum /smoke-target/debug/rustdesk /smoke-target/debug/examples/seed_password /smoke-target/debug/examples/probe_client /smoke-target/debug/examples/smoke_readiness /smoke-target/smoke-bind-loopback.so /smoke-target/smoke-server-launcher /work/scripts/smoke-ready.sh /work/scripts/smoke-process-guard.py /work/scripts/smoke-server-stage.sh)" ]
    echo SOURCE_BIND_UNCHANGED=yes
    ;;
  password-installed)
    export HOME=/tmp/rd2d
    mkdir -p "$HOME"
    install -D /smoke-target/debug/rustdesk /usr/share/rustdesk/rustdesk
    /smoke-target/debug/examples/seed_password "Installed-Initial-Pw-0" >/dev/null 2>&1 || { echo SEED_FAIL; exit 1; }
    start_server /usr/share/rustdesk/rustdesk /tmp/srv2d.log
    $READY --wait-server "$SRV" "$SRV_START" /tmp/srv2d.log /smoke-target/debug/examples/smoke_readiness "$(id -u)"
    RECOVERY_SECONDS=$(/smoke-target/debug/examples/smoke_readiness password-recovery-seconds)
    [ "$RECOVERY_SECONDS" = 600 ]
    if timeout --signal=TERM --kill-after=5s "$((RECOVERY_SECONDS + 60))" /usr/share/rustdesk/rustdesk --password-stdin <<<"Installed-Fallback-Must-Fail-9" >/tmp/pw2d.out 2>&1; then
      PW_EXIT=0
    else
      PW_EXIT=$?
    fi
    echo "PW_EXIT=$PW_EXIT"
    echo "PW_OUT=[$(tr -d '\n' </tmp/pw2d.out)]"
    [ "$PW_EXIT" = 1 ]
    KEYED_NEW_OUT=$(/smoke-target/debug/examples/probe_client 127.0.0.1:21118 Installed-Fallback-Must-Fail-9 fail 2>&1)
    printf '%s\n' "$KEYED_NEW_OUT"
    echo "KEYED_NEW: $(grep -oE 'keying ok=(true|false)' <<<"$KEYED_NEW_OUT")"
    KEYED_OLD_OUT=$(/smoke-target/debug/examples/probe_client 127.0.0.1:21118 Installed-Initial-Pw-0 ok 2>&1)
    printf '%s\n' "$KEYED_OLD_OUT"
    echo "KEYED_OLD: $(grep -oE 'keying ok=(true|false)' <<<"$KEYED_OLD_OUT")"
    $READY --terminate-server "$SRV" "$SRV_START" /tmp/srv2d.log
    wait "$SRV"
    ;;
  keying)
    export HOME=/tmp/rd3
    mkdir -p "$HOME"
    /smoke-target/debug/examples/seed_password "Str0ng-Test-Pw-123" >/dev/null 2>&1 || { echo SEED_FAIL; exit 1; }
    start_server /smoke-target/debug/rustdesk /tmp/srv.log
    $READY --wait-server "$SRV" "$SRV_START" /tmp/srv.log /smoke-target/debug/examples/smoke_readiness "$(id -u)"
    echo "CORRECT: $(/smoke-target/debug/examples/probe_client '127.0.0.1:21118' 'Str0ng-Test-Pw-123' ok)"
    echo "WRONG:   $(/smoke-target/debug/examples/probe_client '127.0.0.1:21118' 'WRONG-Password-xyz' fail)"
    $READY --wait-key-failure "$SRV" "$SRV_START" /tmp/srv.log
    grep -m1 "security summary" /tmp/srv.log || true
    $READY --terminate-server "$SRV" "$SRV_START" /tmp/srv.log
    wait "$SRV"
    ;;
  flood)
    export HOME=/tmp/rd4
    mkdir -p "$HOME"
    /smoke-target/debug/examples/seed_password "Str0ng-Test-Pw-123" >/dev/null 2>&1 || { echo SEED_FAIL; exit 1; }
    start_server /smoke-target/debug/rustdesk /tmp/srv.log
    $READY --wait-server "$SRV" "$SRV_START" /tmp/srv.log /smoke-target/debug/examples/smoke_readiness "$(id -u)"
    /smoke-target/debug/examples/flood_probe "127.0.0.1:21118" 300 >/dev/null 2>&1 & FLOOD=$!
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
    /smoke-target/debug/examples/seed_password "Str0ng-Test-Pw-123" >/dev/null 2>&1 || { echo SEED_FAIL; exit 1; }
    start_server /smoke-target/debug/rustdesk /tmp/srv.log
    $READY --wait-server "$SRV" "$SRV_START" /tmp/srv.log /smoke-target/debug/examples/smoke_readiness "$(id -u)"
    /smoke-target/debug/examples/probe_client "127.0.0.1:21118" "Str0ng-Test-Pw-123" ok login 2>&1
    $READY --terminate-server "$SRV" "$SRV_START" /tmp/srv.log
    wait "$SRV"
    ;;
  video-pipeline)
    readonly XVFB=/xvfb-root/usr/bin/Xvfb
    readonly XKB_COMPILER=/usr/bin/xkbcomp
    readonly MOTION=/smoke-target/smoke-x11-motion
    readonly VIDEO_PROBE=/smoke-target/debug/examples/video_pipeline_probe
    readonly VIEWER_PIPELINE_TESTS=/smoke-target/production-viewer-pipeline-tests
    readonly XVFB_FILE_MANIFEST=/work/scripts/smoke-xvfb-files.tsv
    XVFB_PID=
    XVFB_START=
    MOTION_PID=
    MOTION_START=
    STALLED_PID=
    STALLED_START=
    cleanup_video_pipeline() {
      status=$?
      trap - EXIT HUP INT TERM
      cleanup_status=0
      if [ -n "$STALLED_PID" ] && [ -n "$STALLED_START" ]; then
        if "$READY" --is-running "$STALLED_PID" "$STALLED_START"; then
          "$READY" --stop "$STALLED_PID" "$STALLED_START" || cleanup_status=$?
        fi
        wait "$STALLED_PID" 2>/dev/null || true
      fi
      if [ -n "$SRV" ] && [ -n "$SRV_START" ] && "$READY" --is-running "$SRV" "$SRV_START"; then
        "$READY" --terminate-server "$SRV" "$SRV_START" /tmp/video-server.log \
          || cleanup_status=$?
        wait "$SRV" 2>/dev/null || cleanup_status=$?
      fi
      if [ -n "$MOTION_PID" ] && [ -n "$MOTION_START" ] \
        && "$READY" --is-running "$MOTION_PID" "$MOTION_START"; then
        "$READY" --stop "$MOTION_PID" "$MOTION_START" || cleanup_status=$?
        wait "$MOTION_PID" 2>/dev/null || true
      fi
      if [ -n "$XVFB_PID" ] && [ -n "$XVFB_START" ] \
        && "$READY" --is-running "$XVFB_PID" "$XVFB_START"; then
        "$READY" --stop "$XVFB_PID" "$XVFB_START" || cleanup_status=$?
        wait "$XVFB_PID" 2>/dev/null || true
      fi
      if [ "$cleanup_status" -ne 0 ]; then
        echo "VIDEO_PIPELINE_CLEANUP_EXIT=$cleanup_status" >&2
        exit 125
      fi
      exit "$status"
    }
    trap cleanup_video_pipeline EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM

    for executable in "$XVFB" "$XKB_COMPILER" "$MOTION" "$VIDEO_PROBE" \
      "$VIEWER_PIPELINE_TESTS"; do
      [ -f "$executable" ] && [ ! -L "$executable" ] && [ -x "$executable" ] || {
        echo "video pipeline executable is missing or not a regular non-symlink file: $executable" >&2
        exit 1
      }
    done
    [ -f "$XVFB_FILE_MANIFEST" ] && [ ! -L "$XVFB_FILE_MANIFEST" ]
    xvfb_file_count=0
    while IFS=$'\t' read -r relative size mode digest extra || [ -n "${relative:-}" ]; do
      [ -n "${relative:-}" ] || continue
      [[ "$relative" == \#* ]] && continue
      [ -z "${extra:-}" ]
      [[ "$relative" =~ ^[A-Za-z0-9._+/-]+$ ]]
      [[ "$relative" != /* ]] && [[ "$relative" != ../* ]] && [[ "$relative" != */../* ]]
      [[ "$size" =~ ^[1-9][0-9]*$ ]]
      [[ "$mode" =~ ^(644|755)$ ]]
      [[ "$digest" =~ ^[0-9a-f]{64}$ ]]
      xvfb_file="/xvfb-root/$relative"
      [ -f "$xvfb_file" ] && [ ! -L "$xvfb_file" ]
      [ "$(stat -c %u:%g:%a:%h:%s -- "$xvfb_file")" = "$(id -u):$(id -g):$mode:1:$size" ]
      [ "$(sha256sum "$xvfb_file" | awk '{print $1}')" = "$digest" ]
      xvfb_file_count=$((xvfb_file_count + 1))
    done < "$XVFB_FILE_MANIFEST"
    [ "$xvfb_file_count" -eq 5 ]
    export HOME=/tmp/rd-video-pipeline
    export DISPLAY=:99
    mkdir -p "$HOME"
    LD_LIBRARY_PATH=/xvfb-root/usr/lib/x86_64-linux-gnu \
      "$XVFB" :99 -screen 0 640x480x24 -nolisten tcp -ac -noreset \
      >/tmp/xvfb.log 2>&1 &
    XVFB_PID=$!
    XVFB_START=$($READY --identity "$XVFB_PID")
    "$MOTION" >/tmp/x11-motion.log 2>&1 &
    MOTION_PID=$!
    MOTION_START=$($READY --identity "$MOTION_PID")
    "$READY" --wait-log "$MOTION_PID" "$MOTION_START" /tmp/x11-motion.log \
      'X11_MOTION_READY display=:99 dimensions=640x480 frames=240 interval_ms=100' \
      'X11 motion fixture readiness'
    [ -S /tmp/.X11-unix/X99 ] && [ ! -L /tmp/.X11-unix/X99 ]
    x11_tcp_count=$(awk 'FNR > 1 && $4 == "0A" { count++ } END { print count + 0 }' /proc/net/tcp)
    [ ! -r /proc/net/tcp6 ] \
      || x11_tcp_count=$((x11_tcp_count + $(awk 'FNR > 1 && $4 == "0A" { count++ } END { print count + 0 }' /proc/net/tcp6)))
    x11_udp_count=$(awk 'FNR > 1 { count++ } END { print count + 0 }' /proc/net/udp)
    [ ! -r /proc/net/udp6 ] \
      || x11_udp_count=$((x11_udp_count + $(awk 'FNR > 1 { count++ } END { print count + 0 }' /proc/net/udp6)))
    [ "$x11_tcp_count" = 0 ]
    [ "$x11_udp_count" = 0 ]
    echo 'X11_NETWORK_SURFACE=unix-only tcp=0 udp=0'

    /smoke-target/debug/examples/seed_password 'Str0ng-Test-Pw-123' >/dev/null 2>&1 \
      || { echo SEED_FAIL; exit 1; }
    start_server /smoke-target/debug/rustdesk /tmp/video-server.log
    "$READY" --wait-server "$SRV" "$SRV_START" /tmp/video-server.log \
      /smoke-target/debug/examples/smoke_readiness "$(id -u)"
    if VIDEO_OUT=$(timeout --signal=TERM --kill-after=5s 35s \
      "$VIDEO_PROBE" 127.0.0.1:21118 <<<'Str0ng-Test-Pw-123' 2>&1); then
      VIDEO_STATUS=0
    else
      VIDEO_STATUS=$?
    fi
    printf '%s\n' "$VIDEO_OUT"
    [ "$VIDEO_STATUS" -eq 0 ] || exit "$VIDEO_STATUS"
    grep -Eq '^VIDEO_PIPELINE_OK codec=VP(8|9) dimensions=640x480 frames=[0-9]+ distinct=[0-9]+ receipts=[0-9]+ first_decode_ms=[0-9]+ pts_span_ms=[0-9]+ max_decode_us=[0-9]+ mean_decode_us=[0-9]+ max_receive_backlog_drift_ms=[0-9]+$' \
      <<<"$VIDEO_OUT"
    [ ! -e /tmp/video-stalled-peer.log ] && [ ! -L /tmp/video-stalled-peer.log ]
    RUSTDESK_VIDEO_PIPELINE_STALLED_PEER=1 \
      "$VIDEO_PROBE" 127.0.0.1:21118 <<<'Str0ng-Test-Pw-123' \
      >/tmp/video-stalled-peer.log 2>&1 &
    STALLED_PID=$!
    STALLED_START=$($READY --identity "$STALLED_PID")
    "$READY" --wait-log "$STALLED_PID" "$STALLED_START" /tmp/video-stalled-peer.log \
      'VIDEO_PIPELINE_STALLED_READY receipt=withheld display=0 generation=' \
      'stalled exact-receipt peer readiness'
    if VIEWER_OUT=$(RUSTDESK_PRODUCTION_VIEWER_PIPELINE_SMOKE=1 \
      timeout --signal=TERM --kill-after=5s 35s "$VIEWER_PIPELINE_TESTS" \
      --exact --ignored --nocapture --test-threads=1 \
      viewer_pipeline_smoke_tests::production_viewer_pipeline_recovers_after_stalled_publication_without_reconnect \
      2>&1); then
      VIEWER_STATUS=0
    else
      VIEWER_STATUS=$?
    fi
    printf '%s\n' "$VIEWER_OUT"
    [ "$VIEWER_STATUS" -eq 0 ] || exit "$VIEWER_STATUS"
    grep -Eq '^PRODUCTION_VIEWER_PIPELINE_OK dimensions=640x480 frames=[0-9]+ distinct=[0-9]+ stall_ms=[0-9]+ recovery_ms=[0-9]+ connected=true peer_info=true close_successes=[0-9]+ teardown=io-and-media-joined$' \
      <<<"$VIEWER_OUT"
    "$READY" --is-running "$STALLED_PID" "$STALLED_START"
    grep -Eq '^VIDEO_PIPELINE_STALLED_READY receipt=withheld display=0 generation=[1-9][0-9]* hold_ms=30000$' \
      /tmp/video-stalled-peer.log
    "$READY" --stop "$STALLED_PID" "$STALLED_START"
    wait "$STALLED_PID" 2>/dev/null || true
    STALLED_PID=
    STALLED_START=
    echo 'TWO_VIEWER_CAPTURE_ISOLATION=healthy-active,slow-receipt-withheld,no-reconnect'
    "$READY" --terminate-server "$SRV" "$SRV_START" /tmp/video-server.log
    wait "$SRV"
    SRV=
    SRV_START=
    "$READY" --stop "$MOTION_PID" "$MOTION_START"
    wait "$MOTION_PID" 2>/dev/null || true
    MOTION_PID=
    MOTION_START=
    "$READY" --stop "$XVFB_PID" "$XVFB_START"
    wait "$XVFB_PID" 2>/dev/null || true
    XVFB_PID=
    XVFB_START=
    grep -F 'X11_MOTION_READY' /tmp/x11-motion.log
    [ ! -s /tmp/xvfb.log ] || { echo 'Xvfb emitted unexpected diagnostics:' >&2; cat /tmp/xvfb.log >&2; exit 1; }
    echo 'VIDEO_PIPELINE_CLEANUP=server,stalled-peer,motion,xvfb-joined'
    trap - EXIT HUP INT TERM
    ;;
  port-forward)
    export HOME=/tmp/rd6b
    mkdir -p "$HOME"
    /smoke-target/debug/examples/seed_password "Str0ng-Test-Pw-123" >/dev/null 2>&1 || { echo SEED_FAIL; exit 1; }
    start_server /smoke-target/debug/rustdesk /tmp/srv.log
    $READY --wait-server "$SRV" "$SRV_START" /tmp/srv.log /smoke-target/debug/examples/smoke_readiness "$(id -u)"
    /smoke-target/debug/examples/pf_echo 5555 >/tmp/pf_echo.log 2>&1 & ECHO=$!
    ECHO_START=$($READY --identity "$ECHO")
    $READY --wait-tcp-listener "$ECHO" "$ECHO_START" /tmp/pf_echo.log 0100007F:15B3 "port-forward echo listener"
    PF_TARGET=127.0.0.1:5555 /smoke-target/debug/examples/probe_client "127.0.0.1:21118" "Str0ng-Test-Pw-123" ok portforward 2>&1
    $READY --stop "$ECHO" "$ECHO_START"
    wait "$ECHO" 2>/dev/null || true
    $READY --terminate-server "$SRV" "$SRV_START" /tmp/srv.log
    wait "$SRV"
    ;;
  file-transfer)
    export HOME=/tmp/rd6c
    mkdir -p "$HOME"
    /smoke-target/debug/examples/seed_password "Str0ng-Test-Pw-123" >/dev/null 2>&1 || { echo SEED_FAIL; exit 1; }
    start_server /smoke-target/debug/rustdesk /tmp/srv.log
    $READY --wait-server "$SRV" "$SRV_START" /tmp/srv.log /smoke-target/debug/examples/smoke_readiness "$(id -u)"
    /smoke-target/debug/examples/probe_client "127.0.0.1:21118" "Str0ng-Test-Pw-123" ok filetransfer 2>&1
    $READY --terminate-server "$SRV" "$SRV_START" /tmp/srv.log
    wait "$SRV"
    ;;
  inject)
    export HOME=/tmp/rd7
    mkdir -p "$HOME"
    /smoke-target/debug/examples/seed_password "Str0ng-Test-Pw-123" >/dev/null 2>&1 || { echo SEED_FAIL; exit 1; }
    start_server /smoke-target/debug/rustdesk /tmp/srv.log
    $READY --wait-server "$SRV" "$SRV_START" /tmp/srv.log /smoke-target/debug/examples/smoke_readiness "$(id -u)"
    INJECT_OUT=$(/smoke-target/debug/examples/probe_client "127.0.0.1:21118" "Str0ng-Test-Pw-123" ok inject 2>&1)
    printf '%s\n' "$INJECT_OUT"
    $READY --wait-log "$SRV" "$SRV_START" /tmp/srv.log "Connection closed: decryption error" "forged-frame rejection"
    grep -m1 "Connection closed: decryption error" /tmp/srv.log || echo "(no decryption-error close)"
    $READY --terminate-server "$SRV" "$SRV_START" /tmp/srv.log
    wait "$SRV"
    ;;
  limiter)
    export HOME=/tmp/rd8
    mkdir -p "$HOME"
    /smoke-target/debug/examples/seed_password "Str0ng-Test-Pw-123" >/dev/null 2>&1 || { echo SEED_FAIL; exit 1; }
    start_server /smoke-target/debug/rustdesk /tmp/srv.log
    $READY --wait-server "$SRV" "$SRV_START" /tmp/srv.log /smoke-target/debug/examples/smoke_readiness "$(id -u)"
    for i in $(seq 11); do /smoke-target/debug/examples/probe_client "127.0.0.1:21118" "WRONG-PW-$i-zz" fail >/dev/null 2>&1; done
    OWNER_OUT=$(/smoke-target/debug/examples/probe_client "127.0.0.1:21118" "Str0ng-Test-Pw-123" ok "" "127.0.0.2:0" 2>&1)
    printf '%s\n' "$OWNER_OUT"
    echo "OWNER_DIFF_SRC: $(grep -oE 'keying ok=(true|false)' <<<"$OWNER_OUT")"
    FLOODER_OUT=$(/smoke-target/debug/examples/probe_client "127.0.0.1:21118" "Str0ng-Test-Pw-123" fail 2>&1)
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
    /smoke-target/debug/examples/seed_password "Str0ng-Test-Pw-123" >/dev/null 2>&1 || { echo SEED_FAIL; exit 1; }
    start_server /smoke-target/debug/rustdesk /tmp/srv.log
    $READY --wait-server "$SRV" "$SRV_START" /tmp/srv.log /smoke-target/debug/examples/smoke_readiness "$(id -u)"
    tcpdump -U -i lo -w /tmp/cap.pcap "tcp port 21118" >/tmp/tcpdump.log 2>&1 & TCPD=$!
    TCPD_START=$($READY --identity "$TCPD")
    $READY --wait-log "$TCPD" "$TCPD_START" /tmp/tcpdump.log "listening on lo" "tcpdump capture readiness"
    LOGIN_OUT=$(/smoke-target/debug/examples/probe_client "127.0.0.1:21118" "Str0ng-Test-Pw-123" ok login 2>&1)
    printf '%s\n' "$LOGIN_OUT"
    $READY --interrupt "$TCPD" "$TCPD_START"
    wait "$TCPD"
    echo "PCAP_SIZE: $(wc -c < /tmp/cap.pcap 2>/dev/null || echo 0)"
    echo "CANARY_IN_BINARY: $(grep -a -c PLAINTEXT-CANARY-DEADBEEF /smoke-target/debug/examples/probe_client)"
    grep -a -q "PLAINTEXT-CANARY-DEADBEEF" /tmp/cap.pcap 2>/dev/null && echo "CANARY_ON_WIRE: YES" || echo "CANARY_ON_WIRE: NO"
    $READY --terminate-server "$SRV" "$SRV_START" /tmp/srv.log
    wait "$SRV"
    ;;
  decay)
    export HOME=/tmp/rd10
    mkdir -p "$HOME"
    /smoke-target/debug/examples/seed_password "Str0ng-Test-Pw-123" >/dev/null 2>&1 || { echo SEED_FAIL; exit 1; }
    start_server /smoke-target/debug/rustdesk /tmp/srv.log
    $READY --wait-server "$SRV" "$SRV_START" /tmp/srv.log /smoke-target/debug/examples/smoke_readiness "$(id -u)"
    for i in $(seq 11); do /smoke-target/debug/examples/probe_client "127.0.0.1:21118" "WRONG-PW-$i-zz" fail >/dev/null 2>&1; done
    BLOCKED_OUT=$(/smoke-target/debug/examples/probe_client "127.0.0.1:21118" "Str0ng-Test-Pw-123" fail 2>&1)
    printf '%s\n' "$BLOCKED_OUT"
    echo "BLOCKED_NOW: $(grep -oE 'keying ok=(true|false)' <<<"$BLOCKED_OUT")"
    echo "(holding the exact server identity for 64s so the 60s GUESS_WINDOW lapses...)"
    $READY --hold-running "$SRV" "$SRV_START" /tmp/srv.log 64 "limiter-decay interval"
    DECAYED_OUT=$(/smoke-target/debug/examples/probe_client "127.0.0.1:21118" "Str0ng-Test-Pw-123" ok 2>&1)
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
