#!/usr/bin/env bash
# Inner build/server/viewer stages for the exact full RustDesk peer-presentation probe.
set -euo pipefail
umask 077

fail() {
  echo "flutter peer presentation stage: $*" >&2
  exit 1
}

[ "$(id -u)" -ne 0 ] || fail 'refuses root execution'
[ "$(id -g)" -ne 0 ] || fail 'refuses a root primary group'
[ "$#" -eq 1 ] || fail 'expected one stage: build, server, or viewer'

verify_regular() {
  [ -f "$1" ] && [ ! -L "$1" ] || fail "missing regular input: $1"
}

verify_archive() {
  local path=$1 size=$2 digest=$3 label=$4
  verify_regular "$path"
  [ "$(stat -c %s "$path")" = "$size" ] || fail "$label size differs from its pin"
  [ "$(sha256sum "$path" | awk '{print $1}')" = "$digest" ] \
    || fail "$label digest differs from its pin"
}

verify_xvfb_closure() {
  local count=0 relative size mode digest extra file
  verify_regular /source/scripts/smoke-xvfb-files.tsv
  while IFS=$'\t' read -r relative size mode digest extra || [ -n "${relative:-}" ]; do
    [ -n "${relative:-}" ] || continue
    [[ "$relative" == \#* ]] && continue
    [ -z "${extra:-}" ] || fail 'Xvfb file manifest has extra fields'
    file="/xvfb-root/$relative"
    [ -f "$file" ] && [ ! -L "$file" ] \
      && [ "$(stat -c '%u:%g:%a:%h:%s' "$file")" = \
        "$(id -u):$(id -g):$mode:1:$size" ] \
      && [ "$(sha256sum "$file" | awk '{print $1}')" = "$digest" ] \
      || fail "Xvfb closure file differs from its manifest: $relative"
    count=$((count + 1))
  done < /source/scripts/smoke-xvfb-files.tsv
  [ "$count" -eq 5 ] || fail 'Xvfb closure file cardinality is not five'
}

verify_runtime_bundle() {
  verify_regular /out/manifest.sha256
  [ -z "$(find /out -xdev -type l -print -quit)" ] \
    || fail 'runtime bundle contains a symlink'
  (cd /out && sha256sum --check --strict manifest.sha256 >/dev/null)
  for executable in \
    /out/bundle/rustdesk \
    /out/flutter-peer-source-x11 \
    /out/flutter-peer-presentation-x11 \
    /source/scripts/smoke-ready.sh \
    /xvfb-root/usr/bin/Xvfb; do
    [ -f "$executable" ] && [ ! -L "$executable" ] && [ -x "$executable" ] \
      || fail "runtime executable is missing or invalid: $executable"
  done
  verify_xvfb_closure
}

assert_loopback_only_interface() {
  local interfaces
  interfaces="$(find /sys/class/net -mindepth 1 -maxdepth 1 -printf '%f\n' | sort)" \
    || fail 'cannot inspect runtime network interfaces'
  [ "$interfaces" = lo ] || fail "runtime has a non-loopback interface: $interfaces"
}

tcp_listener_count() {
  local -a tables=(/proc/net/tcp)
  [ -z "$TCP6_TABLE" ] || tables+=("$TCP6_TABLE")
  awk 'FNR > 1 && $4 == "0A" { count++ } END { print count + 0 }' \
    "${tables[@]}"
}

udp_socket_count() {
  local -a tables=(/proc/net/udp)
  [ -z "$UDP6_TABLE" ] || tables+=("$UDP6_TABLE")
  awk 'FNR > 1 { count++ } END { print count + 0 }' \
    "${tables[@]}"
}

listener_is_exact() {
  [ "$(tcp_listener_count)" -eq 1 ] \
    && awk 'FNR > 1 && $4 == "0A" && $2 == "0100007F:527E" { count++ }
      END { exit count == 1 ? 0 : 1 }' /proc/net/tcp
}

start_xvfb() {
  local display=$1 geometry=$2 log=$3
  "$XVFB" "$display" -screen 0 "$geometry" -nolisten tcp -ac -noreset >"$log" 2>&1 &
  XVFB_PID=$!
  XVFB_START=$("$READY" --identity "$XVFB_PID")
  local socket="/tmp/.X11-unix/X${display#:}"
  for _ in $(seq 1 300); do
    [ -S "$socket" ] && break
    "$READY" --is-running "$XVFB_PID" "$XVFB_START" \
      || { cat "$log" >&2; fail "Xvfb $display exited before readiness"; }
    sleep 0.02
  done
  [ -S "$socket" ] && [ ! -L "$socket" ] \
    || fail "Xvfb $display Unix socket did not become ready"
  "$READY" --hold-running "$XVFB_PID" "$XVFB_START" "$log" 1 \
    "Flutter peer presentation Xvfb $display stability"
}

TCP6_TABLE=
[ ! -r /proc/net/tcp6 ] || TCP6_TABLE=/proc/net/tcp6
UDP6_TABLE=
[ ! -r /proc/net/udp6 ] || UDP6_TABLE=/proc/net/udp6

case "$1" in
  build)
    for variable in \
      RUSTDESK_RUST_VERSION RUSTDESK_RUST_SHA256 RUSTDESK_RUST_SIZE \
      RUSTDESK_FLUTTER_VERSION RUSTDESK_FLUTTER_SHA256 RUSTDESK_FLUTTER_SIZE \
      RUSTDESK_LLVM_VERSION RUSTDESK_LLVM_SHA256 RUSTDESK_LLVM_SIZE \
      RUSTDESK_FLUTTER_TOOLS_LOCK_SHA256; do
      [ -n "${!variable:-}" ] || fail "missing build identity: $variable"
    done
    verify_archive "/online/rust-${RUSTDESK_RUST_VERSION}.tar.xz" \
      "$RUSTDESK_RUST_SIZE" "$RUSTDESK_RUST_SHA256" Rust
    verify_archive "/online/flutter-${RUSTDESK_FLUTTER_VERSION}.tar.xz" \
      "$RUSTDESK_FLUTTER_SIZE" "$RUSTDESK_FLUTTER_SHA256" Flutter
    verify_archive "/online/llvm-${RUSTDESK_LLVM_VERSION}.tar.xz" \
      "$RUSTDESK_LLVM_SIZE" "$RUSTDESK_LLVM_SHA256" LLVM
    for input in \
      /online/cargo-vendor-config.toml \
      /online/frb-tool/bin/flutter_rust_bridge_codegen \
      /source/Cargo.lock \
      /source/flutter/pubspec.lock \
      /source/scripts/flutter-offline-shim.sh \
      /source/scripts/flutter-peer-source-x11.c \
      /source/scripts/flutter-peer-presentation-x11.c; do
      verify_regular "$input"
    done
    for directory in /online/cargo-vendor /online/pub-cache /online/vcpkg; do
      [ -d "$directory" ] && [ ! -L "$directory" ] \
        || fail "missing build-input directory: $directory"
    done
    [ -d /out ] && [ ! -L /out ] \
      && [ "$(stat -c '%u:%g:%a' /out)" = "$(id -u):$(id -g):700" ] \
      || fail 'build output is not a private current-user directory'
    [ -z "$(find /out -mindepth 1 -maxdepth 1 -print -quit)" ] \
      || fail 'build output directory is not empty'
    [ -d /build-work ] && [ ! -L /build-work ] \
      && [ "$(stat -c '%u:%g:%a' /build-work)" = "$(id -u):$(id -g):700" ] \
      || fail 'build work is not a private current-user directory'
    [ -z "$(find /build-work -mindepth 1 -maxdepth 1 -print -quit)" ] \
      || fail 'build work directory is not empty'

    readonly TOOLCHAIN=/build-work/toolchain
    readonly BUILD_SOURCE=/build-work/source
    readonly HOME=/build-work/home
    readonly CARGO_HOME=/build-work/cargo-home
    mkdir -m 0700 "$TOOLCHAIN" "$BUILD_SOURCE" "$HOME" "$CARGO_HOME"
    cp -a /source/. "$BUILD_SOURCE/"
    chmod -R u+rwX "$BUILD_SOURCE"
    tar -C "$TOOLCHAIN" -xf "/online/rust-${RUSTDESK_RUST_VERSION}.tar.xz"
    tar -C "$TOOLCHAIN" -xf "/online/flutter-${RUSTDESK_FLUTTER_VERSION}.tar.xz"
    tar -C "$TOOLCHAIN" -xf "/online/llvm-${RUSTDESK_LLVM_VERSION}.tar.xz"
    "$TOOLCHAIN"/rust-1.*/install.sh --prefix="$TOOLCHAIN/rustinstall" \
      --disable-ldconfig \
      --components=rustc,cargo,rust-std-x86_64-unknown-linux-gnu,rustfmt-preview \
      >/dev/null
    readonly FLUTTER_ROOT=$TOOLCHAIN/flutter
    LLVM_ROOT="$(echo "$TOOLCHAIN"/clang+llvm-*)"
    [ -x "$FLUTTER_ROOT/bin/flutter" ] || fail 'Flutter SDK extracted at an unexpected path'
    [ "$(sha256sum "$FLUTTER_ROOT/packages/flutter_tools/pubspec.lock" | awk '{print $1}')" = \
      "$RUSTDESK_FLUTTER_TOOLS_LOCK_SHA256" ] \
      || fail 'Flutter tools lockfile differs from its pin'
    export HOME CARGO_HOME CI=true PUB_CACHE=/online/pub-cache
    export REAL_FLUTTER="$FLUTTER_ROOT/bin/flutter"
    export VCPKG_ROOT=/online/vcpkg
    export LIBCLANG_PATH="$LLVM_ROOT/lib"
    export CARGO_PROFILE_RELEASE_RPATH=false
    export PATH="$FLUTTER_ROOT/bin:$FLUTTER_ROOT/bin/cache/dart-sdk/bin:$TOOLCHAIN/rustinstall/bin:/online/frb-tool/bin:$PATH"
    git config --global --add safe.directory '*'
    cat > "$CARGO_HOME/config.toml" <<'CFG'
[net]
offline = true
CFG
    sed 's#directory = .*#directory = "/online/cargo-vendor"#' \
      /online/cargo-vendor-config.toml >> "$CARGO_HOME/config.toml"
    readonly SHIM=/tmp/flutter-shim
    mkdir "$SHIM"
    cp "$BUILD_SOURCE/scripts/flutter-offline-shim.sh" "$SHIM/flutter"
    chmod 0700 "$SHIM/flutter"
    export PATH="$SHIM:$PATH"
    (
      cd "$FLUTTER_ROOT/packages/flutter_tools"
      dart pub get --offline --enforce-lockfile >/dev/null
    )
    pub_lock_before="$(sha256sum "$BUILD_SOURCE/flutter/pubspec.lock" | awk '{print $1}')"
    (
      cd "$BUILD_SOURCE/flutter"
      dart pub get --offline --enforce-lockfile >/dev/null
      rm -rf linux/flutter/ephemeral/.plugin_symlinks \
        .flutter-plugins-dependencies .flutter-plugins
      "$REAL_FLUTTER" pub get --offline --enforce-lockfile >/dev/null
    )
    [ "$(sha256sum "$BUILD_SOURCE/flutter/pubspec.lock" | awk '{print $1}')" = \
      "$pub_lock_before" ] || fail 'project pubspec.lock changed during offline resolution'
    (
      cd "$BUILD_SOURCE"
      codegen_log=/tmp/flutter-peer-codegen.log
      set +e
      flutter_rust_bridge_codegen --rust-input ./src/flutter_ffi.rs \
        --dart-output ./flutter/lib/generated_bridge.dart \
        --llvm-path "$LLVM_ROOT" \
        --llvm-compiler-opts="-I$(echo "$LLVM_ROOT"/lib/clang/*/include)" \
        >"$codegen_log" 2>&1
      codegen_status=$?
      set -e
      cat "$codegen_log"
      [ "$codegen_status" -eq 0 ] || fail "Flutter bridge generation exited $codegen_status"
      ! grep -Fq '[SEVERE]' "$codegen_log" \
        || fail 'Flutter bridge generation emitted a severe diagnostic'
      cargo build --locked --features flutter,unix-file-copy-paste --lib --release
      sed -i 's/ffi.NativeFunction<ffi.Bool Function(DartPort/ffi.NativeFunction<ffi.Uint8 Function(DartPort/g' \
        flutter/lib/generated_bridge.dart
      (
        cd flutter
        rm -rf build/linux
        "$REAL_FLUTTER" build linux --release --no-pub
      )
    )
    readonly BUNDLE=$BUILD_SOURCE/flutter/build/linux/x64/release/bundle
    [ -x "$BUNDLE/rustdesk" ] || fail 'exact RustDesk Flutter runner is missing'
    verify_regular "$BUNDLE/lib/librustdesk.so"
    verify_regular "$BUNDLE/lib/libtexture_rgba_renderer_plugin.so"
    readelf --wide --dyn-syms "$BUNDLE/lib/librustdesk.so" \
      | grep -Eq '[[:space:]]rustdesk_core_main$' \
      || fail 'Rust core library does not export rustdesk_core_main'
    for symbol in FlutterRgbaRendererPluginTryOnRgba FlutterRgbaRendererPluginTryNotifyPending; do
      readelf --wide --dyn-syms "$BUNDLE/lib/libtexture_rgba_renderer_plugin.so" \
        | grep -Eq "[[:space:]]$symbol$" \
        || fail "texture plugin does not export $symbol"
    done
    cc -std=c11 -O2 -Wall -Wextra -Werror \
      "$BUILD_SOURCE/scripts/flutter-peer-source-x11.c" \
      $(pkg-config --cflags --libs x11) -o /out/flutter-peer-source-x11
    cc -std=c11 -O2 -Wall -Wextra -Werror \
      "$BUILD_SOURCE/scripts/flutter-peer-presentation-x11.c" \
      $(pkg-config --cflags --libs x11 xtst) -o /out/flutter-peer-presentation-x11
    mkdir /out/bundle
    cp -a "$BUNDLE/." /out/bundle/
    [ -z "$(find /out -xdev -type l -print -quit)" ] \
      || fail 'build output contains a symlink'
    [ -z "$(find /out -xdev -type f -perm /6000 -print -quit)" ] \
      || fail 'build output contains a setuid or setgid file'
    printf 'rust=%s flutter=%s llvm=%s features=flutter,unix-file-copy-paste app=rustdesk\n' \
      "$RUSTDESK_RUST_VERSION" "$RUSTDESK_FLUTTER_VERSION" "$RUSTDESK_LLVM_VERSION" \
      > /out/build.identity
    find /out -xdev -type f -exec chmod 0444 {} +
    chmod 0555 /out/flutter-peer-source-x11 /out/flutter-peer-presentation-x11 \
      /out/bundle/rustdesk /out/bundle/lib/*.so*
    (
      cd /out
      find bundle -type f -print0 | sort -z | xargs -0 sha256sum
      sha256sum build.identity flutter-peer-source-x11 flutter-peer-presentation-x11
    ) > /out/manifest.sha256
    chmod 0444 /out/manifest.sha256
    find /out -xdev -type d -exec chmod 0555 {} +
    printf 'FLUTTER_PEER_BUILD_OK rust=%s flutter=%s files=%s exact_runner=true exact_core=true\n' \
      "$RUSTDESK_RUST_VERSION" "$RUSTDESK_FLUTTER_VERSION" \
      "$(wc -l < /out/manifest.sha256)"
    ;;

  server)
    verify_runtime_bundle
    assert_loopback_only_interface
    readonly READY=/source/scripts/smoke-ready.sh
    readonly XVFB=/xvfb-root/usr/bin/Xvfb
    readonly APP=/out/bundle/rustdesk
    readonly SOURCE_FIXTURE=/out/flutter-peer-source-x11
    readonly COORD=/coord
    [ -d "$COORD" ] && [ ! -L "$COORD" ] \
      && [ "$(stat -c '%u:%g:%a' "$COORD")" = "$(id -u):$(id -g):700" ] \
      || fail 'coordination root is not a private current-user directory'
    [ -z "$(find "$COORD" -mindepth 1 -maxdepth 1 -print -quit)" ] \
      || fail 'coordination root was not initially empty'
    export DISPLAY=:98 HOME=/tmp/server-home XDG_RUNTIME_DIR=/tmp/server-runtime
    export GDK_BACKEND=x11 LIBGL_ALWAYS_SOFTWARE=1
    export LD_LIBRARY_PATH="/out/bundle/lib:/xvfb-root/usr/lib/x86_64-linux-gnu"
    mkdir -m 0700 "$HOME" "$XDG_RUNTIME_DIR"
    mkdir -m 1777 /tmp/.X11-unix
    XVFB_PID= XVFB_START= SOURCE_PID= SOURCE_START= SERVER_PID= SERVER_START=
    cleanup_server() {
      local status=$? cleanup_status=0
      trap - EXIT HUP INT TERM
      if [ -n "$SERVER_PID" ] && [ -n "$SERVER_START" ] \
        && "$READY" --is-running "$SERVER_PID" "$SERVER_START"; then
        "$READY" --stop "$SERVER_PID" "$SERVER_START" || cleanup_status=$?
        wait "$SERVER_PID" 2>/dev/null || true
      fi
      if [ -n "$SOURCE_PID" ] && [ -n "$SOURCE_START" ] \
        && "$READY" --is-running "$SOURCE_PID" "$SOURCE_START"; then
        "$READY" --stop "$SOURCE_PID" "$SOURCE_START" || cleanup_status=$?
        wait "$SOURCE_PID" 2>/dev/null || true
      fi
      if [ -n "$XVFB_PID" ] && [ -n "$XVFB_START" ] \
        && "$READY" --is-running "$XVFB_PID" "$XVFB_START"; then
        "$READY" --stop "$XVFB_PID" "$XVFB_START" || cleanup_status=$?
        wait "$XVFB_PID" 2>/dev/null || true
      fi
      [ "$cleanup_status" -eq 0 ] || status=125
      exit "$status"
    }
    trap cleanup_server EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM
    start_xvfb :98 640x480x24 /tmp/server-xvfb.log
    "$SOURCE_FIXTURE" >/tmp/source.log 2>&1 &
    SOURCE_PID=$!
    SOURCE_START=$("$READY" --identity "$SOURCE_PID")
    "$READY" --wait-log "$SOURCE_PID" "$SOURCE_START" /tmp/source.log \
      FLUTTER_PEER_SOURCE_READY 'peer source readiness'
    set +e
    password_output="$(printf '%s\n' 'rustdesk-peer-9f2a7c4e' \
      | (cd /out/bundle && "$APP" --password-stdin) 2>&1)"
    password_status=$?
    set -e
    printf '%s\n' "$password_output"
    [ "$password_status" -eq 0 ] \
      || fail "shipped password-stdin command exited $password_status"
    grep -qx 'Done!' <<<"$password_output" \
      || fail 'password-stdin completion marker differs'
    (cd /out/bundle && exec "$APP" --server) >/tmp/server.log 2>&1 &
    SERVER_PID=$!
    SERVER_START=$("$READY" --identity "$SERVER_PID")
    "$READY" --wait-tcp-listener "$SERVER_PID" "$SERVER_START" /tmp/server.log \
      0100007F:527E 'exact loopback direct server'
    listener_is_exact || fail 'server listener is not exactly 127.0.0.1:21118'
    [ "$(udp_socket_count)" -eq 0 ] || fail 'server network namespace has a UDP socket'
    printf 'server_pid=%s server_start=%s listener=127.0.0.1:21118\n' \
      "$SERVER_PID" "$SERVER_START" > "$COORD/server.ready.tmp"
    mv "$COORD/server.ready.tmp" "$COORD/server.ready"
    echo 'FLUTTER_PEER_SERVER_READY network=none interfaces=lo listener=127.0.0.1:21118 udp=0'
    stop_seen=0
    for _ in $(seq 1 1200); do
      if [ -f "$COORD/stop" ] && [ ! -L "$COORD/stop" ]; then
        stop_seen=1
        break
      fi
      "$READY" --is-running "$SERVER_PID" "$SERVER_START" \
        || { cat /tmp/server.log >&2; fail 'server exited before viewer completion'; }
      "$READY" --is-running "$SOURCE_PID" "$SOURCE_START" \
        || { cat /tmp/source.log >&2; fail 'source fixture exited before viewer completion'; }
      sleep 0.1
    done
    [ "$stop_seen" -eq 1 ] || fail 'viewer completion marker timed out'
    "$READY" --stop "$SERVER_PID" "$SERVER_START"
    wait "$SERVER_PID"
    SERVER_PID= SERVER_START=
    "$READY" --stop "$SOURCE_PID" "$SOURCE_START"
    wait "$SOURCE_PID"
    SOURCE_PID= SOURCE_START=
    grep -q '^FLUTTER_PEER_SOURCE_COMPLETE ' /tmp/source.log \
      || { cat /tmp/source.log >&2; fail 'source fixture did not close exactly'; }
    "$READY" --stop "$XVFB_PID" "$XVFB_START"
    wait "$XVFB_PID" 2>/dev/null || true
    XVFB_PID= XVFB_START=
    [ "$(tcp_listener_count)" -eq 0 ] && [ "$(udp_socket_count)" -eq 0 ] \
      || fail 'server retained an INET listener or UDP socket after teardown'
    printf 'server=joined source=joined xvfb=joined listener=closed\n' \
      > "$COORD/server.result.tmp"
    mv "$COORD/server.result.tmp" "$COORD/server.result"
    echo 'FLUTTER_PEER_SERVER_RUNTIME_OK server=joined source=joined xvfb=joined listener=closed'
    trap - EXIT HUP INT TERM
    ;;

  viewer)
    verify_runtime_bundle
    assert_loopback_only_interface
    readonly READY=/source/scripts/smoke-ready.sh
    readonly XVFB=/xvfb-root/usr/bin/Xvfb
    readonly APP=/out/bundle/rustdesk
    readonly CONTROLLER=/out/flutter-peer-presentation-x11
    readonly COORD=/coord
    [ -f "$COORD/server.ready" ] && [ ! -L "$COORD/server.ready" ] \
      || fail 'server readiness authority is absent'
    [ ! -e "$COORD/stop" ] && [ ! -L "$COORD/stop" ] \
      || fail 'viewer stop marker was not freshly absent'
    export DISPLAY=:99 HOME=/tmp/viewer-home XDG_RUNTIME_DIR=/tmp/viewer-runtime
    export GDK_BACKEND=x11 LIBGL_ALWAYS_SOFTWARE=1
    export LD_LIBRARY_PATH="/out/bundle/lib:/xvfb-root/usr/lib/x86_64-linux-gnu"
    mkdir -m 0700 "$HOME" "$XDG_RUNTIME_DIR"
    mkdir -m 1777 /tmp/.X11-unix
    XVFB_PID= XVFB_START= VIEWER_PID= VIEWER_START=
    cleanup_viewer() {
      local status=$? cleanup_status=0
      trap - EXIT HUP INT TERM
      if [ -n "$VIEWER_PID" ] && [ -n "$VIEWER_START" ] \
        && "$READY" --is-running "$VIEWER_PID" "$VIEWER_START"; then
        "$READY" --stop "$VIEWER_PID" "$VIEWER_START" || cleanup_status=$?
        wait "$VIEWER_PID" 2>/dev/null || true
      fi
      if [ -n "$XVFB_PID" ] && [ -n "$XVFB_START" ] \
        && "$READY" --is-running "$XVFB_PID" "$XVFB_START"; then
        "$READY" --stop "$XVFB_PID" "$XVFB_START" || cleanup_status=$?
        wait "$XVFB_PID" 2>/dev/null || true
      fi
      [ "$cleanup_status" -eq 0 ] || status=125
      exit "$status"
    }
    trap cleanup_viewer EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM
    start_xvfb :99 1280x800x24 /tmp/viewer-xvfb.log
    listener_is_exact || fail 'shared namespace lost the exact loopback server listener'
    [ "$(udp_socket_count)" -eq 0 ] || fail 'shared namespace has a UDP socket before connect'
    (cd /out/bundle && exec "$APP" --connect 127.0.0.1) >/tmp/viewer.log 2>&1 &
    VIEWER_PID=$!
    VIEWER_START=$("$READY" --identity "$VIEWER_PID")
    set +e
    controller_output="$(timeout --signal=TERM --kill-after=3s 70s \
      "$CONTROLLER" :98 :99 "$VIEWER_PID" 2>&1)"
    controller_status=$?
    set -e
    printf '%s\n' "$controller_output"
    if [ "$controller_status" -ne 0 ]; then
      cat /tmp/viewer.log >&2 || true
      cat /tmp/viewer-xvfb.log >&2 || true
      exit "$controller_status"
    fi
    grep -q '^FLUTTER_PEER_PASSWORD_PROMPT_OK typed_via_xtest=true argv_password=false$' \
      <<<"$controller_output" || fail 'real password prompt verdict is missing'
    grep -Eq '^FLUTTER_PEER_FOCUS_RECOVERY_OK .* real_pointer=true stable_connection=true$' \
      <<<"$controller_output" || fail 'stable-connection focus recovery verdict is missing'
    grep -q '^FLUTTER_PEER_PRESENTATION_OK actual_peer=true password_prompt=true capture=true transport=true decode=true flutter_texture=true x11_pixels=true focus_recovery=true$' \
      <<<"$controller_output" || fail 'full peer-presentation verdict is missing'
    for _ in $(seq 1 750); do
      "$READY" --is-running "$VIEWER_PID" "$VIEWER_START" || break
      sleep 0.02
    done
    if "$READY" --is-running "$VIEWER_PID" "$VIEWER_START"; then
      fail 'viewer did not retire after its real remote window closed'
    fi
    set +e
    wait "$VIEWER_PID"
    viewer_status=$?
    set -e
    VIEWER_PID= VIEWER_START=
    [ "$viewer_status" -eq 0 ] \
      || { cat /tmp/viewer.log >&2; fail "viewer exited $viewer_status"; }
    listener_is_exact || fail 'viewer lifecycle changed the exact server listener'
    [ "$(udp_socket_count)" -eq 0 ] || fail 'viewer lifecycle opened a UDP socket'
    "$READY" --stop "$XVFB_PID" "$XVFB_START"
    wait "$XVFB_PID" 2>/dev/null || true
    XVFB_PID= XVFB_START=
    printf 'viewer=joined xvfb=joined stable_connection=true\n' \
      > "$COORD/viewer.result.tmp"
    mv "$COORD/viewer.result.tmp" "$COORD/viewer.result"
    printf 'viewer-complete\n' > "$COORD/stop.tmp"
    mv "$COORD/stop.tmp" "$COORD/stop"
    echo 'FLUTTER_PEER_VIEWER_RUNTIME_OK viewer=joined xvfb=joined stable_connection=true'
    trap - EXIT HUP INT TERM
    ;;

  *)
    fail 'expected build, server, or viewer stage'
    ;;
esac
