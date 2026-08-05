#!/usr/bin/env bash
# Inner stages for the confined real Flutter texture/X11 presentation probe.
set -euo pipefail
umask 077

fail() {
  echo "flutter presentation stage: $*" >&2
  exit 1
}

[ "$(id -u)" -ne 0 ] || fail 'refuses root execution'
[ "$(id -g)" -ne 0 ] || fail 'refuses a root primary group'
[ "$#" -eq 1 ] || fail 'expected one stage: build or runtime'

case "$1" in
  build)
    : "${RUSTDESK_FLUTTER_VERSION:?}"
    : "${RUSTDESK_FLUTTER_SHA256:?}"
    : "${RUSTDESK_FLUTTER_SIZE:?}"
    : "${RUSTDESK_FLUTTER_TOOLS_LOCK_SHA256:?}"
    : "${RUSTDESK_PUB_CACHE_SHA256:?}"
    : "${RUSTDESK_PUB_CACHE_SIZE:?}"
    for input in \
      /inputs/flutter.tar.xz \
      /inputs/pub-cache.tar.gz \
      /source/scripts/flutter-presentation-probe.dart \
      /source/scripts/flutter-presentation-probe-pubspec.yaml \
      /source/scripts/flutter-presentation-probe-x11.c \
      /source/flutter/third_party/texture_rgba_renderer/pubspec.yaml \
      /source/flutter/third_party/texture_rgba_renderer/linux/texture_rgba_renderer_plugin.cc; do
      [ -f "$input" ] && [ ! -L "$input" ] || fail "missing regular input: $input"
    done
    [ -d /out ] && [ ! -L /out ] \
      && [ "$(stat -c '%u:%g:%a' /out)" = "$(id -u):$(id -g):700" ] \
      || fail 'output is not a private current-user directory'
    [ -z "$(find /out -mindepth 1 -maxdepth 1 -print -quit)" ] \
      || fail 'output directory is not empty'
    [ "$(stat -c %s /inputs/flutter.tar.xz)" = "$RUSTDESK_FLUTTER_SIZE" ] \
      || fail 'Flutter archive size differs from its pin'
    [ "$(sha256sum /inputs/flutter.tar.xz | awk '{print $1}')" = \
      "$RUSTDESK_FLUTTER_SHA256" ] || fail 'Flutter archive digest differs from its pin'
    [ "$(stat -c %s /inputs/pub-cache.tar.gz)" = "$RUSTDESK_PUB_CACHE_SIZE" ] \
      || fail 'Flutter pub-cache archive size differs from its pin'
    [ "$(sha256sum /inputs/pub-cache.tar.gz | awk '{print $1}')" = \
      "$RUSTDESK_PUB_CACHE_SHA256" ] \
      || fail 'Flutter pub-cache archive digest differs from its pin'

    readonly TOOLCHAIN=/tmp/toolchain
    readonly FLUTTER_ROOT=$TOOLCHAIN/flutter
    readonly PUB_CACHE=/tmp/pub-cache
    readonly APP=/tmp/rustdesk-presentation-probe
    readonly HOME=/tmp/home
    mkdir -p "$TOOLCHAIN" "$PUB_CACHE" "$HOME"
    tar -C "$TOOLCHAIN" -xf /inputs/flutter.tar.xz
    tar -C "$PUB_CACHE" -xzf /inputs/pub-cache.tar.gz
    # The deterministic pub-cache archive normalizes mtimes to SOURCE_DATE_EPOCH,
    # but Dart uses each advisory response's mtime as cache-validity authority.
    # Reconstruct exactly the mtimes attested inside the matching version/advisory
    # JSON pair; otherwise Dart 3.5 attempts pub.dev even with --offline.
    python3 - "$PUB_CACHE/hosted/pub.dev/.cache" <<'PY'
import calendar
import datetime
import json
import os
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
restored = 0
for versions_path in sorted(root.glob("*-versions.json")):
    with versions_path.open("r", encoding="utf-8") as stream:
        versions = json.load(stream)
    updated = versions.get("advisoriesUpdated")
    if updated is None:
        continue
    suffix = "-versions.json"
    if not versions_path.name.endswith(suffix):
        raise SystemExit(f"invalid version cache name: {versions_path.name}")
    advisory_path = versions_path.with_name(
        versions_path.name[: -len(suffix)] + "-advisories.json"
    )
    if not advisory_path.is_file() or advisory_path.is_symlink():
        raise SystemExit(f"missing regular advisory response for {versions_path.name}")
    with advisory_path.open("r", encoding="utf-8") as stream:
        advisory = json.load(stream)
    if advisory.get("advisoriesUpdated") != updated:
        raise SystemExit(f"advisory timestamp mismatch for {versions_path.name}")
    try:
        parsed = datetime.datetime.strptime(updated, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError as error:
        raise SystemExit(
            f"invalid UTC advisory timestamp for {versions_path.name}: {error}"
        )
    nanoseconds = calendar.timegm(parsed.utctimetuple()) * 1_000_000_000
    nanoseconds += parsed.microsecond * 1_000
    # Dart's FileStat timestamp conversion can expose less precision than the
    # six-digit API timestamp. Make the cache file deterministically newer,
    # rather than merely equal before that conversion.
    nanoseconds += 1_000_000_000
    os.utime(advisory_path, ns=(nanoseconds, nanoseconds), follow_symlinks=False)
    if os.stat(advisory_path, follow_symlinks=False).st_mtime_ns != nanoseconds:
        raise SystemExit(f"cannot reconstruct advisory mtime for {versions_path.name}")
    restored += 1
if restored != 2:
    raise SystemExit(f"expected two cached advisory responses, found {restored}")
print("FLUTTER_PUB_CACHE_SEMANTICS_OK advisories=2 reconstructed_from_json=true")
PY
    [ -x "$FLUTTER_ROOT/bin/flutter" ] \
      || fail 'pinned Flutter SDK did not extract at the expected path'
    [ "$(sha256sum "$FLUTTER_ROOT/packages/flutter_tools/pubspec.lock" | awk '{print $1}')" = \
      "$RUSTDESK_FLUTTER_TOOLS_LOCK_SHA256" ] \
      || fail 'Flutter tools lockfile differs from its pin'
    export HOME PUB_CACHE CI=true
    export PATH="$FLUTTER_ROOT/bin:$FLUTTER_ROOT/bin/cache/dart-sdk/bin:$PATH"
    git config --global --add safe.directory "$FLUTTER_ROOT"
    # Resolve flutter_tools with the SDK's Dart executable before the first
    # Flutter wrapper invocation. A cold wrapper otherwise attempts its own
    # advisory refresh even when the eventual project build is offline.
    echo 'FLUTTER_PRESENTATION_STEP=flutter-tools-pub begin'
    (
      cd "$FLUTTER_ROOT/packages/flutter_tools"
      dart pub get --offline --enforce-lockfile >/dev/null
    )
    echo 'FLUTTER_PRESENTATION_STEP=flutter-tools-pub ok'
    echo 'FLUTTER_PRESENTATION_STEP=flutter-version begin'
    flutter_version="$(flutter --version --no-version-check 2>&1)" \
      || { printf '%s\n' "$flutter_version" >&2; fail 'Flutter version inspection failed'; }
    grep -q "Flutter $RUSTDESK_FLUTTER_VERSION " <<<"$flutter_version" \
      || { printf '%s\n' "$flutter_version" >&2; fail 'Flutter SDK version differs from its pin'; }
    echo 'FLUTTER_PRESENTATION_STEP=flutter-version ok'
    echo 'FLUTTER_PRESENTATION_STEP=flutter-create begin'
    flutter create --platforms=linux --project-name rustdesk_presentation_probe \
      --org com.carriez --no-pub "$APP" >/dev/null
    echo 'FLUTTER_PRESENTATION_STEP=flutter-create ok'
    cp /source/scripts/flutter-presentation-probe.dart "$APP/lib/main.dart"
    cp /source/scripts/flutter-presentation-probe-pubspec.yaml "$APP/pubspec.yaml"
    rm -f "$APP/analysis_options.yaml"
    (
      cd "$APP"
      echo 'FLUTTER_PRESENTATION_STEP=app-dart-pub begin'
      dart pub get --offline >/dev/null
      echo 'FLUTTER_PRESENTATION_STEP=app-dart-pub ok'
      echo 'FLUTTER_PRESENTATION_STEP=app-flutter-pub begin'
      flutter pub get --offline --enforce-lockfile >/dev/null
      echo 'FLUTTER_PRESENTATION_STEP=app-flutter-pub ok'
      dart format --output=none --set-exit-if-changed lib/main.dart
      flutter analyze --no-pub lib/main.dart
      flutter build linux --release --no-pub
    )
    readonly BUNDLE=$APP/build/linux/x64/release/bundle
    [ -x "$BUNDLE/rustdesk_presentation_probe" ] \
      || fail 'Flutter release executable is missing'
    readonly PLUGIN=$BUNDLE/lib/libtexture_rgba_renderer_plugin.so
    [ -f "$PLUGIN" ] && [ ! -L "$PLUGIN" ] \
      || fail 'RustDesk texture plugin is missing from the Flutter bundle'
    for symbol in \
      FlutterRgbaRendererPluginTryOnRgba \
      FlutterRgbaRendererPluginTryNotifyPending; do
      readelf --wide --dyn-syms "$PLUGIN" | grep -Eq "[[:space:]]$symbol$" \
        || fail "bundled texture plugin does not export $symbol"
    done
    cc -std=c11 -O2 -Wall -Wextra -Werror \
      /source/scripts/flutter-presentation-probe-x11.c \
      $(pkg-config --cflags --libs x11) \
      -o /out/flutter-presentation-probe-x11
    mkdir /out/bundle
    cp -a "$BUNDLE/." /out/bundle/
    [ -z "$(find /out -xdev -type l -print -quit)" ] \
      || fail 'build output contains a symlink'
    [ -z "$(find /out -xdev -type f -perm /6000 -print -quit)" ] \
      || fail 'build output contains a setuid or setgid file'
    printf 'flutter=%s direct_abi=true app=rustdesk_presentation_probe\n' \
      "$RUSTDESK_FLUTTER_VERSION" > /out/build.identity
    find /out -xdev -type f -exec chmod 0444 {} +
    chmod 0555 \
      /out/flutter-presentation-probe-x11 \
      /out/bundle/rustdesk_presentation_probe \
      /out/bundle/lib/*.so
    (
      cd /out
      find bundle -type f -print0 \
        | sort -z \
        | xargs -0 sha256sum
      sha256sum build.identity flutter-presentation-probe-x11
    ) > /out/manifest.sha256
    chmod 0444 /out/manifest.sha256
    find /out -xdev -type d -exec chmod 0555 {} +
    printf 'FLUTTER_PRESENTATION_BUILD_OK flutter=%s files=%s direct_abi_symbols=2\n' \
      "$RUSTDESK_FLUTTER_VERSION" \
      "$(grep -cE '  (bundle/|build[.]identity$|flutter-presentation-probe-x11$)' /out/manifest.sha256)"
    ;;

  runtime)
    readonly READY=/source/scripts/smoke-ready.sh
    readonly XVFB=/xvfb-root/usr/bin/Xvfb
    readonly XVFB_MANIFEST=/source/scripts/smoke-xvfb-files.tsv
    readonly APP=/out/bundle/rustdesk_presentation_probe
    readonly HELPER=/out/flutter-presentation-probe-x11
    readonly STATE=/state
    for executable in "$READY" "$XVFB" "$APP" "$HELPER"; do
      [ -f "$executable" ] && [ ! -L "$executable" ] && [ -x "$executable" ] \
        || fail "runtime executable is missing or invalid: $executable"
    done
    [ -f /out/manifest.sha256 ] && [ ! -L /out/manifest.sha256 ] \
      || fail 'build manifest is missing or invalid'
    [ -d "$STATE" ] && [ ! -L "$STATE" ] \
      && [ "$(stat -c '%u:%g:%a' "$STATE")" = "$(id -u):$(id -g):700" ] \
      || fail 'runtime state is not a private current-user directory'
    [ -z "$(find "$STATE" -mindepth 1 -maxdepth 1 -print -quit)" ] \
      || fail 'runtime state directory is not empty'
    [ -z "$(find /out -xdev -type l -print -quit)" ] \
      || fail 'runtime input contains a symlink'
    (cd /out && sha256sum --check --strict manifest.sha256)
    echo 'FLUTTER_PRESENTATION_STEP=runtime-bundle-integrity ok'

    xvfb_file_count=0
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
      xvfb_file_count=$((xvfb_file_count + 1))
    done < "$XVFB_MANIFEST"
    [ "$xvfb_file_count" -eq 5 ] || fail 'Xvfb file manifest cardinality is not five'
    echo 'FLUTTER_PRESENTATION_STEP=runtime-xvfb-closure ok'

    export DISPLAY=:99
    export HOME=/tmp/home
    export XDG_RUNTIME_DIR=/tmp/runtime
    export GDK_BACKEND=x11
    export LIBGL_ALWAYS_SOFTWARE=1
    export LD_LIBRARY_PATH="/out/bundle/lib:/xvfb-root/usr/lib/x86_64-linux-gnu"
    mkdir -m 0700 "$HOME" "$XDG_RUNTIME_DIR"
    TCP_TABLES=(/proc/net/tcp)
    [ ! -r /proc/net/tcp6 ] || TCP_TABLES+=(/proc/net/tcp6)
    UDP_TABLES=(/proc/net/udp)
    [ ! -r /proc/net/udp6 ] || UDP_TABLES+=(/proc/net/udp6)
    XVFB_PID=
    XVFB_START=
    APP_PID=
    APP_START=
    cleanup_runtime() {
      status=$?
      trap - EXIT HUP INT TERM
      cleanup_status=0
      if [ -n "$APP_PID" ] && [ -n "$APP_START" ] \
        && "$READY" --is-running "$APP_PID" "$APP_START"; then
        "$READY" --stop "$APP_PID" "$APP_START" || cleanup_status=$?
        wait "$APP_PID" 2>/dev/null || true
      fi
      if [ -n "$XVFB_PID" ] && [ -n "$XVFB_START" ] \
        && "$READY" --is-running "$XVFB_PID" "$XVFB_START"; then
        "$READY" --stop "$XVFB_PID" "$XVFB_START" || cleanup_status=$?
        wait "$XVFB_PID" 2>/dev/null || true
      fi
      [ "$cleanup_status" -eq 0 ] || status=125
      exit "$status"
    }
    trap cleanup_runtime EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM

    echo 'FLUTTER_PRESENTATION_STEP=runtime-xvfb-start begin'
    "$XVFB" :99 -screen 0 1280x800x24 -nolisten tcp -ac -noreset \
      >/tmp/xvfb.log 2>&1 &
    XVFB_PID=$!
    XVFB_START=$("$READY" --identity "$XVFB_PID")
    for _ in $(seq 1 200); do
      [ -S /tmp/.X11-unix/X99 ] && break
      "$READY" --is-running "$XVFB_PID" "$XVFB_START" \
        || { cat /tmp/xvfb.log >&2; fail 'Xvfb exited before readiness'; }
      sleep 0.02
    done
    [ -S /tmp/.X11-unix/X99 ] && [ ! -L /tmp/.X11-unix/X99 ] \
      || fail 'Xvfb Unix socket did not become ready'
    echo 'FLUTTER_PRESENTATION_STEP=runtime-xvfb-start ok'
    tcp_listeners=$(awk 'FNR > 1 && $4 == "0A" { n++ } END { print n + 0 }' \
      "${TCP_TABLES[@]}")
    udp_sockets=$(awk 'FNR > 1 { n++ } END { print n + 0 }' \
      "${UDP_TABLES[@]}")
    [ "$tcp_listeners" -eq 0 ] && [ "$udp_sockets" -eq 0 ] \
      || fail 'networkless runtime has an INET listener or UDP socket'
    echo 'FLUTTER_PRESENTATION_NETWORK_SURFACE=network-none tcp-listen:0 udp:0 x11:unix-only'

    (
      cd /out/bundle
      exec "$APP" "$STATE"
    ) >/tmp/flutter-app.log 2>&1 &
    APP_PID=$!
    APP_START=$("$READY" --identity "$APP_PID")
    set +e
    helper_output=$(timeout --signal=TERM --kill-after=3s 40s \
      "$HELPER" "$STATE" rustdesk_presentation_probe 2>&1)
    helper_status=$?
    set -e
    printf '%s\n' "$helper_output"
    if [ "$helper_status" -ne 0 ]; then
      cat /tmp/flutter-app.log >&2 || true
      cat /tmp/xvfb.log >&2 || true
      exit "$helper_status"
    fi
    grep -Eq '^FLUTTER_PRESENTATION_PIXELS_OK initial_rgb=255,0,0 final_rgb=[0-9]+,[0-9]+,[0-9]+ hidden_ms=1500 recovery_ms=[0-9]+ direct_abi=true actual_texture=true x11_pixels=true$' \
      <<<"$helper_output" || fail 'X11 pixel verdict is missing or malformed'
    for _ in $(seq 1 200); do
      "$READY" --is-running "$APP_PID" "$APP_START" || break
      sleep 0.02
    done
    if "$READY" --is-running "$APP_PID" "$APP_START"; then
      fail 'Flutter app did not retire after exact texture close'
    fi
    set +e
    wait "$APP_PID"
    app_status=$?
    set -e
    APP_PID=
    APP_START=
    [ "$app_status" -eq 0 ] \
      || { cat /tmp/flutter-app.log >&2; fail "Flutter app exited $app_status"; }
    grep -Eq '^FLUTTER_PROBE_APP_OK texture_id=[1-9][0-9]* direct_abi=true hidden_frames=128 closed=true$' \
      /tmp/flutter-app.log || { cat /tmp/flutter-app.log >&2; fail 'Flutter close verdict is missing'; }
    [ "$(awk 'FNR > 1 && $4 == "0A" { n++ } END { print n + 0 }' \
      "${TCP_TABLES[@]}")" -eq 0 ] \
      || fail 'runtime opened an INET listener'
    [ "$(awk 'FNR > 1 { n++ } END { print n + 0 }' \
      "${UDP_TABLES[@]}")" -eq 0 ] \
      || fail 'runtime opened a UDP socket'
    "$READY" --stop "$XVFB_PID" "$XVFB_START"
    wait "$XVFB_PID" 2>/dev/null || true
    XVFB_PID=
    XVFB_START=
    [ ! -s /tmp/xvfb.log ] \
      || { cat /tmp/xvfb.log >&2; fail 'Xvfb emitted diagnostics'; }
    echo 'FLUTTER_PRESENTATION_RUNTIME_OK app=joined texture=closed xvfb=joined'
    trap - EXIT HUP INT TERM
    ;;
  *)
    fail 'expected build or runtime stage'
    ;;
esac
