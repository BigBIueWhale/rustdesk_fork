#!/usr/bin/env bash
set -euo pipefail
umask 077
[ "$#" -eq 0 ] && [ "$(id -u):$(id -g)" = 1000:1000 ]
source_root=/source
native_work=/work/window-channel
sdk=/work/toolchain/flutter/bin/cache/artifacts/engine/linux-x64
plugin=$source_root/flutter/third_party/desktop_multi_window/linux
mkdir "$native_work"
read -r -a gtk_flags <<<"$(pkg-config --cflags --libs gtk+-3.0)"
for version in before current; do
    implementation=$plugin/window_channel.cc
    if [ "$version" = before ]; then
        implementation=$source_root/scripts/fixtures/linux-window-channel-before-argument-ownership.cc
    fi
    timeout --signal=TERM --kill-after=5s 60s \
        g++ -std=c++14 -O0 -g0 -Wall -Wextra \
        -I"$sdk" -I"$plugin" \
        "$source_root/scripts/test-linux-window-channel.cc" "$implementation" \
        -L"$sdk" -Wl,-rpath,"$sdk" -lflutter_linux_gtk \
        -Wl,--wrap=fl_method_channel_invoke_method_finish \
        -Wl,--wrap=fl_method_channel_invoke_method -Wl,--export-dynamic -ldl \
        "${gtk_flags[@]}" -o "$native_work/$version" \
        >"$native_work/$version.build" 2>&1 \
        || { tail -n 100 "$native_work/$version.build"; exit 1; }
done
sha256sum "$native_work/before" "$native_work/current" "$sdk/libflutter_linux_gtk.so" \
    >"$native_work/artifacts.sha256"
before_status=0
timeout --signal=TERM --kill-after=5s 10s "$native_work/before" \
    >"$native_work/before.out" 2>&1 || before_status=$?
[ "$before_status" -eq 1 ]
[ "$(grep -c '^WINDOW_CHANNEL_CASE=fail case=' "$native_work/before.out")" -eq 8 ]
[ "$(grep -Fxc 'WINDOW_CHANNEL_ASSERT=failed check=temporary-argument-values-retired' "$native_work/before.out")" -eq 8 ]
[ "$(grep -c '^WINDOW_CHANNEL_ASSERT=failed' "$native_work/before.out")" -eq 8 ]
! grep -q '^WINDOW_CHANNEL_CASE=pass' "$native_work/before.out"
timeout --signal=TERM --kill-after=5s 10s "$native_work/current" \
    >"$native_work/current.out" 2>&1 \
    || { cat "$native_work/current.out"; exit 1; }
[ "$(grep -c '^WINDOW_CHANNEL_CASE=pass case=' "$native_work/current.out")" -eq 8 ]
! grep -q '^WINDOW_CHANNEL_ASSERT=failed' "$native_work/current.out"
for name in success explicit-error not-implemented malformed transport-error response-refused self-error self-void; do
    [ "$(grep -Fxc "WINDOW_CHANNEL_CASE=fail case=$name" "$native_work/before.out")" -eq 1 ]
    [ "$(grep -Fxc "WINDOW_CHANNEL_CASE=pass case=$name" "$native_work/current.out")" -eq 1 ]
done
for version in before current; do
    [ "$(grep -Fxc 'WINDOW_VALUE_OBSERVER=pass controls=2' "$native_work/$version.out")" -eq 1 ]
done
[ "$(grep -Fxc 'WINDOW_VALUE_TOTAL=observed maps=135 freed=0' "$native_work/before.out")" -eq 1 ]
[ "$(grep -Fxc 'WINDOW_VALUE_TOTAL=observed maps=135 freed=405' "$native_work/current.out")" -eq 1 ]
sha256sum --check --status "$native_work/artifacts.sha256"
cat "$native_work/before.out" "$native_work/current.out"
printf 'LINUX_WINDOW_CHANNEL_BEFORE=observed cases=8 failed=8\n'
printf 'LINUX_WINDOW_CHANNEL_CURRENT=pass cases=8\n'
printf 'LINUX_WINDOW_VALUE_OWNERSHIP=pass paths=3 maps=135 values=405 before_retired=0 current_retired=405 controls=2\n'
printf 'LINUX_WINDOW_CHANNEL_ARTIFACTS=pass before=%s current=%s flutter=%s unchanged=before-after\n' \
    "$(sha256sum "$native_work/before" | awk '{print $1}')" \
    "$(sha256sum "$native_work/current" | awk '{print $1}')" \
    "$(sha256sum "$sdk/libflutter_linux_gtk.so" | awk '{print $1}')"
printf 'LINUX_WINDOW_CHANNEL_SCOPE=component codec=flutter-3.24.5 messenger=controlled windows=unexecuted\n'
