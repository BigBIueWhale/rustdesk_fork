#!/usr/bin/env bash
#
# dart-verify.sh — verify the Flutter/Dart UI and shipped Linux Rust feature set offline.
#
# This one transaction runs `dart pub get --offline`, full FRB codegen, `flutter analyze lib/`,
# the focused Dart tests, and a locked/offline Rust library check plus mobile-session lifecycle
# regressions with the exact shipped Debian features (`flutter,unix-file-copy-paste`). Analyzer
# errors are forbidden; the accepted upstream info/warning baseline remains nonfatal. All generated
# state lives in a disposable
# invoking-user-owned source snapshot. The real repository and canonical offline-input tree are
# never writable container mounts.
#
# R-R1/R-B12: the committed flutter/pubspec.lock is the authoritative Dart
# dependency pin. This verifier resolves the project from the staged pub cache
# and fails if pub would rewrite the lockfile; it never "restores" drift.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"
load_pins
cd "$REPO_ROOT"

readonly BUILD_UID="$(/usr/bin/id -u)"
readonly BUILD_GID="$(/usr/bin/id -g)"
WORKSPACE=""
WORKSPACE_ID=""
cleanup() {
  local status=$?
  trap - EXIT HUP INT TERM
  if [ -n "$WORKSPACE" ]; then
    if [ "$LOCAL_DOCKER_AUTHORITY_INITIALIZED" -eq 1 ] \
      && ! remove_local_docker_authority; then
      echo "dart-verify: preserving changed private Docker authority: $WORKSPACE" >&2
      status=125
    elif [ -z "$WORKSPACE_ID" ] || [ ! -d "$WORKSPACE" ] || [ -L "$WORKSPACE" ] \
      || [ "$(/usr/bin/stat -c '%d:%i:%u:%g:%a' -- "$WORKSPACE" 2>/dev/null)" != "$WORKSPACE_ID" ]; then
      echo "dart-verify: preserving changed private workspace: $WORKSPACE" >&2
      status=125
    else
      chmod -R u+rwX "$WORKSPACE" 2>/dev/null || status=1
      rm -rf -- "$WORKSPACE" || status=1
    fi
  fi
  exit "$status"
}
signal_exit() {
  local status="$1"
  trap - HUP INT TERM
  exit "$status"
}
trap cleanup EXIT
trap 'signal_exit 129' HUP
trap 'signal_exit 130' INT
trap 'signal_exit 143' TERM

require_cmd git python3 realpath sha256sum tar
[ "$BUILD_UID" -ne 0 ] || die "dart-verify refuses host or container-root execution"
[ "$BUILD_GID" -ne 0 ] || die "dart-verify refuses a root primary group"
require_online_complete
verify_online_shas \
  "rust-${RUST_VERSION}.tar.xz" "$SHA256_RUST_1_75" \
  "flutter-${FLUTTER_VERSION}.tar.xz" "$SHA256_FLUTTER_3_24_5" \
  "llvm-${LLVM_VERSION}.tar.xz" "$SHA256_LLVM_15_0_6" \
  "frb-${FLUTTER_RUST_BRIDGE_VERSION}.tar.gz" "$SHA256_FRB_1_80_1"

IMAGE_ID="$DEB_BUILDER_IMAGE_ID"
[[ "$IMAGE_ID" =~ ^sha256:[0-9a-f]{64}$ ]] \
  || die "dart-verify has a malformed immutable image ID: $IMAGE_ID"

archive_current_source() {
  git -C "$REPO_ROOT" ls-files -z --cached --others --exclude-standard \
    | python3 -c '
import os
import sys

root = os.fsencode(sys.argv[1])
for relative in sys.stdin.buffer.read().split(b"\0"):
    if relative and os.path.lexists(os.path.join(root, relative)):
        sys.stdout.buffer.write(relative + b"\0")
' "$REPO_ROOT" \
    | tar --create --file=- --directory="$REPO_ROOT" --null --verbatim-files-from \
        --no-recursion --files-from=- --sort=name --format=gnu --mtime='@0' \
        --owner=0 --group=0 --numeric-owner
}

WORKSPACE="$(umask 077 && mktemp -d /tmp/rustdesk-dart-verify.XXXXXXXXXX)"
[ -d "$WORKSPACE" ] && [ ! -L "$WORKSPACE" ] \
  || die "dart-verify private workspace creation failed"
[ "$(/usr/bin/stat -c '%u:%g:%a' "$WORKSPACE")" = "$BUILD_UID:$BUILD_GID:700" ] \
  || die "dart-verify private workspace identity or mode is invalid"
WORKSPACE_ID="$(/usr/bin/stat -c '%d:%i:%u:%g:%a' -- "$WORKSPACE")"
initialize_local_docker_authority "$WORKSPACE/docker-config" "dart-verify"
require_pinned_builder_image deb-builder "$IMAGE_ID"

SOURCE_ARCHIVE="$WORKSPACE/source.tar"
SOURCE_SNAPSHOT="$WORKSPACE/source"
FRB_OUTPUT="$WORKSPACE/frb-output"
ANALYSIS_ROOT="$WORKSPACE/analysis"
ONLINE_SNAPSHOT_PARENT="$WORKSPACE/online-input"
create_private_online_snapshot "$ONLINE_SNAPSHOT_PARENT"
verify_private_online_snapshot "$ONLINE_SNAPSHOT_PARENT"
ONLINE_SNAPSHOT="$ONLINE_SNAPSHOT_PARENT/online"
mkdir "$SOURCE_SNAPSHOT" "$ANALYSIS_ROOT"
archive_current_source >"$SOURCE_ARCHIVE"
SOURCE_DIGEST="$(sha256sum "$SOURCE_ARCHIVE" | awk '{print $1}')"
tar --extract --file="$SOURCE_ARCHIVE" --directory="$SOURCE_SNAPSHOT"
chmod -R a-w "$SOURCE_SNAPSHOT"

echo "== full pinned FRB generation in a disposable source snapshot =="
ONLINE_DIR="$ONLINE_SNAPSHOT" FRB_IMAGE_ID="$IMAGE_ID" \
  /usr/bin/bash "$SCRIPT_DIR/frb-codegen.sh" \
    --source-root "$SOURCE_SNAPSHOT" \
    --online-root "$ONLINE_SNAPSHOT" \
    --output-root "$FRB_OUTPUT"

cp -a --reflink=auto "$SOURCE_SNAPSHOT/." "$ANALYSIS_ROOT/"
chmod -R u+rwX "$ANALYSIS_ROOT"
cp -a "$FRB_OUTPUT/." "$ANALYSIS_ROOT/"

echo "== flutter pub/analyze/test + shipped-feature Rust check in the disposable snapshot =="
local_docker run --rm --pull=never --network=none --read-only \
  --user "$BUILD_UID:$BUILD_GID" \
  --cap-drop=ALL --security-opt=no-new-privileges \
  --pids-limit=512 --memory=12g --memory-swap=12g --cpus=4 \
  --tmpfs /tmp:rw,exec,nosuid,nodev,mode=1777,size=10g \
  --mount "type=bind,source=$ANALYSIS_ROOT,target=/src" \
  --mount "type=bind,source=$ONLINE_SNAPSHOT,target=/online,readonly" \
  --env "RUSTDESK_RUST_VERSION=$RUST_VERSION" \
  --env "RUSTDESK_FLUTTER_VERSION=$FLUTTER_VERSION" \
  --workdir /src "$IMAGE_ID" \
  bash -euo pipefail -c '
    toolchain=/tmp/rustdesk-dart-toolchain
    home=/tmp/rustdesk-dart-home
    cargo_home=/tmp/rustdesk-dart-cargo-home
    mkdir -p "$toolchain" "$home" "$cargo_home"
    tar -C "$toolchain" -xf "/online/rust-${RUSTDESK_RUST_VERSION}.tar.xz"
    tar -C "$toolchain" -xf "/online/flutter-${RUSTDESK_FLUTTER_VERSION}.tar.xz"
    rust_installers=("$toolchain"/rust-1.*/install.sh)
    [ "${#rust_installers[@]}" -eq 1 ] && [ -f "${rust_installers[0]}" ]
    "${rust_installers[0]}" --prefix="$toolchain/rustinstall" --disable-ldconfig \
      --components=rustc,cargo,rust-std-x86_64-unknown-linux-gnu,rustfmt-preview >/dev/null
    flutter_roots=("$toolchain"/flutter)
    [ "${#flutter_roots[@]}" -eq 1 ] && [ -x "${flutter_roots[0]}/bin/flutter" ]
    export HOME="$home" CARGO_HOME="$cargo_home" PUB_CACHE=/online/pub-cache CI=true
    export PATH="$toolchain/rustinstall/bin:${flutter_roots[0]}/bin:${flutter_roots[0]}/bin/cache/dart-sdk/bin:$PATH"
    {
      printf "[net]\noffline = true\n"
      sed "s#directory = .*#directory = \"/online/cargo-vendor\"#" /online/cargo-vendor-config.toml
    } >"$CARGO_HOME/config.toml"
    export VCPKG_ROOT=/online/vcpkg
    [ -d "$VCPKG_ROOT/installed/x64-linux/lib" ]
    export CARGO_TARGET_DIR=/src/.dart-verify-cargo-target CARGO_INCREMENTAL=0
    cargo_lock_before="$(sha256sum /src/Cargo.lock | awk "{print \$1}")"
    (cd "$toolchain/flutter/packages/flutter_tools" && dart pub get --offline --enforce-lockfile >/dev/null)
    cd /src/flutter
    lock_before="$(sha256sum pubspec.lock | awk "{print \$1}")"
    dart pub get --offline --enforce-lockfile >/dev/null
    lock_after="$(sha256sum pubspec.lock | awk "{print \$1}")"
    if [ "$lock_before" != "$lock_after" ]; then
      echo "DART-VERIFY: FAILED — dart pub get --offline rewrote flutter/pubspec.lock" >&2
      exit 1
    fi
    mobile_add_line="$(grep -nF "  Future<void> sessionAddMobile(" lib/generated_bridge.dart \
      | tail -n 1 | cut -d: -f1)"
    [ -n "$mobile_add_line" ] \
      || { echo "DART-VERIFY: FAILED — generated bridge lacks asynchronous mobile session add" >&2; exit 1; }
    mobile_add_impl="$(sed -n "${mobile_add_line},$((mobile_add_line + 90))p" lib/generated_bridge.dart)"
    printf "%s\n" "$mobile_add_impl" | grep -qF "_platform.executeNormal(FlutterRustBridgeTask(" \
      || { echo "DART-VERIFY: FAILED — mobile session add is not a normal worker-pool bridge call" >&2; exit 1; }
    if printf "%s\n" "$mobile_add_impl" | grep -qF "_platform.executeSync("; then
      echo "DART-VERIFY: FAILED — mobile session add regained synchronous UI-isolate execution" >&2
      exit 1
    fi
    display_selection_line="$(grep -nF "  Future<void> sessionSwitchDisplay(" lib/generated_bridge.dart \
      | tail -n 1 | cut -d: -f1)"
    [ -n "$display_selection_line" ] \
      || { echo "DART-VERIFY: FAILED — generated bridge lacks fallible display selection" >&2; exit 1; }
    display_selection_impl="$(sed -n "${display_selection_line},$((display_selection_line + 90))p" lib/generated_bridge.dart)"
    printf "%s\n" "$display_selection_impl" | grep -qF "required UuidValue clientOwnerId" \
      || { echo "DART-VERIFY: FAILED — generated display selection lacks the exact UI owner" >&2; exit 1; }
    printf "%s\n" "$display_selection_impl" | grep -qF "_platform.executeNormal(FlutterRustBridgeTask(" \
      || { echo "DART-VERIFY: FAILED — display selection is not a normal worker-pool bridge call" >&2; exit 1; }
    if printf "%s\n" "$display_selection_impl" | grep -qF "_platform.executeSync("; then
      echo "DART-VERIFY: FAILED — display selection moved onto the synchronous UI isolate" >&2
      exit 1
    fi
    if grep -qF "sessionStartWithDisplays" lib/generated_bridge.dart; then
      echo "DART-VERIFY: FAILED — generated bridge retained the second display-capture startup surface" >&2
      exit 1
    fi
    if grep -qE "GpuTexture|gpu_texture|AdapterLuid|adapter_luid|mainHasHwcodec|mainHasVram|main_has_hwcodec|main_has_vram" \
      lib/generated_bridge.dart lib/generated_bridge.freezed.dart; then
      echo "DART-VERIFY: FAILED — freshly generated bridge retained the retired GPU/VRAM presentation surface" >&2
      exit 1
    fi
    dart format --output=none --set-exit-if-changed \
      lib/models/model.dart \
      lib/models/file_model.dart \
      lib/desktop/pages/file_manager_page.dart \
      lib/mobile/pages/file_manager_page.dart \
      lib/models/desktop_render_texture.dart \
      lib/models/desktop_texture_lifecycle.dart \
      third_party/texture_rgba_renderer/lib/texture_rgba_renderer.dart \
      lib/models/mobile_session_start_queue.dart \
      lib/models/display_selection_queue.dart \
      lib/models/session_event_queue.dart \
      lib/models/session_stream_finality.dart \
      lib/models/presentation_recovery.dart \
      lib/models/rgba_publication_order.dart \
      lib/desktop/pages/remote_page.dart \
      lib/desktop/pages/view_camera_page.dart \
      lib/desktop/widgets/tabbar_widget.dart \
      lib/mobile/pages/remote_page.dart \
      lib/mobile/pages/view_camera_page.dart \
      lib/web/bridge.dart \
      test/desktop_texture_lifecycle_test.dart \
      test/mobile_session_start_queue_test.dart \
      test/display_selection_queue_test.dart \
      test/session_event_queue_test.dart \
      test/session_stream_finality_test.dart \
      test/presentation_recovery_test.dart \
      test/rgba_publication_order_test.dart \
      test/desktop_tab_retirement_test.dart \
      test/password_field_semantics_test.dart
    set +e
    out="$(flutter analyze --no-pub --no-fatal-infos --no-fatal-warnings lib/ 2>&1)"
    analyze_status=$?
    set -e
    errs="$(printf "%s\n" "$out" | grep -c "error •" || true)"
    echo "  lib/ analyze errors: $errs"
    if [ "$analyze_status" -ne 0 ] || [ "$errs" != "0" ]; then
      if [ "$errs" != "0" ]; then
        printf "%s\n" "$out" | grep "error •" || true
      else
        printf "%s\n" "$out" >&2
      fi
      echo "DART-VERIFY: FAILED — flutter analyze exited $analyze_status with $errs error diagnostic(s) in lib/" >&2
      exit 1
    fi
    flutter analyze --no-pub --no-fatal-infos --no-fatal-warnings \
      third_party/texture_rgba_renderer/lib/
    flutter analyze --no-pub --no-fatal-infos --no-fatal-warnings \
      third_party/desktop_multi_window/lib/
    flutter analyze --no-pub --no-fatal-infos --no-fatal-warnings \
      third_party/window_manager/lib/
    echo "  == R-SV10 flutter test: address_validator (bare-ID rejection) =="
    flutter test --no-pub test/address_validator_test.dart
    echo "  == R-G9 flutter test: saved-peer serialization contract =="
    flutter test --no-pub test/peer_model_test.dart
    echo "  == R-G4a flutter test: retired role-swap state is ignored =="
    flutter test --no-pub test/server_model_test.dart
    echo "  == R-S11eb flutter test: retired file timeout cannot remove replacement =="
    flutter test --no-pub test/mobile_file_session_lifecycle_test.dart
    echo "  == R-S11eo flutter test: mobile session preparation is bounded and latest-wins =="
    flutter test --no-pub test/mobile_session_start_queue_test.dart
    echo "  == R-S11go flutter test: display admission is ordered, bounded, and latest-wins =="
    flutter test --no-pub test/display_selection_queue_test.dart
    echo "  == R-S11gq flutter test: exact-session topology events are bounded and ordered =="
    flutter test --no-pub test/session_event_queue_test.dart
    echo "  == R-S11gr flutter test: web frames are exact-owner, bounded, and latest-wins =="
    flutter test --no-pub test/latest_frame_queue_test.dart
    echo "  == R-S11eo flutter test: expected close and unexpected stream failure stay distinct =="
    flutter test --no-pub test/session_stream_finality_test.dart
    echo "  == R-S11ex flutter test: desktop texture lifecycle exact finality =="
    flutter test --no-pub test/desktop_texture_lifecycle_test.dart
    echo "  == desktop tab removal awaits engine-backed resource retirement =="
    flutter test --no-pub test/desktop_tab_retirement_test.dart
    echo "  == viewer presentation recovery coalesces background and focus transitions =="
    flutter test --no-pub test/presentation_recovery_test.dart
    echo "  == R-S11fr software RGBA decode commits only the exact newest publication =="
    flutter test --no-pub test/rgba_publication_order_test.dart
    echo "  == R-S11gc obscured password fields retain enabled focused semantics =="
    flutter test --no-pub test/password_field_semantics_test.dart
    echo "  == R-S11ez Linux native texture callback retirement finality =="
    engine="${flutter_roots[0]}/bin/cache/artifacts/engine/linux-x64"
    plugin=/src/flutter/third_party/texture_rgba_renderer/linux
    [ -f "$engine/libflutter_linux_gtk.so" ]
    c++ -std=c++17 -Wall -Wextra -Werror -Wno-unused-parameter \
      -I"$engine" -I"$plugin" \
      "$plugin/test/texture_rgba_renderer_plugin_test.cc" \
      -L"$engine" -Wl,-rpath,"$engine" -lflutter_linux_gtk \
      $(pkg-config --cflags --libs gtk+-3.0) \
      -o /tmp/texture_rgba_renderer_plugin_test
    /tmp/texture_rgba_renderer_plugin_test
    echo "  == Linux URL-launcher shutdown does not recursively register channels =="
    url_launcher=/src/flutter/third_party/url_launcher_linux/linux
    c++ -std=c++17 -Wall -Wextra -Werror -Wno-unused-parameter \
      -I"$engine" -I"$url_launcher" -I"$url_launcher/include" \
      "$url_launcher/test/url_launcher_shutdown_test.cc" \
      "$url_launcher/messages.g.cc" \
      "$url_launcher/url_launcher_plugin.cc" \
      -L"$engine" -Wl,-rpath,"$engine" -lflutter_linux_gtk \
      $(pkg-config --cflags --libs gtk+-3.0) \
      -o /tmp/url_launcher_shutdown_test
    /tmp/url_launcher_shutdown_test
    echo "  == exact stock Linux URL-launcher disposal is rejected by the same regression =="
    upstream_url_launcher=/online/pub-cache/hosted/pub.dev/url_launcher_linux-3.2.1/linux
    printf '%s  %s\n' \
      '52cd2d6ef9bc4e1b28eca16d4593c06c52fbc4de3be8083230060c35c4b0db2d' \
      "$upstream_url_launcher/url_launcher_plugin.cc" | sha256sum -c -
    c++ -std=c++17 -Wall -Wextra -Werror -Wno-unused-parameter \
      -I"$engine" -I"$upstream_url_launcher" -I"$upstream_url_launcher/include" \
      "$url_launcher/test/url_launcher_shutdown_test.cc" \
      "$upstream_url_launcher/messages.g.cc" \
      "$upstream_url_launcher/url_launcher_plugin.cc" \
      -L"$engine" -Wl,-rpath,"$engine" -lflutter_linux_gtk \
      $(pkg-config --cflags --libs gtk+-3.0) \
      -o /tmp/url_launcher_upstream_test
    set +e
    /tmp/url_launcher_upstream_test >/tmp/url_launcher_upstream.out 2>&1
    upstream_status=$?
    set -e
    [ "$upstream_status" -eq 1 ] \
      || { echo "  FAIL URL launcher: exact stock disposal unexpectedly passed or crashed"; exit 1; }
    grep -qF 'FAIL: shutdown did not perform exactly one terminal reset per URL channel' \
      /tmp/url_launcher_upstream.out \
      || { echo "  FAIL URL launcher: exact stock disposal failed for the wrong reason"; exit 1; }
    echo "  == Linux window-manager rejects calls after its GTK window is destroyed =="
    window_manager=/src/flutter/third_party/window_manager/linux
    c++ -std=c++17 -Wall -Wextra -Werror -Wno-unused-parameter \
      -I"$engine" -I"$window_manager" -I"$window_manager/include" \
      "$window_manager/test/window_manager_shutdown_test.cc" \
      "$window_manager/window_manager_plugin.cc" \
      -L"$engine" -Wl,-rpath,"$engine" -lflutter_linux_gtk \
      $(pkg-config --cflags --libs gtk+-3.0) \
      -o /tmp/window_manager_shutdown_test
    /tmp/window_manager_shutdown_test
    echo "  == removing the destroyed-window guard is rejected by the same regression =="
    cp "$window_manager/window_manager_plugin.cc" /tmp/window_manager_guard_disabled.cc
    python3 -I -S - /tmp/window_manager_guard_disabled.cc <<PY
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
source = path.read_text(encoding="utf-8")
guard = """  if (get_window(self) == nullptr) {
    response = FL_METHOD_RESPONSE(fl_method_error_response_new(
        "window_unavailable", "The native window has already been destroyed.",
        nullptr));
    fl_method_call_respond(method_call, response, nullptr);
    return;
  }
"""
if source.count(guard) != 1:
    raise SystemExit("window-manager guard mutation cardinality differs")
path.write_text(source.replace(guard, "", 1), encoding="utf-8")
PY
    c++ -std=c++17 -Wall -Wextra -Werror -Wno-unused-parameter \
      -I"$engine" -I"$window_manager" -I"$window_manager/include" \
      "$window_manager/test/window_manager_shutdown_test.cc" \
      /tmp/window_manager_guard_disabled.cc \
      -L"$engine" -Wl,-rpath,"$engine" -lflutter_linux_gtk \
      $(pkg-config --cflags --libs gtk+-3.0) \
      -o /tmp/window_manager_guard_disabled_test
    set +e
    /tmp/window_manager_guard_disabled_test \
      >/tmp/window_manager_guard_disabled.out 2>&1
    guard_disabled_status=$?
    set -e
    [ "$guard_disabled_status" -eq 1 ] \
      || { echo "  FAIL window manager: guard-disabled source unexpectedly passed or crashed"; exit 1; }
    grep -qF 'FAIL: destroyed-window call was not rejected' \
      /tmp/window_manager_guard_disabled.out \
      || { echo "  FAIL window manager: guard-disabled source failed for the wrong reason"; exit 1; }
    echo "  == R-S11ez portable Windows texture callback-core retirement finality =="
    windows_plugin=/src/flutter/third_party/texture_rgba_renderer/windows
    c++ -std=c++17 -Wall -Wextra -Werror -Wno-unused-parameter \
      -I"$windows_plugin/test/include" -I"$windows_plugin" \
      "$windows_plugin/texture_rgba.cpp" \
      "$windows_plugin/test/texture_rgba_test.cc" \
      -o /tmp/texture_rgba_windows_core_test
    /tmp/texture_rgba_windows_core_test
    cd /src
    python3 scripts/verify-display-selection-finality.py --repo . --self-test
    rustfmt --edition 2021 --check \
      src/client.rs \
      src/client/io_loop.rs \
      src/flutter.rs \
      src/flutter_ffi.rs \
      src/ui_session_interface.rs
    echo "  == shipped Debian Rust library check: flutter,unix-file-copy-paste =="
    cargo check --offline --locked --features flutter,unix-file-copy-paste --lib --color never
    echo "  == R-S11eb generated-bridge mobile session lifecycle regressions =="
    cargo test --offline --locked --lib --features flutter,unix-file-copy-paste \
      flutter::mobile_session_lifecycle_tests:: -- --test-threads=1
    echo "  == R-S11ff generated-bridge exact-owner viewer refresh regression =="
    cargo test --offline --locked --lib --features flutter,unix-file-copy-paste \
      flutter::mobile_session_lifecycle_tests::r_s11ff_r_s11gs_video_refresh_derives_the_current_exact_ui_owner_displays -- --test-threads=1
    echo "  == R-S11gt generated-bridge explicit initial display-owner regressions =="
    cargo test --offline --locked --lib --features flutter,unix-file-copy-paste \
      flutter::mobile_session_lifecycle_tests::r_s11gt_ -- --test-threads=1
    echo "  == R-S11go generated-bridge ordered exact-owner display-selection finality regression =="
    cargo test --offline --locked --lib --features flutter,unix-file-copy-paste \
      r_s11go_ -- --test-threads=1
    echo "  == R-S11fr generated-bridge software RGBA recovery regressions =="
    cargo test --offline --locked --lib --features flutter,unix-file-copy-paste \
      flutter::mobile_session_lifecycle_tests::r_s11fr_ -- --test-threads=1
    echo "  == R-S11gf application-relative Linux texture-plugin load authority =="
    cargo test --offline --locked --lib --features flutter,unix-file-copy-paste \
      flutter::linux_texture_plugin_path_tests::r_s11gf_ -- --test-threads=1
    echo "  == R-S11fg/R-S11fh/R-S11fi/R-S11fj generated-bridge file writer, receive-persistence, and digest-inspection finality regressions =="
    cargo test --offline --locked -p hbb_common --lib \
      fs::tests::r_s11fg_read_step_returns_the_exact_file_frame_receipt -- --test-threads=1
    cargo test --offline --locked --lib --features flutter,unix-file-copy-paste \
      client::io_loop::tests::r_s11fg_ -- --test-threads=1
    cargo test --offline --locked --lib --features flutter,unix-file-copy-paste \
      server::connection::controlled_file_write_tests::r_s11fh_ -- --test-threads=1
    cargo test --offline --locked --lib --features flutter,unix-file-copy-paste \
      client::io_loop::tests::r_s11fi_ -- --test-threads=1
    cargo test --offline --locked --lib --features flutter,unix-file-copy-paste \
      client::io_loop::tests::r_s11fj_ -- --test-threads=1
    echo "  == R-S11ec outgoing clipboard exact-round lifecycle regression =="
    cargo test --offline --locked --lib --features flutter,unix-file-copy-paste \
      client::tests::clipboard_leases_track_exact_network_rounds_without_stale_stop -- --test-threads=1
    echo "  == R-S11ed delayed OS-password input exact-round lifecycle regression =="
    cargo test --offline --locked --lib --features flutter,unix-file-copy-paste \
      client::io_loop::tests::r_s11e148_os_password_input_is_cancelled_and_joined_before_round_replacement -- --test-threads=1
    echo "  == R-S11ee exact-session screenshot ownership regressions =="
    cargo test --offline --locked --lib --features flutter,unix-file-copy-paste \
      client::io_loop::tests::r_s11e149_screenshot_responses_require_the_current_exact_request -- --test-threads=1
    echo "  == R-S11ef controlled screenshot exact-owner/resource regressions =="
    cargo test --offline --locked --lib --features flutter,unix-file-copy-paste \
      server::video_service::screenshot_ownership_tests::r_s11ef_ -- --test-threads=1
    echo "  == R-S11eg controlled video acknowledgement exact-round regressions =="
    cargo test --offline --locked --lib --features flutter,unix-file-copy-paste \
      server::video_service::video_frame_ack_tests::r_s11eg_ -- --test-threads=1
    echo "  == R-S11fb/R-S11fk controlled video egress/local-TCP-boundary regressions =="
    cargo test --offline --locked --lib --features flutter,unix-file-copy-paste \
      server::video_service::video_frame_ack_tests::r_s11fb_ -- --test-threads=1
    cargo test --offline --locked --lib --features flutter,unix-file-copy-paste \
      server::video_service::video_frame_ack_tests::r_s11fl_ -- --test-threads=1
    cargo test --offline --locked --lib --features flutter,unix-file-copy-paste \
      server::connection::video_egress_tests::r_s11fb_ -- --test-threads=1
    cargo test --offline --locked --lib --features flutter,unix-file-copy-paste \
      r_s11fk_ -- --test-threads=1
    cargo test --offline --locked -p hbb_common \
      exact_video_receipt_wire_tests::r_s11fk_ -- --test-threads=1
    cargo test --offline --locked -p hbb_common \
      writer_receipt_tests::r_s11fb_ -- --test-threads=1
    cargo test --offline --locked -p hbb_common \
      writer_receipt_tests::r_s11fk_real_tcp_receipt_can_precede_peer_read -- --test-threads=1
    echo "  == R-S11eh bounded exact-subscriber audio egress regressions =="
    cargo test --offline --locked --lib --features flutter,unix-file-copy-paste \
      server::connection::audio_egress_tests::r_s11eh_ -- --test-threads=1
    cargo_lock_after="$(sha256sum Cargo.lock | awk "{print \$1}")"
    if [ "$cargo_lock_before" != "$cargo_lock_after" ]; then
      echo "DART-VERIFY: FAILED — cargo check rewrote Cargo.lock" >&2
      exit 1
    fi
  '

cd "$ANALYSIS_ROOT"
echo "== §19 / R-A6 Dart-layer grep (dead GUI tokens absent) =="
# Extends the R-A6/R-SV10 grep set into the Dart + asset layers (§19's CI hook). Each
# token names a UI surface whose backend §8/§18 removed; a non-comment hit fails the gate.
# Host-side (plain file content — no flutter needed). Grows as the §19 sweep proceeds.
dg_clean() { # token, label
  local tok="$1" label="$2" hits
  # exclude the FRB-GENERATED bridge (git-ignored, regenerated — not authored Dart)
  hits=$(grep -RInE "$tok" flutter/lib flutter/assets 2>/dev/null | grep -v '//' | grep -v 'generated_bridge' || true)
  if [ -n "$hits" ]; then
    echo "  FAIL §19: '$label' must be absent but is present:"; echo "$hits" | sed 's/^/      /'
    exit 1
  fi
  echo "  ok  $label absent"
}
# R-G3: the insecure/relay security-badge assets + states are deleted — the channel is
# ALWAYS secure+direct (§10 PAKE + R-SV4/R-D4), so a badge that could render "insecure"
# or "relayed" is both dead and a dangerous security MISLABEL. (secure.svg is the one kept.)
dg_clean 'insecure\.svg|secure_relay\.svg|insecure_relay\.svg' 'R-G3 insecure/relay security-badge assets'
# R-G3 (mobile): the literal-asset gate above is BLIND to DYNAMIC construction. The inherited mobile
# badge (model.dart getConnectionImageText) built `SvgPicture.asset('assets/$icon.svg')` where icon was
# a secure/insecure + _relay ternary — so the literal grep never saw the deleted insecure/relay names,
# yet at runtime a non-keyed/relayed peer-info would both MISLABEL the always-secure+direct channel and
# load a deleted asset. Assert the mobile connection badge is the HARDCODED secure asset, like the
# desktop tab-page badges (remote_tab_page.dart). (model.dart has no legit dynamic security `assets/$`.)
if grep -qE "SvgPicture\.asset\(\s*'assets/\\\$" flutter/lib/models/model.dart 2>/dev/null; then
  echo "  FAIL R-G3: model.dart builds a DYNAMIC 'assets/\$..svg' connection badge (channel-security mislabel + deleted-asset render)"; exit 1
fi
echo "  ok  R-G3 mobile connection badge hardcoded secure asset (no dynamic assets/\$ build in model.dart)"
# R-G4 / R-SV3 / §18: the startup version-check FFI trigger is gone — the app makes no
# api.rustdesk.com/version call at launch (the updater + version-check are excised).
dg_clean 'bind\.mainGetSoftwareUpdateUrl' 'R-G4/R-SV3 startup version-check FFI trigger'
# R-G4 / §18: the dead update GUI is removed — the desktop update card, the mobile
# _buildUpdateUI banner, and the UpdateProgress downloader widget (the file that issued the
# `download-new-version` / `update-me` FFI egress). None may reappear.
dg_clean '_buildUpdateUI|UpdateProgress|handleUpdate' 'R-G4 dead update widgets'
# R-G4 / R-SV3 / §18: the check-update / auto-update settings toggles are removed (the
# version-check + updater are excised, so the option keys back nothing).
dg_clean 'enable-check-update|allow-auto-update' 'R-G4/R-SV3 update-toggle option keys'
dg_clean 'Download new version|Click to upgrade|Auto update|Check for software update on startup|updateUrl' 'R-G4 update-UI state and strings'
# R-G4 / §19: the OIDC SSO provider-login is removed — the "Login with Google/GitHub/…" widgets
# (_IconOP / ButtonOP / WidgetOP / LoginWidgetOP / ConfigOP + kOpSvgList), the loginDialog
# third-auth section, queryOidcLoginOptions, and the auth-*.svg provider icons. A direct-IP fork
# has no account server and the account/API FFI is deleted. None may reappear.
dg_clean 'LoginWidgetOP|kOpSvgList|kAuthReqTypeOidc|queryOidcLoginOptions' 'R-G4 OIDC SSO provider-login widgets'
# R-G4 / R-SV6 / §18: the Flutter account/address-book API HTTP client family is deleted, not
# pointed at an empty host. This catches both the old account login methods and generic HTTP bridges.
dg_clean 'utils/http_service|package:http/http\.dart|http\.(get|post|put|delete|Client)|mainGetApiServer|mainAccountAuth|mainPostRequest|mainHttpRequest|mainGetHttpStatus|class LoginRequest|class LoginResponse|class RequestException|enum HttpType|logOut|log_out|apiServer|/api/login|/api/logout|/api/currentUser|/api/ab|/api/users|/api/peers|device-group/accessible|getHttpHeaders|decode_http_response' 'R-G4/R-SV6 Flutter account/address-book/logout HTTP client family'
if grep -qE 'logOut|log_out|apiServer|/api/logout' \
  flutter/lib/generated_bridge.dart flutter/lib/generated_bridge.freezed.dart; then
  echo "  FAIL R-SV6a: freshly generated bridge regained account logout/API-server presentation vocabulary"; exit 1
fi
echo "  ok  R-SV6a freshly generated bridge has no account logout/API-server presentation vocabulary"
# R-S11b-3n: the unused JSON whole-options FFI was the presentation half of the
# desktop whole-map IPC mutation. Option changes are one typed key/value operation,
# and freshly generated bindings must not recreate the deleted batch authority.
dg_clean 'mainSetOptions|main_set_options|wire_main_set_options' 'R-S11b-3n whole-options Flutter bridge'
if grep -qE 'mainSetOptions|main_set_options|wire_main_set_options' \
  flutter/lib/generated_bridge.dart flutter/lib/generated_bridge.freezed.dart; then
  echo "  FAIL R-S11b-3n: freshly generated bridge regained whole-options mutation authority"; exit 1
fi
echo "  ok  R-S11b-3n freshly generated bridge exposes no whole-options mutation"
# R-G4 / §19: the "Network"/server-config UI is deleted — config UI for the rendezvous / relay /
# api-server infrastructure the fork structurally removed. Desktop: the _Network/_NetworkState
# classes ("ID/Relay Server" editor + SOCKS proxy + WebSocket switch) + the SettingsTabKey.network
# enum value + its tabKeys include + both _settingTabs()/_children() switch cases. Mobile: the
# ID/Relay-Server + Socks5/Http(s)-Proxy SettingsTiles + the _hideServer/_hideProxy state. Plus the
# shared changeSocks5Proxy proxy-editor (desktop_setting_page) and showServerSettings dialog
# (mobile/widgets/dialog.dart) — both now uncalled. (The mobile "Use WebSocket" tile is a separate
# follow-on.) None may reappear.
dg_clean 'SettingsTabKey\.network|changeSocks5Proxy|void showServerSettings\(' 'R-G4 Network/server-config UI (tab + SOCKS + server dialog)'
# R-G4 / R-X4 / R-X6 / §19 (mobile sibling, now CLOSED): the MOBILE "ID/Relay Server" editor
# (showServerSettingsWithValue: id/relay/api-server + the trust-anchor `key`), its config-QR entry
# (showServerSettingFromQr in scan_page — the trust-anchor-injection path, same class as
# rustdesk://config), the clipboard import/export (ServerConfigImportExportWidgets), and the
# ServerConfig DTO + setServerConfig/importConfig writers are EXCISED. The desktop twin was already
# gone; this closes the last config-injection surface on any shipped front-end (the writes were
# already inert under the R-S16 pins / R-X4 baked anchor — editable-but-inert is the R-S12/R-G1 trap).
dg_clean 'showServerSettingsWithValue|showServerSettingFromQr|ServerConfigImportExportWidgets|setServerConfig|ID/Relay Server' 'R-G4 mobile server-config editor + config-QR (trust-anchor injection)'
# R-G1: the server/proxy visibility, Change-ID, and deep-link server-setting controls are gone.
# Their Dart aliases are not compatibility API: reject renamed raw-string replacements too.
dg_clean 'kOption(HideServerSetting|HideProxySetting|DisableChangeId|AllowDeepLinkServerSettings)|hide-server-settings|hide-proxy-settings|disable-change-id|allow-deep-link-server-settings' 'R-G1 dead Dart policy-option aliases'
# R-S11gc: the former Linux-Mint workaround wrapped every opted-in Linux text field in
# ExcludeSemantics. That widget intentionally drops its whole descendant semantics tree, so the
# real connect-password field reached AT-SPI as neither password-role nor enabled/focusable. The
# device-specific upstream freeze cannot be mitigated by making all Linux inputs inaccessible.
echo "== R-S11gc Linux text-field semantics remain present =="
if grep -RInF --include='*.dart' 'workaroundFreezeLinuxMint' flutter/lib >/dev/null; then
  echo "  FAIL R-S11gc: authored Dart retained the global Linux semantics exclusion"; exit 1
fi
grep -qF 'obscureText: obscureText,' flutter/lib/common/widgets/dialog.dart \
  || { echo "  FAIL R-S11gc: DialogTextField no longer forwards obscured state"; exit 1; }
grep -qF 'focusable: true,' flutter/lib/common/widgets/dialog.dart \
  || { echo "  FAIL R-S11gc: DialogTextField no longer exports focusability"; exit 1; }
grep -qF 'obscureText: !_passwordVisible,' flutter/lib/common/widgets/dialog.dart \
  || { echo "  FAIL R-S11gc: PasswordWidget no longer defaults to obscured state"; exit 1; }
for flag in isTextField isObscured hasEnabledState isEnabled isFocusable isFocused; do
  grep -qF "$flag: true" flutter/test/password_field_semantics_test.dart \
    || { echo "  FAIL R-S11gc: password semantics regression lacks $flag"; exit 1; }
done
grep -qF 'semanticsEnabled: true' flutter/test/password_field_semantics_test.dart \
  || { echo "  FAIL R-S11gc: password regression does not enable real semantics"; exit 1; }
echo "  ok  R-S11gc Linux password/text fields retain their real Flutter semantics"

echo "== desktop viewer teardown completes before Flutter engine destruction =="
for page in flutter/lib/desktop/pages/remote_page.dart \
  flutter/lib/desktop/pages/view_camera_page.dart; do
  grep -qF 'Future<void> prepareForRemoval({bool closeSession = true})' "$page" \
    || { echo "  FAIL desktop teardown: $page lacks explicit awaited cleanup"; exit 1; }
  grep -qF 'await _awaitCleanup('\''texture retirement'\'', textureDisposal);' "$page" \
    || { echo "  FAIL desktop teardown: $page does not await texture retirement"; exit 1; }
  grep -qF 'void dispose() {' "$page" \
    || { echo "  FAIL desktop teardown: $page retained asynchronous State.dispose"; exit 1; }
  if grep -qF 'Future<void> dispose() async' "$page"; then
    echo "  FAIL desktop teardown: $page has an unawaitable asynchronous State.dispose"; exit 1
  fi
done
grep -qF 'await onBeforeRemove?.call(tab, closeSession);' \
  flutter/lib/desktop/widgets/tabbar_widget.dart \
  || { echo "  FAIL desktop teardown: individual tab removal bypasses cleanup"; exit 1; }
grep -qF 'await Future.wait<void>(' flutter/lib/desktop/widgets/tabbar_widget.dart \
  || { echo "  FAIL desktop teardown: window-level tab cleanup is not awaited"; exit 1; }
grep -qF 'while (state.value.tabs.isNotEmpty) {' \
  flutter/lib/desktop/widgets/tabbar_widget.dart \
  || { echo "  FAIL desktop teardown: window cleanup does not drain tabs arriving during close"; exit 1; }
grep -qF 'await controller.closeAll();' flutter/lib/desktop/widgets/tabbar_widget.dart \
  || { echo "  FAIL desktop teardown: native window close bypasses tab cleanup"; exit 1; }
for tab_page in flutter/lib/desktop/pages/remote_tab_page.dart \
  flutter/lib/desktop/pages/view_camera_tab_page.dart; do
  grep -qF 'tabController.onBeforeRemove = _prepareTabForRemoval;' "$tab_page" \
    || { echo "  FAIL desktop teardown: $tab_page does not bind page cleanup"; exit 1; }
  grep -qF 'await tabController.closeAll();' "$tab_page" \
    || { echo "  FAIL desktop teardown: $tab_page does not await window cleanup"; exit 1; }
  if grep -qF 'tabController.clear();' "$tab_page"; then
    echo "  FAIL desktop teardown: $tab_page retained an unsafe synchronous clear"; exit 1
  fi
done
grep -qF "testWidgets('tab removal waits for exact resource retirement'" \
  flutter/test/desktop_tab_retirement_test.dart \
  || { echo "  FAIL desktop teardown: individual retirement regression is missing"; exit 1; }
grep -qF "testWidgets('window close retires every snapshotted tab before clearing'" \
  flutter/test/desktop_tab_retirement_test.dart \
  || { echo "  FAIL desktop teardown: window retirement regression is missing"; exit 1; }
grep -qF "expect(started, unorderedEquals(['first', 'second', 'late']));" \
  flutter/test/desktop_tab_retirement_test.dart \
  || { echo "  FAIL desktop teardown: late-arriving tab regression is missing"; exit 1; }
echo "  ok  desktop remote/view-camera resources retire before tab and engine destruction"

echo "== desktop multi-window waits for Dart cleanup response before owner retirement =="
multi_window=flutter/third_party/desktop_multi_window
grep -qF 'third_party/desktop_multi_window/** -text' flutter/.gitattributes \
  || { echo "  FAIL desktop multi-window: vendored bytes are subject to text conversion"; exit 1; }
grep -qF 'path: third_party/desktop_multi_window' flutter/pubspec.yaml \
  || { echo "  FAIL desktop multi-window: pubspec does not use the vendored plugin"; exit 1; }
grep -qF 'path: "third_party/desktop_multi_window"' flutter/pubspec.lock \
  || { echo "  FAIL desktop multi-window: lockfile does not bind the vendored plugin"; exit 1; }
grep -qF 'b47e8385e5a75d38319ad706a64b0ead3108b093' "$multi_window/UPSTREAM.md" \
  || { echo "  FAIL desktop multi-window: exact upstream provenance is absent"; exit 1; }
grep -qF 'waits for the method' "$multi_window/UPSTREAM.md" \
  && grep -qF 'response before scheduling the idle erase' "$multi_window/UPSTREAM.md" \
  || { echo "  FAIL desktop multi-window: native/Dart teardown deviation is unrecorded"; exit 1; }
grep -qF 'bool destroy_pending_ = false;' "$multi_window/linux/flutter_window.h" \
  || { echo "  FAIL desktop multi-window: close scheduling is not idempotent"; exit 1; }
grep -qF 'gulong releasedEmissionHook = 0;' "$multi_window/linux/flutter_window.h" \
  || { echo "  FAIL desktop multi-window: release-hook ownership is absent"; exit 1; }
grep -qF 'using CompletionHandler = std::function<void()>;' \
  "$multi_window/linux/window_channel.h" \
  || { echo "  FAIL desktop multi-window: Dart cleanup has no native completion contract"; exit 1; }
for token in \
  'struct SelfMethodInvokeAsyncUserData' \
  'fl_method_channel_invoke_method_finish(data->channel, res, &error);' \
  'auto completion = std::move(data->completion);' \
  'delete data;' \
  'completion();'; do
  grep -qF "$token" "$multi_window/linux/window_channel.cc" \
    || { echo "  FAIL desktop multi-window: missing response-completion stage: $token"; exit 1; }
done
for token in \
  'this->releasedEmissionHook = g_signal_add_emission_hook(' \
  'if (this->pressedEmissionHook != 0)' \
  'this->pressedEmissionHook);' \
  'if (this->releasedEmissionHook != 0)' \
  'this->releasedEmissionHook);'; do
  grep -qF "$token" "$multi_window/linux/flutter_window.cc" \
    || { echo "  FAIL desktop multi-window: unmatched GTK hook lifetime: $token"; exit 1; }
done
for token in \
  'gboolean destroyWindowWhenIdle(gpointer data)' \
  'pending->callback->OnWindowDestroy(pending->id);' \
  'if (self->destroy_pending_)' \
  'self->destroy_pending_ = true;' \
  'channel->InvokeMethodSelf("onDestroy", args, [callback, id]() {' \
  'g_idle_add_full(' \
  'new PendingWindowDestroy{callback, id}'; do
  grep -qF "$token" "$multi_window/linux/flutter_window.cc" \
    || { echo "  FAIL desktop multi-window: missing native lifetime stage: $token"; exit 1; }
done
if grep -qF 'InvokeMethodSelfVoid("onDestroy"' \
  "$multi_window/linux/flutter_window.cc"; then
  echo "  FAIL desktop multi-window: engine teardown does not await Dart cleanup"; exit 1
fi
if grep -qF 'callback->OnWindowDestroy(self->id_);' \
  "$multi_window/linux/flutter_window.cc"; then
  echo "  FAIL desktop multi-window: GTK callback still destroys its own owner"; exit 1
fi
if grep -qF 'callback->OnWindowDestroy(id);' \
  "$multi_window/linux/flutter_window.cc"; then
  echo "  FAIL desktop multi-window: GTK callback synchronously destroys its owner"; exit 1
fi
if grep -qF 'return self->isPreventClose;' \
  "$multi_window/linux/flutter_window.cc"; then
  echo "  FAIL desktop multi-window: GTK callback still reads its destroyed owner"; exit 1
fi
echo "  ok  desktop multi-window waits for Dart cleanup response before owner retirement"

echo "== Linux URL-launcher handlers retire without recursive engine-shutdown registration =="
url_launcher=flutter/third_party/url_launcher_linux
grep -qF 'third_party/url_launcher_linux/** -text' flutter/.gitattributes \
  || { echo "  FAIL URL launcher: vendored bytes are subject to text conversion"; exit 1; }
grep -qF 'path: third_party/url_launcher_linux' flutter/pubspec.yaml \
  || { echo "  FAIL URL launcher: override does not use the vendored plugin"; exit 1; }
grep -qF 'path: "third_party/url_launcher_linux"' flutter/pubspec.lock \
  || { echo "  FAIL URL launcher: lockfile does not bind the vendored plugin"; exit 1; }
grep -qF '4e9ba368772369e3e08f231d2301b4ef72b9ff87c31192ef471b380ef29a4935' \
  "$url_launcher/UPSTREAM.md" \
  || { echo "  FAIL URL launcher: exact hosted provenance is absent"; exit 1; }
grep -qF '52cd2d6ef9bc4e1b28eca16d4593c06c52fbc4de3be8083230060c35c4b0db2d' \
  "$url_launcher/UPSTREAM.md" \
  || { echo "  FAIL URL launcher: exact upstream Linux source identity is absent"; exit 1; }
if grep -qF 'ful_url_launcher_api_clear_method_handlers(' \
  "$url_launcher/linux/url_launcher_plugin.cc"; then
  echo "  FAIL URL launcher: plugin disposal recursively clears messenger handlers"; exit 1
fi
for token in \
  'FL_BINARY_MESSENGER_GET_IFACE(messenger)->shutdown(' \
  'messenger->handler_sets_during_shutdown == 2' \
  'weak_plugin == nullptr'; do
  grep -qF "$token" "$url_launcher/linux/test/url_launcher_shutdown_test.cc" \
    || { echo "  FAIL URL launcher: missing shutdown regression: $token"; exit 1; }
done
for token in \
  'upstream_url_launcher=/online/pub-cache/hosted/pub.dev/url_launcher_linux-3.2.1/linux' \
  '/tmp/url_launcher_upstream_test >/tmp/url_launcher_upstream.out 2>&1' \
  '[ "$upstream_status" -eq 1 ]' \
  'FAIL: shutdown did not perform exactly one terminal reset per URL channel'; do
  grep -qF "$token" scripts/dart-verify.sh \
    || { echo "  FAIL URL launcher: missing exact-stock negative control: $token"; exit 1; }
done
echo "  ok  Linux URL-launcher shutdown has one non-recursive handler owner"

echo "== Linux window-manager callbacks stop at GTK window destruction =="
window_manager=flutter/third_party/window_manager
grep -qF 'third_party/window_manager/** -text' flutter/.gitattributes \
  || { echo "  FAIL window manager: vendored bytes are subject to text conversion"; exit 1; }
grep -qF 'path: third_party/window_manager' flutter/pubspec.yaml \
  || { echo "  FAIL window manager: override does not use the vendored plugin"; exit 1; }
grep -qF 'path: "third_party/window_manager"' flutter/pubspec.lock \
  || { echo "  FAIL window manager: lockfile does not bind the vendored plugin"; exit 1; }
for asset in \
  'images/ic_chrome_close.png' \
  'images/ic_chrome_maximize.png' \
  'images/ic_chrome_minimize.png' \
  'images/ic_chrome_unmaximize.png'; do
  grep -qxF "!flutter/third_party/window_manager/$asset" .gitignore \
    || { echo "  FAIL window manager: shipped asset remains ignored: $asset"; exit 1; }
done
(
  cd "$window_manager"
  sha256sum -c - <<'EOF'
70fe0130bbbd928d04cd33a49ecde422ec54fd748b7a4e983f4e31be6e73f5f5  images/ic_chrome_close.png
93f2ed012ec01288b78ad4816ef254261e9ff25e8a9858359b45431c9a5de5f4  images/ic_chrome_maximize.png
0976edbb9977136544af17de125f345a41065694de92036d9365817ea6d8f05a  images/ic_chrome_minimize.png
3d375930c514ec2ebc0603ad1e1398b4daf458951042a97232d16f17e1c9603b  images/ic_chrome_unmaximize.png
EOF
) || { echo "  FAIL window manager: shipped asset identity mismatch"; exit 1; }
for token in \
  '85789bfe6e4cfaf4ecc00c52857467fdb7f26879' \
  '9627e63c85411da995da37cb7cd6d392766a509d' \
  '5b2a562f2e853cde3661468aea2a38fc9d1abef5e2fbd3befbc86831a7f7cd87'; do
  grep -qF "$token" "$window_manager/UPSTREAM.md" \
    || { echo "  FAIL window manager: exact upstream provenance is absent: $token"; exit 1; }
done
for token in \
  'GtkWindow* window;' \
  'gulong button_press_emission_hook;' \
  'g_signal_connect(window, "destroy", G_CALLBACK(on_window_destroy), plugin);' \
  'plugin->window = nullptr;' \
  '"window_unavailable"' \
  'g_signal_handlers_disconnect_by_data(self->window, self);' \
  'g_clear_object(&self->channel);' \
  'g_clear_object(&self->registrar);'; do
  grep -qF "$token" "$window_manager/linux/window_manager_plugin.cc" \
    || { echo "  FAIL window manager: missing native lifetime edge: $token"; exit 1; }
done
for token in \
  'gpointer weak_plugin =' \
  'window_manager_plugin_register_with_registrar_for_window(' \
  'g_object_add_weak_pointer(G_OBJECT(weak_plugin), &weak_plugin);' \
  'messenger->handler_sets_during_shutdown == 0' \
  'FL_IS_METHOD_ERROR_RESPONSE(response)' \
  'g_strcmp0(code, "window_unavailable") == 0' \
  'weak_plugin == nullptr'; do
  grep -qF "$token" "$window_manager/linux/test/window_manager_shutdown_test.cc" \
    || { echo "  FAIL window manager: missing native regression edge: $token"; exit 1; }
done
for token in \
  '/tmp/window_manager_shutdown_test' \
  '/tmp/window_manager_guard_disabled_test' \
  '[ "$guard_disabled_status" -eq 1 ]' \
  'FAIL: destroyed-window call was not rejected'; do
  grep -qF "$token" scripts/dart-verify.sh \
    || { echo "  FAIL window manager: missing confined behavior gate: $token"; exit 1; }
done
for token in \
  'Timer? _initialMaximizedTimer;' \
  '_initialMaximizedTimer?.cancel();' \
  'if (!mounted || stateGlobal.isMaximized.value == maximized)' \
  'if (mounted) {'; do
  grep -qF "$token" flutter/lib/desktop/widgets/tabbar_widget.dart \
    || { echo "  FAIL window manager: delayed Dart callback outlives its widget: $token"; exit 1; }
done
echo "  ok  Linux window-manager callbacks stop at GTK window destruction"

# R-G2/R-SV5: numeric IDs are not viewer identities. Keep the authored Flutter API, connect choke
# point, autocomplete, and peer rendering on one exact direct-address model. In particular, never
# delete interior spaces: doing so changes an invalid target into a different target before validation.
echo "== R-G2/R-SV5 direct-address UI model and exact-target preservation =="
direct_address_fail=
[ ! -e flutter/lib/common/formatter/id_formatter.dart ] \
  || direct_address_fail="$direct_address_fail legacy-id-formatter-file-present"
if grep -RInE --include='*.dart' 'IDTextEditingController|IDTextInputFormatter|formatID|trimID' \
  flutter/lib >/dev/null; then
  direct_address_fail="$direct_address_fail legacy-numeric-id-api-present"
fi
grep -qF 'class DirectAddressTextEditingController extends TextEditingController' \
  flutter/lib/common/formatter/direct_address.dart \
  || direct_address_fail="$direct_address_fail direct-address-controller-missing"
grep -qF 'String normalizeDirectAddress(String address) => address.trim();' \
  flutter/lib/common/formatter/direct_address.dart \
  || direct_address_fail="$direct_address_fail outer-whitespace-only-normalizer-missing"
if grep -nF "replaceAll(' ', '')" flutter/lib/common.dart \
  flutter/lib/common/formatter/direct_address.dart flutter/lib/desktop/pages/connection_page.dart \
  flutter/lib/mobile/pages/connection_page.dart >/dev/null \
  || grep -nF 'replaceAll(" ", "")' flutter/lib/common.dart \
  flutter/lib/common/formatter/direct_address.dart flutter/lib/desktop/pages/connection_page.dart \
  flutter/lib/mobile/pages/connection_page.dart >/dev/null; then
  direct_address_fail="$direct_address_fail all-space-deletion-present"
fi
grep -qF 'connect(BuildContext context, String address,' flutter/lib/common.dart \
  || direct_address_fail="$direct_address_fail address-choke-point-signature-missing"
grep -qF 'address = normalizeDirectAddress(address);' flutter/lib/common.dart \
  || direct_address_fail="$direct_address_fail pre-validation-normalization-missing"
grep -qF '? widget.peer.id' flutter/lib/common/widgets/autocomplete.dart \
  || direct_address_fail="$direct_address_fail raw-autocomplete-address-display-missing"
[ "$(grep -Fc 'peer.alias.isEmpty ? peer.id : peer.alias' flutter/lib/common/widgets/peer_card.dart)" -eq 3 ] \
  || direct_address_fail="$direct_address_fail raw-peer-address-display-inventory-wrong"
grep -qF "const malformedIpv4 = '192. 168.1.10';" flutter/test/address_validator_test.dart \
  || direct_address_fail="$direct_address_fail interior-whitespace-regression-missing"
if [ -n "$direct_address_fail" ]; then
  echo "  FAIL R-G2/R-SV5 direct-address UI closure:$direct_address_fail"; exit 1
fi
echo "  ok  R-G2/R-SV5 direct-address controller/choke point preserve exact targets and peer UI shows raw addresses"
# R-G4 / R-SV6a / §18: Android device deployment is structurally absent through UI and bridge.
dg_clean 'showDeployDialog|showDeployPromptDialog|deploy_dialog|android_needs_deploy|mainDeployDevice' 'R-G4/R-SV6a Android device-deploy UI and bridge ABI'
# R-G4 / R-SV6 / §19: the desktop "Account" settings tab is deleted — the _Account/_AccountState
# classes (the rustdesk-account login/logout panel) + the SettingsTabKey.account enum value + its
# tabKeys include + both _settingTabs()/_children() switch cases. A direct-IP fork has no account
# server (account/OIDC compiled out, R-SV6); the account is no longer a configurable concept. The
# loginDialog/UserModel/toolbar+mobile account entry points are the rest of the account sweep. No
# desktop Account tab may reappear.
dg_clean 'SettingsTabKey\.account' 'R-G4 desktop Account settings tab'
# R-X2 / R-G4 / §19: the desktop "Plugin" settings tab is deleted — the native-plugin loader is
# excised (R-X2: mod plugin / plugin_framework absent) and plugin_feature_is_enabled() is pinned
# SyncReturn(false), so the tab was always hidden + dead. Removed the _Plugin/_PluginState classes
# (incl. the "login to use plugins" loginDialog button) + the SettingsTabKey.plugin enum value +
# its tabKeys include + both switch cases. (The plugin_feature_is_enabled FFI stub stays — a
# flutter-verify trim follow-on.) No desktop Plugin tab may reappear.
dg_clean 'SettingsTabKey\.plugin|class _Plugin\b' 'R-X2/R-G4 dead Plugin settings tab'
# R-SV6c / R-G / R-D: no authored or generated Dart surface may carry rendezvous peer-presence
# state, queries, callbacks, timers, sorting, or the retired generic connect-status bridge.
dg_clean 'queryOnlines|query_onlines|callback_query_onlines|_updateOnlineState|_getOnlineStates|UpdateEvent\.online|PeerSortType\.status|_startCheckOnlines|_queryOnlines|getOnline\(|mainGetConnectStatus|mainCheckConnectStatus|OnlineStatusWidget|connectStatus|status_num' 'R-SV6c rendezvous peer-presence and compatibility status plane'
if grep -qE 'queryOnlines|query_onlines|callback_query_onlines|mainGetConnectStatus|mainCheckConnectStatus|status_num' \
  flutter/lib/generated_bridge.dart; then
  echo "  FAIL R-SV6c: freshly generated bridge regained a retired peer-presence/status operation"; exit 1
fi
if grep -qE 'VisibilityDetector|WindowListener|_curPeers|_lastQueryPeers' flutter/lib/common/widgets/peers_view.dart; then
  echo "  FAIL R-SV6c: peer list regained presence-only visibility or lifecycle tracking"; exit 1
fi
if grep -qE 'bool[[:space:]]+online([[:space:]]|=)' flutter/lib/models/peer_model.dart; then
  echo "  FAIL R-SV6c: saved-peer model regained rendezvous online state"; exit 1
fi
# R-G9: the account/address-book synchronizer was the only same-server provenance consumer.
# Historical peer JSON may contain the key, but the local saved-peer DTO ignores it and never
# reserializes it. The controlled-side Client parser likewise has no duplicate policy booleans;
# those live only on the authenticated Rust Connection and in the viewer Permission protocol.
if grep -qE 'sameServer|same_server' flutter/lib/models/peer_model.dart; then
  echo "  FAIL R-G9: saved-peer model retained retired cloud provenance"; exit 1
fi
grep -qF "expect(serialized, isNot(contains('same_server')));" flutter/test/peer_model_test.dart \
  || { echo "  FAIL R-G9: saved-peer legacy-key serialization regression is missing"; exit 1; }
for field in restart recording block_input; do
  if grep -qF "json['$field']" flutter/lib/models/server_model.dart; then
    echo "  FAIL R-G9: controlled-side Flutter Client parses duplicate $field policy"; exit 1
  fi
done
echo "  ok  R-G9 saved-peer cloud provenance and duplicate CM policy fields are absent"
# R-G4a: switch-sides was deleted, so authored/generated Flutter must not preserve an event,
# method, UUID, or CM presentation field for that nonexistent role transition. Historical CM JSON
# is ignored and never reserialized.
dg_clean 'SwitchSides|SwitchBack|switch_sides|switchSides|switch_back|switchBack|switch_uuid|switchUuid|from_switch|fromSwitch' 'R-G4a retired switch-sides role-swap state and API'
if grep -qE 'SwitchSides|SwitchBack|switch_sides|switchSides|switch_back|switchBack|switch_uuid|switchUuid|from_switch|fromSwitch' \
  flutter/lib/generated_bridge.dart; then
  echo "  FAIL R-G4a: freshly generated bridge regained retired switch-sides role-swap state"; exit 1
fi
grep -qF "'from_switch': true" flutter/test/server_model_test.dart \
  || { echo "  FAIL R-G4a: historical role-swap JSON fixture is missing"; exit 1; }
grep -qF "expect(serialized, isNot(contains('from_switch')));" flutter/test/server_model_test.dart \
  || { echo "  FAIL R-G4a: role-swap serialization-absence regression is missing"; exit 1; }
echo "  ok  R-G4a authored/generated Flutter has no role-swap API/state and ignores historical from_switch JSON"
grep -qF 'Future<void> mainStartStatusSync' flutter/lib/generated_bridge.dart \
  || { echo "  FAIL R-SV6c: generated bridge lacks typed main status-sync operation"; exit 1; }
grep -qF 'await bind.mainStartStatusSync();' flutter/lib/main.dart \
  || { echo "  FAIL R-SV6c: desktop main does not start typed status synchronization"; exit 1; }
grep -qF 'class DirectListenerStatusWidget extends StatefulWidget' flutter/lib/desktop/pages/connection_page.dart \
  || { echo "  FAIL R-SV6c: explicit direct-listener status widget is missing"; exit 1; }
grep -qF "mainGetCommon(key: 'direct-listener-bound')" flutter/lib/desktop/pages/connection_page.dart \
  || { echo "  FAIL R-SV6c: status widget lost real listener-bound authority"; exit 1; }
grep -qF "mainGetCommon(key: 'permanent-password-set')" flutter/lib/desktop/pages/connection_page.dart \
  || { echo "  FAIL R-SV6c: status widget lost password-provisioning reason"; exit 1; }
if grep -RInE 'isPresetPassword|is_preset_password|buildPresetPasswordWarning|preset_password_warning|preset-password-in-use-tip|remove-preset-password-warning|local-permanent-password-set' \
  flutter/lib >/dev/null; then
  echo "  FAIL R-S11b-3q: authored/generated Dart retained a preset/local password compatibility surface"; exit 1
fi
echo "  ok  R-S11b-3q Dart exposes one PRS-derived permanent-password status and no preset/local subtype"
# R-SV6d / R-G / R-D: public/custom rendezvous classification has no meaning in a direct-only
# product. Reject authored comments/aliases as well as code, then inspect the freshly generated ABI.
dg_clean 'using_public_server|usingPublicServer|mainIsUsingPublicServer|is_using_public_server' 'R-SV6d public/custom-rendezvous selection state'
if grep -RInE --include='*.dart' --exclude='generated_bridge.dart' \
  'using_public_server|usingPublicServer|mainIsUsingPublicServer|is_using_public_server' flutter/lib >/dev/null; then
  echo "  FAIL R-SV6d: authored Dart regained public/custom-rendezvous state or an explanatory scar"; exit 1
fi
if grep -qE 'using_public_server|usingPublicServer|mainIsUsingPublicServer|is_using_public_server' \
  flutter/lib/generated_bridge.dart; then
  echo "  FAIL R-SV6d: freshly generated bridge regained public/custom-rendezvous state"; exit 1
fi
grep -qF "bool hideFps = versionCmp(ffi.ffiModel.pi.version, '1.2.0') < 0;" \
  flutter/lib/common/widgets/dialog.dart \
  || { echo "  FAIL R-SV6d: custom-FPS presentation is not peer-version-only"; exit 1; }
grep -qF "bool hideMoreQuality = versionCmp(ffi.ffiModel.pi.version, '1.2.2') < 0;" \
  flutter/lib/common/widgets/dialog.dart \
  || { echo "  FAIL R-SV6d: extended-quality presentation is not peer-version-only"; exit 1; }
if grep -qE '_queryInterval|Duration\(seconds: (6|20)\)' flutter/lib/common/widgets/peers_view.dart; then
  echo "  FAIL R-SV6d: saved peers regained a public/custom rendezvous polling cadence"; exit 1
fi
# R-G8 / §19 (de-brand): a sovereign fork advertises no upstream brand — the user-facing
# rustdesk.com links are removed (the About/website "rustdesk.com" + "powered by" badge, the
# Privacy Statement / EULA privacy.html links, the macOS/Linux permission-card docs "Help"
# links). Gate the privacy + docs URL paths (the `rustdesk.com/pricing` in the dead
# "use public server" guide goes with the R-G2 server-UI removal). Only `//` comments name them.
dg_clean 'rustdesk\.com/privacy|rustdesk\.com/docs' 'R-G8 rustdesk.com privacy/docs links'
# R-G8 / §19 (de-brand): the desktop About tab dropped the upstream marketing slogan
# (translate('Slogan_tip') = "Made with heart in this chaotic world!") in favour of the honest
# fork identity ("RustDesk Hardened Fork"). The Slogan_tip lang key is also deleted from all 51
# lang tables (verify.sh R-A6). The AGPL Purslane Ltd. copyright line above it is PRESERVED — this
# gate targets only the marketing tagline. No live translate() may reference it again (only the
# `//` de-brand comment names it, which dg_clean excludes).
dg_clean 'Slogan_tip' 'R-G8 About-tab marketing slogan'
# R-X12 / R-G8 / §19: the Wayland-keyboard prompt machinery is excised. The fork is X11-pinned
# (R-X12), so a controlled peer is never Wayland (current_is_wayland() is false on the §17 Xorg box,
# and fork-to-fork is the only PAKE-compatible topology) — the "Wayland keyboard input" warning was
# DEAD, and it carried an upstream github "learn more" link (github.com/rustdesk/.../issues/14586 —
# a de-brand miss). Removed across toolbar.dart (the dialog + helpers + the menu items) and both
# remote_page.dart gate/normalizer machineries; keyboardInputAllowed defaults true so the keyboard
# is unaffected. None may reappear (only `//` comments name these).
dg_clean 'kWaylandKeyboardIssueUrl|showWaylandKeyboardInputWarningDialog|shouldShowWaylandKeyboardPrompt|kPeerOptionAllowWaylandKeyboard|issues/14586' 'R-X12/R-G8 dead Wayland-keyboard prompt + upstream link'
# R-S18 / R-X8 / §19: the viewer never solicits OS credentials to push to the host. The
# host-triggered os-login dialogs (enterUserLoginDialog / enterUserLoginAndPasswordDialog, fed
# by the session-login / terminal-admin-login msgbox prompts) AND the os-username/os-password
# fields in the connect dialog (_connectDialog's osUsernameController / osPasswordController)
# are deleted — the responder strips os_login (R-X14/0685c28) and create_login_msg no longer
# sends it (R-S18), so the UI that collected the operator's OS creds is structurally gone.
dg_clean 'enterUserLoginDialog|enterUserLoginAndPasswordDialog|osUsernameController|osPasswordController' 'R-S18/R-X8 viewer os-login dialog (OS-credential push UI)'
# The web bridge is authored Dart, not generated FRB glue. It must not carry second-credential
# login fields or peer-triggered elevation-with-logon senders either.
dg_clean '\bosUsername\b|\bosPassword\b|\bos_username\b|\bos_password\b|sessionElevateWithLogon|elevate_with_logon' 'R-S18/R-X9 authored Dart/web OS-credential bridge senders'
# R-G6 / R-SV4: the relay-fallback peer-card actions ("Always connect via relay", its
# force-always-relay option) and the Wake-on-LAN action are dead on a direct-only fork (no
# relay; WoL is the R-SV4(c) accepted loss). The relay-hint dialog the Rust core fed is gone
# too (the core now emits a plain error, R-G6). All removed at the widget, not greyed (R-G1).
dg_clean '_forceAlwaysRelayAction|_isForceAlwaysRelay|kOptionForceAlwaysRelay|_wolAction|showRelayHintDialog' 'R-G6 relay-fallback + WoL peer-card actions'
# R-G6 / R-X6 / R-SV4: stale relay-route syntax (`/r`, `/r@server`) is rejected, never stripped.
# The old authored-Dart path called mainHandleRelayId and carried forceRelay through page/window
# constructors. The direct-only API has no compatibility relay choice: after FRB regeneration the
# authored, web, and generated bridges must all be free of that parameter.
if grep -RInE 'mainHandleRelayId' flutter/lib --include='*.dart' 2>/dev/null \
    | grep -v 'generated_bridge.dart' | grep -v 'web/bridge.dart' >/dev/null; then
  echo "  FAIL R-G6/R-X6: authored Dart still calls mainHandleRelayId (relay suffix strip path)"; exit 1
fi
relay_hits=$(grep -RInE 'forceRelay|_forceRelay' flutter/lib --include='*.dart' 2>/dev/null || true)
if [ -n "$relay_hits" ]; then
  echo "  FAIL R-SV4a: Dart/FRB still carries a relay-choice parameter:"; echo "$relay_hits" | sed 's/^/      /'
  exit 1
fi
if grep -RInE '"forceRelay"|'\''forceRelay'\''' flutter/lib --include='*.dart' 2>/dev/null \
    >/dev/null; then
  echo "  FAIL R-SV4a: Dart still serializes/deserializes a forceRelay window field"; exit 1
fi
grep -qF "uri.path == '/r' || uri.path.startsWith('/r@')" flutter/lib/common.dart \
  || { echo "  FAIL R-G6/R-X6: urlLinkToCmdArgs no longer rejects /r and /r@ relay deep links"; exit 1; }
grep -qF "hasRelayRouteSyntax" flutter/lib/common/formatter/direct_address.dart \
  || { echo "  FAIL R-G6/R-SV4: direct-address validator lost relay-route rejection"; exit 1; }
echo "  ok  R-G6/R-X6/R-SV4a relay suffixes rejected and relay-choice ABI absent"
# R-G2 / R-G8 / §19: the connection-status row's rendezvous strings — connecting_status ("Connecting
# to the RustDesk network…") and not_ready_status — are repurposed away: the controlled side just
# shows direct-listener reachability, so neither is rendered on desktop (DirectListenerStatusWidget) or mobile
# (server_page ConnectionStateNotification). Neither may reappear as a rendered string (the keys carry
# the R-G8 upstream-brand "RustDesk network" nomenclature). Closes the audit's P3 dead-lang-key gap.
dg_clean 'connecting_status|not_ready_status' 'R-G2/R-G8 rendezvous status-row strings'
# R-X7 / R-G4 / R-G1 (the one-time-password UI is fully excised, not greyed): R-X7 removed the
# TEMPORARY_PASSWORD backend and R-S16 pins verification-method=use-permanent-password, so the
# rotating-OTP surface is dead. The desktop home board's OTP label+refresh (buildPasswordBoard2,
# 2173710), the mobile "Your Device" card password row (1a383c1), and the server_model
# OTP-length/numeric-mode state + its refresh sync are all removed — the permanent password is the
# sole credential. No hand-written Dart may call the OTP-refresh FFI or read the excised OTP-state
# getters. (The FRB binding DEFINES mainUpdateTemporaryPassword and web/bridge stubs it — neither is
# authored Dart; the `bind.`/`.`-access patterns match CALLERS, not those definitions.)
dg_clean 'bind\.mainUpdateTemporaryPassword|\.temporaryPasswordLength|\.allowNumericOneTimePassword' 'R-X7/R-G4 one-time-password UI + OTP-state (refresh FFI caller + length/numeric getters)'

# R-G1 / §19 (terminal legibility — all platforms, client/viewer render): the Terminal (Beta) is a
# PRESERVED session type (R-X8), so unlike the surfaces above it is KEPT — but its xterm TerminalView
# MUST render on an OPAQUE background. Upstream shipped `backgroundOpacity: 0.7`, compositing xterm's
# dark default theme (bg #1E1E1E / fg #CCCCCC — no `theme:` is passed) over the app Scaffold; on a
# light theme that dropped terminal text contrast to ~3.8:1, below WCAG AA (4.5:1). The terminal owns
# the whole surface, so translucency has no function; it MUST stay opaque so legibility is independent
# of the app theme by construction. Both render sites are gated — mobile (Android + iOS) and desktop
# (Windows/Linux/macOS) — so the translucent value cannot creep back on any platform.
for tp in flutter/lib/mobile/pages/terminal_page.dart flutter/lib/desktop/pages/terminal_page.dart; do
  # a translucent value (0.x, or a bare .x) must never return to the terminal surface
  if grep -nE 'backgroundOpacity:[[:space:]]*[0.]' "$tp" >/dev/null 2>&1; then
    echo "  FAIL §19 terminal: translucent TerminalView backgroundOpacity in $tp (MUST be opaque 1.0 — WCAG contrast):"
    grep -nE 'backgroundOpacity:[[:space:]]*[0.]' "$tp" | sed 's/^/      /'
    exit 1
  fi
  # …and the opaque value MUST be asserted explicitly (not silently dropped to a library default)
  grep -qE 'backgroundOpacity:[[:space:]]*1' "$tp" \
    || { echo "  FAIL §19 terminal: $tp lost its explicit opaque backgroundOpacity (expected 1.0)"; exit 1; }
done
echo "  ok  §19 terminal TerminalView backgroundOpacity opaque (1.0) — desktop + mobile (WCAG contrast)"

cd "$REPO_ROOT"
verify_private_online_snapshot "$ONLINE_SNAPSHOT_PARENT"
SOURCE_DIGEST_AFTER="$(archive_current_source | sha256sum | awk '{print $1}')"
[ "$SOURCE_DIGEST_AFTER" = "$SOURCE_DIGEST" ] \
  || die "dart-verify detected a change in the real source worktree"
echo "DART-VERIFY: Flutter analyze/test + shipped-feature Rust check are GREEN; §19 greps clean; source worktree unchanged"
