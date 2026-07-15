#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

SCRIPT_DIR="$PWD/scripts"
# shellcheck source=scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"
load_pins
require_cmd docker readlink stat
require_online_complete
require_pinned_builder_image android-builder "$ANDROID_BUILDER_IMAGE_ID"

repo="$(readlink -f -- "$REPO_ROOT")"
online="$(readlink -f -- "$ONLINE_DIR")"
[ "$repo" = "$REPO_ROOT" ] || die "repository root must be canonical"
[ "$online" = "$ONLINE_DIR" ] || die "online closure must be canonical"

docker run --rm --pull=never --network=none --read-only \
    --user "$(id -u):$(id -g)" \
    --cap-drop=ALL \
    --security-opt no-new-privileges \
    --tmpfs /tmp:rw,nosuid,nodev,mode=1777 \
    -e SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH_PIN" \
    -e RUSTDESK_CANARY_OFFLINE=1 \
    -e APK_MODE=rust-check \
    -v "$repo:/src" \
    -v "$online:/online:ro" \
    -w /src \
    "$ANDROID_BUILDER_IMAGE_ID" \
    /bin/bash /src/scripts/android-apk-build.sh

require_online_complete
echo "ANDROID-RUST-CHECK: aarch64 Android Rust library is GREEN"
